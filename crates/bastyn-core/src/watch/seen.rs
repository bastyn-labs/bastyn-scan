//! The keys of alerts that were delivered, kept across runs so a restart does
//! not repeat them.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::alert::hex;
use crate::reporting::state::{state_dir, write_private};

/// The most keys kept in memory and on disk.
pub const MAX_SEEN_KEYS: usize = 10_000;

/// Length of an alert key, in hex characters.
const KEY_LEN: usize = 64;

/// A file larger than this is not read: it is far beyond what
/// [`MAX_SEEN_KEYS`] keys occupy, so it is not ours.
const MAX_FILE_BYTES: u64 = (MAX_SEEN_KEYS as u64 + 16) * (KEY_LEN as u64 + 2);

/// The set of delivered alert keys for one watched root.
///
/// Persistence is best effort: a failure to read gives an empty set and a
/// failure to write is returned to the caller, which reports it and carries
/// on. The file holds one lowercase hex key per line, sorted.
#[derive(Debug, Clone, Default)]
pub struct SeenStore {
    keys: BTreeSet<String>,
    path: Option<PathBuf>,
}

impl SeenStore {
    /// A store that is never written to disk.
    #[must_use]
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// The store for `root`, loaded from the per-user state directory.
    ///
    /// The file is `watch-seen-<16 hex>.txt` where the hex is the start of the
    /// SHA-256 of the canonical root path, so two roots never share a file.
    /// With no usable state directory the store is memory only. `env` looks
    /// up an environment variable, as in
    /// [`state_dir`](crate::reporting::state::state_dir).
    #[must_use]
    pub fn for_root(root: &Path, env: &dyn Fn(&str) -> Option<OsString>) -> Self {
        let Some(dir) = state_dir(env) else {
            return Self::in_memory();
        };
        let canonical = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
        let digest = Sha256::digest(canonical.to_string_lossy().as_bytes());
        let name = format!("watch-seen-{}.txt", &hex(&digest)[..16]);
        Self::load(dir.join(name))
    }

    /// Loads the store at `path`, tolerating a missing, oversized or
    /// partly corrupt file: lines that are not a 64-character lowercase hex
    /// key are skipped.
    #[must_use]
    pub fn load(path: PathBuf) -> Self {
        let keys = read_keys(&path);
        Self {
            keys,
            path: Some(path),
        }
    }

    /// Whether `key` was delivered before.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.keys.contains(key)
    }

    /// How many keys are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether no key is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Records `key` and writes the file.
    ///
    /// The key is kept in memory even when the write fails. When the set is
    /// over [`MAX_SEEN_KEYS`], the lowest keys in sort order are dropped.
    ///
    /// # Errors
    ///
    /// The write error, when the state file could not be written.
    pub fn insert(&mut self, key: &str) -> io::Result<()> {
        self.keys.insert(key.to_owned());
        while self.keys.len() > MAX_SEEN_KEYS {
            self.keys.pop_first();
        }
        self.write()
    }

    fn write(&self) -> io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let mut text = String::with_capacity(self.keys.len() * (KEY_LEN + 1));
        for key in &self.keys {
            text.push_str(key);
            text.push('\n');
        }
        write_private(path, text.as_bytes())
    }
}

fn is_key(line: &str) -> bool {
    line.len() == KEY_LEN && line.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn read_keys(path: &Path) -> BTreeSet<String> {
    let too_big = std::fs::metadata(path).is_ok_and(|m| m.len() > MAX_FILE_BYTES);
    if too_big {
        return BTreeSet::new();
    }
    let Ok(text) = std::fs::read_to_string(path) else {
        return BTreeSet::new();
    };
    text.lines()
        .map(str::trim)
        .filter(|line| is_key(line))
        .take(MAX_SEEN_KEYS)
        .map(str::to_owned)
        .collect()
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "a failed assumption in a test should fail the test"
)]
mod tests {
    use super::*;

    use tempfile::TempDir;

    fn key(n: u8) -> String {
        format!("{n:02x}").repeat(32)
    }

    fn env_for(dir: &TempDir) -> impl Fn(&str) -> Option<OsString> + use<> {
        let base = dir.path().to_path_buf();
        move |name| (name == "XDG_STATE_HOME").then(|| base.clone().into_os_string())
    }

    #[test]
    fn round_trips_sorted_one_key_per_line() {
        let state = TempDir::new().unwrap();
        let root = TempDir::new().unwrap();
        let mut store = SeenStore::for_root(root.path(), &env_for(&state));
        store.insert(&key(2)).unwrap();
        store.insert(&key(1)).unwrap();

        let reloaded = SeenStore::for_root(root.path(), &env_for(&state));
        assert!(reloaded.contains(&key(1)) && reloaded.contains(&key(2)));
        assert_eq!(reloaded.len(), 2);

        let file = std::fs::read_dir(state.path().join("bastyn"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("watch-seen-")
            })
            .unwrap();
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(name.len(), "watch-seen-".len() + 16 + ".txt".len());
        let text = std::fs::read_to_string(file).unwrap();
        assert_eq!(text, format!("{}\n{}\n", key(1), key(2)));
    }

    #[test]
    fn garbage_lines_are_skipped() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seen.txt");
        let upper = "A".repeat(64);
        std::fs::write(
            &path,
            format!(
                "not a key\n{}\n\n{upper}\n{}\n\u{1b}[31m\n",
                key(3),
                "b".repeat(63)
            ),
        )
        .unwrap();
        let store = SeenStore::load(path);
        assert_eq!(store.len(), 1);
        assert!(store.contains(&key(3)));
    }

    #[test]
    fn non_utf8_and_missing_files_load_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seen.txt");
        assert!(SeenStore::load(path.clone()).is_empty());
        std::fs::write(&path, [0xff, 0xfe, 0x00]).unwrap();
        assert!(SeenStore::load(path).is_empty());
    }

    #[test]
    fn different_roots_use_different_files() {
        let state = TempDir::new().unwrap();
        let a = TempDir::new().unwrap();
        let b = TempDir::new().unwrap();
        let mut store = SeenStore::for_root(a.path(), &env_for(&state));
        store.insert(&key(1)).unwrap();
        assert!(SeenStore::for_root(b.path(), &env_for(&state)).is_empty());
    }

    #[test]
    fn without_a_state_directory_the_store_is_memory_only() {
        let root = TempDir::new().unwrap();
        let mut store = SeenStore::for_root(root.path(), &|_| None);
        store.insert(&key(1)).unwrap();
        assert!(store.contains(&key(1)));
    }

    #[test]
    fn the_set_is_capped() {
        let dir = TempDir::new().unwrap();
        let mut store = SeenStore::load(dir.path().join("seen.txt"));
        for n in 0..=MAX_SEEN_KEYS {
            store.keys.insert(format!("{n:064x}"));
        }
        store.insert(&key(9)).unwrap();
        assert_eq!(store.len(), MAX_SEEN_KEYS);
        assert!(store.contains(&key(9)));
        assert!(SeenStore::load(dir.path().join("seen.txt")).len() <= MAX_SEEN_KEYS);
    }

    #[test]
    fn a_failed_write_is_returned_and_the_key_is_kept() {
        let dir = TempDir::new().unwrap();
        // The parent of the state file is a regular file, so it cannot be created.
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, "x").unwrap();
        let mut store = SeenStore::load(blocker.join("seen.txt"));
        assert!(store.insert(&key(1)).is_err());
        assert!(store.contains(&key(1)));
    }
}
