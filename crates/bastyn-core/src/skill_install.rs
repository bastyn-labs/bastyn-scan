//! Finding "download and run" commands in the text of a skill.
//!
//! [`candidates`] reads shell and PowerShell command lines out of Markdown
//! prose, fenced code blocks and script files, and reports the position of each
//! download command whose result is run without a check:
//!
//! - **piped**: `curl URL | sh`, `wget -qO- URL | sudo bash -s`,
//!   `irm URL | iex`;
//! - **substituted**: `bash <(curl URL)`, `sh -c "$(curl URL)"`,
//!   `eval "$(curl URL)"`, `iex (irm URL)`;
//! - **saved then run**: a script or executable downloaded to a named file that
//!   a later command in the same block runs, with no checksum or signature
//!   command in between;
//! - **cloned then run**: `git clone URL` followed in the same block by an
//!   `install`, `setup` or `bootstrap` script.
//!
//! Every shape needs a literal `http://` or `https://` URL on the download
//! command, so a download whose address is a variable is never reported. A
//! command is only reported when it can be read as written; anything the reader
//! cannot follow (a pipeline with a further stage, a quoted argument it cannot
//! split) is left alone, which can only make it miss a command, never invent
//! one. Whether the surrounding text refuses or quotes the command is decided by
//! the caller, which owns that machinery.

/// Which shape of download-and-run a candidate has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shape {
    /// The download's output is piped into a shell or interpreter.
    Piped,
    /// The download's output is handed to a shell or interpreter through
    /// command or process substitution.
    Substituted,
    /// A script or executable is downloaded to a file that is then run.
    SavedThenRun,
    /// A repository is cloned and its install script is then run.
    ClonedThenRun,
}

impl Shape {
    /// A phrase naming the shape, for the finding text.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::Piped => "a download piped into a shell or interpreter",
            Self::Substituted => "a download passed to a shell or interpreter",
            Self::SavedThenRun => "a file downloaded from a URL and then run",
            Self::ClonedThenRun => "a cloned repository whose install script is then run",
        }
    }
}

/// One download command that is run without a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Candidate {
    /// Byte offset in the original text of the download command word.
    pub(crate) offset: usize,
    /// How the download is run.
    pub(crate) shape: Shape,
}

/// Text that, on a command line or between a download and its run, shows the
/// download is checked first. Lowercase substrings.
pub(crate) const VERIFICATION_MARKERS: &[&str] = &[
    "sha256sum",
    "sha512sum",
    "sha1sum",
    "md5sum",
    "shasum",
    "gpg --verify",
    "gpg2 --verify",
    "gpgv ",
    "cosign verify",
    "minisign",
    "signify -v",
    "get-filehash",
    "get-authenticodesignature",
    "certutil -hashfile",
    "openssl dgst",
    "openssl sha",
    "checksum",
    "slsa-verifier",
    "attestation verify",
    "git verify-",
    "review the installer",
    "review the script",
    "inspect the installer",
    "inspect the script",
    "read the installer",
    "read the script",
];

/// File extensions of a downloaded file that count as a script or program.
const RUNNABLE_EXTENSIONS: &[&str] = &[
    "sh", "bash", "zsh", "ps1", "bat", "cmd", "exe", "msi", "run", "py",
];

/// Names (without extension) of an install script in a cloned repository.
const INSTALL_SCRIPT_STEMS: &[&str] = &["install", "setup", "bootstrap"];

/// Extensions an install script in a cloned repository can have.
const INSTALL_SCRIPT_EXTENSIONS: &[&str] = &["sh", "bash", "ps1", "bat", "cmd"];

/// Words that start a download command.
const DOWNLOAD_COMMANDS: &[&str] = &[
    "curl",
    "curl.exe",
    "wget",
    "wget.exe",
    "iwr",
    "irm",
    "invoke-webrequest",
    "invoke-restmethod",
];

/// Shells that run a script read from standard input or a substitution.
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ash", "ksh"];

/// Interpreters that run a program read from standard input.
const INTERPRETERS: &[&str] = &["python", "python2", "python3", "perl", "ruby", "node"];

/// One command line, after joining continuation lines.
struct LogicalLine {
    text: String,
    /// `(offset in text, offset in the original)` where a physical line starts.
    spans: Vec<(usize, usize)>,
    /// Lines of one fenced block, or of one paragraph, share a block number.
    block: usize,
}

impl LogicalLine {
    /// The offset in the original text of `at` in this line.
    fn original(&self, at: usize) -> usize {
        let index = self.spans.partition_point(|&(start, _)| start <= at);
        let (start, original) = self.spans[index.saturating_sub(1)];
        original + (at - start)
    }
}

/// True if `text` ends in a character that continues the command on the next
/// line. A trailing `|` or `&&` continues a command only inside a code block,
/// where a table row would not end in one.
fn continues(text: &str, in_fence: bool) -> bool {
    let trimmed = text.trim_end();
    trimmed.ends_with('\\')
        || (in_fence
            && (trimmed.ends_with('|') || trimmed.ends_with("&&") || trimmed.ends_with("||")))
}

/// Split `contents` into command lines, joining a continuation, and number the
/// blocks: a fence line or (outside a fence) a blank line starts a new block.
fn logical_lines(contents: &str) -> Vec<LogicalLine> {
    let mut physical: Vec<(usize, &str)> = Vec::new();
    let mut start = 0;
    for line in contents.split_inclusive('\n') {
        physical.push((start, line.trim_end_matches(['\n', '\r'])));
        start += line.len();
    }

    let mut lines = Vec::new();
    let mut block = 0usize;
    let mut fence: Option<char> = None;
    let mut index = 0;
    while index < physical.len() {
        let (line_start, line) = physical[index];
        index += 1;
        if let Some(marker) = crate::skill::fence_marker(line) {
            match fence {
                None => fence = Some(marker),
                Some(open) if open == marker => fence = None,
                Some(_) => {}
            }
            block += 1;
            continue;
        }
        if line.trim().is_empty() {
            if fence.is_none() {
                block += 1;
            }
            continue;
        }
        let mut text = line.to_owned();
        let mut spans = vec![(0, line_start)];
        let mut joined = 0;
        while joined < 8 && continues(&text, fence.is_some()) && index < physical.len() {
            let (next_start, next) = physical[index];
            if next.trim().is_empty() || crate::skill::fence_marker(next).is_some() {
                break;
            }
            index += 1;
            joined += 1;
            let trimmed = text.trim_end();
            let keep = trimmed.strip_suffix('\\').unwrap_or(trimmed).len();
            text.truncate(keep);
            text.push(' ');
            let skipped = next.len() - next.trim_start().len();
            spans.push((text.len(), next_start + skipped));
            text.push_str(next.trim_start());
        }
        lines.push(LogicalLine { text, spans, block });
    }
    lines
}

/// True if `word` is `keyword`, ignoring ASCII case.
fn is_word(word: &str, keyword: &str) -> bool {
    word.eq_ignore_ascii_case(keyword)
}

/// A word with the quoting, brackets and prose punctuation around it removed.
fn clean(word: &str) -> &str {
    word.trim_matches(|c: char| {
        matches!(
            c,
            '"' | '\'' | '`' | '(' | ')' | ',' | ';' | '<' | '>' | '[' | ']' | '{' | '}'
        )
    })
}

/// The file name in a path or URL, lowercase.
fn base_name(path: &str) -> String {
    let path = clean(path);
    let path = path.split(['?', '#']).next().unwrap_or(path);
    path.rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase()
}

/// The lowercase extension of a file name, if it has one.
fn extension(name: &str) -> Option<&str> {
    let (stem, extension) = name.rsplit_once('.')?;
    (!stem.is_empty()).then_some(extension)
}

/// True if `word` is a literal `http` or `https` URL that names a host outside
/// the machine: a dotted name that is not `localhost`, a loopback or wildcard
/// address, or a reserved documentation host.
fn is_remote_url(word: &str) -> bool {
    let lower = clean(word).to_ascii_lowercase();
    let Some(rest) = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"))
    else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    let valid = host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && host.starts_with(|c: char| c.is_ascii_alphanumeric())
        && host.contains('.')
        && !host.ends_with('.');
    let local = host.starts_with("127.")
        || host == "0.0.0.0"
        || host == "localhost"
        || host.ends_with(".localhost");
    let reserved = ["example.com", "example.org", "example.net"]
        .iter()
        .any(|name| host == *name || host.ends_with(&format!(".{name}")));
    valid && !local && !reserved
}

/// Where the arguments of a command end, and what ended them.
struct Segment {
    /// Byte offset of the first character after the arguments.
    end: usize,
    /// The character that ended them, or `None` at the end of the line.
    stop: Option<char>,
    /// The file the output is redirected to, for `> file`.
    redirect: Option<String>,
}

/// Scan from `from` to the end of the command: an unquoted `|`, `&`, `;`, `)`,
/// backtick, or the end of the line. A `>` that is not part of a numbered or
/// `&>` redirection ends the command and names the file the output goes to.
fn segment(text: &str, from: usize) -> Segment {
    let bytes = text.as_bytes();
    let mut quote: Option<u8> = None;
    let mut at = from;
    while at < bytes.len() {
        let byte = bytes[at];
        if let Some(open) = quote {
            if byte == open {
                quote = None;
            }
            at += 1;
            continue;
        }
        match byte {
            b'"' | b'\'' => quote = Some(byte),
            b'|' | b'&' | b';' | b')' | b'`' => {
                return Segment {
                    end: at,
                    stop: Some(char::from(byte)),
                    redirect: None,
                };
            }
            b'>' => {
                let previous = at.checked_sub(1).map(|p| bytes[p]);
                let numbered = previous.is_some_and(|p| p.is_ascii_digit() || p == b'&');
                let after = text[at + 1..].trim_start_matches(['>', ' ']);
                let target = after.split_whitespace().next().unwrap_or("");
                if numbered || target.starts_with('&') {
                    at += 1 + (text.len() - (at + 1) - after.len()) + target.len();
                    continue;
                }
                return Segment {
                    end: at,
                    stop: Some('>'),
                    redirect: Some(clean(target).to_owned()),
                };
            }
            _ => {}
        }
        at += 1;
    }
    Segment {
        end: bytes.len(),
        stop: None,
        redirect: None,
    }
}

/// A download command found in a line.
struct Download<'a> {
    /// Offset of the command word in the line.
    start: usize,
    /// The command word, lowercase, without `.exe`.
    program: String,
    /// The arguments up to the end of the command.
    words: Vec<&'a str>,
    segment: Segment,
}

impl Download<'_> {
    fn url(&self) -> Option<&str> {
        self.words
            .iter()
            .map(|word| clean(word))
            .find(|word| is_remote_url(word))
    }

    /// True if the command writes the response to standard output.
    fn writes_to_stdout(&self) -> bool {
        match self.program.as_str() {
            "curl" => !self.words.iter().any(|word| {
                let is_flag = word.starts_with('-') && !word.starts_with("--");
                (is_flag && word[1..].contains(['o', 'O']))
                    || word.starts_with("--output")
                    || *word == "--remote-name"
            }),
            "wget" => {
                self.words.iter().enumerate().any(|(index, word)| {
                    let short = word.starts_with('-') && !word.starts_with("--");
                    (short && word.ends_with("O-"))
                        || (short
                            && word.ends_with('O')
                            && self.words.get(index + 1).is_some_and(|next| *next == "-"))
                        || *word == "--output-document=-"
                }) && self.segment.redirect.is_none()
            }
            _ => {
                !self
                    .words
                    .iter()
                    .any(|word| is_word(word, "-outfile") || is_word(word, "-o"))
                    && self.segment.redirect.is_none()
            }
        }
    }

    /// The file the response is saved to, when the command saves one.
    fn saved_file(&self) -> Option<String> {
        let url = self.url()?;
        let url_name = base_name(url);
        let next = |index: usize| self.words.get(index + 1).map(|word| clean(word));
        match self.program.as_str() {
            "curl" => {
                for (index, word) in self.words.iter().enumerate() {
                    let short = word.starts_with('-') && !word.starts_with("--");
                    if (short && word[1..].contains('o')) || *word == "--output" {
                        return next(index).filter(|name| *name != "-").map(base_name);
                    }
                    if let Some(name) = word.strip_prefix("--output=") {
                        return Some(base_name(name));
                    }
                    if (short && word[1..].contains('O')) || *word == "--remote-name" {
                        return Some(url_name).filter(|name| !name.is_empty());
                    }
                }
                self.segment.redirect.as_deref().map(base_name)
            }
            "wget" => {
                for (index, word) in self.words.iter().enumerate() {
                    let short = word.starts_with('-') && !word.starts_with("--");
                    if (short && word.ends_with('O')) || *word == "--output-document" {
                        return next(index).filter(|name| *name != "-").map(base_name);
                    }
                    if let Some(name) = word.strip_prefix("--output-document=") {
                        return Some(base_name(name)).filter(|name| name != "-");
                    }
                }
                if self.words.iter().any(|word| word.contains("O-")) {
                    return None;
                }
                Some(url_name).filter(|name| !name.is_empty())
            }
            _ => {
                for (index, word) in self.words.iter().enumerate() {
                    if is_word(word, "-outfile") || is_word(word, "-o") {
                        return next(index).map(base_name);
                    }
                }
                None
            }
        }
    }
}

/// The offsets of every download command in `text`, with its program word.
fn download_commands(text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut previous: Option<char> = None;
    for (at, ch) in text.char_indices() {
        let word_start =
            previous.is_none_or(|p| !p.is_alphanumeric() && !matches!(p, '-' | '_' | '.'));
        previous = Some(ch);
        if !word_start || !ch.is_ascii_alphabetic() {
            continue;
        }
        let rest = &text[at..];
        let end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
        let word = &rest[..end];
        if let Some(program) = DOWNLOAD_COMMANDS.iter().find(|name| is_word(word, name)) {
            let program = program.strip_suffix(".exe").unwrap_or(program);
            found.push((at, program.to_ascii_lowercase()));
        }
    }
    found
}

/// Read the download command at `start`.
fn read_download<'a>(text: &'a str, start: usize, program: &str) -> Download<'a> {
    let after = text[start..]
        .find(char::is_whitespace)
        .map_or(text.len(), |n| start + n);
    let segment = segment(text, after);
    let words = text[after..segment.end].split_whitespace().collect();
    Download {
        start,
        program: program.to_owned(),
        words,
        segment,
    }
}

/// True if `word` names a shell (with any directory).
fn shell_name(word: &str) -> Option<&'static str> {
    let name = clean(word).rsplit('/').next().unwrap_or("");
    SHELLS.iter().find(|shell| is_word(name, shell)).copied()
}

/// True if the command that starts `words` runs a program it reads from
/// standard input: a shell given no script, `-s`, `-` or `--`, a language
/// interpreter given no program or `-`, or PowerShell's `iex`.
fn reads_a_program_from_input(words: &[&str]) -> bool {
    let mut words = words.iter().map(|word| clean(word)).peekable();
    // Skip a privilege or environment wrapper.
    while let Some(&word) = words.peek() {
        if is_word(word, "sudo") {
            words.next();
            while let Some(&flag) = words.peek() {
                if !flag.starts_with('-') {
                    break;
                }
                words.next();
                if matches!(flag, "-u" | "-g") {
                    words.next();
                }
            }
        } else if is_word(word, "env") || is_word(word, "time") || is_word(word, "nohup") {
            words.next();
            while words.peek().is_some_and(|w| w.contains('=')) {
                words.next();
            }
        } else {
            break;
        }
    }
    let Some(program) = words.next() else {
        return false;
    };
    if is_word(program, "iex") || is_word(program, "invoke-expression") {
        return true;
    }
    let name = program.rsplit('/').next().unwrap_or(program);
    let first = words.next();
    if SHELLS.iter().any(|shell| is_word(name, shell)) {
        return match first {
            None => true,
            Some(flag) => {
                matches!(
                    flag,
                    "-" | "--" | "-e" | "-x" | "-ex" | "-xe" | "-eu" | "-ue" | "-l"
                ) || flag.starts_with("-s")
            }
        };
    }
    let interpreter = INTERPRETERS.iter().any(|candidate| {
        name.len() >= candidate.len()
            && is_word(&name[..candidate.len()], candidate)
            && name[candidate.len()..]
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.')
    });
    interpreter && matches!(first, None | Some("-"))
}

/// True if the text before a download command hands what follows to a shell or
/// interpreter: `bash <(`, `sh -c "$(`, `eval "$(`, `. <(`, `iex (`.
fn substituted_into_interpreter(prefix: &str) -> bool {
    let mut rest = prefix.trim_end();
    let mut opened = false;
    loop {
        let before = rest;
        for opener in ["$(", "<(", "(", "`"] {
            if let Some(stripped) = rest.strip_suffix(opener) {
                rest = stripped.trim_end();
                opened = true;
            }
        }
        if rest == before {
            break;
        }
    }
    if !opened {
        return false;
    }
    let rest = rest.trim_end_matches(['"', '\'']).trim_end();
    let rest = rest.strip_suffix("-c").map_or(rest, str::trim_end);
    let Some(word) = rest.split_whitespace().next_back() else {
        return false;
    };
    let word = clean(word);
    let name = word.rsplit('/').next().unwrap_or(word);
    shell_name(word).is_some()
        || matches!(name, "." | "source" | "eval")
        || is_word(name, "iex")
        || is_word(name, "invoke-expression")
}

/// True if a single `|` follows `from` in `text`, allowing the closing
/// parentheses and `.Property` chain of `(iwr URL).Content | iex`. Returns the
/// offset just after the pipe.
fn pipe_after(text: &str, from: usize) -> Option<usize> {
    for (offset, ch) in text[from..].char_indices() {
        match ch {
            '|' => {
                let after = from + offset + 1;
                return (!text[after..].starts_with('|')).then_some(after);
            }
            ')' | '.' | ' ' => {}
            c if c.is_ascii_alphanumeric() => {}
            _ => return None,
        }
    }
    None
}

/// The words of the command after a pipe, up to the end of its arguments or the
/// first backtick.
fn piped_command(text: &str, after_pipe: usize) -> Vec<&str> {
    let rest = &text[after_pipe..];
    let end = rest
        .find(['`', ';', '&', '|', ')', '>', '<'])
        .unwrap_or(rest.len());
    rest[..end].split_whitespace().collect()
}

/// True if `text` carries a marker that the download is checked.
fn has_verification(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    VERIFICATION_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

/// The words of every command in `text`: split at `&&`, `||`, `;` and `|`, with
/// a leading prompt, wrapper or call operator removed from each.
fn commands(text: &str) -> Vec<(usize, Vec<&str>)> {
    let mut found = Vec::new();
    let mut start = 0;
    let bytes = text.as_bytes();
    let mut quote: Option<u8> = None;
    let mut at = 0;
    let mut flush = |from: usize, to: usize| {
        let words: Vec<&str> = text[from..to].split_whitespace().collect();
        if !words.is_empty() {
            found.push((from, words));
        }
    };
    while at < bytes.len() {
        let byte = bytes[at];
        match quote {
            Some(open) => {
                if byte == open {
                    quote = None;
                }
            }
            None => match byte {
                b'"' | b'\'' => quote = Some(byte),
                b'&' | b'|' | b';' | b'(' | b')' => {
                    flush(start, at);
                    start = at + 1;
                }
                _ => {}
            },
        }
        at += 1;
    }
    flush(start, bytes.len());
    found
}

/// The program word and its arguments of a command, after a prompt marker,
/// `sudo`, `exec`, `call` or `time` and backticks around the first word.
fn program_and_args<'a>(words: &[&'a str]) -> Option<(&'a str, Vec<&'a str>)> {
    let mut index = 0;
    while let Some(word) = words.get(index) {
        let bare = clean(word);
        if matches!(bare, "" | "$" | "#" | "%" | ">")
            || is_word(bare, "ps>")
            || ["sudo", "exec", "call", "time", "nohup"]
                .iter()
                .any(|wrapper| is_word(bare, wrapper))
        {
            index += 1;
            while bare.eq_ignore_ascii_case("sudo")
                && words.get(index).is_some_and(|w| w.starts_with('-'))
            {
                index += 1;
            }
            continue;
        }
        break;
    }
    let program = clean(words.get(index)?);
    let args = words[index + 1..].to_vec();
    Some((program, args))
}

/// Programs that run a file named in their arguments.
const RUNNERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ash",
    "ksh",
    "source",
    ".",
    "python",
    "python2",
    "python3",
    "perl",
    "ruby",
    "node",
    "pwsh",
    "powershell",
    "powershell.exe",
    "msiexec",
    "msiexec.exe",
    "start-process",
    "start",
    "cmd",
    "cmd.exe",
];

/// The base names (lowercase) of the files a command line runs.
fn runs(text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for (offset, words) in commands(text) {
        let Some((program, args)) = program_and_args(&words) else {
            continue;
        };
        let name = base_name(program);
        let is_path = program.contains('/') || program.contains('\\') || program.starts_with('$');
        let runner = RUNNERS.iter().any(|runner| is_word(program, runner));
        if runner {
            for arg in args {
                found.push((offset, base_name(arg)));
            }
        } else if is_path || extension(&name).is_some() {
            found.push((offset, name));
        }
    }
    found
}

/// The directory name `git clone` creates, and its position.
fn clone_at(text: &str) -> Option<usize> {
    for (offset, words) in commands(text) {
        let Some((program, args)) = program_and_args(&words) else {
            continue;
        };
        if !is_word(program, "git") {
            continue;
        }
        let mut args = args.into_iter();
        if args.next().is_some_and(|word| is_word(word, "clone"))
            && args.any(|word| {
                let word = clean(word);
                is_remote_url(word) || word.starts_with("git@")
            })
        {
            return Some(offset);
        }
    }
    None
}

/// A 40-digit hexadecimal commit name given to `git checkout`.
fn pins_a_commit(text: &str) -> bool {
    commands(text).iter().any(|(_, words)| {
        words.windows(2).any(|pair| {
            is_word(pair[0], "checkout") && {
                let rev = clean(pair[1]);
                rev.len() == 40 && rev.chars().all(|c| c.is_ascii_hexdigit())
            }
        })
    })
}

/// Every download command in `contents` that is run unchecked, in order.
pub(crate) fn candidates(contents: &str) -> Vec<Candidate> {
    let lines = logical_lines(contents);
    let mut found = Vec::new();

    // State for the shapes that need two commands in one block.
    let mut block = usize::MAX;
    let mut saved: Vec<(String, usize)> = Vec::new();
    let mut cloned: Option<usize> = None;

    for line in &lines {
        if line.block != block {
            block = line.block;
            saved.clear();
            cloned = None;
        }
        let text = line.text.as_str();
        let verified = has_verification(text);
        if verified {
            saved.clear();
            cloned = None;
        }

        let downloads: Vec<Download<'_>> = download_commands(text)
            .into_iter()
            .map(|(start, program)| read_download(text, start, &program))
            .collect();

        // Piped and substituted: decided from this command alone.
        for download in &downloads {
            if let Some(shape) = direct_shape(text, download) {
                found.push(Candidate {
                    offset: line.original(download.start),
                    shape,
                });
            }
        }
        if let Some(candidate) = downloadstring_into_iex(line) {
            found.push(candidate);
        }

        if !verified {
            sequence(line, &downloads, &mut saved, &mut cloned, &mut found);
            if pins_a_commit(text) {
                cloned = None;
            }
        }
    }
    found.sort_by_key(|candidate| candidate.offset);
    found.dedup_by_key(|candidate| candidate.offset);
    found
}

/// The shape of a download whose output goes straight into a shell or
/// interpreter, decided from the one command line: a pipe, or a substitution.
fn direct_shape(text: &str, download: &Download<'_>) -> Option<Shape> {
    download.url()?;
    if !download.writes_to_stdout() {
        return None;
    }
    if substituted_into_interpreter(&text[..download.start]) {
        return (download.segment.stop == Some(')')).then_some(Shape::Substituted);
    }
    if !matches!(download.segment.stop, Some(')' | '|')) {
        return None;
    }
    let pipe = pipe_after(text, download.segment.end)?;
    reads_a_program_from_input(&piped_command(text, pipe)).then_some(Shape::Piped)
}

/// One step of a block, in the order it sits in a line.
enum Event {
    /// A runnable file is downloaded: its name and the original offset.
    Save(String, usize),
    /// A file is run: its name.
    Run(String),
    /// A repository is cloned: the original offset.
    Clone(usize),
}

/// True if `name` is an install script of a cloned repository.
fn is_install_script(name: &str) -> bool {
    name.rsplit_once('.').is_some_and(|(stem, extension)| {
        INSTALL_SCRIPT_STEMS.contains(&stem) && INSTALL_SCRIPT_EXTENSIONS.contains(&extension)
    })
}

/// Follow the downloads, clones and runs of one line against the earlier ones
/// in its block: a run of a file `saved` earlier, or of an install script after
/// a clone, is a candidate anchored at the download or the clone.
fn sequence(
    line: &LogicalLine,
    downloads: &[Download<'_>],
    saved: &mut Vec<(String, usize)>,
    cloned: &mut Option<usize>,
    found: &mut Vec<Candidate>,
) {
    let text = line.text.as_str();
    let runnable = |file: &str| extension(file).is_some_and(|e| RUNNABLE_EXTENSIONS.contains(&e));
    let mut events: Vec<(usize, Event)> = Vec::new();
    for download in downloads {
        let Some(name) = download.saved_file() else {
            continue;
        };
        let url_name = download.url().map(base_name).unwrap_or_default();
        if runnable(&name) || runnable(&url_name) {
            let original = line.original(download.start);
            events.push((download.start, Event::Save(name, original)));
        }
    }
    events.extend(
        runs(text)
            .into_iter()
            .map(|(at, name)| (at, Event::Run(name))),
    );
    if let Some(offset) = clone_at(text) {
        events.push((offset, Event::Clone(line.original(offset))));
    }
    events.sort_by_key(|(offset, _)| *offset);
    for (_, event) in events {
        match event {
            Event::Save(name, original) => saved.push((name, original)),
            Event::Clone(original) => *cloned = Some(original),
            Event::Run(name) => {
                if let Some(position) = saved.iter().position(|(file, _)| *file == name) {
                    let (_, offset) = saved.remove(position);
                    found.push(Candidate {
                        offset,
                        shape: Shape::SavedThenRun,
                    });
                } else if let (Some(offset), true) = (*cloned, is_install_script(&name)) {
                    *cloned = None;
                    found.push(Candidate {
                        offset,
                        shape: Shape::ClonedThenRun,
                    });
                }
            }
        }
    }
}

/// `iex ((New-Object Net.WebClient).DownloadString('URL'))` and its piped form:
/// a `DownloadString(` call on a remote URL in a line that also runs `iex` or
/// `Invoke-Expression`.
fn downloadstring_into_iex(line: &LogicalLine) -> Option<Candidate> {
    let lower = line.text.to_ascii_lowercase();
    let call = lower.find("downloadstring(")?;
    let argument = &line.text[call + "downloadstring(".len()..];
    let end = argument.find(')').unwrap_or(argument.len());
    if !argument[..end].split(',').next().is_some_and(is_remote_url) {
        return None;
    }
    let runs_iex = lower
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
        .any(|word| word == "iex" || word == "invoke-expression");
    runs_iex.then(|| Candidate {
        offset: line.original(call),
        shape: Shape::Piped,
    })
}
