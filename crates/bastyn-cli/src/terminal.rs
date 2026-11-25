//! Decisions about the terminal that colour and glyphs share.

use std::io::IsTerminal as _;

use bastyn_core::render::Glyphs;

use crate::cli::{Format, GlobalArgs};

/// Everything the terminal decisions are made from, gathered once.
///
/// One place asks the environment, so colour and glyphs cannot end up
/// disagreeing about what kind of terminal this is, and both decisions stay
/// testable without one.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TerminalInputs {
    pub(crate) no_color_flag: bool,
    pub(crate) no_color_env: bool,
    pub(crate) format: Format,
    pub(crate) stdout_is_tty: bool,
}

impl TerminalInputs {
    pub(crate) fn gathered(global: &GlobalArgs) -> Self {
        Self {
            no_color_flag: global.no_color,
            no_color_env: std::env::var_os("NO_COLOR").is_some(),
            format: global.format,
            stdout_is_tty: std::io::stdout().is_terminal(),
        }
    }
}

/// Whether to emit ANSI colour on the report.
///
/// `--no-color` wins, then `NO_COLOR` as the cross-tool convention, then
/// whether stdout is actually a terminal. The last one matters: `bastyn scan >
/// report.txt` should produce a readable file, not one peppered with escape
/// sequences, and a CI log should not be full of them either.
pub(crate) const fn color_decision(inputs: TerminalInputs) -> bool {
    inputs.stdout_is_tty
        && matches!(inputs.format, Format::Text)
        && !inputs.no_color_flag
        && !inputs.no_color_env
}

/// Whether the report may draw with Unicode.
///
/// A different question from colour, and it turns on a smaller set of inputs.
/// `--no-color` asks for plain text, not for a report that spells its ticks
/// `[ok]`; a terminal that renders colour renders a tick. What Unicode cannot
/// survive is going somewhere that is not a terminal at all — a log file, a CI
/// job's captured output, a pipe — or a `NO_COLOR` that, in practice, is set
/// by people whose terminal is the reason they set it.
pub(crate) const fn glyph_decision(inputs: TerminalInputs) -> Glyphs {
    if inputs.stdout_is_tty && !inputs.no_color_env {
        Glyphs::Unicode
    } else {
        Glyphs::Ascii
    }
}

#[cfg(test)]
mod tests {
    use super::{Glyphs, TerminalInputs, color_decision, glyph_decision};
    use crate::cli::Format;

    fn tty_text() -> TerminalInputs {
        TerminalInputs {
            no_color_flag: false,
            no_color_env: false,
            format: Format::Text,
            stdout_is_tty: true,
        }
    }

    #[test]
    fn colour_on_a_text_terminal() {
        assert!(color_decision(tty_text()));
    }

    #[test]
    fn no_colour_when_stdout_is_redirected() {
        // `bastyn scan > report.txt` must produce a readable file.
        let inputs = TerminalInputs {
            stdout_is_tty: false,
            ..tty_text()
        };
        assert!(!color_decision(inputs));
    }

    #[test]
    fn no_colour_for_machine_formats() {
        for format in [Format::Json, Format::Sarif] {
            let inputs = TerminalInputs {
                format,
                ..tty_text()
            };
            assert!(!color_decision(inputs), "{format:?} must never be coloured");
        }
    }

    #[test]
    fn no_color_flag_and_env_both_disable_colour() {
        assert!(!color_decision(TerminalInputs {
            no_color_flag: true,
            ..tty_text()
        }));
        assert!(!color_decision(TerminalInputs {
            no_color_env: true,
            ..tty_text()
        }));
    }

    /// A tick and a box-drawing rule survive a real terminal and mangle
    /// everywhere else, so the fallback turns on for everywhere else.
    #[test]
    fn unicode_only_on_a_terminal_that_did_not_ask_to_be_left_alone() {
        assert_eq!(glyph_decision(tty_text()), Glyphs::Unicode);

        assert_eq!(
            glyph_decision(TerminalInputs {
                stdout_is_tty: false,
                ..tty_text()
            }),
            Glyphs::Ascii,
            "a redirect or a CI log must get ASCII"
        );
        assert_eq!(
            glyph_decision(TerminalInputs {
                no_color_env: true,
                ..tty_text()
            }),
            Glyphs::Ascii,
            "NO_COLOR is usually set by someone whose terminal is the reason"
        );
    }

    /// `--no-color` asks for plain text, not for a report that spells its
    /// ticks `[ok]`.
    #[test]
    fn the_no_color_flag_does_not_take_the_glyphs_with_it() {
        let inputs = TerminalInputs {
            no_color_flag: true,
            ..tty_text()
        };
        assert!(!color_decision(inputs));
        assert_eq!(glyph_decision(inputs), Glyphs::Unicode);
    }
}
