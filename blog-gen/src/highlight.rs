//! Build-time syntax highlighting for fenced code blocks.
//!
//! Colours are emitted as CSS classes, not inline styles: the stylesheet keeps
//! ownership of the palette, so the light/dark toggle keeps working and the
//! browser never downloads a highlighter.

use syntect::{
    html::{ClassStyle, ClassedHTMLGenerator},
    parsing::{SyntaxReference, SyntaxSet},
    util::LinesWithEndings,
};

use crate::escape_html;

/// Scope atoms are generic words (`string`, `c`, `function`); the prefix keeps
/// them from colliding with the site's own class names.
const CLASS_STYLE: ClassStyle = ClassStyle::SpacedPrefixed { prefix: "hl-" };

pub struct Highlighter {
    syntaxes: SyntaxSet,
}

impl Highlighter {
    pub fn new() -> Self {
        Highlighter {
            syntaxes: SyntaxSet::load_defaults_newlines(),
        }
    }

    /// Renders one fenced block. An absent or unrecognised language degrades to
    /// plain escaped text rather than failing the build.
    pub fn block(&self, lang: Option<&str>, code: &str) -> String {
        let body = lang
            .and_then(|l| self.syntaxes.find_syntax_by_token(l))
            .and_then(|syntax| self.spans(syntax, code))
            .unwrap_or_else(|| escape_html(code));

        match lang {
            Some(l) => format!(
                "<pre><code class=\"language-{}\">{}</code></pre>\n",
                escape_html(l),
                body
            ),
            None => format!("<pre><code>{}</code></pre>\n", body),
        }
    }

    fn spans(&self, syntax: &SyntaxReference, code: &str) -> Option<String> {
        let mut generator =
            ClassedHTMLGenerator::new_with_class_style(syntax, &self.syntaxes, CLASS_STYLE);
        for line in LinesWithEndings::from(code) {
            generator
                .parse_html_for_line_which_includes_newline(line)
                .ok()?;
        }
        Some(generator.finalize())
    }
}

impl Default for Highlighter {
    fn default() -> Self {
        Self::new()
    }
}
