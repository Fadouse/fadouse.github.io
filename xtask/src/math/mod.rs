pub mod assets;
// Reference data: KaTeX v0.18.9, 71a7bc02435353b4ed2420bb7b904cae6a0231bc.
// Fonts, metrics, syntax tables and fixtures retain the adjacent MIT LICENSE.
mod ast;
mod data;
mod expand;
mod lexer;
mod parser;
mod render;
#[cfg(test)]
mod tests;

use expand::Macro;
use std::{collections::BTreeSet, fmt};

#[derive(Debug)]
pub struct Error {
    pub offset: usize,
    pub message: String,
}
impl Error {
    pub fn new(offset: usize, message: impl Into<String>) -> Self {
        Self {
            offset,
            message: message.into(),
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at formula byte {}", self.message, self.offset + 1)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Default)]
pub struct Renderer {
    globals: std::collections::BTreeMap<String, Macro>,
    equation_count: usize,
}
#[derive(Debug)]
pub struct Rendered {
    pub html: String,
    pub text: String,
    pub fonts: BTreeSet<String>,
}
impl Renderer {
    pub fn render(&mut self, source: &str, display: bool) -> Result<Rendered> {
        let mut parser = parser::Parser::new(source, display, &self.globals, self.equation_count)?;
        let tree = parser.parse()?;
        let rendered = render::render(&tree, source, display)?;
        self.globals = parser.global_macros();
        self.equation_count = parser.equation_count;
        Ok(rendered)
    }
}
