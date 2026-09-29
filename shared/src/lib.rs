#![cfg_attr(not(feature = "build"), no_std)]

extern crate alloc;

use alloc::string::String;

pub mod search;

pub fn escape_html(text: &str) -> String {
    let mut html = String::with_capacity(text.len());
    escape_html_into(text, &mut html);
    html
}

pub fn escape_html_into(text: &str, html: &mut String) {
    let mut start = 0;
    for (index, byte) in text.bytes().enumerate() {
        let escaped = match byte {
            b'&' => "&amp;",
            b'<' => "&lt;",
            b'>' => "&gt;",
            b'"' => "&quot;",
            b'\'' => "&#39;",
            _ => continue,
        };
        html.push_str(&text[start..index]);
        html.push_str(escaped);
        start = index + 1;
    }
    html.push_str(&text[start..]);
}

#[cfg(feature = "build")]
mod content;
#[cfg(feature = "build")]
pub use content::*;
#[cfg(feature = "build")]
pub use search::normalize;
