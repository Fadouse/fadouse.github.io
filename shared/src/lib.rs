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
    escape_bytes(text.as_bytes(), |part| {
        html.push_str(core::str::from_utf8(part).unwrap())
    });
}
pub fn escape_html_into_bytes(text: &[u8], html: &mut alloc::vec::Vec<u8>) {
    escape_bytes(text, |part| append_bytes(html, part));
}
#[inline(never)]
pub fn append_bytes(bytes: &mut alloc::vec::Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(value);
}
fn escape_bytes(text: &[u8], mut append: impl FnMut(&[u8])) {
    let mut start = 0;
    for (index, byte) in text.iter().enumerate() {
        let escaped: &[u8] = match byte {
            b'&' => b"&amp;",
            b'<' => b"&lt;",
            b'>' => b"&gt;",
            b'"' => b"&quot;",
            b'\'' => b"&#39;",
            _ => continue,
        };
        append(&text[start..index]);
        append(escaped);
        start = index + 1;
    }
    append(&text[start..]);
}

#[cfg(feature = "build")]
mod content;
#[cfg(feature = "build")]
pub use content::*;
#[cfg(feature = "build")]
pub use search::normalize;
