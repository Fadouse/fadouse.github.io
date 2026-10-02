// Copyright (C) 2026 Fadouse
// SPDX-License-Identifier: GPL-3.0-only

use super::ast::{Class, Mode, Node};
use serde::Deserialize;
use std::{collections::BTreeMap, sync::OnceLock};

#[derive(Deserialize)]
pub struct Symbol(pub String, pub String, pub String);
pub fn symbols() -> &'static BTreeMap<String, Symbol> {
    static DATA: OnceLock<BTreeMap<String, Symbol>> = OnceLock::new();
    DATA.get_or_init(|| serde_json::from_str(include_str!("data/symbols.json")).unwrap())
}
pub fn macros() -> &'static BTreeMap<String, String> {
    static DATA: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    DATA.get_or_init(|| serde_json::from_str(include_str!("data/macros.json")).unwrap())
}
pub fn functions() -> &'static std::collections::BTreeSet<String> {
    static DATA: OnceLock<std::collections::BTreeSet<String>> = OnceLock::new();
    DATA.get_or_init(|| serde_json::from_str(include_str!("data/functions.json")).unwrap())
}
#[derive(Deserialize)]
pub struct FunctionFlags {
    pub text: bool,
    pub argument: bool,
}
pub fn function_flags(name: &str) -> Option<&'static FunctionFlags> {
    static DATA: OnceLock<BTreeMap<String, FunctionFlags>> = OnceLock::new();
    DATA.get_or_init(|| serde_json::from_str(include_str!("data/function-flags.json")).unwrap())
        .get(name)
}
pub fn metrics(font: &str, c: char) -> Option<[f64; 5]> {
    type Metrics = BTreeMap<String, BTreeMap<String, [f64; 5]>>;
    static DATA: OnceLock<Metrics> = OnceLock::new();
    DATA.get_or_init(|| serde_json::from_str(include_str!("data/metrics.json")).unwrap())
        .get(font)?
        .get(&(c as u32).to_string())
        .copied()
}
pub fn decomposed(c: char) -> Option<&'static str> {
    static DATA: OnceLock<BTreeMap<char, String>> = OnceLock::new();
    DATA.get_or_init(|| serde_json::from_str(include_str!("data/unicode.json")).unwrap())
        .get(&c)
        .map(String::as_str)
}
pub fn unicode_script(name: &str) -> Option<(String, bool)> {
    static DATA: OnceLock<BTreeMap<String, (String, bool)>> = OnceLock::new();
    DATA.get_or_init(|| serde_json::from_str(include_str!("data/scripts.json")).unwrap())
        .get(name)
        .cloned()
}
pub fn accent(c: char, mode: Mode) -> Option<&'static str> {
    let (text, math) = match c {
        '\u{0301}' => ("\\'", "\\acute"),
        '\u{0300}' => ("\\`", "\\grave"),
        '\u{0308}' => ("\\\"", "\\ddot"),
        '\u{0303}' => ("\\~", "\\tilde"),
        '\u{0304}' => ("\\=", "\\bar"),
        '\u{0306}' => ("\\u", "\\breve"),
        '\u{030c}' => ("\\v", "\\check"),
        '\u{0302}' => ("\\^", "\\hat"),
        '\u{0307}' => ("\\.", "\\dot"),
        '\u{030a}' => ("\\r", "\\mathring"),
        '\u{030b}' => ("\\H", "\\H"),
        '\u{0327}' => ("\\c", "\\c"),
        _ => return None,
    };
    Some(if mode == Mode::Math { math } else { text })
}
pub fn symbol(name: &str, mode: Mode) -> Option<Node> {
    let mode_name = if mode == Mode::Math { "math" } else { "text" };
    let s = symbols().get(&format!("{mode_name}|{name}"))?;
    Some(Node::Symbol {
        value: s.0.clone(),
        class: Class::from_name(&s.2),
        italic: mode == Mode::Math && s.2 == "mathord",
        ams: s.1 == "ams",
        mode,
    })
}
pub fn unicode_font(c: char) -> Option<(char, &'static str)> {
    let code = c as u32;
    let blocks = [
        (0x1d400, 52, "mathbf"),
        (0x1d434, 52, "mathnormal"),
        (0x1d468, 52, "boldsymbol"),
        (0x1d49c, 26, "mathscr"),
        (0x1d504, 52, "mathfrak"),
        (0x1d538, 26, "mathbb"),
        (0x1d56c, 52, "mathfrak-bold"),
        (0x1d5a0, 52, "mathsf"),
        (0x1d5d4, 52, "mathsf-bold"),
        (0x1d608, 52, "mathsfit"),
        (0x1d670, 52, "mathtt"),
    ];
    for (start, len, font) in blocks {
        if (start..start + len).contains(&code) {
            let n = code - start;
            return Some((
                char::from_u32(if n < 26 { 65 + n } else { 97 + n - 26 })?,
                font,
            ));
        }
    }
    if code == 0x1d55c {
        return Some(('k', "mathbb"));
    }
    for (start, font) in [
        (0x1d7ce, "mathbf"),
        (0x1d7e2, "mathsf"),
        (0x1d7ec, "mathsf-bold"),
        (0x1d7f6, "mathtt"),
    ] {
        if (start..start + 10).contains(&code) {
            return Some((char::from_u32(48 + code - start)?, font));
        }
    }
    None
}
