// Copyright (C) 2026 Fadouse
// SPDX-License-Identifier: GPL-3.0-only

use super::{
    Error, Result,
    ast::Mode,
    data,
    lexer::{Token, lex},
};
use std::collections::{BTreeMap, VecDeque};

#[derive(Clone, Debug)]
pub struct Macro {
    body: Vec<Token>,
    args: usize,
    delimiters: Vec<Vec<String>>,
    literal: bool,
}
impl Macro {
    fn template(source: &str, offset: usize) -> Result<Self> {
        let mut body = lex(source)?;
        let mut args = 0;
        let mut cursor = 0;
        while cursor + 1 < body.len() {
            if body[cursor].text == "#" {
                args = args.max(body[cursor + 1].text.parse::<usize>().unwrap_or(0));
                cursor += 2;
            } else {
                cursor += 1;
            }
        }
        for t in &mut body {
            t.offset = offset;
        }
        Ok(Self {
            body,
            args,
            delimiters: Vec::new(),
            literal: false,
        })
    }
}

pub struct Expander {
    pub queue: VecDeque<Token>,
    pub globals: BTreeMap<String, Macro>,
    scopes: Vec<BTreeMap<String, Macro>>,
    expansions: usize,
    edef: bool,
}
impl Expander {
    pub fn new(source: &str, globals: &BTreeMap<String, Macro>) -> Result<Self> {
        Ok(Self {
            queue: lex(source)?.into(),
            globals: globals.clone(),
            scopes: vec![BTreeMap::new()],
            expansions: 0,
            edef: false,
        })
    }
    pub fn begin(&mut self) {
        self.scopes.push(BTreeMap::new());
    }
    pub fn end(&mut self) {
        self.scopes.pop();
    }
    pub fn push(&mut self, t: Token) {
        self.queue.push_front(t);
    }
    pub fn push_all(&mut self, tokens: Vec<Token>) {
        for t in tokens.into_iter().rev() {
            self.push(t);
        }
    }
    pub fn raw(&mut self) -> Token {
        self.queue
            .pop_front()
            .unwrap_or_else(|| Token::new("EOF", 0))
    }
    pub fn spaces(&mut self) {
        while self.queue.front().is_some_and(|t| t.text == " ") {
            self.queue.pop_front();
        }
    }
    pub fn future(&self) -> &str {
        self.queue.front().map_or("EOF", |t| t.text.as_str())
    }
    fn lookup(&self, name: &str) -> Option<Macro> {
        for scope in self.scopes.iter().rev() {
            if let Some(m) = scope.get(name) {
                return Some(m.clone());
            }
        }
        self.globals.get(name).cloned().or_else(|| {
            data::macros()
                .get(name)
                .map(|s| Macro::template(s, 0).unwrap())
        })
    }
    fn set(&mut self, name: String, value: Macro, global: bool) {
        if global {
            for scope in &mut self.scopes {
                scope.remove(&name);
            }
            self.globals.insert(name, value);
        } else {
            self.scopes.last_mut().unwrap().insert(name, value);
        }
    }
    fn is_expandable(&self, name: &str) -> bool {
        if let Some(mac) = self.lookup(name) {
            return !mac.literal;
        }
        self.defined(name)
            && !matches!(
                name,
                "\\def"
                    | "\\gdef"
                    | "\\edef"
                    | "\\xdef"
                    | "\\let"
                    | "\\futurelet"
                    | "\\global"
                    | "\\long"
                    | "\\relax"
            )
    }
    pub fn defined(&self, name: &str) -> bool {
        self.lookup(name).is_some()
            || data::functions().contains(name)
            || data::symbols().contains_key(&format!("math|{name}"))
            || data::symbols().contains_key(&format!("text|{name}"))
            || matches!(
                name,
                "\\newcommand"
                    | "\\renewcommand"
                    | "\\providecommand"
                    | "\\dots"
                    | "\\char"
                    | "\\noexpand"
                    | "\\expandafter"
            )
    }
    pub fn macro_text(&mut self, name: &str, mode: Mode) -> Result<Option<String>> {
        if let Some(mac) = self.lookup(name) {
            let expanded = self.expand_tokens(mac.body, mode)?;
            Ok(Some(expanded.iter().map(|t| t.text.as_str()).collect()))
        } else {
            Ok(None)
        }
    }
    pub fn global_text(&mut self, name: &str, value: &str) -> Result<()> {
        self.set(name.into(), Macro::template(value, 0)?, true);
        Ok(())
    }
    pub fn argument(&mut self) -> Result<Vec<Token>> {
        self.spaces();
        let first = self.raw();
        if first.text == "EOF" {
            return Err(Error::new(first.offset, "Missing macro argument"));
        }
        if first.text != "{" {
            return Ok(vec![first]);
        }
        let mut depth = 1;
        let mut body = Vec::new();
        loop {
            let t = self.raw();
            match t.text.as_str() {
                "EOF" => return Err(Error::new(first.offset, "Unclosed macro argument")),
                "{" => depth += 1,
                "}" => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            body.push(t);
        }
        Ok(body)
    }
    fn delimited(&mut self, delimiter: &[String]) -> Result<Vec<Token>> {
        if delimiter.is_empty() {
            return self.argument();
        }
        let mut out = Vec::new();
        let mut depth = 0;
        loop {
            let t = self.raw();
            if t.text == "EOF" {
                return Err(Error::new(t.offset, "Missing macro argument delimiter"));
            }
            let previous_depth = depth;
            if t.text == "{" {
                depth += 1;
            } else if t.text == "}" {
                depth -= 1;
            }
            out.push(t);
            if (depth == 0 || previous_depth == 0 && delimiter.last().is_some_and(|d| d == "{"))
                && out.len() >= delimiter.len()
                && out[out.len() - delimiter.len()..]
                    .iter()
                    .map(|t| &t.text)
                    .eq(delimiter.iter())
            {
                out.truncate(out.len() - delimiter.len());
                break;
            }
        }
        if out.first().is_some_and(|t| t.text == "{") && out.last().is_some_and(|t| t.text == "}") {
            let mut balance = 0;
            let outer = out[..out.len() - 1].iter().all(|t| {
                if t.text == "{" {
                    balance += 1;
                }
                if t.text == "}" {
                    balance -= 1;
                }
                balance > 0
            });
            if outer {
                out.remove(0);
                out.pop();
            }
        }
        Ok(out)
    }
    fn substitute(&mut self, m: Macro, offset: usize) -> Result<Vec<Token>> {
        if let Some(prefix) = m.delimiters.first() {
            for expected in prefix {
                let t = self.raw();
                if &t.text != expected {
                    return Err(Error::new(t.offset, "Macro prefix mismatch"));
                }
            }
        }
        let args = (0..m.args)
            .map(|i| self.delimited(m.delimiters.get(i + 1).map_or(&[], Vec::as_slice)))
            .collect::<Result<Vec<_>>>()?;
        let mut result = Vec::new();
        let mut cursor = 0;
        while cursor < m.body.len() {
            let mut t = m.body[cursor].clone();
            t.offset = offset;
            if !m.literal && t.text == "#" {
                cursor += 1;
                let next = m
                    .body
                    .get(cursor)
                    .ok_or_else(|| Error::new(offset, "Incomplete macro parameter"))?;
                if next.text == "#" {
                    result.push(t);
                } else {
                    let n = next
                        .text
                        .parse::<usize>()
                        .map_err(|_| Error::new(offset, "Invalid macro parameter"))?;
                    result.extend(
                        args.get(n.wrapping_sub(1))
                            .ok_or_else(|| Error::new(offset, "Macro parameter out of range"))?
                            .iter()
                            .cloned(),
                    );
                }
            } else {
                result.push(t);
            }
            cursor += 1;
        }
        Ok(result)
    }
    fn expand_tokens(&mut self, tokens: Vec<Token>, mode: Mode) -> Result<Vec<Token>> {
        let saved = std::mem::replace(&mut self.queue, tokens.into());
        let previous = self.edef;
        self.edef = true;
        let mut expanded = Vec::new();
        loop {
            let mut t = self.next(mode)?;
            if t.text == "EOF" {
                break;
            }
            if !t.frozen && t.text.starts_with('\\') && !self.defined(&t.text) {
                return Err(Error::new(
                    t.offset,
                    format!("Undefined macro {} in expanded definition", t.text),
                ));
            }
            t.frozen = false;
            t.relax = false;
            expanded.push(t);
        }
        self.edef = previous;
        self.queue = saved;
        Ok(expanded)
    }
    fn define(&mut self, command: &str, offset: usize, global: bool, mode: Mode) -> Result<()> {
        let name = self.raw();
        if matches!(
            name.text.as_str(),
            "EOF" | "{" | "}" | "$" | "#" | "&" | "^" | "_"
        ) {
            return Err(Error::new(name.offset, "Expected a macro name"));
        }
        let mut delimiters = vec![Vec::new()];
        let mut args = 0;
        let mut inserted = false;
        while self.future() != "{" {
            let t = self.raw();
            if t.text == "EOF" {
                return Err(Error::new(offset, "Missing macro definition"));
            }
            if t.text == "#" {
                if self.future() == "{" {
                    delimiters[args].push("{".into());
                    inserted = true;
                    break;
                }
                let n = self.raw();
                args += 1;
                if n.text != args.to_string() || args > 9 {
                    return Err(Error::new(
                        n.offset,
                        "Macro parameters must be numbered consecutively from 1 to 9",
                    ));
                }
                delimiters.push(Vec::new());
            } else {
                delimiters[args].push(t.text);
            }
        }
        let mut body = self.argument()?;
        if inserted {
            body.push(Token::new("{", offset));
        }
        if matches!(command, "\\edef" | "\\xdef") {
            body = self.expand_tokens(body, mode)?;
        }
        self.set(
            name.text,
            Macro {
                body,
                args,
                delimiters,
                literal: false,
            },
            global || matches!(command, "\\gdef" | "\\xdef"),
        );
        Ok(())
    }
    fn newcommand(&mut self, command: &str, offset: usize) -> Result<()> {
        let name = self.argument()?;
        if name.len() != 1 {
            return Err(Error::new(offset, "Expected one macro name"));
        }
        let name = &name[0].text;
        let exists = self.defined(name);
        if command == "\\newcommand" && exists {
            return Err(Error::new(
                offset,
                format!("Macro {name} is already defined"),
            ));
        }
        if command == "\\renewcommand" && !exists {
            return Err(Error::new(offset, format!("Macro {name} is not defined")));
        }
        self.spaces();
        let mut args = 0;
        if self.future() == "[" {
            self.raw();
            let mut digits = String::new();
            while self.future() != "]" {
                let t = self.raw();
                if t.text == "EOF" {
                    return Err(Error::new(offset, "Unclosed argument count"));
                }
                digits.push_str(&t.text);
            }
            self.raw();
            args = digits
                .trim()
                .parse()
                .map_err(|_| Error::new(offset, "Invalid argument count"))?;
        }
        let body = self.argument()?;
        if command != "\\providecommand" || !exists {
            self.set(
                name.clone(),
                Macro {
                    body,
                    args,
                    delimiters: Vec::new(),
                    literal: false,
                },
                false,
            );
        }
        Ok(())
    }
    fn alias(&mut self, future: bool, global: bool, offset: usize) -> Result<()> {
        let name = self.raw();
        self.spaces();
        if self.future() == "=" {
            self.raw();
            if self.future() == " " {
                self.raw();
            }
        }
        let middle = if future { Some(self.raw()) } else { None };
        let mut target = self.raw();
        if target.text == "EOF" {
            return Err(Error::new(offset, "Missing let assignment"));
        }
        let value = self.lookup(&target.text).unwrap_or_else(|| {
            target.frozen = true;
            Macro {
                body: vec![target.clone()],
                args: 0,
                delimiters: Vec::new(),
                literal: true,
            }
        });
        self.set(name.text, value, global);
        if let Some(middle) = middle {
            self.push(target);
            self.push(middle);
        }
        Ok(())
    }
    pub fn assignment(&mut self, name: &str, offset: usize, mode: Mode) -> Result<()> {
        match name {
            "\\def" | "\\gdef" | "\\edef" | "\\xdef" => self.define(name, offset, false, mode),
            "\\let" | "\\futurelet" => self.alias(name == "\\futurelet", false, offset),
            "\\global" | "\\long" => {
                self.spaces();
                let mut next = self.next(mode)?;
                let mut global = name == "\\global";
                while next.text == "\\long" || next.text == "\\global" {
                    global |= next.text == "\\global";
                    self.spaces();
                    next = self.next(mode)?;
                }
                match next.text.as_str() {
                    "\\def" | "\\gdef" | "\\edef" | "\\xdef" => {
                        self.define(&next.text, next.offset, global, mode)
                    }
                    "\\let" | "\\futurelet" => {
                        self.alias(next.text == "\\futurelet", global, next.offset)
                    }
                    _ => Err(Error::new(offset, "Invalid macro assignment prefix")),
                }
            }
            _ => unreachable!(),
        }
    }
    pub fn next(&mut self, mode: Mode) -> Result<Token> {
        loop {
            let t = self.raw();
            if let Some(expansion) = self.expand_once(&t, mode)? {
                self.push_all(expansion);
            } else {
                return Ok(t);
            }
        }
    }
    fn expand_once(&mut self, t: &Token, mode: Mode) -> Result<Option<Vec<Token>>> {
        if t.frozen || t.text == "EOF" {
            return Ok(None);
        }
        let name = t.text.as_str();
        let offset = t.offset;
        if self.lookup(name).is_none()
            && !matches!(
                name,
                "\\newcommand"
                    | "\\renewcommand"
                    | "\\providecommand"
                    | "\\noexpand"
                    | "\\expandafter"
                    | "\\@firstoftwo"
                    | "\\@secondoftwo"
                    | "\\@ifnextchar"
                    | "\\TextOrMath"
                    | "\\char"
                    | "\\message"
                    | "\\errmessage"
                    | "\\show"
                    | "\\tag@literal"
                    | "\\dots"
                    | "\\dotso"
                    | "\\dotsc"
                    | "\\cdots"
                    | "\\bra@ket"
                    | "\\bra@set"
            )
        {
            return Ok(None);
        }
        if self.edef && self.lookup(name).is_some_and(|mac| mac.literal) {
            return Ok(None);
        }
        self.count_expansion(offset)?;
        let custom = self
            .scopes
            .iter()
            .rev()
            .find_map(|s| s.get(name))
            .or_else(|| self.globals.get(name))
            .cloned();
        let expansion = if let Some(mac) = custom {
            if self.edef && mac.literal {
                return Ok(None);
            }
            self.substitute(mac, offset)?
        } else {
            match name {
                "\\def" | "\\gdef" | "\\edef" | "\\xdef" | "\\let" | "\\futurelet" | "\\global"
                | "\\long" => return Ok(None),
                "\\newcommand" | "\\renewcommand" | "\\providecommand" => {
                    self.newcommand(name, offset)?;
                    Vec::new()
                }
                "\\noexpand" => {
                    let mut token = self.raw();
                    if self.is_expandable(&token.text) {
                        token.frozen = true;
                        token.relax = true;
                    }
                    vec![token]
                }
                "\\expandafter" => {
                    let first = self.raw();
                    let mut second = self.raw();
                    let mut expansion = vec![first];
                    while second.text == "\\expandafter"
                        && !second.frozen
                        && self.lookup(&second.text).is_none()
                    {
                        self.count_expansion(second.offset)?;
                        expansion.push(self.raw());
                        second = self.raw();
                    }
                    expansion.extend(
                        self.expand_once(&second, mode)?
                            .unwrap_or_else(|| vec![second]),
                    );
                    expansion
                }
                "\\@firstoftwo" | "\\@secondoftwo" => {
                    let a = self.argument()?;
                    let b = self.argument()?;
                    if name == "\\@firstoftwo" { a } else { b }
                }
                "\\@ifnextchar" => {
                    let ch = self.argument()?;
                    let yes = self.argument()?;
                    let no = self.argument()?;
                    self.spaces();
                    if ch.len() == 1 && ch[0].text == self.future() {
                        yes
                    } else {
                        no
                    }
                }
                "\\TextOrMath" => {
                    let text = self.argument()?;
                    let math = self.argument()?;
                    if mode == Mode::Text { text } else { math }
                }
                "\\char" => {
                    self.spaces();
                    let first = self.raw();
                    let mut radix = 10;
                    let mut digits = String::new();
                    let code = if first.text == "`" {
                        let ch = self.raw();
                        ch.text
                            .trim_start_matches('\\')
                            .chars()
                            .next()
                            .map(u32::from)
                            .ok_or_else(|| Error::new(offset, "Missing character"))?
                    } else {
                        if first.text == "'" {
                            radix = 8;
                        } else if first.text == "\"" {
                            radix = 16;
                        } else {
                            digits = first.text;
                        }
                        while self.queue.front().is_some_and(|t| {
                            t.text.len() == 1 && t.text.chars().next().unwrap().is_digit(radix)
                        }) {
                            digits.push_str(&self.raw().text);
                        }
                        u32::from_str_radix(&digits, radix)
                            .map_err(|_| Error::new(offset, "Invalid character code"))?
                    };
                    if char::from_u32(code).is_none() {
                        return Err(Error::new(offset, "Invalid Unicode scalar"));
                    }
                    lex(&format!("\\@char{{{code}}}"))?
                }
                "\\message" | "\\errmessage" => {
                    let body = self.argument()?;
                    eprintln!(
                        "{}",
                        body.iter().map(|t| t.text.as_str()).collect::<String>()
                    );
                    Vec::new()
                }
                "\\show" => {
                    self.raw();
                    Vec::new()
                }
                "\\tag@literal" => {
                    let body = self.argument()?;
                    let mut out = vec![Token::new("\\rusttag", offset), Token::new("{", offset)];
                    out.extend(body);
                    out.push(Token::new("}", offset));
                    out
                }
                "\\dots" => {
                    let next = self.future();
                    let symbol = data::symbol(next, mode);
                    let centered = symbol.is_some_and(|n| {
                        matches!(n.class(), super::ast::Class::Bin | super::ast::Class::Rel)
                    }) || matches!(next, "\\sum" | "\\prod" | "\\DOTSB");
                    lex(if centered {
                        "\\cdots"
                    } else if next.starts_with("\\int") {
                        "\\dotsi"
                    } else {
                        "\\dotso"
                    })?
                }
                "\\dotso" | "\\dotsc" | "\\cdots" => {
                    let extra = matches!(
                        self.future(),
                        ")" | "]" | "\\rbrace" | "\\rangle" | "\\right" | ";" | "."
                    ) || name == "\\dotso" && self.future() == ",";
                    lex(&format!(
                        "{}{}",
                        if name == "\\cdots" {
                            "\\@cdots"
                        } else {
                            "\\ldots"
                        },
                        if extra { "\\," } else { "" }
                    ))?
                }
                "\\bra@ket" | "\\bra@set" => {
                    let left = self.argument()?;
                    let middle = self.argument()?;
                    let double = self.argument()?;
                    let right = self.argument()?;
                    let body = self.argument()?;
                    let mut result = left;
                    let mut replaced = false;
                    let mut i = 0;
                    while i < body.len() {
                        let item = &body[i];
                        if (item.text == "|" || item.text == "\\|" && !double.is_empty())
                            && (name == "\\bra@ket" || !replaced)
                        {
                            let doubled = !double.is_empty()
                                && (item.text == "\\|"
                                    || body.get(i + 1).is_some_and(|t| t.text == "|"));
                            if doubled && item.text == "|" {
                                i += 1;
                            }
                            result.extend(if doubled {
                                double.clone()
                            } else {
                                middle.clone()
                            });
                            replaced = true;
                        } else {
                            result.push(item.clone());
                        }
                        i += 1;
                    }
                    result.extend(right);
                    result
                }
                _ => {
                    if let Some(m) = self.lookup(name) {
                        self.substitute(m, offset)?
                    } else {
                        return Ok(None);
                    }
                }
            }
        };
        Ok(Some(expansion))
    }
    fn count_expansion(&mut self, offset: usize) -> Result<()> {
        self.expansions += 1;
        if self.expansions > 1000 {
            Err(Error::new(offset, "Macro expansion limit exceeded (1000)"))
        } else {
            Ok(())
        }
    }
}
