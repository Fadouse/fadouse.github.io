// Copyright (C) 2026 Fadouse
// SPDX-License-Identifier: GPL-3.0-only

use super::{
    Error, Result,
    ast::{Class, Dimension, Mode, Node},
    data,
    expand::{Expander, Macro},
    lexer::Token,
};
use std::collections::BTreeMap;

pub struct Parser {
    expander: Expander,
    look: Option<Token>,
    mode: Mode,
    display: bool,
    tag: Option<Node>,
    depth: usize,
    pub equation_count: usize,
}

fn styled(
    body: Node,
    font: Option<String>,
    size: Option<f64>,
    style: Option<u8>,
    color: Option<String>,
) -> Node {
    Node::Styled {
        body: Box::new(body),
        font,
        size,
        style,
        color,
    }
}
fn text_node(value: &str) -> Node {
    Node::Row(
        value
            .chars()
            .map(|c| Node::Symbol {
                value: c.to_string(),
                class: Class::Ord,
                italic: false,
                ams: false,
                mode: Mode::Text,
            })
            .collect(),
    )
}

impl Parser {
    pub fn new(
        source: &str,
        display: bool,
        globals: &BTreeMap<String, Macro>,
        equation_count: usize,
    ) -> Result<Self> {
        Ok(Self {
            expander: Expander::new(source, globals)?,
            look: None,
            mode: Mode::Math,
            display,
            tag: None,
            depth: 0,
            equation_count,
        })
    }
    pub fn global_macros(&self) -> BTreeMap<String, Macro> {
        self.expander.globals.clone()
    }
    fn peek(&mut self) -> Result<&Token> {
        if self.look.is_none() {
            self.look = Some(self.expander.next(self.mode)?);
        }
        Ok(self.look.as_ref().unwrap())
    }
    fn take(&mut self) -> Result<Token> {
        self.peek()?;
        Ok(self.look.take().unwrap())
    }
    fn name(&mut self) -> Result<String> {
        Ok(self.peek()?.text.clone())
    }
    fn expect(&mut self, name: &str) -> Result<()> {
        let t = self.take()?;
        if t.text != name {
            return Err(Error::new(
                t.offset,
                format!("Expected {name}, found {}", t.text),
            ));
        }
        Ok(())
    }
    fn spaces(&mut self) -> Result<()> {
        while self.name()? == " " {
            self.take()?;
        }
        Ok(())
    }
    fn raw_argument(&mut self) -> Result<Vec<Token>> {
        if let Some(t) = self.look.take() {
            self.expander.push(t);
        }
        self.expander.argument()
    }
    fn raw_string(&mut self) -> Result<String> {
        Ok(self
            .raw_argument()?
            .iter()
            .map(|t| t.text.as_str())
            .collect())
    }
    fn optional_string(&mut self) -> Result<Option<String>> {
        self.spaces()?;
        if self.name()? != "[" {
            return Ok(None);
        }
        self.take()?;
        let mut value = String::new();
        let mut depth = 0;
        loop {
            let t = self.take()?;
            match t.text.as_str() {
                "EOF" => return Err(Error::new(t.offset, "Unclosed optional argument")),
                "{" => depth += 1,
                "}" => depth -= 1,
                "]" if depth == 0 => break,
                _ => {}
            }
            value.push_str(&t.text);
        }
        Ok(Some(value))
    }
    fn argument(&mut self, mode: Mode) -> Result<Node> {
        let previous = self.mode;
        self.mode = mode;
        self.spaces()?;
        let t = self.take()?;
        let result = if t.text == "{" || t.text == "\\begingroup" {
            self.expander.begin();
            let end = if t.text == "{" { "}" } else { "\\endgroup" };
            let node = self.row(&[end])?;
            self.expect(end)?;
            self.expander.end();
            node
        } else if t.text == "EOF" || t.text == "}" {
            return Err(Error::new(t.offset, "Missing formula argument"));
        } else {
            if data::function_flags(&t.text).is_some_and(|flags| !flags.argument) {
                return Err(Error::new(
                    t.offset,
                    format!("{} requires a braced argument", t.text),
                ));
            }
            self.atom(t, &[])?
        };
        self.mode = previous;
        Ok(result)
    }
    fn dimension(&mut self) -> Result<Dimension> {
        self.spaces()?;
        let offset = self.peek()?.offset;
        if self.name()? == "{" {
            let source = self.raw_string()?;
            return Dimension::parse(&source).map_err(|e| Error::new(offset, e));
        }
        let mut source = String::new();
        let mut unit = false;
        let mut unit_count = 0;
        loop {
            let t = self.peek()?;
            let one = t
                .text
                .chars()
                .next()
                .filter(|_| t.text.chars().count() == 1);
            let accept = one.is_some_and(|c| {
                if unit {
                    c.is_ascii_alphabetic() && unit_count < 2
                } else {
                    c.is_ascii_digit()
                        || c == '.'
                        || c == '+'
                        || c == '-'
                        || c.is_ascii_alphabetic()
                }
            });
            if !accept {
                break;
            }
            let t = self.take()?;
            if t.text.chars().all(|c| c.is_ascii_alphabetic()) {
                unit = true;
                unit_count += 1;
            }
            source.push_str(&t.text);
            if unit_count == 2 {
                break;
            }
        }
        Dimension::parse(&source).map_err(|e| Error::new(offset, e))
    }
    fn delimiter(&mut self) -> Result<String> {
        self.spaces()?;
        let t = self.take()?;
        if t.text == "." {
            return Ok(String::new());
        }
        let value = if let Some(Node::Symbol { value, .. }) = data::symbol(&t.text, Mode::Math) {
            value
        } else {
            match t.text.as_str() {
                "\\langle" => "⟨".into(),
                "\\rangle" => "⟩".into(),
                "\\lbrace" | "\\{" => "{".into(),
                "\\rbrace" | "\\}" => "}".into(),
                "\\Vert" | "\\|" | "\\lVert" | "\\rVert" => "‖".into(),
                "\\vert" | "\\lvert" | "\\rvert" => "|".into(),
                "\\llbracket" => "⟦".into(),
                "\\rrbracket" => "⟧".into(),
                "\\lBrace" => "⦃".into(),
                "\\rBrace" => "⦄".into(),
                _ => t.text.clone(),
            }
        };
        let value = match value.as_str() {
            "∣" => "|".into(),
            "‖" => "∥".into(),
            "<" => "⟨".into(),
            ">" => "⟩".into(),
            _ => value,
        };
        if value.chars().count() != 1 || !"()[]{}⟨⟩⌈⌉⌊⌋|∥/\\↑↓↕⇑⇓⇕⎰⎱⟮⟯⟦⟧⦃⦄".contains(&value)
        {
            return Err(Error::new(
                t.offset,
                format!("Invalid delimiter {}", t.text),
            ));
        }
        Ok(value)
    }
    pub fn parse(&mut self) -> Result<Node> {
        let body = self.row(&["EOF"])?;
        self.expect("EOF")?;
        if let Some(tag) = self.tag.take() {
            if !self.display {
                return Err(Error::new(0, "Equation tags require display mode"));
            }
            Ok(Node::Tagged {
                body: Box::new(body),
                tag: Box::new(tag),
            })
        } else {
            Ok(body)
        }
    }
    fn row(&mut self, stops: &[&str]) -> Result<Node> {
        self.depth += 1;
        if self.depth > 256 {
            return Err(Error::new(
                self.peek()?.offset,
                "Formula nesting exceeds 256 levels",
            ));
        }
        let mut nodes: Vec<Node> = Vec::new();
        loop {
            let name = self.name()?;
            if stops.contains(&name.as_str()) {
                break;
            }
            if name == "EOF" {
                return Err(Error::new(self.peek()?.offset, "Unexpected end of formula"));
            }
            if self.mode == Mode::Math && name == " " {
                self.take()?;
                continue;
            }
            if self.mode == Mode::Math
                && let Some((_, is_sub)) = data::unicode_script(&name)
            {
                let mut scripts = Vec::new();
                while let Some((value, sub)) = data::unicode_script(&self.name()?) {
                    if sub != is_sub {
                        break;
                    }
                    let token = self.take()?;
                    scripts.push(self.atom(Token::new(value, token.offset), &[])?);
                }
                let base = nodes.pop().unwrap_or_else(Node::empty);
                let (base, mut sup, mut sub, limits) = match base {
                    Node::Scripts {
                        base,
                        sup,
                        sub,
                        limits,
                    } => (base, sup, sub, limits),
                    other => (Box::new(other), None, None, None),
                };
                if is_sub {
                    sub = Some(Box::new(Node::row(scripts)));
                } else {
                    sup = Some(Box::new(Node::row(scripts)));
                }
                nodes.push(Node::Scripts {
                    base,
                    sup,
                    sub,
                    limits,
                });
                continue;
            }
            if matches!(
                name.as_str(),
                "\\over" | "\\atop" | "\\choose" | "\\brace" | "\\brack" | "\\above"
            ) {
                let t = self.take()?;
                let bar = match name.as_str() {
                    "\\over" => Some(Dimension::em(0.04)),
                    "\\above" => Some(self.dimension()?),
                    _ => None,
                };
                let den = self.row(stops)?;
                let delimiters = match name.as_str() {
                    "\\choose" => Some(("(".into(), ")".into())),
                    "\\brace" => Some(("{".into(), "}".into())),
                    "\\brack" => Some(("[".into(), "]".into())),
                    _ => None,
                };
                if let Node::Fraction { .. } = den {
                    return Err(Error::new(
                        t.offset,
                        "Only one infix fraction is allowed per group",
                    ));
                }
                self.depth -= 1;
                return Ok(Node::Fraction {
                    num: Box::new(Node::row(nodes)),
                    den: Box::new(den),
                    bar,
                    delimiters,
                    style: None,
                });
            }
            if name == "^"
                || name == "_"
                || self.mode == Mode::Math && name == "'"
                || matches!(name.as_str(), "\\limits" | "\\nolimits" | "\\displaylimits")
            {
                if self.mode == Mode::Text {
                    return Err(Error::new(self.peek()?.offset, "Scripts require math mode"));
                }
                let t = self.take()?;
                let base = nodes.pop().unwrap_or_else(Node::empty);
                let (base, mut sup, mut sub, mut limits) = match base {
                    Node::Scripts {
                        base,
                        sup,
                        sub,
                        limits,
                    } => (base, sup, sub, limits),
                    other => (Box::new(other), None, None, None),
                };
                if matches!(name.as_str(), "\\limits" | "\\nolimits" | "\\displaylimits") {
                    if base.class() != Class::Op {
                        return Err(Error::new(t.offset, "Limits must follow an operator"));
                    }
                    limits = Some(name != "\\nolimits");
                } else if name == "'" {
                    let mut primes = vec![data::symbol("\\prime", Mode::Math).unwrap()];
                    while self.name()? == "'" {
                        self.take()?;
                        primes.push(data::symbol("\\prime", Mode::Math).unwrap());
                    }
                    if self.name()? == "^" {
                        self.take()?;
                        primes.push(self.argument(Mode::Math)?);
                    }
                    if sup.is_some() {
                        return Err(Error::new(t.offset, "Double superscript"));
                    }
                    sup = Some(Box::new(Node::row(primes)));
                } else {
                    let argument = self.argument(Mode::Math)?;
                    let target = if name == "^" { &mut sup } else { &mut sub };
                    if target.is_some() {
                        return Err(Error::new(
                            t.offset,
                            if name == "^" {
                                "Double superscript"
                            } else {
                                "Double subscript"
                            },
                        ));
                    }
                    *target = Some(Box::new(argument));
                }
                nodes.push(Node::Scripts {
                    base,
                    sup,
                    sub,
                    limits,
                });
                continue;
            }
            let t = self.take()?;
            let node = self.atom(t, stops)?;
            if !node.is_empty() {
                nodes.push(node);
            }
        }
        self.depth -= 1;
        Ok(Node::row(nodes))
    }
    fn atom(&mut self, t: Token, stops: &[&str]) -> Result<Node> {
        let name = t.text.as_str();
        let offset = t.offset;
        if !name.starts_with('\\')
            && let Some(first) = name.chars().next()
        {
            let expanded = if data::symbol(&first.to_string(), self.mode).is_none() {
                data::decomposed(first)
            } else {
                None
            };
            let spelling = format!(
                "{}{}",
                expanded.unwrap_or(&first.to_string()),
                &name[first.len_utf8()..]
            );
            if spelling.chars().count() > 1
                && spelling
                    .chars()
                    .skip(1)
                    .all(|c| ('\u{0300}'..='\u{036f}').contains(&c))
            {
                let mut chars = spelling.chars();
                let base = match chars.next().unwrap() {
                    'i' => "ı".into(),
                    'j' => "ȷ".into(),
                    c => c.to_string(),
                };
                let mut node = self.atom(Token::new(base, offset), &[])?;
                for accent in chars {
                    let command = data::accent(accent, self.mode)
                        .ok_or_else(|| Error::new(offset, "Unsupported combining accent"))?;
                    node = Node::Accent {
                        name: command.into(),
                        body: Box::new(node),
                        below: command == "\\c",
                    };
                }
                return Ok(node);
            }
        }
        if t.relax {
            return Ok(Node::empty());
        }
        if self.mode == Mode::Text && data::function_flags(name).is_some_and(|flags| !flags.text) {
            return Err(Error::new(offset, format!("{name} requires math mode")));
        }
        let node = match name {
            "{" | "\\begingroup" => {
                self.expander.begin();
                let end = if name == "{" { "}" } else { "\\endgroup" };
                let row = self.row(&[end])?;
                self.expect(end)?;
                self.expander.end();
                row
            }
            "}" | "\\endgroup" | "\\right" | "\\end" | "&" => {
                return Err(Error::new(offset, format!("Unexpected {name}")));
            }
            "\\relax" | "\\nonumber" | "\\notag" => Node::empty(),
            "\\allowbreak" | "\\nobreak" => Node::LineControl(name == "\\allowbreak"),
            "\\def" | "\\gdef" | "\\edef" | "\\xdef" | "\\let" | "\\futurelet" | "\\global"
            | "\\long" => {
                self.expander.assignment(name, offset, self.mode)?;
                Node::empty()
            }
            "\\rusttag" => {
                let tag = self.argument(Mode::Text)?;
                if self.tag.replace(tag).is_some() {
                    return Err(Error::new(offset, "Multiple equation tags"));
                }
                Node::empty()
            }
            "\\@char" => {
                let number = self
                    .raw_string()?
                    .parse::<u32>()
                    .map_err(|_| Error::new(offset, "Invalid character code"))?;
                let value = char::from_u32(number)
                    .ok_or_else(|| Error::new(offset, "Invalid Unicode scalar"))?
                    .to_string();
                data::symbol(&value, self.mode).unwrap_or(Node::Symbol {
                    value,
                    class: Class::Ord,
                    italic: self.mode == Mode::Math,
                    ams: false,
                    mode: self.mode,
                })
            }
            "\\sqrt" => {
                let index = if self.name()? == "[" {
                    self.take()?;
                    let n = self.row(&["]"])?;
                    self.expect("]")?;
                    Some(Box::new(n))
                } else {
                    None
                };
                Node::Root {
                    body: Box::new(self.argument(Mode::Math)?),
                    index,
                }
            }
            "\\frac" | "\\dfrac" | "\\tfrac" | "\\cfrac" | "\\binom" | "\\dbinom" | "\\tbinom"
            | "\\\\atopfrac" | "\\\\bracefrac" | "\\\\brackfrac" => {
                if name == "\\cfrac" {
                    self.optional_string()?;
                }
                let num = self.argument(Mode::Math)?;
                let den = self.argument(Mode::Math)?;
                let delimiters = if name.contains("binom") {
                    Some(("(".into(), ")".into()))
                } else if name.contains("bracefrac") {
                    Some(("{".into(), "}".into()))
                } else if name.contains("brackfrac") {
                    Some(("[".into(), "]".into()))
                } else {
                    None
                };
                let bar = if delimiters.is_some() || name.contains("atopfrac") {
                    None
                } else {
                    Some(Dimension::em(0.04))
                };
                let style = if name.starts_with("\\d") || name == "\\cfrac" {
                    Some(0)
                } else if name.starts_with("\\t") {
                    Some(1)
                } else {
                    None
                };
                Node::Fraction {
                    num: Box::new(num),
                    den: Box::new(den),
                    bar,
                    delimiters,
                    style,
                }
            }
            "\\genfrac" => {
                let left = self.raw_string()?;
                let right = self.raw_string()?;
                let line = self.raw_string()?;
                let style = self.raw_string()?;
                let bar = if line.is_empty() {
                    Some(Dimension::em(0.04))
                } else {
                    let d = Dimension::parse(&line).map_err(|e| Error::new(offset, e))?;
                    if d.value == 0.0 { None } else { Some(d) }
                };
                let style = if style.is_empty() {
                    None
                } else {
                    Some(
                        style
                            .parse::<u8>()
                            .ok()
                            .filter(|s| *s <= 3)
                            .ok_or_else(|| Error::new(offset, "Invalid fraction style"))?,
                    )
                };
                let delimiters = if left.is_empty() && right.is_empty() {
                    None
                } else {
                    Some((delimiter_value(&left), delimiter_value(&right)))
                };
                Node::Fraction {
                    num: Box::new(self.argument(Mode::Math)?),
                    den: Box::new(self.argument(Mode::Math)?),
                    bar,
                    delimiters,
                    style,
                }
            }
            "\\left" => {
                let left = self.delimiter()?;
                self.expander.begin();
                let body = self.row(&["\\right"])?;
                self.expect("\\right")?;
                let right = self.delimiter()?;
                self.expander.end();
                Node::Fence {
                    left,
                    body: Box::new(body),
                    right,
                }
            }
            "\\middle" => Node::Middle(self.delimiter()?),
            "\\big" | "\\Big" | "\\bigg" | "\\Bigg" | "\\bigl" | "\\Bigl" | "\\biggl"
            | "\\Biggl" | "\\bigr" | "\\Bigr" | "\\biggr" | "\\Biggr" | "\\bigm" | "\\Bigm"
            | "\\biggm" | "\\Biggm" => {
                let size = if name.contains("Bigg") {
                    4
                } else if name.contains("bigg") {
                    3
                } else if name.contains("Big") {
                    2
                } else {
                    1
                };
                let class = if name.ends_with('l') {
                    Class::Open
                } else if name.ends_with('r') {
                    Class::Close
                } else if name.ends_with('m') {
                    Class::Rel
                } else {
                    Class::Ord
                };
                Node::SizedDelimiter {
                    value: self.delimiter()?,
                    size,
                    class,
                }
            }
            "\\begin" => {
                let env = self.raw_string()?;
                self.environment(&env, offset)?
            }
            "\\text" | "\\textrm" | "\\textsf" | "\\texttt" | "\\textnormal" | "\\textbf"
            | "\\textmd" | "\\textit" | "\\textup" | "\\emph" | "\\hbox" => {
                let body = self.argument(Mode::Text)?;
                styled(
                    body,
                    Some(name.trim_start_matches('\\').into()),
                    None,
                    None,
                    None,
                )
            }
            "$" | "\\(" if self.mode == Mode::Text => {
                let end = if name == "$" { "$" } else { "\\)" };
                let previous = self.mode;
                self.mode = Mode::Math;
                let body = self.row(&[end])?;
                self.expect(end)?;
                self.mode = previous;
                styled(body, Some("mathnormal".into()), None, Some(1), None)
            }
            "\\mathrm" | "\\mathit" | "\\mathbf" | "\\mathnormal" | "\\mathsfit" | "\\mathbb"
            | "\\mathcal" | "\\mathfrak" | "\\mathscr" | "\\mathsf" | "\\mathtt" | "\\Bbb"
            | "\\bold" | "\\frak" | "\\boldsymbol" | "\\bm" => {
                self.spaces()?;
                if matches!(
                    self.name()?.as_str(),
                    "\\mathrm"
                        | "\\mathit"
                        | "\\mathbf"
                        | "\\mathnormal"
                        | "\\mathsfit"
                        | "\\mathbb"
                        | "\\mathcal"
                        | "\\mathfrak"
                        | "\\mathscr"
                        | "\\mathsf"
                        | "\\mathtt"
                        | "\\Bbb"
                        | "\\bold"
                        | "\\frak"
                ) {
                    return Err(Error::new(offset, "Nested font commands require braces"));
                }
                let body = self.argument(self.mode)?;
                styled(
                    body,
                    Some(name.trim_start_matches('\\').into()),
                    None,
                    None,
                    None,
                )
            }
            "\\rm" | "\\sf" | "\\tt" | "\\bf" | "\\it" | "\\cal" => {
                let font = match name {
                    "\\rm" => "mathrm",
                    "\\sf" => "mathsf",
                    "\\tt" => "mathtt",
                    "\\bf" => "mathbf",
                    "\\it" => "mathit",
                    _ => "mathcal",
                };
                styled(self.row(stops)?, Some(font.into()), None, None, None)
            }
            "\\displaystyle" | "\\textstyle" | "\\scriptstyle" | "\\scriptscriptstyle" => {
                let style = match name {
                    "\\displaystyle" => 0,
                    "\\textstyle" => 1,
                    "\\scriptstyle" => 2,
                    _ => 3,
                };
                styled(self.row(stops)?, None, None, Some(style), None)
            }
            "\\tiny" | "\\sixptsize" | "\\scriptsize" | "\\footnotesize" | "\\small"
            | "\\normalsize" | "\\large" | "\\Large" | "\\LARGE" | "\\huge" | "\\Huge" => {
                let size = match name {
                    "\\tiny" => 0.5,
                    "\\sixptsize" => 0.6,
                    "\\scriptsize" => 0.7,
                    "\\footnotesize" => 0.8,
                    "\\small" => 0.9,
                    "\\normalsize" => 1.0,
                    "\\large" => 1.2,
                    "\\Large" => 1.44,
                    "\\LARGE" => 1.728,
                    "\\huge" => 2.074,
                    _ => 2.488,
                };
                styled(self.row(stops)?, None, Some(size), None, None)
            }
            "\\textcolor" => {
                let color = self.color(offset)?;
                styled(self.argument(self.mode)?, None, None, None, Some(color))
            }
            "\\color" => {
                let color = self.color(offset)?;
                styled(self.row(stops)?, None, None, None, Some(color))
            }
            "\\mathord" | "\\mathbin" | "\\mathrel" | "\\mathopen" | "\\mathclose"
            | "\\mathpunct" | "\\mathinner" => {
                let class = match name {
                    "\\mathbin" => Class::Bin,
                    "\\mathrel" => Class::Rel,
                    "\\mathopen" => Class::Open,
                    "\\mathclose" => Class::Close,
                    "\\mathpunct" => Class::Punct,
                    "\\mathinner" => Class::Inner,
                    _ => Class::Ord,
                };
                Node::Classed {
                    body: Box::new(self.argument(Mode::Math)?),
                    class,
                }
            }
            "\\@binrel" => {
                let base = self.argument(Mode::Math)?;
                let body = self.argument(Mode::Math)?;
                let class = first_class(&base);
                Node::Classed {
                    body: Box::new(body),
                    class,
                }
            }
            "\\stackrel" | "\\overset" | "\\underset" => {
                let annotation = self.argument(Mode::Math)?;
                let base = self.argument(Mode::Math)?;
                let class = if name == "\\stackrel" {
                    Class::Rel
                } else {
                    first_class(&base)
                };
                Node::Classed {
                    body: Box::new(Node::Scripts {
                        base: Box::new(Node::Operator {
                            body: Box::new(base),
                            limits: true,
                            large: false,
                        }),
                        sup: if name != "\\underset" {
                            Some(Box::new(annotation.clone()))
                        } else {
                            None
                        },
                        sub: if name == "\\underset" {
                            Some(Box::new(annotation))
                        } else {
                            None
                        },
                        limits: Some(true),
                    }),
                    class,
                }
            }
            "\\operatorname@" | "\\operatornamewithlimits" => {
                let body = self.argument(Mode::Math)?;
                Node::Operator {
                    body: Box::new(styled(body, Some("mathrm".into()), None, None, None)),
                    limits: name == "\\operatornamewithlimits",
                    large: false,
                }
            }
            "\\mathop" => Node::Operator {
                body: Box::new(self.argument(Mode::Math)?),
                limits: false,
                large: false,
            },
            "\\kern" | "\\mkern" | "\\hskip" | "\\mskip" => Node::Space(self.dimension()?),
            "\\rule" => {
                let shift = self
                    .optional_string()?
                    .map(|s| Dimension::parse(&s).map_err(|e| Error::new(offset, e)))
                    .transpose()?
                    .unwrap_or(Dimension::em(0.0));
                let width = self.dimension()?;
                let height = self.dimension()?;
                Node::Rule {
                    width,
                    height,
                    shift,
                }
            }
            "\\raisebox" => {
                let shift = self.dimension()?;
                Node::Raise {
                    body: Box::new(self.argument(Mode::Text)?),
                    shift,
                }
            }
            "\\phantom" | "\\vphantom" => Node::Phantom {
                body: Box::new(self.argument(self.mode)?),
                horizontal: name == "\\phantom",
                vertical: true,
            },
            "\\smash" => {
                let flags = self.optional_string()?.unwrap_or("tb".into());
                if !flags.chars().all(|c| c == 't' || c == 'b') {
                    return Err(Error::new(offset, "Smash option must contain t or b"));
                }
                Node::Smash {
                    body: Box::new(self.argument(self.mode)?),
                    top: flags.contains('t'),
                    bottom: flags.contains('b'),
                }
            }
            "\\mathllap" | "\\mathrlap" | "\\mathclap" => Node::Lap {
                body: Box::new(self.argument(self.mode)?),
                align: name.chars().nth(5).unwrap_or('c'),
            },
            "\\vcenter" => Node::VCenter(Box::new(self.argument(Mode::Math)?)),
            "\\pmb" => Node::Bold(Box::new(self.argument(self.mode)?)),
            "\\reflectbox" | "\\mathreflectbox" => {
                Node::Reflect(Box::new(self.argument(if name == "\\reflectbox" {
                    Mode::Text
                } else {
                    Mode::Math
                })?))
            }
            "\\mathchoice" => Node::Choice([
                Box::new(self.argument(Mode::Math)?),
                Box::new(self.argument(Mode::Math)?),
                Box::new(self.argument(Mode::Math)?),
                Box::new(self.argument(Mode::Math)?),
            ]),
            "\\html@mathml" => Node::Alternative {
                html: Box::new(self.argument(self.mode)?),
                mathml: Box::new(self.argument(self.mode)?),
            },
            "\\colorbox" | "\\fcolorbox" => {
                let border = self.color(offset)?;
                let background = if name == "\\fcolorbox" {
                    self.color(offset)?
                } else {
                    border.clone()
                };
                Node::Enclose {
                    body: Box::new(self.argument(Mode::Text)?),
                    name: name.into(),
                    background: Some(background),
                    border: if name == "\\fcolorbox" {
                        Some(border)
                    } else {
                        None
                    },
                }
            }
            "\\fbox" => Node::Enclose {
                body: Box::new(self.argument(Mode::Text)?),
                name: name.into(),
                background: None,
                border: None,
            },
            "\\cancel" | "\\bcancel" | "\\xcancel" | "\\sout" | "\\phase" | "\\angl" => {
                Node::Enclose {
                    body: Box::new(self.argument(self.mode)?),
                    name: name.into(),
                    background: None,
                    border: None,
                }
            }
            "\\href" => {
                self.raw_string()?;
                self.argument(self.mode)?;
                Node::Unsupported(name.into())
            }
            "\\url" => {
                self.raw_string()?;
                Node::Unsupported(name.into())
            }
            "\\htmlClass" | "\\htmlId" | "\\htmlStyle" | "\\htmlData" => {
                self.raw_string()?;
                self.argument(self.mode)?;
                Node::Unsupported(name.into())
            }
            "\\includegraphics" => {
                self.optional_string()?;
                self.raw_string()?;
                Node::Unsupported(name.into())
            }
            "\\\\" | "\\cr" => Node::Break(if self.expander.future() == " " {
                None
            } else {
                self.optional_string()?
                    .map(|s| Dimension::parse(&s).map_err(|e| Error::new(offset, e)))
                    .transpose()?
            }),
            " " if self.mode == Mode::Text => text_node("\u{a0}"),
            _ if name.starts_with("\\verb") => {
                let (content, visible) = if let Some(s) = name.strip_prefix("\\verb*") {
                    (s, true)
                } else {
                    (name.strip_prefix("\\verb").unwrap(), false)
                };
                let mut chars = content.chars();
                chars.next();
                let mut value = chars.collect::<String>();
                value.pop();
                if visible {
                    value = value.replace(' ', "␣");
                }
                styled(text_node(&value), Some("texttt".into()), None, None, None)
            }
            _ if is_accent(name) => {
                let text_accent = self.mode == Mode::Text
                    && matches!(
                        name,
                        "\\'"
                            | "\\`"
                            | "\\^"
                            | "\\~"
                            | "\\="
                            | "\\u"
                            | "\\."
                            | "\\\""
                            | "\\c"
                            | "\\r"
                            | "\\H"
                            | "\\v"
                    );
                let body = if text_accent && self.name()? == " " {
                    self.take()?;
                    Node::empty()
                } else if text_accent && self.name()? == "}" {
                    Node::empty()
                } else {
                    self.argument(self.mode)?
                };
                Node::Accent {
                    name: name.into(),
                    body: Box::new(body),
                    below: name.starts_with("\\under") || name == "\\utilde" || name == "\\c",
                }
            }
            _ if name.starts_with("\\x") && is_arrow(name) || name.starts_with("\\\\cd") => {
                let below = if self.name()? == "[" {
                    self.take()?;
                    let row = self.row(&["]"])?;
                    self.expect("]")?;
                    Some(Box::new(row))
                } else {
                    None
                };
                Node::Arrow {
                    name: name.into(),
                    above: Box::new(self.argument(Mode::Math)?),
                    below,
                }
            }
            _ if operator(name).is_some() => {
                let (glyph, limits, large) = operator(name).unwrap();
                let body = if large {
                    Node::Symbol {
                        value: glyph.into(),
                        class: Class::Op,
                        italic: false,
                        ams: false,
                        mode: Mode::Math,
                    }
                } else {
                    text_node(glyph)
                };
                Node::Operator {
                    body: Box::new(body),
                    limits,
                    large,
                }
            }
            _ => {
                if self.mode == Mode::Text && matches!(name, "-" | "`" | "'") {
                    let mut ligature = name.to_owned();
                    let max = if name == "-" { 3 } else { 2 };
                    while ligature.len() < max && self.name()? == name {
                        self.take()?;
                        ligature.push_str(name);
                    }
                    if let Some(n) = data::symbol(&ligature, self.mode) {
                        return Ok(n);
                    }
                }
                if let Some(node) = data::symbol(name, self.mode) {
                    node
                } else if name.chars().count() == 1
                    && !name.starts_with('\\')
                    && !matches!(name, "$" | "#" | "^" | "_")
                {
                    let c = name.chars().next().unwrap();
                    if let Some((ch, font)) = data::unicode_font(c) {
                        styled(
                            data::symbol(&ch.to_string(), self.mode).unwrap(),
                            Some(font.into()),
                            None,
                            None,
                            None,
                        )
                    } else {
                        Node::Symbol {
                            value: name.into(),
                            class: Class::Ord,
                            italic: self.mode == Mode::Math && c.is_alphabetic(),
                            ams: false,
                            mode: self.mode,
                        }
                    }
                } else {
                    return Err(Error::new(offset, format!("Unknown command {name}")));
                }
            }
        };
        Ok(node)
    }
    fn color(&mut self, offset: usize) -> Result<String> {
        let value = self.raw_string()?;
        if value.is_empty() || !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '#') {
            return Err(Error::new(offset, "Invalid color"));
        }
        Ok(
            if !value.starts_with('#')
                && matches!(value.len(), 3 | 6)
                && value.chars().all(|c| c.is_ascii_hexdigit())
            {
                format!("#{value}")
            } else {
                value
            },
        )
    }
    fn environment(&mut self, env: &str, offset: usize) -> Result<Node> {
        let allowed = [
            "array",
            "darray",
            "matrix",
            "pmatrix",
            "bmatrix",
            "Bmatrix",
            "vmatrix",
            "Vmatrix",
            "matrix*",
            "pmatrix*",
            "bmatrix*",
            "Bmatrix*",
            "vmatrix*",
            "Vmatrix*",
            "smallmatrix",
            "subarray",
            "cases",
            "dcases",
            "rcases",
            "drcases",
            "aligned",
            "align",
            "align*",
            "alignedat",
            "alignat",
            "alignat*",
            "gather",
            "gather*",
            "gathered",
            "split",
            "equation",
            "equation*",
            "CD",
        ];
        if !allowed.contains(&env) {
            return Err(Error::new(offset, format!("Unknown environment {env}")));
        }
        if matches!(
            env,
            "align"
                | "align*"
                | "alignat"
                | "alignat*"
                | "gather"
                | "gather*"
                | "equation"
                | "equation*"
                | "split"
                | "CD"
        ) && !self.display
        {
            return Err(Error::new(offset, format!("{env} requires display mode")));
        }
        self.expander.begin();
        let outer_tag = self.tag.take();
        let stretch = if env.contains("cases") {
            1.2
        } else if env == "smallmatrix" || env == "subarray" {
            0.5
        } else if let Some(value) = self.expander.macro_text("\\arraystretch", self.mode)? {
            value
                .trim()
                .parse::<f64>()
                .ok()
                .filter(|n| n.is_finite() && *n > 0.0)
                .ok_or_else(|| Error::new(offset, "Invalid array stretch"))?
        } else {
            1.0
        };
        let mut columns = if matches!(env, "array" | "darray" | "subarray") {
            self.raw_string()?
        } else if env.contains("align") || env == "split" {
            "rl".into()
        } else if env.contains("cases") {
            "ll".into()
        } else if env.ends_with('*') && env.contains("matrix") {
            let col = self.optional_string()?.unwrap_or("c".into());
            if !matches!(col.as_str(), "l" | "c" | "r") {
                return Err(Error::new(offset, "Matrix alignment must be l, c, or r"));
            }
            col
        } else {
            "c".into()
        };
        if env.contains("alignat") {
            let count = self
                .raw_string()?
                .parse::<usize>()
                .map_err(|_| Error::new(offset, "Invalid alignat column count"))?;
            columns = "rl".repeat(count);
        }
        if !columns.chars().all(|c| "lcr|: ".contains(c)) {
            return Err(Error::new(offset, "Invalid array column specification"));
        }
        if env == "subarray" && !matches!(columns.as_str(), "l" | "c") {
            return Err(Error::new(offset, "Subarray requires one l or c column"));
        }
        let mut rows = Vec::new();
        let mut row = Vec::new();
        let mut tags = Vec::new();
        let mut gaps = Vec::new();
        let mut rules = Vec::new();
        let auto_tag = matches!(env, "align" | "alignat" | "gather" | "equation");
        if auto_tag {
            self.expander.global_text("\\@eqnsw", "1")?;
        }
        loop {
            self.spaces()?;
            while matches!(self.name()?.as_str(), "\\hline" | "\\hdashline" | "\\relax") {
                let t = self.take()?;
                if t.text != "\\relax" {
                    rules.push((rows.len(), t.text == "\\hdashline"));
                }
                self.spaces()?;
            }
            self.expander.begin();
            let cell = self.row(&["&", "\\\\", "\\cr", "\\end"])?;
            self.expander.end();
            row.push(cell);
            let max = if matches!(
                env,
                "equation" | "equation*" | "gather" | "gather*" | "gathered" | "subarray"
            ) {
                Some(1)
            } else if env == "split" {
                Some(2)
            } else if env.contains("alignat") || matches!(env, "array" | "darray") {
                Some(columns.chars().filter(|c| "lcr".contains(*c)).count())
            } else {
                None
            };
            if max.is_some_and(|max| row.len() > max) {
                return Err(Error::new(offset, "Too many columns in math environment"));
            }
            let end = self.take()?;
            if end.text == "&" {
                if env == "subarray" {
                    return Err(Error::new(end.offset, "Subarray only has one column"));
                }
                continue;
            }
            if end.text == "\\end" {
                let actual = self.raw_string()?;
                if actual != env {
                    return Err(Error::new(
                        end.offset,
                        format!("Expected end of {env}, found {actual}"),
                    ));
                }
                if !row.iter().all(Node::is_empty) || rows.is_empty() || self.tag.is_some() {
                    rows.push(row);
                    tags.push(self.row_tag(auto_tag)?);
                }
                break;
            }
            rows.push(row);
            row = Vec::new();
            tags.push(self.row_tag(auto_tag)?);
            if auto_tag {
                self.expander.global_text("\\@eqnsw", "1")?;
            }
            gaps.push(if end.text == "\\cr" || self.expander.future() == " " {
                Dimension::em(0.0)
            } else {
                self.optional_string()?
                    .map(|s| Dimension::parse(&s).map_err(|e| Error::new(offset, e)))
                    .transpose()?
                    .unwrap_or(Dimension::em(0.0))
            });
        }
        self.tag = outer_tag;
        self.expander.end();
        if env == "CD" {
            rows = cd_rows(rows, offset)?;
        }
        Ok(Node::Array {
            rows,
            columns,
            environment: env.into(),
            gaps,
            rules,
            tags,
            stretch,
        })
    }
    fn row_tag(&mut self, auto: bool) -> Result<Option<Node>> {
        if let Some(tag) = self.tag.take() {
            return Ok(Some(tag));
        }
        if auto && self.expander.macro_text("\\@eqnsw", self.mode)?.as_deref() != Some("0") {
            self.equation_count += 1;
            Ok(Some(text_node(&format!("({})", self.equation_count))))
        } else {
            Ok(None)
        }
    }
}

fn cd_rows(rows: Vec<Vec<Node>>, offset: usize) -> Result<Vec<Vec<Node>>> {
    let mut result = Vec::new();
    for (row_number, row) in rows.into_iter().enumerate() {
        let nodes: Vec<_> = row
            .into_iter()
            .flat_map(|cell| match cell {
                Node::Row(nodes) => nodes,
                other => vec![other],
            })
            .collect();
        let mut cells = Vec::new();
        let mut cell = Vec::new();
        let mut iter = nodes.into_iter();
        while let Some(node) = iter.next() {
            if !matches!(&node,Node::Symbol {value,..} if value == "@") {
                cell.push(node);
                continue;
            }
            cells.push(Node::row(std::mem::take(&mut cell)));
            let mut arrow = iter
                .next()
                .ok_or_else(|| Error::new(offset, "Missing CD arrow"))?
                .text();
            if arrow == "∣" {
                arrow = "|".into();
            }
            if !matches!(arrow.as_str(), ">" | "<" | "A" | "V" | "=" | "|" | ".") {
                return Err(Error::new(offset, format!("Invalid CD arrow {arrow}")));
            }
            let mut labels = Vec::new();
            if matches!(arrow.as_str(), ">" | "<" | "A" | "V") {
                for _ in 0..2 {
                    let mut label = Vec::new();
                    loop {
                        let node = iter
                            .next()
                            .ok_or_else(|| Error::new(offset, "Unclosed CD arrow label"))?;
                        if matches!(&node,Node::Symbol {value,..} if value == &arrow) {
                            break;
                        }
                        if matches!(&node,Node::Symbol {value,..} if value == "@") {
                            return Err(Error::new(offset, "Unclosed CD arrow label"));
                        }
                        label.push(node);
                    }
                    labels.push(Node::row(label));
                }
            }
            let node = match arrow.as_str() {
                ">" | "<" => Node::Arrow {
                    name: if arrow == ">" {
                        "\\\\cdrightarrow"
                    } else {
                        "\\\\cdleftarrow"
                    }
                    .into(),
                    above: Box::new(labels.remove(0)),
                    below: Some(Box::new(labels.remove(0))),
                },
                "A" | "V" => Node::VerticalArrow {
                    value: if arrow == "A" { "↑" } else { "↓" }.into(),
                    left: Box::new(labels.remove(0)),
                    right: Box::new(labels.remove(0)),
                },
                "=" => Node::Arrow {
                    name: "\\\\cdlongequal".into(),
                    above: Box::new(Node::empty()),
                    below: None,
                },
                "|" => Node::SizedDelimiter {
                    value: "∥".into(),
                    size: 2,
                    class: Class::Rel,
                },
                _ => Node::Space(Dimension::em(0.5)),
            };
            cells.push(node);
        }
        if row_number % 2 == 0 {
            cells.push(Node::row(cell));
        } else if !cells.is_empty() {
            cells.remove(0);
        }
        result.push(cells);
    }
    Ok(result)
}

fn first_class(node: &Node) -> Class {
    match node {
        Node::Row(v) => v.first().map_or(Class::Ord, first_class),
        _ => node.class(),
    }
}
fn delimiter_value(value: &str) -> String {
    data::symbol(value, Mode::Math)
        .map(|n| n.text())
        .unwrap_or_else(|| match value {
            "\\{" => "{".into(),
            "\\}" => "}".into(),
            "\\|" | "\\Vert" => "‖".into(),
            "\\langle" => "⟨".into(),
            "\\rangle" => "⟩".into(),
            _ => value.into(),
        })
}
fn is_accent(n: &str) -> bool {
    matches!(
        n,
        "\\acute"
            | "\\grave"
            | "\\ddot"
            | "\\tilde"
            | "\\bar"
            | "\\breve"
            | "\\check"
            | "\\hat"
            | "\\vec"
            | "\\dot"
            | "\\mathring"
            | "\\widecheck"
            | "\\widehat"
            | "\\widetilde"
            | "\\overrightarrow"
            | "\\overleftarrow"
            | "\\Overrightarrow"
            | "\\overleftrightarrow"
            | "\\overgroup"
            | "\\overlinesegment"
            | "\\overleftharpoon"
            | "\\overrightharpoon"
            | "\\'"
            | "\\`"
            | "\\^"
            | "\\~"
            | "\\="
            | "\\u"
            | "\\."
            | "\\\""
            | "\\c"
            | "\\r"
            | "\\H"
            | "\\v"
            | "\\textcircled"
            | "\\underleftarrow"
            | "\\underrightarrow"
            | "\\underleftrightarrow"
            | "\\undergroup"
            | "\\underlinesegment"
            | "\\utilde"
            | "\\overbrace"
            | "\\underbrace"
            | "\\overbracket"
            | "\\underbracket"
            | "\\overline"
            | "\\underline"
    )
}
fn is_arrow(n: &str) -> bool {
    matches!(
        n,
        "\\xleftarrow"
            | "\\xrightarrow"
            | "\\xLeftarrow"
            | "\\xRightarrow"
            | "\\xleftrightarrow"
            | "\\xLeftrightarrow"
            | "\\xhookleftarrow"
            | "\\xhookrightarrow"
            | "\\xmapsto"
            | "\\xrightharpoondown"
            | "\\xrightharpoonup"
            | "\\xleftharpoondown"
            | "\\xleftharpoonup"
            | "\\xrightleftharpoons"
            | "\\xleftrightharpoons"
            | "\\xlongequal"
            | "\\xtwoheadrightarrow"
            | "\\xtwoheadleftarrow"
            | "\\xtofrom"
            | "\\xrightleftarrows"
            | "\\xrightequilibrium"
            | "\\xleftequilibrium"
    )
}
fn operator(n: &str) -> Option<(&str, bool, bool)> {
    Some(match n {
        "\\sum" | "∑" => ("∑", true, true),
        "\\prod" | "∏" => ("∏", true, true),
        "\\coprod" | "∐" => ("∐", true, true),
        "\\bigvee" | "⋁" => ("⋁", true, true),
        "\\bigwedge" | "⋀" => ("⋀", true, true),
        "\\biguplus" | "⨄" => ("⨄", true, true),
        "\\bigcap" | "⋂" => ("⋂", true, true),
        "\\bigcup" | "⋃" => ("⋃", true, true),
        "\\bigotimes" | "⨂" => ("⨂", true, true),
        "\\bigoplus" | "⨁" => ("⨁", true, true),
        "\\bigodot" | "⨀" => ("⨀", true, true),
        "\\bigsqcup" | "⨆" => ("⨆", true, true),
        "\\int" | "∫" => ("∫", false, true),
        "\\intop" => ("∫", true, true),
        "\\smallint" => ("∫", false, false),
        "\\iint" | "∬" => ("∬", false, true),
        "\\iiint" | "∭" => ("∭", false, true),
        "\\oint" | "∮" => ("∮", false, true),
        "\\oiint" | "∯" => ("∯", false, true),
        "\\oiiint" | "∰" => ("∰", false, true),
        "\\det" | "\\gcd" | "\\inf" | "\\lim" | "\\max" | "\\min" | "\\Pr" | "\\sup" => {
            (n.trim_start_matches('\\'), true, false)
        }
        "\\arcsin" | "\\arccos" | "\\arctan" | "\\arctg" | "\\arcctg" | "\\arg" | "\\ch"
        | "\\cos" | "\\cosec" | "\\cosh" | "\\cot" | "\\cotg" | "\\coth" | "\\csc" | "\\ctg"
        | "\\cth" | "\\deg" | "\\dim" | "\\exp" | "\\hom" | "\\ker" | "\\lg" | "\\ln" | "\\log"
        | "\\sec" | "\\sin" | "\\sinh" | "\\sh" | "\\tan" | "\\tanh" | "\\tg" | "\\th" => {
            (n.trim_start_matches('\\'), false, false)
        }
        _ => return None,
    })
}
