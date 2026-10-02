// Copyright (C) 2026 Fadouse
// SPDX-License-Identifier: GPL-3.0-only

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Math,
    Text,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Ord,
    Op,
    Bin,
    Rel,
    Open,
    Close,
    Punct,
    Inner,
    Space,
}

impl Class {
    pub fn from_name(name: &str) -> Self {
        match name {
            "op-token" => Self::Op,
            "bin" => Self::Bin,
            "rel" => Self::Rel,
            "open" => Self::Open,
            "close" => Self::Close,
            "punct" => Self::Punct,
            "inner" => Self::Inner,
            "spacing" => Self::Space,
            _ => Self::Ord,
        }
    }
}

#[derive(Clone, Debug)]
pub enum Node {
    Row(Vec<Node>),
    Symbol {
        value: String,
        class: Class,
        italic: bool,
        ams: bool,
        mode: Mode,
    },
    Scripts {
        base: Box<Node>,
        sup: Option<Box<Node>>,
        sub: Option<Box<Node>>,
        limits: Option<bool>,
    },
    Fraction {
        num: Box<Node>,
        den: Box<Node>,
        bar: Option<Dimension>,
        delimiters: Option<(String, String)>,
        style: Option<u8>,
    },
    Root {
        body: Box<Node>,
        index: Option<Box<Node>>,
    },
    Fence {
        left: String,
        body: Box<Node>,
        right: String,
    },
    Middle(String),
    SizedDelimiter {
        value: String,
        size: u8,
        class: Class,
    },
    Accent {
        name: String,
        body: Box<Node>,
        below: bool,
    },
    Operator {
        body: Box<Node>,
        limits: bool,
        large: bool,
    },
    Styled {
        body: Box<Node>,
        font: Option<String>,
        size: Option<f64>,
        style: Option<u8>,
        color: Option<String>,
    },
    Classed {
        body: Box<Node>,
        class: Class,
    },
    Space(Dimension),
    Rule {
        width: Dimension,
        height: Dimension,
        shift: Dimension,
    },
    Raise {
        body: Box<Node>,
        shift: Dimension,
    },
    Phantom {
        body: Box<Node>,
        horizontal: bool,
        vertical: bool,
    },
    Smash {
        body: Box<Node>,
        top: bool,
        bottom: bool,
    },
    Lap {
        body: Box<Node>,
        align: char,
    },
    Enclose {
        body: Box<Node>,
        name: String,
        background: Option<String>,
        border: Option<String>,
    },
    Reflect(Box<Node>),
    VCenter(Box<Node>),
    Bold(Box<Node>),
    Choice([Box<Node>; 4]),
    Alternative {
        html: Box<Node>,
        mathml: Box<Node>,
    },
    Arrow {
        name: String,
        above: Box<Node>,
        below: Option<Box<Node>>,
    },
    Array {
        rows: Vec<Vec<Node>>,
        columns: String,
        environment: String,
        gaps: Vec<Dimension>,
        rules: Vec<(usize, bool)>,
        tags: Vec<Option<Node>>,
        stretch: f64,
    },
    VerticalArrow {
        value: String,
        left: Box<Node>,
        right: Box<Node>,
    },
    Tagged {
        body: Box<Node>,
        tag: Box<Node>,
    },
    Break(Option<Dimension>),
    LineControl(bool),
    Unsupported(String),
}

impl Node {
    pub fn empty() -> Self {
        Self::Row(Vec::new())
    }
    pub fn row(nodes: Vec<Self>) -> Self {
        Self::Row(nodes)
    }
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Row(v) if v.is_empty())
    }
    pub fn class(&self) -> Class {
        match self {
            Self::Symbol { class, .. }
            | Self::Classed { class, .. }
            | Self::SizedDelimiter { class, .. } => *class,
            Self::Operator { .. } => Class::Op,
            Self::Scripts { base, .. }
            | Self::Accent { body: base, .. }
            | Self::Styled { body: base, .. } => base.class(),
            Self::Arrow { .. } | Self::VerticalArrow { .. } => Class::Rel,
            Self::Fraction { .. } | Self::Fence { .. } | Self::Array { .. } => Class::Inner,
            Self::Space(_) | Self::Break(_) | Self::LineControl(_) => Class::Space,
            _ => Class::Ord,
        }
    }
    pub fn text(&self) -> String {
        match self {
            Self::Symbol { value, .. } | Self::Unsupported(value) => value.clone(),
            Self::Row(v) => v.iter().map(Self::text).collect(),
            Self::Scripts { base, sup, sub, .. } => format!(
                "{}{}{}",
                base.text(),
                sub.as_ref()
                    .map(|n| format!("_{}", n.text()))
                    .unwrap_or_default(),
                sup.as_ref()
                    .map(|n| format!("^{}", n.text()))
                    .unwrap_or_default()
            ),
            Self::Fraction { num, den, .. } => format!("({})/({})", num.text(), den.text()),
            Self::Root { body, index } => format!(
                "{}√({})",
                index.as_ref().map(|n| n.text()).unwrap_or_default(),
                body.text()
            ),
            Self::Fence { left, body, right } => format!("{left}{}{right}", body.text()),
            Self::Middle(s) | Self::SizedDelimiter { value: s, .. } => s.clone(),
            Self::Accent { body, .. }
            | Self::Operator { body, .. }
            | Self::Styled { body, .. }
            | Self::Classed { body, .. }
            | Self::Raise { body, .. }
            | Self::Smash { body, .. }
            | Self::Lap { body, .. }
            | Self::Enclose { body, .. }
            | Self::Reflect(body)
            | Self::VCenter(body)
            | Self::Bold(body) => body.text(),
            Self::Phantom { .. } | Self::Rule { .. } => String::new(),
            Self::Space(_) | Self::Break(_) => " ".into(),
            Self::Choice(c) => c[1].text(),
            Self::Alternative { mathml, .. } => mathml.text(),
            Self::Arrow { name, above, below } => format!(
                "{} {} {}",
                below.as_ref().map(|n| n.text()).unwrap_or_default(),
                arrow_character(name),
                above.text()
            ),
            Self::Array { rows, .. } => rows
                .iter()
                .map(|r| r.iter().map(Self::text).collect::<Vec<_>>().join(" "))
                .collect::<Vec<_>>()
                .join("; "),
            Self::Tagged { body, tag, .. } => format!("{} {}", body.text(), tag.text()),
            Self::VerticalArrow { value, left, right } => {
                format!("{} {value} {}", left.text(), right.text())
            }
            Self::LineControl(_) => String::new(),
        }
    }
}

pub fn arrow_character(name: &str) -> &'static str {
    if name.contains("longequal") {
        "="
    } else if name.contains("leftrightharpoons") {
        "⇋"
    } else if name.contains("rightleftharpoons") || name.contains("rightequilibrium") {
        "⇌"
    } else if name.contains("leftequilibrium") {
        "⇋"
    } else if name.contains("rightleftarrows") {
        "⇄"
    } else if name.contains("tofrom") {
        "⇆"
    } else if name.contains("Leftright") {
        "⇔"
    } else if name.contains("leftright") {
        "↔"
    } else if name.contains("Left") {
        "⇐"
    } else if name.contains("Right") {
        "⇒"
    } else if name.contains("leftharpoonup") {
        "↼"
    } else if name.contains("leftharpoondown") {
        "↽"
    } else if name.contains("rightharpoonup") {
        "⇀"
    } else if name.contains("rightharpoondown") {
        "⇁"
    } else if name.contains("leftharpoon") {
        "↼"
    } else if name.contains("rightharpoon") {
        "⇀"
    } else if name.contains("twoheadleft") {
        "↞"
    } else if name.contains("twoheadright") {
        "↠"
    } else if name.contains("hookleft") {
        "↩"
    } else if name.contains("hookright") {
        "↪"
    } else if name.contains("mapsto") {
        "↦"
    } else if name.contains("left") {
        "←"
    } else {
        "→"
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Dimension {
    pub value: f64,
    pub unit: &'static str,
}
impl Dimension {
    pub const fn em(value: f64) -> Self {
        Self { value, unit: "em" }
    }
    pub fn parse(source: &str) -> Result<Self, String> {
        let s = source.trim();
        let split = s.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(s.len());
        let number = s[..split]
            .replace(' ', "")
            .parse::<f64>()
            .map_err(|_| format!("Invalid dimension: {source}"))?;
        let unit = match s[split..].trim() {
            "em" => "em",
            "ex" => "ex",
            "mu" => "mu",
            "pt" => "pt",
            "mm" => "mm",
            "cm" => "cm",
            "in" => "in",
            "bp" => "bp",
            "pc" => "pc",
            "dd" => "dd",
            "cc" => "cc",
            "nd" => "nd",
            "nc" => "nc",
            "sp" => "sp",
            "px" => "px",
            "" if number == 0.0 => "em",
            _ => return Err(format!("Invalid dimension unit: {source}")),
        };
        if !number.is_finite() {
            return Err(format!("Non-finite dimension: {source}"));
        }
        Ok(Self {
            value: number,
            unit,
        })
    }
    pub fn ems(self, scale: f64) -> f64 {
        self.value
            * match self.unit {
                "em" => scale,
                "ex" => 0.431 * scale,
                "mu" => scale / 18.0,
                "pt" => 0.1,
                "bp" => 0.100375,
                "pc" => 1.2,
                "in" => 7.227,
                "cm" => 7.227 / 2.54,
                "mm" => 7.227 / 25.4,
                "dd" => 1238.0 / 1157.0 / 10.0,
                "cc" => 12.0 * 1238.0 / 1157.0 / 10.0,
                "nd" => 685.0 / 642.0 / 10.0,
                "nc" => 12.0 * 685.0 / 642.0 / 10.0,
                "sp" => 1.0 / 655360.0,
                "px" => 0.100375,
                _ => unreachable!(),
            }
    }
}
