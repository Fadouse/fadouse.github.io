use super::{Error, Result};

#[derive(Clone, Debug)]
pub struct Token {
    pub text: String,
    pub offset: usize,
    pub frozen: bool,
    pub relax: bool,
}
impl Token {
    pub fn new(text: impl Into<String>, offset: usize) -> Self {
        Self {
            text: text.into(),
            offset,
            frozen: false,
            relax: false,
        }
    }
}

pub fn lex(source: &str) -> Result<Vec<Token>> {
    let mut out = Vec::new();
    let mut chars = source.char_indices().peekable();
    while let Some((offset, c)) = chars.next() {
        let mut text = c.to_string();
        if c == '%' {
            for (_, next) in chars.by_ref() {
                if next == '\n' {
                    break;
                }
            }
            continue;
        }
        if c == '\\' {
            let Some((_, next)) = chars.next() else {
                return Err(Error::new(offset, "Trailing backslash"));
            };
            text.push(next);
            if next.is_ascii_alphabetic() || next == '@' {
                while chars
                    .peek()
                    .is_some_and(|(_, n)| n.is_ascii_alphabetic() || *n == '@')
                {
                    text.push(chars.next().unwrap().1);
                }
                if text == "\\verb" {
                    if chars.peek().is_some_and(|(_, n)| *n == '*') {
                        text.push(chars.next().unwrap().1);
                    }
                    let Some((_, delimiter)) = chars.next() else {
                        return Err(Error::new(offset, "Missing verb delimiter"));
                    };
                    text.push(delimiter);
                    let mut closed = false;
                    for (_, n) in chars.by_ref() {
                        text.push(n);
                        if n == delimiter {
                            closed = true;
                            break;
                        }
                        if n == '\n' {
                            break;
                        }
                    }
                    if !closed {
                        return Err(Error::new(offset, "Unterminated verbatim text"));
                    }
                } else {
                    while chars.peek().is_some_and(|(_, n)| n.is_whitespace()) {
                        chars.next();
                    }
                }
            } else if next.is_whitespace() {
                text = "\\ ".into();
            }
        } else if c.is_whitespace() {
            text = " ".into();
            while chars.peek().is_some_and(|(_, n)| n.is_whitespace()) {
                chars.next();
            }
        } else {
            while chars
                .peek()
                .is_some_and(|(_, c)| ('\u{0300}'..='\u{036f}').contains(c))
            {
                text.push(chars.next().unwrap().1);
            }
        }
        out.push(Token::new(text, offset));
    }
    Ok(out)
}
