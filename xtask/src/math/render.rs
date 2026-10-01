use super::{
    Rendered, Result,
    ast::{Class, Dimension, Mode, Node},
    data,
};
use shared::escape_html as escape;
use std::{collections::BTreeSet, fmt::Write};

#[derive(Clone)]
struct Context {
    style: u8,
    size: f64,
    font: String,
    cramped: bool,
    text_family: char,
    text_bold: bool,
    text_italic: bool,
}
impl Context {
    fn scale(&self) -> f64 {
        self.size
            * match self.style {
                0 | 1 => 1.0,
                2 => 0.7,
                _ => 0.5,
            }
    }
    fn script(&self) -> Self {
        let mut c = self.clone();
        c.style = (c.style + 1).clamp(2, 3);
        c
    }
    fn frac(&self) -> Self {
        let mut c = self.clone();
        c.style = (c.style + 1).min(3);
        c
    }
    fn length(&self, d: Dimension) -> f64 {
        d.ems(if d.unit == "mu" {
            self.scale()
        } else {
            self.size
        })
    }
}
#[derive(Default)]
struct BoxLayout {
    w: f64,
    h: f64,
    d: f64,
    italic: f64,
    skew: f64,
    svg: String,
}
impl BoxLayout {
    fn place(&mut self, child: &Self, x: f64, shift: f64) {
        self.h = self.h.max(child.h + shift);
        self.d = self.d.max(child.d - shift);
        write!(
            self.svg,
            "<g transform=\"translate({} {})\">{}</g>",
            num(x),
            num(-shift),
            child.svg
        )
        .unwrap();
    }
    fn line(&mut self, x1: f64, y1: f64, x2: f64, y2: f64, thickness: f64) {
        write!(
            self.svg,
            "<path d=\"M{} {}L{} {}\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"{}\"/>",
            num(x1),
            num(-y1),
            num(x2),
            num(-y2),
            num(thickness)
        )
        .unwrap();
    }
    fn rect(&mut self, x: f64, bottom: f64, w: f64, h: f64, color: &str) {
        write!(
            self.svg,
            "<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"{}\"/>",
            num(x),
            num(-bottom - h),
            num(w.max(0.0)),
            num(h.max(0.0)),
            escape(color)
        )
        .unwrap();
    }
}
fn num(value: f64) -> String {
    let s = format!("{value:.5}");
    s.trim_end_matches('0').trim_end_matches('.').to_owned()
}
struct Layout {
    fonts: BTreeSet<String>,
}

impl Layout {
    fn glyph(&mut self, value: &str, font: &str, scale: f64, class: Class) -> BoxLayout {
        let mut out = BoxLayout::default();
        let mut x = 0.0;
        for c in value.chars() {
            let mut chosen = font.to_owned();
            let metrics = data::metrics(font, c).or_else(|| {
                chosen = "Main-Regular".into();
                data::metrics(&chosen, c)
            });
            let m = metrics.unwrap_or([
                0.2,
                0.7,
                0.0,
                0.0,
                if c.is_whitespace() {
                    0.25
                } else if (0x2e80..=0xffff).contains(&(c as u32)) {
                    1.0
                } else {
                    0.6
                },
            ]);
            if metrics.is_some() {
                self.fonts.insert(chosen.clone());
            }
            let family = if metrics.is_some() {
                format!("BlogMath-{chosen}")
            } else {
                "serif".into()
            };
            write!(
                out.svg,
                "<text x=\"{}\" y=\"0\" font-family=\"{}\" font-size=\"{}\">{}</text>",
                num(x),
                family,
                num(scale),
                escape(&c.to_string())
            )
            .unwrap();
            out.h = out.h.max(m[1] * scale);
            out.d = out.d.max(m[0] * scale);
            out.italic = m[2] * scale;
            out.skew = m[3] * scale;
            x += m[4] * scale;
        }
        out.w = x + if class == Class::Ord { out.italic } else { 0.0 };
        out
    }
    fn symbol(
        &mut self,
        value: &str,
        italic: bool,
        ams: bool,
        mode: Mode,
        c: &Context,
    ) -> BoxLayout {
        let font = if mode == Mode::Text
            && (c.font.is_empty()
                || c.font.starts_with("text")
                || matches!(c.font.as_str(), "emph" | "hbox"))
        {
            match (c.text_family, c.text_bold, c.text_italic) {
                ('s', true, _) => "SansSerif-Bold",
                ('s', _, true) => "SansSerif-Italic",
                ('s', _, _) => "SansSerif-Regular",
                ('t', _, _) => "Typewriter-Regular",
                (_, true, true) => "Main-BoldItalic",
                (_, true, _) => "Main-Bold",
                (_, _, true) => "Main-Italic",
                _ => "Main-Regular",
            }
        } else {
            match c.font.as_str() {
                "mathbf" | "bold" | "textbf" => "Main-Bold",
                "boldsymbol" | "bm" => {
                    if italic {
                        "Math-BoldItalic"
                    } else {
                        "Main-Bold"
                    }
                }
                "mathrm" | "textrm" | "textnormal" | "textmd" | "textup" | "hbox" => "Main-Regular",
                "mathit" | "textit" | "emph" => "Main-Italic",
                "mathbb" | "Bbb" => "AMS-Regular",
                "mathcal" => "Caligraphic-Regular",
                "mathscr" => "Script-Regular",
                "mathfrak" | "frak" => "Fraktur-Regular",
                "mathfrak-bold" => "Fraktur-Bold",
                "mathsf" | "textsf" => "SansSerif-Regular",
                "mathsf-bold" => "SansSerif-Bold",
                "mathsfit" => "SansSerif-Italic",
                "mathtt" | "texttt" => "Typewriter-Regular",
                _ => {
                    if ams {
                        "AMS-Regular"
                    } else if italic && mode == Mode::Math {
                        "Math-Italic"
                    } else {
                        "Main-Regular"
                    }
                }
            }
        };
        self.glyph(value, font, c.scale(), Class::Ord)
    }
    fn row(&mut self, nodes: &[Node], c: &Context, fence_height: Option<f64>) -> BoxLayout {
        if nodes.iter().any(|n| matches!(n, Node::Break(_))) {
            let mut out = BoxLayout::default();
            let mut start = 0;
            let mut baseline = 0.0;
            let mut previous_depth = 0.0;
            let mut gap = 0.0;
            for end in 0..=nodes.len() {
                if end != nodes.len() && !matches!(nodes[end], Node::Break(_)) {
                    continue;
                }
                let line = self.row(&nodes[start..end], c, fence_height);
                if start != 0 {
                    baseline -= previous_depth + line.h + 0.4 * c.scale() + gap;
                }
                out.place(&line, 0.0, baseline);
                out.w = out.w.max(line.w);
                previous_depth = line.d;
                gap = if let Some(Node::Break(d)) = nodes.get(end) {
                    d.map_or(0.0, |d| d.ems(c.scale()))
                } else {
                    0.0
                };
                start = end + 1;
            }
            return out;
        }
        let classes = atom_classes(nodes);
        let mut out = BoxLayout::default();
        let mut previous = None;
        for (i, node) in nodes.iter().enumerate() {
            let child = if let Node::Middle(value) = node {
                self.delimiter(value, fence_height.unwrap_or(c.scale()), c)
            } else {
                self.node(node, c)
            };
            let class = classes[i];
            if class != Class::Space {
                if let Some(left) = previous {
                    out.w += spacing(left, class, c.style) * c.scale();
                }
                previous = Some(class);
            }
            out.place(&child, out.w, 0.0);
            out.w += child.w;
            out.italic = child.italic;
            out.skew = child.skew;
        }
        out
    }
    fn inline(&mut self, tree: &Node, c: &Context) -> Result<String> {
        let Node::Row(nodes) = tree else {
            return svg(&self.node(tree, c));
        };
        if nodes.iter().any(|n| matches!(n, Node::Break(_))) {
            return svg(&self.node(tree, c));
        }
        let classes = atom_classes(nodes);
        let mut out = BoxLayout::default();
        let mut html = String::new();
        let mut previous = None;
        let mut pending = false;
        for (i, node) in nodes.iter().enumerate() {
            if let Node::LineControl(allowed) = node {
                pending = *allowed;
                continue;
            }
            let class = classes[i];
            if class != Class::Space {
                if let Some(left) = previous {
                    out.w += spacing(left, class, c.style) * c.scale();
                }
                if pending {
                    html.push_str(&svg(&out)?);
                    html.push_str("<wbr>");
                    out = BoxLayout::default();
                    pending = false;
                }
                previous = Some(class);
            }
            let child = self.node(node, c);
            out.place(&child, out.w, 0.0);
            out.w += child.w;
            if matches!(class, Class::Bin | Class::Rel) {
                pending = true;
            }
        }
        html.push_str(&svg(&out)?);
        Ok(html)
    }
    fn delimiter(&mut self, value: &str, height: f64, c: &Context) -> BoxLayout {
        if value.is_empty() {
            return BoxLayout {
                w: 0.12 * c.scale(),
                ..Default::default()
            };
        }
        let ch = value.chars().next().unwrap();
        let mut font = "Main-Regular";
        let mut found = false;
        for choice in [
            "Main-Regular",
            "Size1-Regular",
            "Size2-Regular",
            "Size3-Regular",
            "Size4-Regular",
        ] {
            if let Some(m) = data::metrics(choice, ch) {
                font = choice;
                if (m[0] + m[1]) * c.scale() >= height {
                    found = true;
                    break;
                }
            }
        }
        let glyph = self.glyph(value, font, c.scale(), Class::Ord);
        if !found
            && glyph.h + glyph.d < height
            && let Some(stacked) = self.stacked_delimiter(ch, height, c)
        {
            return stacked;
        }
        let shift = (glyph.d - glyph.h) / 2.0 + 0.25 * c.scale();
        let mut out = BoxLayout {
            w: glyph.w,
            ..Default::default()
        };
        out.place(&glyph, 0.0, shift);
        out
    }
    fn stacked_delimiter(&mut self, ch: char, height: f64, c: &Context) -> Option<BoxLayout> {
        let (top, repeat, middle, bottom, font) = match ch {
            '(' => ("⎛", "⎜", None, "⎝", "Size4-Regular"),
            ')' => ("⎞", "⎟", None, "⎠", "Size4-Regular"),
            '[' => ("⎡", "⎢", None, "⎣", "Size4-Regular"),
            ']' => ("⎤", "⎥", None, "⎦", "Size4-Regular"),
            '⌈' => ("⎡", "⎢", None, "⎢", "Size4-Regular"),
            '⌉' => ("⎤", "⎥", None, "⎥", "Size4-Regular"),
            '⌊' => ("⎢", "⎢", None, "⎣", "Size4-Regular"),
            '⌋' => ("⎥", "⎥", None, "⎦", "Size4-Regular"),
            '{' => ("⎧", "⎪", Some("⎨"), "⎩", "Size4-Regular"),
            '}' => ("⎫", "⎪", Some("⎬"), "⎭", "Size4-Regular"),
            '⟮' => ("⎧", "⎪", None, "⎩", "Size4-Regular"),
            '⟯' => ("⎫", "⎪", None, "⎭", "Size4-Regular"),
            '⎰' => ("⎧", "⎪", None, "⎭", "Size4-Regular"),
            '⎱' => ("⎫", "⎪", None, "⎩", "Size4-Regular"),
            '|' => ("∣", "∣", None, "∣", "Size1-Regular"),
            '∥' => ("∥", "∥", None, "∥", "Size1-Regular"),
            '↑' => ("↑", "⏐", None, "⏐", "Size1-Regular"),
            '↓' => ("⏐", "⏐", None, "↓", "Size1-Regular"),
            '↕' => ("↑", "⏐", None, "↓", "Size1-Regular"),
            '⇑' => ("⇑", "‖", None, "‖", "Size1-Regular"),
            '⇓' => ("‖", "‖", None, "⇓", "Size1-Regular"),
            '⇕' => ("⇑", "‖", None, "⇓", "Size1-Regular"),
            _ => return None,
        };
        let s = c.scale();
        let top = self.glyph(top, font, s, Class::Ord);
        let bottom = self.glyph(bottom, font, s, Class::Ord);
        let middle = middle.map(|ch| self.glyph(ch, font, s, Class::Ord));
        let repeat = self.glyph(repeat, font, s, Class::Ord);
        let fixed =
            top.h + top.d + bottom.h + bottom.d + middle.as_ref().map_or(0.0, |b| b.h + b.d);
        let segments = if middle.is_some() { 2.0 } else { 1.0 };
        let repeat_height = repeat.h + repeat.d;
        let repeated = ((height - fixed) / (segments * repeat_height))
            .ceil()
            .max(0.0)
            * repeat_height;
        let total = fixed + segments * repeated;
        let depth = total / 2.0 - 0.25 * s;
        let mut out = BoxLayout {
            w: top.w.max(bottom.w).max(repeat.w),
            h: total - depth,
            d: depth,
            ..Default::default()
        };
        let mut cursor = -depth;
        out.place(&bottom, 0.0, cursor + bottom.d);
        cursor += bottom.h + bottom.d;
        let mut stem = BoxLayout {
            w: repeat.w,
            h: repeated + 0.016 * s,
            d: 0.0,
            ..Default::default()
        };
        if repeated > 0.0 {
            stem.svg = format!(
                "<g transform=\"scale(1 {}) translate(0 {})\">{}</g>",
                num(stem.h / repeat_height),
                num(-repeat.d),
                repeat.svg
            );
            out.place(&stem, 0.0, cursor - 0.008 * s);
            cursor += repeated;
        }
        if let Some(middle) = middle {
            out.place(&middle, 0.0, cursor + middle.d);
            cursor += middle.h + middle.d;
            if repeated > 0.0 {
                out.place(&stem, 0.0, cursor - 0.008 * s);
                cursor += repeated;
            }
        }
        out.place(&top, 0.0, cursor + top.d);
        Some(out)
    }
    fn node(&mut self, node: &Node, c: &Context) -> BoxLayout {
        let scale = c.scale();
        match node {
            Node::Row(v) => self.row(v, c, None),
            Node::Symbol {
                value,
                italic,
                ams,
                mode,
                ..
            } => self.symbol(value, *italic, *ams, *mode, c),
            Node::Styled {
                body,
                font,
                size,
                style,
                color,
            } => {
                let mut context = c.clone();
                if let Some(f) = font {
                    context.font = f.clone();
                    match f.as_str() {
                        "textsf" => context.text_family = 's',
                        "texttt" => context.text_family = 't',
                        "textrm" | "hbox" => context.text_family = 'r',
                        "textbf" => context.text_bold = true,
                        "textmd" => context.text_bold = false,
                        "textit" => context.text_italic = true,
                        "textup" => context.text_italic = false,
                        "emph" => context.text_italic = !context.text_italic,
                        "textnormal" => {
                            context.text_family = 'r';
                            context.text_bold = false;
                            context.text_italic = false;
                        }
                        _ => {}
                    }
                }
                if let Some(s) = size {
                    context.size = *s;
                }
                if let Some(s) = style {
                    context.style = *s;
                }
                let mut b = self.node(body, &context);
                if let Some(color) = color {
                    b.svg = format!("<g color=\"{}\">{}</g>", escape(color), b.svg);
                }
                b
            }
            Node::Classed { body, .. } => self.node(body, c),
            Node::Operator { body, large, .. } => {
                if *large && let Node::Symbol { value, .. } = body.as_ref() {
                    let font = if c.style == 0 {
                        "Size2-Regular"
                    } else {
                        "Size1-Regular"
                    };
                    let mut b = self.glyph(
                        if value == "∯" {
                            "∬"
                        } else if value == "∰" {
                            "∭"
                        } else {
                            value
                        },
                        font,
                        scale,
                        Class::Op,
                    );
                    if value == "∯" || value == "∰" {
                        write!(b.svg,"<ellipse cx=\"{}\" cy=\"{}\" rx=\"{}\" ry=\"{}\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"{}\"/>",num(b.w/2.0+b.italic/2.0),num(-0.25*scale),num(0.3*scale),num(0.15*scale),num(0.03*scale)).unwrap();
                    }
                    b.w += b.italic;
                    let shift = (b.d - b.h) / 2.0 + 0.25 * scale;
                    let mut out = BoxLayout {
                        w: b.w,
                        italic: b.italic,
                        ..Default::default()
                    };
                    out.place(&b, 0.0, shift);
                    return out;
                }
                self.node(body, c)
            }
            Node::Scripts {
                base,
                sup,
                sub,
                limits,
            } => {
                let b = self.node(base, c);
                let sctx = c.script();
                let sup = sup.as_ref().map(|s| self.node(s, &sctx));
                let sub = sub.as_ref().map(|s| self.node(s, &sctx));
                let use_limits =
                    limits.unwrap_or(has_limits(base, c.style, sup.is_some(), sub.is_some()));
                let mut out = BoxLayout::default();
                if use_limits {
                    out.w =
                        b.w.max(sup.as_ref().map_or(0.0, |s| s.w))
                            .max(sub.as_ref().map_or(0.0, |s| s.w));
                    out.place(&b, (out.w - b.w) / 2.0, 0.0);
                    if let Some(s) = sup {
                        out.place(&s, (out.w - s.w + b.italic) / 2.0, b.h + 0.2 * scale + s.d);
                        out.h += 0.1 * scale;
                    }
                    if let Some(s) = sub {
                        out.place(&s, (out.w - s.w - b.italic) / 2.0, -b.d - 0.3 * scale - s.h);
                        out.d += 0.1 * scale;
                    }
                } else {
                    out.w = b.w;
                    out.place(&b, 0.0, 0.0);
                    let mut up = (if c.cramped {
                        0.289
                    } else if c.style == 0 {
                        0.413
                    } else {
                        0.363
                    }) * scale;
                    if let Some(s) = &sup {
                        up = up
                            .max(b.h - 0.386 * sctx.scale())
                            .max(s.d + 0.25 * 0.431 * scale);
                    }
                    let mut down = 0.15 * scale;
                    if let Some(s) = &sub {
                        down = down
                            .max(b.d + 0.05 * sctx.scale())
                            .max(s.h - 0.8 * 0.431 * scale);
                    }
                    if let (Some(s), Some(t)) = (&sup, &sub) {
                        let gap = (up - s.d) - (t.h - down);
                        if gap < 0.16 * scale {
                            down += 0.16 * scale - gap;
                        }
                        let psi = 0.8 * 0.431 * scale - (up - s.d);
                        if psi > 0.0 {
                            up += psi;
                            down -= psi;
                        }
                    }
                    if let Some(s) = sup {
                        out.place(&s, b.w, up);
                        out.w = out.w.max(b.w + s.w + 0.05 * scale);
                    }
                    if let Some(s) = sub {
                        let x = (b.w - b.italic).max(0.0);
                        out.place(&s, x, -down);
                        out.w = out.w.max(x + s.w + 0.05 * scale);
                    }
                }
                out
            }
            Node::Fraction {
                num: upper,
                den: lower,
                bar,
                delimiters,
                style,
            } => {
                let mut c = c.clone();
                if let Some(s) = style {
                    c.style = *s;
                }
                let scale = c.scale();
                let mut nc = c.frac();
                let n = self.node(upper, &nc);
                nc.cramped = true;
                let d = self.node(lower, &nc);
                let rule = bar.map_or(0.0, |v| v.ems(scale));
                let axis = 0.25 * scale;
                let mut up = if c.style == 0 {
                    0.677 * scale
                } else {
                    (if rule > 0.0 { 0.394 } else { 0.444 }) * scale
                };
                let mut down = if c.style == 0 {
                    0.686 * scale
                } else {
                    0.345 * scale
                };
                if rule > 0.0 {
                    let clearance = if c.style == 0 { 3.0 } else { 1.0 } * rule;
                    up = up.max(n.d + axis + rule / 2.0 + clearance);
                    down = down.max(d.h - axis + rule / 2.0 + clearance);
                } else {
                    let clearance = if c.style == 0 { 0.28 } else { 0.12 } * scale;
                    let gap = up + down - n.d - d.h;
                    if gap < clearance {
                        up += (clearance - gap) / 2.0;
                        down += (clearance - gap) / 2.0;
                    }
                }
                let pad = 0.12 * scale;
                let mut b = BoxLayout {
                    w: n.w.max(d.w) + 2.0 * pad,
                    ..Default::default()
                };
                b.place(&n, (b.w - n.w) / 2.0, up);
                b.place(&d, (b.w - d.w) / 2.0, -down);
                if rule > 0.0 {
                    b.rect(
                        pad,
                        axis - rule / 2.0,
                        b.w - 2.0 * pad,
                        rule,
                        "currentColor",
                    );
                }
                if let Some((left, right)) = delimiters {
                    self.fence(left, b, right, &c)
                } else {
                    b
                }
            }
            Node::Root { body, index } => {
                let mut cc = c.clone();
                cc.cramped = true;
                let b = self.node(body, &cc);
                let rule = 0.04 * scale;
                let clearance = if c.style == 0 {
                    0.25 * 0.431 * scale + rule
                } else {
                    1.25 * rule
                };
                let h = b.h + b.d + clearance + rule;
                let surd = if h > 3.0 * scale {
                    let mut b = BoxLayout {
                        w: 1.05 * scale,
                        h: b.h + clearance + rule,
                        d: b.d,
                        ..Default::default()
                    };
                    b.line(
                        0.05 * scale,
                        -b.d + 0.3 * scale,
                        0.22 * scale,
                        -b.d + 0.4 * scale,
                        0.04 * scale,
                    );
                    b.line(
                        0.22 * scale,
                        -b.d + 0.4 * scale,
                        0.42 * scale,
                        -b.d,
                        0.09 * scale,
                    );
                    b.line(0.42 * scale, -b.d, 0.98 * scale, b.h, 0.04 * scale);
                    b.line(0.98 * scale, b.h, b.w, b.h, rule);
                    b
                } else {
                    self.delimiter("√", h, c)
                };
                let mut out = BoxLayout {
                    w: surd.w + b.w + 0.1 * scale,
                    ..Default::default()
                };
                out.place(&surd, 0.0, b.h + clearance + rule - surd.h);
                out.place(&b, surd.w, 0.0);
                out.rect(
                    surd.w - 0.02 * scale,
                    b.h + clearance,
                    b.w + 0.12 * scale,
                    rule,
                    "currentColor",
                );
                out.h = out.h.max(b.h + clearance + rule);
                if let Some(index) = index {
                    let mut sc = c.clone();
                    sc.style = 3;
                    let degree = self.node(index, &sc);
                    let mut result = BoxLayout {
                        w: out.w + degree.w * 0.4,
                        ..Default::default()
                    };
                    result.place(&out, degree.w * 0.4, 0.0);
                    result.place(&degree, 0.0, 0.6 * (out.h - out.d));
                    result
                } else {
                    out
                }
            }
            Node::Fence { left, body, right } => {
                let provisional = self.node(body, c);
                let height = 2.0
                    * (provisional.h - 0.25 * scale)
                        .max(provisional.d + 0.25 * scale)
                        .max(0.5 * scale)
                    * 0.901;
                let b = if let Node::Row(v) = body.as_ref() {
                    self.row(v, c, Some(height))
                } else {
                    provisional
                };
                self.fence(left, b, right, c)
            }
            Node::Middle(value) => self.delimiter(value, scale, c),
            Node::SizedDelimiter { value, size, .. } => {
                self.delimiter(value, [0.0, 1.2, 1.8, 2.4, 3.0][*size as usize] * scale, c)
            }
            Node::Space(d) => BoxLayout {
                w: c.length(*d),
                ..Default::default()
            },
            Node::Rule {
                width,
                height,
                shift,
            } => {
                let w = c.length(*width);
                let h = c.length(*height);
                let sh = c.length(*shift);
                let mut out = BoxLayout {
                    w,
                    h: (h + sh).max(0.0),
                    d: (-sh).max(0.0),
                    ..Default::default()
                };
                out.rect(0.0, sh, w, h, "currentColor");
                out
            }
            Node::Raise { body, shift } => {
                let b = self.node(body, c);
                let mut out = BoxLayout {
                    w: b.w,
                    ..Default::default()
                };
                out.place(&b, 0.0, c.length(*shift));
                out
            }
            Node::Phantom {
                body,
                horizontal,
                vertical,
            } => {
                let b = self.node(body, c);
                BoxLayout {
                    w: if *horizontal { b.w } else { 0.0 },
                    h: if *vertical { b.h } else { 0.0 },
                    d: if *vertical { b.d } else { 0.0 },
                    ..Default::default()
                }
            }
            Node::Smash { body, top, bottom } => {
                let mut b = self.node(body, c);
                if *top {
                    b.h = 0.0;
                }
                if *bottom {
                    b.d = 0.0;
                }
                b
            }
            Node::Lap { body, align } => {
                let b = self.node(body, c);
                let mut out = BoxLayout::default();
                out.place(
                    &b,
                    if *align == 'l' {
                        -b.w
                    } else if *align == 'c' {
                        -b.w / 2.0
                    } else {
                        0.0
                    },
                    0.0,
                );
                out
            }
            Node::VCenter(body) => {
                let b = self.node(body, c);
                let mut out = BoxLayout {
                    w: b.w,
                    ..Default::default()
                };
                out.place(&b, 0.0, (b.d - b.h) / 2.0 + 0.25 * scale);
                out
            }
            Node::Reflect(body) => {
                let mut b = self.node(body, c);
                b.svg = format!(
                    "<g transform=\"translate({} 0) scale(-1 1)\">{}</g>",
                    num(b.w),
                    b.svg
                );
                b
            }
            Node::Bold(body) => {
                let mut b = self.node(body, c);
                b.svg = format!(
                    "<g stroke=\"currentColor\" stroke-width=\"{}\">{}</g>",
                    num(0.02 * scale),
                    b.svg
                );
                b
            }
            Node::Choice(choices) => self.node(&choices[c.style as usize], c),
            Node::Alternative { html, .. } => self.node(html, c),
            Node::Accent { name, body, below } => self.accent(name, body, *below, c),
            Node::Arrow { name, above, below } => {
                let sc = c.script();
                let a = self.node(above, &sc);
                let b = below.as_ref().map(|n| self.node(n, &sc));
                let width = a.w.max(b.as_ref().map_or(0.0, |v| v.w)) + 0.6 * scale;
                let mut out = BoxLayout {
                    w: width.max(1.75 * scale),
                    h: 0.5 * scale,
                    d: 0.0,
                    ..Default::default()
                };
                self.arrow(&mut out, name, 0.25 * scale, scale);
                out.place(&a, (out.w - a.w) / 2.0, 0.6 * scale + a.d);
                if let Some(b) = b {
                    out.place(&b, (out.w - b.w) / 2.0, -0.15 * scale - b.h);
                }
                out
            }
            Node::Enclose {
                body,
                name,
                background,
                border,
            } => self.enclose(body, name, background.as_deref(), border.as_deref(), c),
            Node::Array {
                rows,
                columns,
                environment,
                gaps,
                rules,
                tags,
                stretch,
            } => self.array(rows, columns, environment, gaps, rules, tags, *stretch, c),
            Node::VerticalArrow { value, left, right } => {
                let sc = c.script();
                let left = self.node(left, &sc);
                let right = self.node(right, &sc);
                let arrow = self.delimiter(value, 1.8 * scale, c);
                let mut out = BoxLayout {
                    w: left.w + arrow.w + right.w + 0.3 * scale,
                    ..Default::default()
                };
                out.place(&left, 0.0, (left.d - left.h) / 2.0 + 0.25 * scale);
                out.place(&arrow, left.w + 0.15 * scale, 0.0);
                out.place(
                    &right,
                    left.w + arrow.w + 0.3 * scale,
                    (right.d - right.h) / 2.0 + 0.25 * scale,
                );
                out
            }
            Node::Tagged { body, tag } => {
                let b = self.node(body, c);
                let t = self.node(tag, c);
                let gap = 1.0 * scale;
                let mut out = BoxLayout {
                    w: b.w + gap + t.w,
                    ..Default::default()
                };
                out.place(&b, 0.0, 0.0);
                out.place(&t, b.w + gap, 0.0);
                out
            }
            Node::Unsupported(value) => {
                let mut b = self.glyph(value, "Main-Regular", scale, Class::Ord);
                b.svg = format!("<g color=\"#cc0000\">{}</g>", b.svg);
                b
            }
            Node::Break(_) | Node::LineControl(_) => BoxLayout::default(),
        }
    }
    fn fence(&mut self, left: &str, b: BoxLayout, right: &str, c: &Context) -> BoxLayout {
        let height = 2.0
            * (b.h - 0.25 * c.scale())
                .max(b.d + 0.25 * c.scale())
                .max(0.5 * c.scale())
            * 0.901;
        let l = self.delimiter(left, height, c);
        let r = self.delimiter(right, height, c);
        let mut out = BoxLayout {
            w: l.w + b.w + r.w,
            ..Default::default()
        };
        out.place(&l, 0.0, 0.0);
        out.place(&b, l.w, 0.0);
        out.place(&r, l.w + b.w, 0.0);
        out
    }
    fn arrow(&self, b: &mut BoxLayout, name: &str, y: f64, s: f64) {
        let symbol = super::ast::arrow_character(name);
        let double = matches!(symbol, "⇐" | "⇒" | "⇔" | "=");
        let multi = matches!(symbol, "⇋" | "⇌" | "⇄" | "⇆");
        let left = matches!(symbol, "←" | "↔" | "⇐" | "⇔" | "↼" | "↽" | "↞" | "↩");
        let right = matches!(symbol, "→" | "↔" | "⇒" | "⇔" | "⇀" | "⇁" | "↠" | "↪" | "↦");
        let thickness = 0.04 * s;
        let start = 0.02 * s;
        let end = b.w - 0.02 * s;
        let offsets = if double || multi {
            vec![-0.07 * s, 0.07 * s]
        } else {
            vec![0.0]
        };
        for dy in offsets {
            let upper = dy >= 0.0;
            let first_left = symbol == "⇋";
            let (l, r) = if multi {
                (upper == first_left, upper != first_left)
            } else {
                (left, right)
            };
            let short = name.contains("equilibrium") && !upper;
            let x1 = if short && r {
                end - 0.6 * (end - start)
            } else {
                start
            };
            let x2 = if short && l {
                start + 0.6 * (end - start)
            } else {
                end
            };
            b.line(x1, y + dy, x2, y + dy, thickness);
            if double {
                continue;
            }
            let harpoon = matches!(symbol, "⇋" | "⇌" | "↼" | "↽" | "⇀" | "⇁");
            let up_arm = !harpoon || multi && upper || matches!(symbol, "↼" | "⇀");
            let down_arm = !harpoon || multi && !upper || matches!(symbol, "↽" | "⇁");
            for (head, inward) in [(l, 1.0), (r, -1.0)] {
                if !head {
                    continue;
                }
                let x = if inward > 0.0 { x1 } else { x2 };
                for inset in if name.contains("twohead") {
                    vec![0.0, 0.16 * s]
                } else {
                    vec![0.0]
                } {
                    let x = x + inward * inset;
                    if up_arm {
                        b.line(
                            x + inward * 0.22 * s,
                            y + dy + 0.13 * s,
                            x,
                            y + dy,
                            thickness,
                        );
                    }
                    if down_arm {
                        b.line(
                            x + inward * 0.22 * s,
                            y + dy - 0.13 * s,
                            x,
                            y + dy,
                            thickness,
                        );
                    }
                }
            }
        }
        if double && symbol != "=" {
            for (head, inward) in [(left, 1.0), (right, -1.0)] {
                if !head {
                    continue;
                }
                let x = if inward > 0.0 { start } else { end };
                b.line(x + inward * 0.3 * s, y + 0.2 * s, x, y, thickness);
                b.line(x + inward * 0.3 * s, y - 0.2 * s, x, y, thickness);
            }
        }
        if symbol == "↦" {
            b.line(start, y - 0.15 * s, start, y + 0.15 * s, thickness);
        }
        if name.contains("hook") {
            let x = if left { end } else { start };
            let inward = if left { -1.0 } else { 1.0 };
            write!(b.svg,"<path d=\"M{} {}Q{} {} {} {}\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"{}\"/>",num(x),num(-y),num(x+inward*0.2*s),num(-y-0.3*s),num(x+inward*0.26*s),num(-y-0.15*s),num(thickness)).unwrap();
        }
    }
    fn accent(&mut self, name: &str, body: &Node, below: bool, c: &Context) -> BoxLayout {
        let b = self.node(body, c);
        let s = c.scale();
        let below = below || name == "\\underline" || name.starts_with("\\under");
        let y = if below {
            -b.d - 0.12 * s
        } else {
            b.h + 0.1 * s
        };
        let mut out = BoxLayout {
            w: b.w,
            ..Default::default()
        };
        out.place(&b, 0.0, 0.0);
        if matches!(name, "\\overline" | "\\underline") {
            out.line(0.0, y, b.w, y, 0.04 * s);
        } else if name.contains("arrow") || name.contains("harpoon") || name == "\\vec" {
            let mut arrow = BoxLayout {
                w: if name == "\\vec" {
                    0.5 * s
                } else {
                    b.w.max(0.6 * s)
                },
                ..Default::default()
            };
            self.arrow(
                &mut arrow,
                if name == "\\vec" {
                    "\\overrightarrow"
                } else {
                    name
                },
                0.0,
                s,
            );
            out.place(&arrow, (b.w - arrow.w) / 2.0, y);
        } else if name.contains("brace") || name.contains("group") {
            let sign = if below { -1.0 } else { 1.0 };
            let h = 0.2 * s;
            write!(out.svg,"<path d=\"M0 {} Q0 {} {} {} Q{} {} {} {} Q{} {} {} {} Q{} {} {} {}\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"{}\"/>",num(-y),num(-y-sign*h),num(b.w/4.0),num(-y-sign*h),num(b.w/2.0),num(-y-sign*h),num(b.w/2.0),num(-y-sign*2.0*h),num(b.w/2.0),num(-y-sign*h),num(3.0*b.w/4.0),num(-y-sign*h),num(b.w),num(-y-sign*h),num(b.w),num(-y),num(0.04*s)).unwrap();
        } else if name.contains("bracket") || name.contains("linesegment") {
            let sign = if below { -1.0 } else { 1.0 };
            out.line(0.0, y, b.w, y, 0.04 * s);
            out.line(0.0, y, 0.0, y - sign * 0.15 * s, 0.04 * s);
            out.line(b.w, y, b.w, y - sign * 0.15 * s, 0.04 * s);
        } else {
            let mark = match name {
                "\\acute" | "\\'" => "´",
                "\\grave" | "\\`" => "`",
                "\\ddot" | "\\\"" => "¨",
                "\\tilde" | "\\widetilde" | "\\utilde" | "\\~" => "˜",
                "\\breve" | "\\u" => "˘",
                "\\check" | "\\widecheck" | "\\v" => "ˇ",
                "\\hat" | "\\widehat" | "\\^" => "ˆ",
                "\\vec" => "⃗",
                "\\dot" | "\\." => "˙",
                "\\mathring" | "\\r" => "˚",
                "\\bar" | "\\=" => "¯",
                "\\c" => "¸",
                "\\H" => "˝",
                "\\textcircled" => "◯",
                _ => "ˆ",
            };
            let mut a = self.glyph(mark, "Main-Regular", s, Class::Ord);
            let stretch = name.starts_with("\\wide") || name == "\\utilde";
            if stretch && a.w > 0.0 {
                let factor = b.w.max(0.5 * s) / a.w;
                a.svg = format!("<g transform=\"scale({} 1)\">{}</g>", num(factor), a.svg);
                a.w *= factor;
            }
            let shift = if name == "\\textcircled" {
                a.d - 0.2 * s
            } else if name == "\\c" {
                -b.d
            } else if below {
                y - a.h
            } else {
                b.h - b.h.min(0.431 * s) + a.d
            };
            out.place(&a, (b.w - a.w) / 2.0 + b.skew, shift);
        }
        if below && name != "\\c" {
            out.d = out.d.max(-y + 0.18 * s);
        } else if name.contains("arrow")
            || name.contains("harpoon")
            || name == "\\vec"
            || name.contains("brace")
            || name.contains("bracket")
            || name.contains("group")
            || name.contains("linesegment")
            || name == "\\overline"
        {
            out.h = out.h.max(y + 0.18 * s);
        }
        out
    }
    fn enclose(
        &mut self,
        body: &Node,
        name: &str,
        background: Option<&str>,
        border: Option<&str>,
        c: &Context,
    ) -> BoxLayout {
        let b = self.node(body, c);
        let s = c.scale();
        let boxed = name.contains("box");
        let padding = if boxed { 0.3 * s } else { 0.0 };
        let mut out = BoxLayout {
            w: b.w + 2.0 * padding,
            h: b.h + padding,
            d: b.d + padding,
            ..Default::default()
        };
        if let Some(color) = background {
            out.rect(0.0, -out.d, out.w, out.h + out.d, color);
        }
        out.place(&b, padding, 0.0);
        if boxed && name != "\\colorbox" {
            write!(out.svg,"<rect x=\"{}\" y=\"{}\" width=\"{}\" height=\"{}\" fill=\"none\" stroke=\"{}\" stroke-width=\"{}\"/>",num(0.02*s),num(-out.h+0.02*s),num((out.w-0.04*s).max(0.0)),num((out.h+out.d-0.04*s).max(0.0)),escape(border.unwrap_or("currentColor")),num(0.04*s)).unwrap();
        }
        if matches!(name, "\\cancel" | "\\xcancel") {
            out.line(0.0, -b.d, b.w, b.h, 0.04 * s);
        }
        if matches!(name, "\\bcancel" | "\\xcancel") {
            out.line(0.0, b.h, b.w, -b.d, 0.04 * s);
        }
        if name == "\\sout" {
            out.line(0.0, 0.25 * s, b.w, 0.25 * s, 0.04 * s);
        }
        if name == "\\angl" {
            out.h += 0.12 * s;
            out.w += 0.08 * s;
            out.line(0.0, out.h, out.w, out.h, 0.04 * s);
            out.line(out.w, out.h, out.w, 0.0, 0.04 * s);
        }
        if name == "\\phase" {
            out.w += 0.5 * s;
            out.line(0.0, -b.d, 0.4 * s, b.h, 0.04 * s);
            out.line(0.0, -b.d, out.w, -b.d, 0.04 * s);
        }
        out
    }
    #[allow(clippy::too_many_arguments)] // The array AST stores each TeX layout parameter explicitly.
    fn array(
        &mut self,
        rows: &[Vec<Node>],
        columns: &str,
        env: &str,
        gaps: &[Dimension],
        rules: &[(usize, bool)],
        tags: &[Option<Node>],
        stretch: f64,
        c: &Context,
    ) -> BoxLayout {
        let mut ctx = c.clone();
        ctx.style = array_style(env);
        let s = ctx.scale();
        let cells = rows
            .iter()
            .map(|row| row.iter().map(|n| self.node(n, &ctx)).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let count = rows.iter().map(Vec::len).max().unwrap_or(0);
        let align = columns
            .chars()
            .filter(|c| "lcr".contains(*c))
            .collect::<Vec<_>>();
        let mut widths = vec![0.0_f64; count];
        let mut heights = Vec::new();
        let mut depths = Vec::new();
        for row in &cells {
            heights.push(
                row.iter()
                    .map(|b| b.h)
                    .fold(0.7 * c.scale() * stretch, f64::max),
            );
            depths.push(
                row.iter()
                    .map(|b| b.d)
                    .fold(0.3 * c.scale() * stretch, f64::max),
            );
            for (col, b) in row.iter().enumerate() {
                widths[col] = widths[col].max(b.w);
            }
        }
        let gap = if env.contains("align") || env == "split" {
            0.0
        } else if env == "CD" {
            0.5 * s
        } else if env == "smallmatrix" {
            0.333 * s
        } else {
            1.0 * s
        };
        let mut x = Vec::new();
        let mut w = 0.0;
        for (i, &width) in widths.iter().enumerate() {
            x.push(w);
            w += width;
            if i + 1 < count {
                w += if env.contains("align") && i % 2 == 1 {
                    2.0 * s
                } else {
                    gap
                };
            }
        }
        let mut baselines = Vec::new();
        let mut total = 0.0;
        for i in 0..rows.len() {
            total += heights[i];
            baselines.push(total);
            total += depths[i]
                + if i + 1 < rows.len() {
                    (if env.contains("align") || env.contains("gather") || env == "CD" {
                        0.3
                    } else {
                        0.2
                    }) * s
                        + gaps.get(i).copied().unwrap_or(Dimension::em(0.0)).ems(s)
                } else {
                    0.0
                };
        }
        let axis = 0.25 * c.scale();
        let h = total / 2.0 + axis;
        let mut out = BoxLayout {
            w,
            h,
            d: (total - h).max(0.0),
            ..Default::default()
        };
        for (r, row) in cells.iter().enumerate() {
            for (col, b) in row.iter().enumerate() {
                let a = align
                    .get(col)
                    .copied()
                    .unwrap_or_else(|| if align.len() == 1 { align[0] } else { 'c' });
                let offset = if a == 'l' {
                    0.0
                } else if a == 'r' {
                    widths[col] - b.w
                } else {
                    (widths[col] - b.w) / 2.0
                };
                out.place(b, x[col] + offset, h - baselines[r]);
            }
            if let Some(Some(tag)) = tags.get(r) {
                let b = self.node(tag, c);
                out.place(&b, w + 1.0 * c.scale(), h - baselines[r]);
                out.w = out.w.max(w + 1.0 * c.scale() + b.w);
            }
        }
        for &(row, dashed) in rules {
            let y = if row == 0 {
                h
            } else if row >= rows.len() {
                -out.d
            } else {
                h - baselines[row] + heights[row] + 0.1 * s
            };
            if dashed {
                write!(out.svg,"<path d=\"M0 {}H{}\" stroke=\"currentColor\" stroke-width=\"{}\" stroke-dasharray=\"{} {}\"/>",num(-y),num(w),num(0.04*s),num(0.2*s),num(0.1*s)).unwrap();
            } else {
                out.line(0.0, y, w, y, 0.04 * s);
            }
        }
        let mut col = 0;
        for ch in columns.chars() {
            if "lcr".contains(ch) {
                col += 1;
            } else if ch == '|' || ch == ':' {
                let px = if col == 0 {
                    0.0
                } else if col >= count {
                    w
                } else {
                    x[col] - gap / 2.0
                };
                out.line(px, h, px, -out.d, 0.04 * s);
            }
        }
        if let Some((left, right)) = array_delimiters(env) {
            self.fence(left, out, right, c)
        } else {
            out
        }
    }
}

fn array_style(environment: &str) -> u8 {
    if matches!(environment, "smallmatrix" | "subarray") {
        2
    } else if environment.starts_with('d')
        || environment.contains("align")
        || environment.contains("gather")
        || environment.contains("equation")
        || environment == "CD"
    {
        0
    } else {
        1
    }
}
fn array_delimiters(environment: &str) -> Option<(&'static str, &'static str)> {
    Some(match environment.trim_end_matches('*') {
        "pmatrix" => ("(", ")"),
        "bmatrix" => ("[", "]"),
        "Bmatrix" => ("{", "}"),
        "vmatrix" => ("|", "|"),
        "Vmatrix" => ("∥", "∥"),
        "cases" | "dcases" => ("{", ""),
        "rcases" | "drcases" => ("", "}"),
        _ => return None,
    })
}

fn spacing(left: Class, right: Class, style: u8) -> f64 {
    use Class::*;
    if style >= 2 {
        return if matches!((left, right), (Ord | Op | Close | Inner, Op) | (Op, Ord)) {
            3.0 / 18.0
        } else {
            0.0
        };
    }
    let mu = match (left, right) {
        (Ord, Op | Inner)
        | (Op, Ord | Op | Inner)
        | (Close, Op | Inner)
        | (Punct, Ord | Op | Rel | Open | Close | Punct | Inner)
        | (Inner, Ord | Op | Open | Punct | Inner) => 3.0,
        (Ord | Close | Inner, Bin) | (Bin, Ord | Op | Open | Inner) => 4.0,
        (Ord | Op | Close | Inner, Rel) | (Rel, Ord | Op | Open | Inner) => 5.0,
        _ => 0.0,
    };
    mu / 18.0
}
fn atom_classes(nodes: &[Node]) -> Vec<Class> {
    let mut classes = nodes.iter().map(Node::class).collect::<Vec<_>>();
    let visible = classes
        .iter()
        .enumerate()
        .filter_map(|(i, c)| (*c != Class::Space).then_some(i))
        .collect::<Vec<_>>();
    for (pos, &i) in visible.iter().enumerate() {
        if classes[i] != Class::Bin {
            continue;
        }
        let left = pos.checked_sub(1).map(|p| classes[visible[p]]);
        let right = visible.get(pos + 1).map(|&p| classes[p]);
        if left.is_none()
            || matches!(
                left,
                Some(Class::Bin | Class::Op | Class::Rel | Class::Open | Class::Punct)
            )
            || right.is_none()
            || matches!(right, Some(Class::Rel | Class::Close | Class::Punct))
        {
            classes[i] = Class::Ord;
        }
    }
    classes
}
fn has_limits(node: &Node, style: u8, sup: bool, sub: bool) -> bool {
    match node {
        Node::Operator { limits, .. } => *limits && style == 0,
        Node::Accent { name, .. } => {
            (name.starts_with("\\over") && sup || name.starts_with("\\under") && sub)
                && (name.contains("brace") || name.contains("bracket"))
        }
        Node::Styled { body, .. } | Node::Classed { body, .. } => has_limits(body, style, sup, sub),
        Node::Row(nodes) if nodes.len() == 1 => has_limits(&nodes[0], style, sup, sub),
        _ => false,
    }
}

fn mml(node: &Node, style: u8) -> String {
    let wrap = |tag: &str, body: String| format!("<{tag}>{body}</{tag}>");
    match node {
        Node::Row(nodes) => {
            let mut html = String::new();
            let mut cursor = 0;
            while cursor < nodes.len() {
                if let Node::Symbol { value, mode, .. } = &nodes[cursor] {
                    let number = *mode == Mode::Math && value.chars().all(|c| c.is_ascii_digit());
                    if number || *mode == Mode::Text {
                        let mut text = value.clone();
                        cursor += 1;
                        while let Some(Node::Symbol {
                            value, mode: next, ..
                        }) = nodes.get(cursor)
                        {
                            if next != mode || number && !value.chars().all(|c| c.is_ascii_digit())
                            {
                                break;
                            }
                            text.push_str(value);
                            cursor += 1;
                        }
                        html.push_str(&wrap(if number { "mn" } else { "mtext" }, escape(&text)));
                        continue;
                    }
                }
                html.push_str(&mml(&nodes[cursor], style));
                cursor += 1;
            }
            wrap("mrow", html)
        }
        Node::Symbol {
            value, class, mode, ..
        } => {
            let tag = if *mode == Mode::Text {
                "mtext"
            } else if value.chars().all(|c| c.is_numeric()) {
                "mn"
            } else if *class == Class::Ord && value.chars().all(|c| c.is_alphabetic()) {
                "mi"
            } else {
                "mo"
            };
            wrap(tag, escape(value))
        }
        Node::Scripts {
            base,
            sup,
            sub,
            limits,
        } => {
            let limits = limits.unwrap_or(has_limits(base, style, sup.is_some(), sub.is_some()));
            let tag = match (sup.is_some(), sub.is_some(), limits) {
                (true, true, true) => "munderover",
                (true, false, true) => "mover",
                (false, true, true) => "munder",
                (true, true, false) => "msubsup",
                (true, false, false) => "msup",
                (false, true, false) => "msub",
                _ => return mml(base, style),
            };
            wrap(
                tag,
                format!(
                    "{}{}{}",
                    mml(base, style),
                    sub.as_ref()
                        .map(|n| mml(n, (style + 1).clamp(2, 3)))
                        .unwrap_or_default(),
                    sup.as_ref()
                        .map(|n| mml(n, (style + 1).clamp(2, 3)))
                        .unwrap_or_default()
                ),
            )
        }
        Node::Fraction {
            num,
            den,
            bar,
            delimiters,
            ..
        } => {
            let body = format!(
                "<mfrac{}>{}{}</mfrac>",
                if bar.is_none() {
                    " linethickness=\"0\""
                } else {
                    ""
                },
                mml(num, (style + 1).min(3)),
                mml(den, (style + 1).min(3))
            );
            if let Some((l, r)) = delimiters {
                format!(
                    "<mrow><mo fence=\"true\">{}</mo>{body}<mo fence=\"true\">{}</mo></mrow>",
                    escape(l),
                    escape(r)
                )
            } else {
                body
            }
        }
        Node::Root { body, index } => {
            if let Some(index) = index {
                wrap("mroot", format!("{}{}", mml(body, style), mml(index, 3)))
            } else {
                wrap("msqrt", mml(body, style))
            }
        }
        Node::Fence { left, body, right } => format!(
            "<mrow><mo fence=\"true\">{}</mo>{}<mo fence=\"true\">{}</mo></mrow>",
            escape(left),
            mml(body, style),
            escape(right)
        ),
        Node::Middle(s) | Node::SizedDelimiter { value: s, .. } => wrap("mo", escape(s)),
        Node::Styled {
            body,
            font,
            size,
            style: s,
            color,
        } => format!(
            "<mstyle{}{}{}{}>{}</mstyle>",
            font.as_ref()
                .map(|f| format!(
                    " mathvariant=\"{}\"",
                    match f.as_str() {
                        "mathbf" | "bold" | "textbf" => "bold",
                        "mathit" | "textit" => "italic",
                        "boldsymbol" | "bm" => "bold-italic",
                        "mathbb" | "Bbb" => "double-struck",
                        "mathcal" | "mathscr" => "script",
                        "mathfrak" | "frak" => "fraktur",
                        "mathsf" | "textsf" => "sans-serif",
                        "mathsfit" => "sans-serif-italic",
                        "mathtt" | "texttt" => "monospace",
                        _ => "normal",
                    }
                ))
                .unwrap_or_default(),
            size.map(|s| format!(" mathsize=\"{}em\"", num(s)))
                .unwrap_or_default(),
            s.map(|s| format!(
                " displaystyle=\"{}\" scriptlevel=\"{}\"",
                s == 0,
                s.saturating_sub(1)
            ))
            .unwrap_or_default(),
            color
                .as_ref()
                .map(|c| format!(" mathcolor=\"{}\"", escape(c)))
                .unwrap_or_default(),
            mml(body, s.unwrap_or(style))
        ),
        Node::Operator {
            body,
            limits,
            large,
        } => format!(
            "<mo largeop=\"{large}\" movablelimits=\"{limits}\">{}</mo>",
            escape(&body.text())
        ),
        Node::Classed { body, .. }
        | Node::VCenter(body)
        | Node::Reflect(body)
        | Node::Bold(body) => mml(body, style),
        Node::Space(d) => format!("<mspace width=\"{}em\"/>", num(d.ems(1.0))),
        Node::Rule { width, height, .. } => format!(
            "<mspace width=\"{}em\" height=\"{}em\" mathbackground=\"currentColor\"/>",
            num(width.ems(1.0)),
            num(height.ems(1.0))
        ),
        Node::Raise { body, shift } => format!(
            "<mpadded voffset=\"{}em\">{}</mpadded>",
            num(shift.ems(1.0)),
            mml(body, style)
        ),
        Node::Phantom { body, .. } => wrap("mphantom", mml(body, style)),
        Node::Smash { body, .. } | Node::Lap { body, .. } => mml(body, style),
        Node::Enclose { body, name, .. } => format!(
            "<menclose notation=\"{}\">{}</menclose>",
            match name.as_str() {
                "\\cancel" => "updiagonalstrike",
                "\\bcancel" => "downdiagonalstrike",
                "\\xcancel" => "updiagonalstrike downdiagonalstrike",
                "\\sout" => "horizontalstrike",
                "\\angl" => "actuarial",
                _ => "box",
            },
            mml(body, style)
        ),
        Node::Choice(choices) => mml(&choices[style as usize], style),
        Node::Alternative { mathml, .. } => mml(mathml, style),
        Node::Accent { name, body, below } => format!(
            "<{} {}=\"true\">{}<mo>{}</mo></{}>",
            if *below { "munder" } else { "mover" },
            if *below { "accentunder" } else { "accent" },
            mml(body, style),
            escape(match name.as_str() {
                "\\hat" | "\\widehat" => "^",
                "\\acute" | "\\'" => "´",
                "\\grave" | "\\`" => "`",
                "\\check" | "\\widecheck" | "\\v" => "ˇ",
                "\\breve" | "\\u" => "˘",
                "\\mathring" | "\\r" => "˚",
                "\\c" => "¸",
                "\\H" => "˝",
                "\\textcircled" => "◯",
                "\\tilde" | "\\widetilde" | "\\utilde" | "\\~" => "~",
                "\\dot" | "\\." => "˙",
                "\\ddot" | "\\\"" => "¨",
                "\\overline" | "\\bar" | "\\underline" | "\\=" => "¯",
                "\\vec" | "\\overrightarrow" | "\\underrightarrow" => "→",
                "\\overleftarrow" | "\\underleftarrow" => "←",
                "\\overleftrightarrow" | "\\underleftrightarrow" => "↔",
                "\\Overrightarrow" => "⇒",
                "\\overleftharpoon" => "↼",
                "\\overrightharpoon" => "⇀",
                "\\overbrace" => "⏞",
                "\\underbrace" => "⏟",
                "\\overbracket" => "⎴",
                "\\underbracket" => "⎵",
                "\\overgroup" => "⏠",
                "\\undergroup" => "⏡",
                "\\overlinesegment" | "\\underlinesegment" => "―",
                _ => "^",
            }),
            if *below { "munder" } else { "mover" }
        ),
        Node::Arrow { name, above, below } => {
            let arrow = wrap("mo", escape(super::ast::arrow_character(name)));
            if let Some(below) = below {
                wrap(
                    "munderover",
                    format!("{arrow}{}{}", mml(below, 2), mml(above, 2)),
                )
            } else {
                wrap("mover", format!("{arrow}{}", mml(above, 2)))
            }
        }
        Node::Array {
            rows,
            tags,
            environment,
            ..
        } => {
            let cell_style = array_style(environment);
            let table = wrap(
                "mtable",
                rows.iter()
                    .enumerate()
                    .map(|(i, r)| {
                        let cells = r
                            .iter()
                            .map(|n| wrap("mtd", mml(n, cell_style)))
                            .collect::<String>();
                        if let Some(Some(tag)) = tags.get(i) {
                            wrap(
                                "mlabeledtr",
                                format!("{}{}", wrap("mtd", mml(tag, style)), cells),
                            )
                        } else {
                            wrap("mtr", cells)
                        }
                    })
                    .collect(),
            );
            let table = format!(
                "<mstyle displaystyle=\"{}\" scriptlevel=\"{}\">{table}</mstyle>",
                cell_style == 0,
                cell_style.saturating_sub(1)
            );
            if let Some((left, right)) = array_delimiters(environment) {
                format!(
                    "<mrow><mo fence=\"true\">{}</mo>{table}<mo fence=\"true\">{}</mo></mrow>",
                    escape(left),
                    escape(right)
                )
            } else {
                table
            }
        }
        Node::VerticalArrow { value, left, right } => wrap(
            "mrow",
            format!(
                "<mstyle scriptlevel=\"1\">{}</mstyle><mo>{}</mo><mstyle scriptlevel=\"1\">{}</mstyle>",
                mml(left, 2),
                escape(value),
                mml(right, 2)
            ),
        ),
        Node::Tagged { body, tag, .. } => {
            wrap("mrow", format!("{}{}", mml(body, style), mml(tag, style)))
        }
        Node::Break(_) => "<mspace linebreak=\"newline\"/>".into(),
        Node::LineControl(allow) => format!(
            "<mspace linebreak=\"{}\"/>",
            if *allow { "goodbreak" } else { "nobreak" }
        ),
        Node::Unsupported(value) => wrap("mtext", escape(value)),
    }
}

fn svg(b: &BoxLayout) -> Result<String> {
    if ![b.w, b.h, b.d].iter().all(|n| n.is_finite()) {
        return Err(super::Error::new(0, "Formula layout is not finite"));
    }
    let height = (b.h + b.d).max(0.01);
    let w = b.w.max(0.01);
    Ok(format!(
        "<svg class=\"math-visual\" xmlns=\"http://www.w3.org/2000/svg\" aria-hidden=\"true\" focusable=\"false\" fill=\"currentColor\" width=\"{}em\" height=\"{}em\" viewBox=\"0 {} {} {}\" style=\"vertical-align:-{}em\">{}</svg>",
        num(w),
        num(height),
        num(-b.h),
        num(w),
        num(height),
        num(b.d),
        b.svg
    ))
}
pub fn render(tree: &Node, source: &str, display: bool) -> Result<Rendered> {
    let context = Context {
        style: if display { 0 } else { 1 },
        size: 1.0,
        font: String::new(),
        cramped: false,
        text_family: 'r',
        text_bold: false,
        text_italic: false,
    };
    let mut layout = Layout {
        fonts: BTreeSet::new(),
    };
    let visual = if let Node::Tagged { body, tag } = tree {
        let body = layout.node(body, &context);
        let tag = layout.node(tag, &context);
        format!(
            "<span class=\"math-tagged-line\" style=\"grid-template-columns:{}em auto {}em\"><span></span><span class=\"math-body\">{}</span><span class=\"math-tag\">{}</span></span>",
            num(tag.w + 1.0),
            num(tag.w + 1.0),
            svg(&body)?,
            svg(&tag)?
        )
    } else if display {
        svg(&layout.node(tree, &context))?
    } else {
        layout.inline(tree, &context)?
    };
    let html = format!(
        "<span class=\"math{}\" dir=\"ltr\"><span class=\"math-accessible\"><math xmlns=\"http://www.w3.org/1998/Math/MathML\" display=\"{}\"><semantics>{}<annotation encoding=\"application/x-tex\">{}</annotation></semantics></math></span>{visual}</span>",
        if display { " math-display" } else { "" },
        if display { "block" } else { "inline" },
        mml(tree, context.style),
        // Character references preserve CR/CRLF through HTML newline normalization.
        escape(source).replace('\r', "&#13;"),
    );
    let fonts = layout
        .fonts
        .into_iter()
        .filter(|font| html.contains(&format!("font-family=\"BlogMath-{font}\"")))
        .collect();
    Ok(Rendered {
        html,
        text: tree.text(),
        fonts,
    })
}
