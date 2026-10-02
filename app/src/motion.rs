// Copyright (C) 2026 Fadouse
// SPDX-License-Identifier: GPL-3.0-only

use crate::{
    app,
    browser::{Arg, Js, Key, document, window},
    update_header,
};
fn animate(element: Js, property: Key, from: Arg<'_>, to: Arg<'_>, duration: u32) -> Js {
    let keyframes = Js::object();
    keyframes.set(property, Js::array(&[from, to]).arg());
    let timing = Js::object();
    timing.set(Key::Duration, Arg::integer(duration));
    timing.set(Key::Easing, Arg::literal(lit!("cubic-bezier(.22,1,.36,1)")));
    element.call(Key::Animate, &[keyframes.arg(), timing.arg()])
}
pub fn pixels(value: f64) -> Js {
    crate::browser::suffixed_number(value, lit!("px"))
}
pub fn reduced() -> bool {
    window()
        .call(
            Key::MatchMedia,
            &[Arg::literal(lit!("(prefers-reduced-motion)"))],
        )
        .boolean(Key::Matches)
}
fn bounds(element: Js) -> Js {
    element.call(Key::GetBoundingClientRect, &[])
}
fn boxes(elements: Js, stop: bool) -> Js {
    let boxes = Js::construct(Key::Array, &[]);
    for i in 0..elements.uint(Key::Length) {
        let element = elements.item(i);
        boxes.call_void(Key::Push, bounds(element).arg());
        if stop {
            cancel(element);
        }
    }
    boxes
}
fn cancel(element: Js) {
    let animations = element.call(Key::GetAnimations, &[]);
    for i in 0..animations.uint(Key::Length) {
        animations.item(i).call(Key::Cancel, &[]);
    }
}
pub fn replace(current: Js, incoming: Js, layout: bool, path: Js) {
    if reduced() || current.uint(Key::ChildElementCount) == 0 {
        if !path.is_null() {
            update_header(path);
        }
        current.call(Key::ReplaceWith, &[incoming.arg()]);
        return;
    }
    let elements = document().call(
        Key::QuerySelectorAll,
        &[Arg::literal(lit!(".brand,.navigation,.site-footer"))],
    );
    // Sample visible geometry before cancelling or committing the new layout.
    // A redirected transition therefore starts exactly where the reader saw it.
    let before = boxes(elements, true);
    let outgoing = bounds(current);
    let opacity = window()
        .call(Key::GetComputedStyle, &[current.arg()])
        .get(Key::Opacity);
    cancel(current);
    if !path.is_null() {
        update_header(path);
    }
    current.call(Key::ReplaceWith, &[incoming.arg()]);
    current.remove_attr(lit!("id"));
    let ids = current.call(Key::QuerySelectorAll, &[Arg::literal(lit!("[id]"))]);
    for i in 0..ids.uint(Key::Length) {
        ids.item(i).remove_attr(lit!("id"));
    }
    current.set(Key::Inert, Arg::boolean(true));
    current.set_attr(lit!("aria-hidden"), lit!("true"));
    current
        .get(Key::ClassList)
        .call(Key::Add, &[Arg::literal(lit!("content-departing"))]);
    let style = current.get(Key::Style);
    for key in [Key::Left, Key::Top, Key::Width] {
        style.set(key, pixels(outgoing.number(key)).arg());
    }
    document()
        .get(Key::Body)
        .call_void(Key::Append, current.arg());
    // FLIP only transforms the shell; content has its final layout throughout.
    // Read all final boxes together before writing any animation styles.
    let after = boxes(elements, false);
    if layout {
        let viewport = window().number(Key::InnerHeight);
        for i in 0..elements.uint(Key::Length) {
            let element = elements.item(i);
            let old = before.item(i);
            let new = after.item(i);
            let top = old.number(Key::Top);
            let new_top = new.number(Key::Top);
            if top >= viewport
                || old.number(Key::Bottom) <= scalar(0)
                || new_top >= viewport
                || new.number(Key::Bottom) <= scalar(0)
            {
                continue;
            }
            let scale = if i == 0 {
                old.number(Key::Width) / new.number(Key::Width)
            } else {
                scalar(1)
            };
            let x = old.number(Key::Left) - new.number(Key::Left);
            let y = top - new_top;
            if scale == scalar(1) && x == scalar(0) && y == scalar(0) {
                continue;
            }
            let matrix = Js::construct(Key::DomMatrix, &[])
                .call(Key::TranslateSelf, &[Arg::number(x), Arg::number(y)])
                .call(Key::ScaleSelf, &[Arg::number(scale)])
                .call(Key::ToString, &[]);
            animate(
                element,
                Key::Transform,
                matrix.arg(),
                Arg::literal(lit!("none")),
                180,
            );
        }
    }
    let leaving = animate(
        current,
        Key::Opacity,
        opacity.arg(),
        Arg::literal(lit!("0")),
        100,
    );
    animate(
        incoming,
        Key::Opacity,
        Arg::literal(lit!("0")),
        Arg::literal(lit!("1")),
        130,
    );
    app().remove_after(current, &leaving.get(Key::Finished));
}

// Keep exact integer geometry constants compact in the compiler artifact.
#[inline(never)]
pub fn scalar(value: u32) -> f64 {
    value as f64
}
