use crate::{
    app,
    browser::{Arg, Js, Key, document, required, window},
};
fn animate(element: &Js, property: Key, from: Arg<'_>, to: Arg<'_>, duration: u32) -> Js {
    let keyframes = Js::object();
    keyframes.set(property, Js::array(&[from, to]).arg());
    let timing = Js::object();
    timing.set(Key::Duration, Arg::integer(duration));
    timing.set(
        Key::Easing,
        Arg::literal(lit!("cubic-bezier(0.22, 1, 0.36, 1)")),
    );
    element.call(Key::Animate, &[keyframes.arg(), timing.arg()])
}
pub fn pixels(value: f64) -> Js {
    window()
        .call(Key::String, &[Arg::number(value)])
        .call(Key::Concat, &[Arg::literal(lit!("px"))])
}
pub fn reduced() -> bool {
    window()
        .call(
            Key::MatchMedia,
            &[Arg::literal(lit!("(prefers-reduced-motion: reduce)"))],
        )
        .boolean(Key::Matches)
}
pub fn replace(current: &Js, incoming: &Js, layout: bool) {
    if reduced() || current.uint(Key::ChildElementCount) == 0 {
        current.call(Key::ReplaceWith, &[incoming.arg()]);
        return;
    }
    let page = required(lit!("#page-content"));
    let previous_height = page
        .call(Key::GetBoundingClientRect, &[])
        .number(Key::Height);
    let bounds = current.call(Key::GetBoundingClientRect, &[]);
    let opacity = window()
        .call(Key::GetComputedStyle, &[current.arg()])
        .call(Key::GetPropertyValue, &[Arg::literal(lit!("opacity"))]);
    for (element, only_layout) in [(current, false), (&page, true)] {
        let animations = element.call(Key::GetAnimations, &[]);
        for i in 0..animations.uint(Key::Length) {
            let animation = animations.item(i);
            if !only_layout || animation.get(Key::Id).equal_text(lit!("content-layout")) {
                animation.call(Key::Cancel, &[]);
            }
        }
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
    for (property, key) in [
        (lit!("left"), Key::Left),
        (lit!("top"), Key::Top),
        (lit!("width"), Key::Width),
    ] {
        style.call(
            Key::SetProperty,
            &[Arg::literal(property), pixels(bounds.number(key)).arg()],
        );
    }
    document()
        .get(Key::Body)
        .call_void(Key::Append, current.arg());
    let page = required(lit!("#page-content"));
    let height = page
        .call(Key::GetBoundingClientRect, &[])
        .number(Key::Height);
    if layout && (previous_height - height).abs() > 0.5 {
        animate(
            &page,
            Key::Height,
            pixels(previous_height).arg(),
            pixels(height).arg(),
            180,
        )
        .set(Key::Id, Arg::literal(lit!("content-layout")));
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
    app().remove_after(*current, &leaving.get(Key::Finished));
}
