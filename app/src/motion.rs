use crate::{
    app,
    browser::{Arg, Js, Key, document, required, window},
};
fn animate(element: &Js, property: Key, from: Arg<'_>, to: Arg<'_>, duration: u32) -> Js {
    let keyframes = Js::object();
    keyframes.set(property, Js::array(&[from, to]).arg());
    let timing = Js::object();
    timing.set(Key::Duration, Arg::integer(duration));
    timing.set(Key::Easing, Arg::literal("cubic-bezier(0.22, 1, 0.36, 1)"));
    element.call(Key::Animate, &[keyframes.arg(), timing.arg()])
}
fn pixels(value: f64) -> Js {
    window()
        .call(Key::String, &[Arg::number(value)])
        .call(Key::Concat, &[Arg::literal("px")])
}
pub fn replace_html(current: &Js, html: &str, layout: bool) {
    replace_bytes(current, html.as_bytes(), layout);
}
pub fn replace_bytes(current: &Js, html: &[u8], layout: bool) {
    replace_text(current, &Js::from_bytes(html), layout);
}
pub fn replace_text(current: &Js, html: &Js, layout: bool) {
    let incoming = current.call(Key::CloneNode, &[]);
    incoming.set(Key::InnerHTML, html.arg());
    replace(current, &incoming, layout);
}
pub fn reduced() -> bool {
    window()
        .call(
            Key::MatchMedia,
            &[Arg::literal("(prefers-reduced-motion: reduce)")],
        )
        .boolean(Key::Matches)
}
pub fn replace(current: &Js, incoming: &Js, layout: bool) {
    if reduced() || current.number(Key::ChildElementCount) == 0.0 {
        current.call(Key::ReplaceWith, &[incoming.arg()]);
        return;
    }
    let page = required("#page-content");
    let previous_height = page
        .call(Key::GetBoundingClientRect, &[])
        .number(Key::Height);
    let bounds = current.call(Key::GetBoundingClientRect, &[]);
    let opacity = window()
        .call(Key::GetComputedStyle, &[current.arg()])
        .call(Key::GetPropertyValue, &[Arg::literal("opacity")]);
    for (element, only_layout) in [(current, false), (&page, true)] {
        let animations = element.call(Key::GetAnimations, &[]);
        for i in 0..animations.number(Key::Length) as u32 {
            let animation = animations.call(Key::At, &[Arg::integer(i)]);
            if !only_layout || animation.get(Key::Id).equal_text("content-layout") {
                animation.call(Key::Cancel, &[]);
            }
        }
    }
    current.call(Key::ReplaceWith, &[incoming.arg()]);
    current.remove_attr("id");
    let ids = current.call(Key::QuerySelectorAll, &[Arg::literal("[id]")]);
    for i in 0..ids.number(Key::Length) as u32 {
        ids.call(Key::Item, &[Arg::integer(i)]).remove_attr("id");
    }
    current.set(Key::Inert, Arg::boolean(true));
    current.set_attr("aria-hidden", "true");
    current
        .get(Key::ClassList)
        .call(Key::Add, &[Arg::literal("content-departing")]);
    let style = current.get(Key::Style);
    for (property, key) in [
        ("left", Key::Left),
        ("top", Key::Top),
        ("width", Key::Width),
    ] {
        style.call(
            Key::SetProperty,
            &[Arg::literal(property), pixels(bounds.number(key)).arg()],
        );
    }
    document()
        .get(Key::Body)
        .call(Key::AppendChild, &[current.arg()]);
    let page = required("#page-content");
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
        .set(Key::Id, Arg::literal("content-layout"));
    }
    let leaving = animate(current, Key::Opacity, opacity.arg(), Arg::literal("0"), 100);
    animate(
        incoming,
        Key::Opacity,
        Arg::literal("0"),
        Arg::literal("1"),
        130,
    );
    app().remove_after(*current, &leaving.get(Key::Finished));
}
