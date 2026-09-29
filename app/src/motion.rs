use alloc::string::String;

use wasm_bindgen::{JsCast, prelude::wasm_bindgen};
use web_sys::{Animation, Element, HtmlElement};

use crate::browser::{document, required, window};

// These standard browser methods are still gated by web-sys.
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(extends = Element, js_name = Element)]
    type MotionElement;
    #[wasm_bindgen(method, js_name = animate)]
    fn animate(
        this: &MotionElement,
        keyframes: &js_sys::Object,
        timing: &js_sys::Object,
    ) -> Animation;
    #[wasm_bindgen(method, js_name = getAnimations)]
    fn animations(this: &MotionElement) -> js_sys::Array<Animation>;
}

fn animate(element: &Element, property: &str, from: &str, to: &str, duration: f64) -> Animation {
    let keyframes = js_sys::Object::new();
    let _ = js_sys::Reflect::set(
        &keyframes,
        &property.into(),
        &js_sys::Array::of2(&from.into(), &to.into()),
    );
    let timing = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&timing, &"duration".into(), &duration.into());
    let _ = js_sys::Reflect::set(
        &timing,
        &"easing".into(),
        &"cubic-bezier(0.22, 1, 0.36, 1)".into(),
    );
    element
        .unchecked_ref::<MotionElement>()
        .animate(&keyframes, &timing)
}

fn pixels(value: f64) -> String {
    let mut value = crate::browser::number(value);
    value.push_str("px");
    value
}

pub fn replace_html(current: &Element, html: &str, layout: bool) {
    let incoming: Element = current.clone_node().unwrap().unchecked_into();
    incoming.set_inner_html(html);
    replace(current, &incoming, layout);
}

pub fn replace(current: &Element, incoming: &Element, layout: bool) {
    let reduced = window()
        .match_media("(prefers-reduced-motion: reduce)")
        .unwrap()
        .unwrap()
        .matches();
    if reduced || current.child_element_count() == 0 {
        current.replace_with_with_node_1(incoming).unwrap();
        return;
    }
    let page = required("#page-content");
    let previous_height = page.get_bounding_client_rect().height();
    let bounds = current.get_bounding_client_rect();
    let opacity = window()
        .get_computed_style(current)
        .unwrap()
        .unwrap()
        .get_property_value("opacity")
        .unwrap();
    for animation in current.unchecked_ref::<MotionElement>().animations().iter() {
        animation.cancel();
    }
    for animation in page.unchecked_ref::<MotionElement>().animations().iter() {
        if animation.id() == "content-layout" {
            animation.cancel();
        }
    }
    current.replace_with_with_node_1(incoming).unwrap();
    let outgoing: &HtmlElement = current.unchecked_ref();
    let _ = outgoing.remove_attribute("id");
    let ids = outgoing.query_selector_all("[id]").unwrap();
    for i in 0..ids.length() {
        let _ = ids
            .item(i)
            .unwrap()
            .unchecked_into::<Element>()
            .remove_attribute("id");
    }
    outgoing.set_inert(true);
    let _ = outgoing.set_attribute("aria-hidden", "true");
    let _ = outgoing.class_list().add_1("content-departing");
    for (property, value) in [
        ("left", bounds.left()),
        ("top", bounds.top()),
        ("width", bounds.width()),
    ] {
        let _ = outgoing.style().set_property(property, &pixels(value));
    }
    document().body().unwrap().append_child(outgoing).unwrap();
    let page = required("#page-content");
    let height = page.get_bounding_client_rect().height();
    if layout && (previous_height - height).abs() > 0.5 {
        animate(
            &page,
            "height",
            &pixels(previous_height),
            &pixels(height),
            300.0,
        )
        .set_id("content-layout");
    }
    let leaving = animate(outgoing, "opacity", &opacity, "0", 120.0);
    animate(incoming, "opacity", "0", "1", 160.0);
    let outgoing = outgoing.clone();
    wasm_bindgen_futures::spawn_local(async move {
        let _ = wasm_bindgen_futures::JsFuture::from(leaving.finished().unwrap()).await;
        outgoing.remove();
    });
}
