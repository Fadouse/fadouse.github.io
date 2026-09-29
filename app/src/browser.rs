use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
};

use gloo_net::http::Request;
use leptos::prelude::*;
use leptos_router::hooks::use_location;
use serde::de::DeserializeOwned;
use wasm_bindgen::{JsCast, closure::Closure, prelude::wasm_bindgen};

// Web Animations is stable in browsers; web-sys still gates these bindings.
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(extends = web_sys::Element, js_name = Element)]
    type MotionElement;

    #[wasm_bindgen(method, js_name = animate)]
    fn animate(
        this: &MotionElement,
        keyframes: &js_sys::Object,
        options: &js_sys::Object,
    ) -> web_sys::Animation;

    #[wasm_bindgen(method, js_name = getAnimations)]
    fn animations(this: &MotionElement) -> js_sys::Array<web_sys::Animation>;
}

thread_local! {
    static SCROLL_POSITIONS: RefCell<HashMap<String, f64>> = RefCell::new(HashMap::new());
    static CURRENT_PATH: RefCell<String> = const { RefCell::new(String::new()) };
    static HISTORY_NAVIGATION: Cell<bool> = const { Cell::new(false) };
    static RESTORE_POSITION: Cell<f64> = const { Cell::new(0.0) };
}

pub fn window() -> web_sys::Window {
    web_sys::window().expect("Browser window")
}

pub fn document() -> web_sys::Document {
    window().document().expect("Browser document")
}

pub fn mark(name: &str) {
    if let Some(performance) = window().performance() {
        let _ = performance.mark(name);
    }
}

pub fn transition_page() {
    if let Some(content) = document().get_element_by_id("page-content") {
        transition_content(&content);
    }
}

pub fn transition_content(current: &web_sys::Element) {
    if current.child_element_count() == 0
        || window()
            .match_media("(prefers-reduced-motion: reduce)")
            .expect("Motion preference query")
            .is_some_and(|query| query.matches())
    {
        return;
    }

    transition_layout();
    let opacity = window()
        .get_computed_style(current)
        .expect("Content style")
        .expect("Mounted content style")
        .get_property_value("opacity")
        .expect("Content opacity")
        .parse::<f64>()
        .expect("Computed opacity number");
    let bounds = current.get_bounding_client_rect();
    let outgoing = current
        .clone_node_with_deep(true)
        .expect("Outgoing content snapshot")
        .unchecked_into::<web_sys::HtmlElement>();
    // The visual copy must never take focus or become an anchor target.
    let _ = outgoing.remove_attribute("id");
    let ids = outgoing.query_selector_all("[id]").expect("Snapshot IDs");
    for index in 0..ids.length() {
        let _ = ids
            .item(index)
            .expect("Snapshot element")
            .unchecked_into::<web_sys::Element>()
            .remove_attribute("id");
    }
    outgoing.set_inert(true);
    let _ = outgoing.set_attribute("aria-hidden", "true");
    let _ = outgoing.class_list().add_1("content-departing");
    let style = outgoing.style();
    for (name, value) in [
        ("left", bounds.left()),
        ("top", bounds.top()),
        ("width", bounds.width()),
    ] {
        let _ = style.set_property(name, &format!("{value}px"));
    }
    document()
        .body()
        .expect("Document body")
        .append_child(&outgoing)
        .expect("Mount outgoing content");

    // Keep the current visual opacity when a new navigation interrupts a fade.
    for animation in current.unchecked_ref::<MotionElement>().animations().iter() {
        animation.cancel();
    }
    let leaving = fade(&outgoing, opacity, 0.0, 120.0);
    fade(current, 0.0, 1.0, 160.0);
    leptos::task::spawn_local(async move {
        let _ = wasm_bindgen_futures::JsFuture::from(
            leaving.finished().expect("Outgoing animation completion"),
        )
        .await;
        outgoing.remove();
    });
}

fn fade(element: &web_sys::Element, from: f64, to: f64, duration: f64) -> web_sys::Animation {
    animate(
        element,
        "opacity",
        &from.to_string(),
        &to.to_string(),
        duration,
    )
}

fn transition_layout() {
    let content = document()
        .get_element_by_id("page-content")
        .expect("Page content container");
    let from = content.get_bounding_client_rect().height();
    request_animation_frame(move || {
        for animation in content.unchecked_ref::<MotionElement>().animations().iter() {
            if animation.id() == "content-layout" {
                animation.cancel();
            }
        }
        // Restored reading positions need the full article height immediately.
        if RESTORE_POSITION.get() > 0.0
            || !window().location().hash().unwrap_or_default().is_empty()
        {
            return;
        }
        let to = content.get_bounding_client_rect().height();
        if (from - to).abs() > 0.5 {
            animate(
                &content,
                "height",
                &format!("{from}px"),
                &format!("{to}px"),
                300.0,
            )
            .set_id("content-layout");
        }
    });
}

fn animate(
    element: &web_sys::Element,
    property: &str,
    from: &str,
    to: &str,
    duration: f64,
) -> web_sys::Animation {
    let keyframes = js_sys::Object::new();
    let values = js_sys::Array::of2(&from.into(), &to.into());
    let _ = js_sys::Reflect::set(&keyframes, &property.into(), &values);
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

pub async fn fetch_json<T: DeserializeOwned>(url: &str) -> Result<T, String> {
    let response = Request::get(url)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.ok() {
        return Err(format!("Request failed: HTTP {}", response.status()));
    }
    response.json().await.map_err(|error| error.to_string())
}

pub fn saved_theme() -> String {
    window()
        .local_storage()
        .ok()
        .flatten()
        .and_then(|storage| storage.get_item("theme").ok().flatten())
        .filter(|theme| matches!(theme.as_str(), "light" | "dark"))
        .unwrap_or_else(|| "system".into())
}

pub fn apply_saved_theme() {
    set_theme(&saved_theme());
}

pub fn set_theme(theme: &str) {
    let root = document().document_element().expect("Document root");
    if theme == "system" {
        let _ = root.remove_attribute("data-theme");
    } else {
        let _ = root.set_attribute("data-theme", theme);
    }
    if let Ok(Some(storage)) = window().local_storage() {
        let _ = storage.set_item("theme", theme);
    }
}

pub fn prepare_history() {
    let history = window().history().expect("Browser history");
    let _ = history.set_scroll_restoration(web_sys::ScrollRestoration::Manual);
    // Observe history changes before the router updates reactive state.
    let popstate = Closure::<dyn Fn()>::new(|| {
        record_scroll();
        HISTORY_NAVIGATION.set(true);
    });
    window()
        .add_event_listener_with_callback("popstate", popstate.as_ref().unchecked_ref())
        .expect("History listener");
    popstate.forget();
}

pub fn use_scroll_restoration() {
    let location = use_location();
    let scroll = Closure::<dyn Fn()>::new(record_scroll);
    window()
        .add_event_listener_with_callback("scroll", scroll.as_ref().unchecked_ref())
        .expect("Scroll listener");
    // A quick click can precede the next scroll event or shrink the document.
    window()
        .add_event_listener_with_callback_and_bool("click", scroll.as_ref().unchecked_ref(), true)
        .expect("Navigation scroll listener");
    // This listener shares the lifetime of the mounted application.
    scroll.forget();
    Effect::new(move |_| {
        let path = location.pathname.get();
        let changed = CURRENT_PATH.with(|current| {
            let changed = *current.borrow() != path;
            *current.borrow_mut() = path.clone();
            changed
        });
        if changed {
            let y = if HISTORY_NAVIGATION.replace(false) {
                SCROLL_POSITIONS
                    .with(|positions| positions.borrow().get(&path).copied().unwrap_or(0.0))
            } else {
                0.0
            };
            RESTORE_POSITION.set(y);
            restore_scroll();
        }
    });
}

fn record_scroll() {
    let y = window().scroll_y().unwrap_or(0.0);
    CURRENT_PATH.with(|path| {
        SCROLL_POSITIONS.with(|positions| positions.borrow_mut().insert(path.borrow().clone(), y));
    });
}

pub fn restore_scroll() {
    gloo_timers::callback::Timeout::new(0, || {
        let hash = window().location().hash().unwrap_or_default();
        if !hash.is_empty()
            && let Ok(id) = js_sys::decode_uri_component(hash.trim_start_matches('#'))
            && let Some(element) = document().get_element_by_id(&String::from(id))
        {
            element.scroll_into_view();
            return;
        }
        window().scroll_to_with_x_and_y(0.0, RESTORE_POSITION.get());
        if let Some(main) = document()
            .get_element_by_id("main-content")
            .and_then(|element| element.dyn_into::<web_sys::HtmlElement>().ok())
        {
            let options = web_sys::FocusOptions::new();
            options.set_prevent_scroll(true);
            let _ = main.focus_with_options(&options);
        }
    })
    .forget();
}

pub fn copy_code(event: web_sys::MouseEvent) {
    let Some(target) = event
        .target()
        .and_then(|target| target.dyn_into::<web_sys::Element>().ok())
    else {
        return;
    };
    let Ok(Some(button)) = target.closest("button[data-copy]") else {
        return;
    };
    let block = button
        .closest(".code-block")
        .expect("Code block selector")
        .expect("Copy button container");
    let code = block
        .query_selector("code")
        .expect("Code selector")
        .expect("Code block content")
        .text_content()
        .unwrap_or_default();
    leptos::task::spawn_local(async move {
        let result = wasm_bindgen_futures::JsFuture::from(
            window().navigator().clipboard().write_text(&code),
        )
        .await;
        let message = if result.is_ok() {
            "Copied"
        } else {
            "Copy failed"
        };
        button.set_text_content(Some(message));
        if let Some(status) = document().get_element_by_id("copy-status") {
            status.set_text_content(Some(message));
        }
        gloo_timers::callback::Timeout::new(1800, move || button.set_text_content(Some("Copy")))
            .forget();
    });
}
