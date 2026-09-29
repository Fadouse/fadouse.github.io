use alloc::string::String;

use wasm_bindgen::{JsCast, JsValue, closure::Closure, prelude::wasm_bindgen};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Document, Element, Event, EventTarget, HtmlElement, Response, Window};

// Keep fetched HTML in the browser instead of copying it through WASM memory.
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(extends = web_sys::DomParser, js_name = DOMParser)]
    type HtmlParser;
    #[wasm_bindgen(method, catch, js_name = parseFromString)]
    fn parse(this: &HtmlParser, html: &js_sys::JsString, kind: &str) -> Result<Document, JsValue>;
}

pub fn parse_html(html: &js_sys::JsString) -> Result<Document, JsValue> {
    web_sys::DomParser::new()?
        .unchecked_ref::<HtmlParser>()
        .parse(html, "text/html")
}

pub fn duplicate(element: &Element) -> Element {
    element.clone_node_with_deep(true).unwrap().unchecked_into()
}

pub fn window() -> Window {
    web_sys::window().unwrap()
}
pub fn document() -> Document {
    window().document().unwrap()
}
pub fn query(selector: &str) -> Option<Element> {
    document().query_selector(selector).unwrap()
}
pub fn required(selector: &str) -> Element {
    query(selector).expect("Page element")
}

pub fn number(value: f64) -> String {
    String::from(
        js_sys::Number::from(value)
            .to_string_with_radix(10)
            .unwrap(),
    )
}

pub fn listen(target: &EventTarget, name: &str, handler: impl FnMut(Event) + 'static) {
    let callback = Closure::<dyn FnMut(Event)>::new(handler);
    target
        .add_event_listener_with_callback(name, callback.as_ref().unchecked_ref())
        .unwrap();
    callback.forget();
}

pub fn delay(milliseconds: i32, callback: impl FnOnce() + 'static) {
    let callback = Closure::once_into_js(callback);
    window()
        .set_timeout_with_callback_and_timeout_and_arguments_0(
            callback.unchecked_ref(),
            milliseconds,
        )
        .unwrap();
}

pub fn mark(name: &str) {
    if let Some(performance) = window().performance() {
        let _ = performance.mark(name);
    }
}

pub async fn fetch(url: &str) -> Result<Response, JsValue> {
    let response: Response = JsFuture::from(window().fetch_with_str(url))
        .await?
        .unchecked_into();
    if response.ok() || response.status() == 404 {
        Ok(response)
    } else {
        Err("Request failed".into())
    }
}

pub fn focus(element: &Element) {
    let options = web_sys::FocusOptions::new();
    options.set_prevent_scroll(true);
    let _ = element
        .unchecked_ref::<HtmlElement>()
        .focus_with_options(&options);
}

pub fn saved_theme() -> String {
    window()
        .local_storage()
        .ok()
        .flatten()
        .and_then(|storage| storage.get_item("theme").ok().flatten())
        .filter(|theme| theme == "light" || theme == "dark")
        .unwrap_or_else(|| "system".into())
}

pub fn set_theme(theme: &str) {
    let root = document().document_element().unwrap();
    if theme == "system" {
        let _ = root.remove_attribute("data-theme");
    } else {
        let _ = root.set_attribute("data-theme", theme);
    }
    if let Ok(Some(storage)) = window().local_storage() {
        let _ = storage.set_item("theme", theme);
    }
    let buttons = document()
        .query_selector_all("[data-theme-choice]")
        .unwrap();
    for i in 0..buttons.length() {
        let button: Element = buttons.item(i).unwrap().unchecked_into();
        let active = button.get_attribute("data-theme-choice").as_deref() == Some(theme);
        let _ = button.set_attribute("aria-pressed", if active { "true" } else { "false" });
    }
}

pub fn copy_code(button: Element) {
    let code = button
        .closest(".code-block")
        .unwrap()
        .unwrap()
        .query_selector("code")
        .unwrap()
        .unwrap()
        .text_content()
        .unwrap_or_default();
    wasm_bindgen_futures::spawn_local(async move {
        let copied = JsFuture::from(window().navigator().clipboard().write_text(&code))
            .await
            .is_ok();
        let message = if copied { "Copied" } else { "Copy failed" };
        button.set_text_content(Some(message));
        required("#copy-status").set_text_content(Some(message));
        delay(1800, move || button.set_text_content(Some("Copy")));
    });
}
