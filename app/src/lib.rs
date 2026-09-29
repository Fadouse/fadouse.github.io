#![cfg_attr(target_arch = "wasm32", no_std)]

extern crate alloc;

mod browser;
mod motion;
mod search;

use alloc::{rc::Rc, string::String, vec::Vec};
use core::cell::RefCell;

use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{Document, Element, Event, HtmlInputElement, KeyboardEvent, MouseEvent, Url};

use browser::{document, query, required, window};

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOCATOR: lol_alloc::AssumeSingleThreaded<lol_alloc::FreeListAllocator> =
    // This WASM instance runs only on the browser's main thread.
    unsafe { lol_alloc::AssumeSingleThreaded::new(lol_alloc::FreeListAllocator::new()) };

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

#[derive(Clone, Default)]
struct App {
    state: Rc<RefCell<State>>,
    search: search::Search,
}

#[derive(Default)]
struct State {
    path: String,
    navigation: u32,
    pages: Vec<(String, Rc<Page>)>,
    positions: Vec<(String, f64)>,
}

struct Page {
    body: Element,
    metadata: web_sys::DocumentFragment,
}

impl Page {
    fn read(document: &Document) -> Result<Self, JsValue> {
        let content = document
            .get_element_by_id("page-content")
            .ok_or("Missing page content")?;
        let nodes = document.query_selector_all("[data-page-meta]")?;
        let metadata = document.create_document_fragment();
        for i in 0..nodes.length() {
            metadata.append_child(&nodes.item(i).unwrap().clone_node_with_deep(true)?)?;
        }
        Ok(Self {
            body: browser::duplicate(&content),
            metadata,
        })
    }
}

#[wasm_bindgen::prelude::wasm_bindgen(start)]
pub fn start() {
    browser::mark("wasm-start");
    browser::set_theme(&browser::saved_theme());
    document()
        .document_element()
        .unwrap()
        .class_list()
        .add_1("js")
        .unwrap();
    let path = window().location().pathname().unwrap();
    let page = Rc::new(Page::read(&document()).expect("Static page"));
    let app = App::default();
    {
        let mut state = app.state.borrow_mut();
        state.path = path.clone();
        state.pages.push((path, page));
    }
    let _ = window()
        .history()
        .unwrap()
        .set_scroll_restoration(web_sys::ScrollRestoration::Manual);
    for (name, handler) in [
        ("click", App::click as fn(&App, Event)),
        ("keydown", App::keydown),
    ] {
        let app = app.clone();
        browser::listen(document().as_ref(), name, move |event| handler(&app, event));
    }
    for (name, handler) in [
        ("popstate", App::popstate as fn(&App, Event)),
        ("scroll", App::scroll),
    ] {
        let app = app.clone();
        browser::listen(window().as_ref(), name, move |event| handler(&app, event));
    }
    app.search.listen();
    app.search.on_page();
    browser::mark("app-mounted");
}

fn target(event: &Event) -> Option<Element> {
    event.target()?.dyn_into().ok()
}

impl App {
    fn scroll(&self, _: Event) {
        self.record_scroll();
    }

    fn record_scroll(&self) {
        let y = window().scroll_y().unwrap_or(0.0);
        let mut state = self.state.borrow_mut();
        let State {
            path, positions, ..
        } = &mut *state;
        if let Some((_, position)) = positions.iter_mut().find(|(key, _)| key == path) {
            *position = y;
        } else {
            positions.push((path.clone(), y));
        }
    }

    fn click(&self, event: Event) {
        let mouse: &MouseEvent = event.unchecked_ref();
        if mouse.button() != 0
            || mouse.ctrl_key()
            || mouse.meta_key()
            || mouse.alt_key()
            || mouse.shift_key()
        {
            return;
        }
        let Some(target) = target(&event) else {
            return;
        };
        if let Some(button) = target.closest("[data-theme-choice]").unwrap() {
            browser::set_theme(&button.get_attribute("data-theme-choice").unwrap());
            return;
        }
        if let Some(button) = target.closest("button[data-copy]").unwrap() {
            browser::copy_code(button);
            return;
        }
        if target.closest("[data-retry]").unwrap().is_some() {
            if query("#search-input").is_some() {
                self.search.on_page();
                focus_search_input();
            } else {
                let url = Url::new(&window().location().href().unwrap()).unwrap();
                self.navigate(url, false, false);
            }
            return;
        }
        let Some(anchor) = target.closest("a[href]").unwrap() else {
            return;
        };
        if anchor.has_attribute("download")
            || anchor
                .get_attribute("target")
                .is_some_and(|target| target != "_self")
        {
            return;
        }
        let Ok(url) = Url::new_with_base(
            &anchor.get_attribute("href").unwrap(),
            &window().location().href().unwrap(),
        ) else {
            return;
        };
        if url.origin() != window().location().origin().unwrap() || !url.pathname().ends_with('/') {
            return;
        }
        if url.pathname() == window().location().pathname().unwrap() && !url.hash().is_empty() {
            return;
        }
        event.prevent_default();
        if url.href() == window().location().href().unwrap() {
            return;
        }
        self.navigate(url, true, false);
    }

    fn keydown(&self, event: Event) {
        let key: &KeyboardEvent = event.unchecked_ref();
        if (key.meta_key() || key.ctrl_key())
            && !key.alt_key()
            && !key.shift_key()
            && key.key().eq_ignore_ascii_case("k")
        {
            event.prevent_default();
            if query("#search-input").is_some() {
                focus_search_input();
                return;
            }
            let url = Url::new_with_base("/search/", &window().location().href().unwrap()).unwrap();
            self.navigate(url, true, true);
        }
    }

    fn popstate(&self, _: Event) {
        let url = Url::new(&window().location().href().unwrap()).unwrap();
        self.navigate(url, false, false);
    }

    fn navigate(&self, url: Url, push: bool, focus_search: bool) {
        self.record_scroll();
        let path = url.pathname();
        let (token, cached, unchanged, position) = {
            let mut state = self.state.borrow_mut();
            state.navigation += 1;
            let cached = state
                .pages
                .iter()
                .find(|(key, _)| key == &path)
                .map(|(_, page)| Rc::clone(page));
            let unchanged = state.path == path && cached.is_some();
            (
                state.navigation,
                cached,
                unchanged,
                if push {
                    0.0
                } else {
                    state
                        .positions
                        .iter()
                        .find(|(key, _)| key == &path)
                        .map_or(0.0, |(_, y)| *y)
                },
            )
        };
        if push && url.href() != window().location().href().unwrap() {
            let _ = window().history().unwrap().push_state_with_url(
                &JsValue::NULL,
                "",
                Some(&url.href()),
            );
        }
        if unchanged {
            let _ = required("#main-content").remove_attribute("aria-busy");
            self.search.on_page();
            if focus_search {
                focus_search_input();
            } else if !push {
                restore_position(&url, position);
            }
            return;
        }
        if let Some(page) = cached {
            self.commit(&url, &page, position, focus_search);
            return;
        }
        let _ = required("#main-content").set_attribute("aria-busy", "true");
        required("#navigation-status").set_text_content(Some("Loading page…"));
        let app = self.clone();
        spawn_local(async move {
            let result = load_page(&path).await;
            let current = app.state.borrow().navigation == token;
            match result {
                Ok(page) => {
                    let page = Rc::new(page);
                    app.state.borrow_mut().pages.push((path, Rc::clone(&page)));
                    if current {
                        app.commit(&url, &page, position, focus_search);
                    }
                }
                Err(_) if current => {
                    app.state.borrow_mut().path = path;
                    update_header(&url.pathname());
                    motion::replace_html(
                        &required("#page-content"),
                        "<div class=\"error-state\" role=\"alert\"><h1>Unable to load this page.</h1><p>Check your connection and try again.</p><button type=\"button\" data-retry>Retry ↗</button></div>",
                        true,
                    );
                    let _ = required("#main-content").remove_attribute("aria-busy");
                    required("#navigation-status")
                        .set_text_content(Some("Unable to load this page."));
                    restore_position(&url, 0.0);
                }
                Err(_) => {}
            }
        });
    }
}

async fn load_page(path: &str) -> Result<Page, JsValue> {
    let response = browser::fetch(path).await?;
    let html = JsFuture::from(response.text()?).await?.unchecked_into();
    let document = browser::parse_html(&html)?;
    Page::read(&document)
}

fn update_header(path: &str) {
    let home = path == "/";
    required(".site-header").set_class_name(if home {
        "site-header home-header"
    } else {
        "site-header"
    });
    let heading = required("#brand-heading");
    let _ = heading.set_attribute("role", if home { "heading" } else { "none" });
    if home {
        let _ = heading.set_attribute("aria-level", "1");
        let _ = required(".brand").set_attribute("aria-current", "page");
    } else {
        let _ = heading.remove_attribute("aria-level");
        let _ = required(".brand").remove_attribute("aria-current");
    }
    let links = document().query_selector_all("[data-nav]").unwrap();
    for i in 0..links.length() {
        let link: Element = links.item(i).unwrap().unchecked_into();
        let href = link.get_attribute("href").unwrap();
        if href != "/" && path.starts_with(&href) {
            let _ = link.set_attribute("aria-current", "page");
        } else {
            let _ = link.remove_attribute("aria-current");
        }
    }
}

impl App {
    fn commit(&self, url: &Url, page: &Page, position: f64, focus_search: bool) {
        self.state.borrow_mut().path = url.pathname();
        update_header(&url.pathname());
        motion::replace(
            &required("#page-content"),
            &browser::duplicate(&page.body),
            position == 0.0 && url.hash().is_empty(),
        );
        let _ = required("#main-content").remove_attribute("aria-busy");
        let nodes = document().query_selector_all("[data-page-meta]").unwrap();
        for i in 0..nodes.length() {
            nodes.item(i).unwrap().unchecked_into::<Element>().remove();
        }
        document()
            .head()
            .unwrap()
            .append_child(&page.metadata.clone_node_with_deep(true).unwrap())
            .unwrap();
        required("#navigation-status").set_text_content(Some(&document().title()));
        restore_position(url, position);
        self.search.on_page();
        if focus_search {
            focus_search_input();
        }
        browser::mark("page-rendered");
    }
}

fn restore_position(url: &Url, position: f64) {
    if !url.hash().is_empty()
        && let Ok(id) = js_sys::decode_uri_component(url.hash().trim_start_matches('#'))
        && let Some(element) = document().get_element_by_id(&String::from(id))
    {
        element.scroll_into_view();
        return;
    }
    window().scroll_to_with_x_and_y(0.0, position);
    browser::focus(&required("#main-content"));
}

fn focus_search_input() {
    if let Some(input) = query("#search-input") {
        browser::focus(&input);
        input.unchecked_ref::<HtmlInputElement>().select();
    }
}
