use alloc::{rc::Rc, string::String, vec::Vec};
use core::{cell::RefCell, ops::Range};

use shared::{
    escape_html_into,
    search::{SearchEntry, SearchText, highlight_parts, search},
};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{Event, HtmlInputElement, Url};

use crate::{
    browser::{self, query, required, window},
    motion, target,
};

#[derive(Default)]
struct State {
    entries: Option<Vec<SearchEntry>>,
    loading: bool,
    failed: bool,
    composing: bool,
    query: String,
    key: String,
    html: String,
}

#[derive(Clone, Default)]
pub struct Search(Rc<RefCell<State>>);

impl Search {
    pub fn listen(&self) {
        for (name, handler) in [
            ("input", Search::input as fn(&Search, Event)),
            ("submit", Search::submit),
            ("compositionstart", Search::composition_start),
            ("compositionend", Search::composition_end),
        ] {
            let search = self.clone();
            browser::listen(browser::document().as_ref(), name, move |event| {
                handler(&search, event)
            });
        }
    }

    pub fn on_page(&self) {
        let Some(input) = query("#search-input") else {
            return;
        };
        let container = required("#search-results");
        let value = web_sys::UrlSearchParams::new_with_str(&window().location().search().unwrap())
            .unwrap()
            .get("q")
            .unwrap_or_default();
        input.unchecked_ref::<HtmlInputElement>().set_value(&value);
        let load = {
            let mut state = self.0.borrow_mut();
            state.query = value;
            state.composing = false;
            if !container.has_attribute("data-search-ready") {
                state.html = container.inner_html();
                state.key = "empty".into();
            }
            let load = state.entries.is_none() && !state.loading;
            if load {
                state.loading = true;
                state.failed = false;
            }
            load
        };
        let _ = container.set_attribute("data-search-ready", "");
        self.render();
        if load {
            let url = required(".site-shell")
                .get_attribute("data-search-url")
                .unwrap();
            let search = self.clone();
            spawn_local(async move {
                let result = load_index(&url).await;
                {
                    let mut state = search.0.borrow_mut();
                    state.loading = false;
                    match result {
                        Ok(entries) => state.entries = Some(entries),
                        Err(_) => state.failed = true,
                    }
                }
                search.render();
            });
        }
    }
}

fn field(value: &JsValue, name: &str) -> Result<JsValue, JsValue> {
    js_sys::Reflect::get(value, &name.into())
}
fn string(value: &JsValue, name: &str) -> Result<String, JsValue> {
    field(value, name)?
        .as_string()
        .ok_or("Invalid search index".into())
}

fn text(value: JsValue) -> Result<SearchText, JsValue> {
    let rows: js_sys::Array = field(&value, "spans")?.dyn_into()?;
    let mut spans = Vec::new();
    for row in rows.iter() {
        let row: js_sys::Array = row.dyn_into()?;
        let mut span = [0; 4];
        for (index, offset) in span.iter_mut().enumerate() {
            *offset = row
                .get(index as u32)
                .as_f64()
                .ok_or("Invalid search boundary")? as usize;
        }
        spans.push(span);
    }
    Ok(SearchText {
        text: string(&value, "text")?,
        normalized: string(&value, "normalized")?,
        spans,
    })
}

async fn load_index(url: &str) -> Result<Vec<SearchEntry>, JsValue> {
    let response = browser::fetch(url).await?;
    let rows: js_sys::Array = JsFuture::from(response.json()?).await?.dyn_into()?;
    rows.iter()
        .map(|row| {
            Ok(SearchEntry {
                slug: string(&row, "slug")?,
                title: text(field(&row, "title")?)?,
                tags: string(&row, "tags")?,
                description: string(&row, "description")?,
                body: text(field(&row, "body")?)?,
            })
        })
        .collect()
}

impl Search {
    fn composition_start(&self, event: Event) {
        if target(&event).is_some_and(|element| element.id() == "search-input") {
            self.0.borrow_mut().composing = true;
        }
    }
    fn composition_end(&self, event: Event) {
        if target(&event).is_some_and(|element| element.id() == "search-input") {
            self.0.borrow_mut().composing = false;
            self.update_query();
        }
    }
    fn input(&self, event: Event) {
        if target(&event).is_some_and(|element| element.id() == "search-input")
            && !self.0.borrow().composing
        {
            self.update_query();
        }
    }
    fn submit(&self, event: Event) {
        if target(&event).is_some_and(|element| element.class_list().contains("search-form")) {
            event.prevent_default();
            self.update_query();
        }
    }

    fn update_query(&self) {
        let value = required("#search-input")
            .unchecked_ref::<HtmlInputElement>()
            .value();
        if value == self.0.borrow().query {
            return;
        }
        let url = Url::new(&window().location().href().unwrap()).unwrap();
        if value.is_empty() {
            url.search_params().delete("q");
        } else {
            url.search_params().set("q", &value);
        }
        let _ = window().history().unwrap().replace_state_with_url(
            &JsValue::NULL,
            "",
            Some(&url.href()),
        );
        self.0.borrow_mut().query = value;
        self.render();
    }
}

fn highlighted(html: &mut String, text: &SearchText, query: &str, range: Range<usize>) {
    for (part, matched) in highlight_parts(text, query, range) {
        if matched {
            html.push_str("<mark>");
        }
        escape_html_into(part, html);
        if matched {
            html.push_str("</mark>");
        }
    }
}

fn results(state: &State) -> (String, String) {
    if state.query.trim().is_empty() {
        return (
            "empty".into(),
            "<p class=\"muted\" role=\"status\">Start with a word or phrase.</p>".into(),
        );
    }
    if state.failed {
        return ("error".into(), "<div class=\"error-state\" role=\"alert\"><h2>Unable to load search.</h2><p>Check your connection and try again.</p><button type=\"button\" data-retry>Retry ↗</button></div>".into());
    }
    let Some(entries) = &state.entries else {
        return (
            "loading".into(),
            "<p class=\"muted\" role=\"status\">Loading…</p>".into(),
        );
    };
    // Use the browser's Unicode primitive; ranking and highlighting stay in Rust.
    let query = String::from(
        js_sys::JsString::from(state.query.as_str())
            .normalize("NFKC")
            .to_lower_case(),
    )
    .replace('ς', "σ");
    let hits = search(entries, &query);
    if hits.is_empty() {
        return (
            "none".into(),
            "<p class=\"muted\" role=\"status\">No results. Try another word.</p>".into(),
        );
    }
    let mut key = String::new();
    let mut html = String::from("<p class=\"muted\" role=\"status\">");
    html.push_str(&browser::number(hits.len() as f64));
    html.push_str(if hits.len() == 1 {
        " result"
    } else {
        " results"
    });
    html.push_str("</p><div class=\"search-results\">");
    for hit in hits {
        key.push_str(&hit.entry.slug);
        key.push('|');
        html.push_str("<article><h2 class=\"post-title\" dir=\"auto\"><a href=\"/posts/");
        escape_html_into(&hit.entry.slug, &mut html);
        html.push_str("/\">");
        highlighted(
            &mut html,
            &hit.entry.title,
            &query,
            0..hit.entry.title.text.len(),
        );
        html.push_str("</a></h2><p dir=\"auto\">");
        if hit.excerpt.start > 0 {
            html.push('…');
        }
        highlighted(&mut html, &hit.entry.body, &query, hit.excerpt.clone());
        if hit.excerpt.end < hit.entry.body.text.len() {
            html.push('…');
        }
        html.push_str("</p></article>");
    }
    html.push_str("</div>");
    (key, html)
}

impl Search {
    fn render(&self) {
        let Some(container) = query("#search-results") else {
            return;
        };
        let change = {
            let mut state = self.0.borrow_mut();
            let (key, html) = results(&state);
            if html == state.html {
                return;
            }
            let transition = key != state.key;
            state.key = key;
            state.html = html.clone();
            (html, transition)
        };
        let (html, transition) = change;
        if transition {
            motion::replace_html(&container, &html, true);
        } else {
            container.set_inner_html(&html);
        }
    }
}
