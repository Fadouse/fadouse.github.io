use crate::{
    INDEX_RESPONSE,
    browser::{self, Arg, Js, Key, query, required, window},
    motion, target,
};
use alloc::{string::String, vec::Vec};
use core::{cell::RefCell, ops::Range};
use shared::{
    append_bytes, escape_html_into_bytes,
    search::{BorrowedSpans, Index, SearchText, highlight_bytes, search_terms, terms},
};

#[derive(Default)]
struct State {
    entries: Option<Index>,
    loading: bool,
    failed: bool,
    composing: bool,
    query: String,
    key: String,
    html: Vec<u8>,
}

#[derive(Default)]
pub struct Search(RefCell<State>);

impl Search {
    pub fn on_page(&self) {
        let input = query("#search-input");
        if input.is_null() {
            return;
        }
        let container = required("#search-results");
        let params = Js::construct(
            Key::UrlSearchParams,
            &[browser::location().get(Key::Search).arg()],
        );
        let value = params.call(Key::Get, &[Arg::literal("q")]).text();
        input.set(Key::Value, Arg::string(&value));
        let load = {
            let mut state = self.0.borrow_mut();
            state.query = value;
            state.composing = false;
            if !container.has_attr("data-search-ready") {
                state.html = container.get(Key::InnerHTML).text().into_bytes();
                state.key = "empty".into();
            }
            let load = state.entries.is_none() && !state.loading;
            if load {
                state.loading = true;
                state.failed = false;
            }
            load
        };
        container.set_attr("data-search-ready", "");
        self.render();
        if load {
            let url = required(".site-shell").attr("data-search-url");
            match window().try_call(Key::Fetch, &[Arg::string(&url)]) {
                Ok(promise) => promise.subscribe(INDEX_RESPONSE, 0),
                Err(_) => self.loaded(None),
            }
        }
    }
    pub fn loaded(&self, entries: Option<Index>) {
        {
            let mut state = self.0.borrow_mut();
            state.loading = false;
            state.failed = entries.is_none();
            state.entries = entries;
        }
        self.render();
    }
    pub fn event(&self, kind: u32, event: &Js) {
        let target = target(event);
        if target.is_null() {
            return;
        }
        let input = target.get(Key::Id).equal_text("search-input");
        match kind {
            4 if input && !self.0.borrow().composing => self.update_query(),
            5 if target
                .get(Key::ClassList)
                .call(Key::Contains, &[Arg::literal("search-form")])
                .truthy() =>
            {
                event.call(Key::PreventDefault, &[]);
                self.update_query();
            }
            6 if input => self.0.borrow_mut().composing = true,
            7 if input => {
                self.0.borrow_mut().composing = false;
                self.update_query();
            }
            _ => {}
        }
    }
    fn update_query(&self) {
        let value = required("#search-input").get(Key::Value).text();
        if value == self.0.borrow().query {
            return;
        }
        let url = browser::url();
        let params = url.get(Key::SearchParams);
        if value.is_empty() {
            params.call(Key::Delete, &[Arg::literal("q")]);
        } else {
            params.call(Key::Set, &[Arg::literal("q"), Arg::string(&value)]);
        }
        window().get(Key::History).call(
            Key::ReplaceState,
            &[Arg::null(), Arg::literal(""), url.get(Key::Href).arg()],
        );
        self.0.borrow_mut().query = value;
        self.render();
    }
    fn render(&self) {
        let container = query("#search-results");
        if container.is_null() {
            return;
        }
        let (html, transition) = {
            let mut state = self.0.borrow_mut();
            let (key, html) = results(&state);
            if html == state.html {
                return;
            }
            let transition = key != state.key;
            state.key = key;
            let text = Js::from_bytes(&html);
            state.html = html;
            (text, transition)
        };
        if transition {
            motion::replace_text(&container, &html, true);
        } else {
            container.set(Key::InnerHTML, html.arg());
        }
    }
}

fn highlighted(
    html: &mut Vec<u8>,
    text: &SearchText<&str, BorrowedSpans<'_>>,
    terms: &[&str],
    range: Range<usize>,
) {
    for (part, matched) in highlight_bytes(text, terms, range) {
        if matched {
            append_bytes(html, b"<mark>");
        }
        escape_html_into_bytes(part, html);
        if matched {
            append_bytes(html, b"</mark>");
        }
    }
}

fn results(state: &State) -> (String, Vec<u8>) {
    let query = Js::from_text(&state.query)
        .call(Key::Normalize, &[Arg::literal("NFKC")])
        .call(Key::ToLowerCase, &[])
        .call(Key::ReplaceAll, &[Arg::literal("ς"), Arg::literal("σ")])
        .text();
    let terms = terms(&query);
    if terms.is_empty() {
        return (
            "empty".into(),
            "<p class=\"muted\" role=\"status\">Start with a word or phrase.</p>"
                .as_bytes()
                .into(),
        );
    }
    if state.failed {
        return ("error".into(), "<div class=\"error-state\" role=\"alert\"><h2>Unable to load search.</h2><p>Check your connection and try again.</p><button type=\"button\" data-retry>Retry ↗</button></div>".as_bytes().into());
    }
    let Some(entries) = &state.entries else {
        return (
            "loading".into(),
            "<p class=\"muted\" role=\"status\">Loading…</p>"
                .as_bytes()
                .into(),
        );
    };
    let entries = entries.entries();
    let hits = search_terms(entries, &terms);
    if hits.len() == 0 {
        return (
            "none".into(),
            "<p class=\"muted\" role=\"status\">No results. Try another word.</p>"
                .as_bytes()
                .into(),
        );
    }
    let mut key = String::new();
    let mut html = b"<p class=\"muted\" role=\"status\">".to_vec();
    append_bytes(
        &mut html,
        browser::number_text(hits.len() as u32).as_bytes(),
    );
    append_bytes(
        &mut html,
        if hits.len() == 1 {
            b" result"
        } else {
            b" results"
        },
    );
    append_bytes(&mut html, b"</p><div class=\"search-results\">");
    for hit in hits {
        key.push_str(hit.entry.slug);
        key.push('|');
        append_bytes(
            &mut html,
            b"<article><h2 class=\"post-title\" dir=\"auto\"><a href=\"/posts/",
        );
        escape_html_into_bytes(hit.entry.slug.as_bytes(), &mut html);
        append_bytes(&mut html, b"/\">");
        highlighted(
            &mut html,
            &hit.entry.title,
            &terms,
            0..hit.entry.title.text.len(),
        );
        append_bytes(&mut html, b"</a></h2><p dir=\"auto\">");
        if hit.excerpt.start > 0 {
            append_bytes(&mut html, "…".as_bytes());
        }
        highlighted(&mut html, &hit.entry.body, &terms, hit.excerpt.clone());
        if hit.excerpt.end < hit.entry.body.text.len() {
            append_bytes(&mut html, "…".as_bytes());
        }
        append_bytes(&mut html, b"</p></article>");
    }
    append_bytes(&mut html, b"</div>");
    (key, html)
}
