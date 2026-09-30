use crate::{
    INDEX_RESPONSE,
    browser::{self, Arg, Js, Key, document, query, required, template, window},
    motion, target,
};
use core::{cell::RefCell, ops::Range};
use shared::search::{BorrowedSpans, Index, SearchText, highlight_bytes, search_terms, terms};

#[derive(Default)]
struct State {
    entries: Option<Index>,
    loading: bool,
    failed: bool,
    composing: bool,
    query: Js,
    key: Js,
    layout: Js,
    entry: Js,
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
        let value = params.call(Key::Get, &[Arg::literal("q")]);
        let value = if value.is_null() {
            Js::from_text("")
        } else {
            value
        };
        input.set(Key::Value, value.arg());
        let load = {
            let mut state = self.0.borrow_mut();
            state.query.replace(value);
            state.composing = false;
            state
                .layout
                .replace(required("#search-layout").get(Key::Content));
            state
                .entry
                .replace(required("#search-entry").get2(Key::Content, Key::FirstChild));
            if !container.has_attr("data-search-ready") {
                state
                    .key
                    .replace(Js::from_text("Start with a word or phrase."));
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
            let url =
                required(".site-shell").call(Key::GetAttribute, &[Arg::literal("data-search-url")]);
            match window().try_call(Key::Fetch, &[url.arg()]) {
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
                .call_boolean(Key::Contains, Arg::literal("search-form")) =>
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
        let value = required("#search-input").get(Key::Value);
        if value.same(self.0.borrow().query) {
            return;
        }
        let url = browser::url();
        let params = url.get(Key::SearchParams);
        if value.equal_text("") {
            params.call(Key::Delete, &[Arg::literal("q")]);
        } else {
            params.call(Key::Set, &[Arg::literal("q"), value.arg()]);
        }
        window().get(Key::History).call(
            Key::ReplaceState,
            &[Arg::null(), Arg::literal(""), url.get(Key::Href).arg()],
        );
        self.0.borrow_mut().query.replace(value);
        self.render();
    }
    fn render(&self) {
        let container = query("#search-results");
        if container.is_null() {
            return;
        }
        let (incoming, transition) = {
            let mut state = self.0.borrow_mut();
            let (key, fragment) = results(&state);
            let incoming = container.call(Key::CloneNode, &[]);
            incoming.call_void(Key::Append, fragment.arg());
            if container.call_boolean(Key::IsEqualNode, incoming.arg()) {
                return;
            }
            let transition = !key.same(state.key);
            state.key.replace(key);
            (incoming, transition)
        };
        if transition {
            motion::replace(&container, &incoming, true);
        } else {
            // Templates have one or two root nodes. Repeating the only node
            // moves it once and preserves any opacity animation on container.
            container.call(
                Key::ReplaceChildren,
                &[
                    incoming.get(Key::FirstChild).arg(),
                    incoming.get(Key::LastChild).arg(),
                ],
            );
        }
    }
}

fn append_text(parent: Js, text: Arg<'_>) {
    parent.call_void(Key::Append, text);
}

fn highlighted(
    parent: Js,
    text: &SearchText<&str, BorrowedSpans<'_>>,
    terms: &[&str],
    range: Range<usize>,
) {
    for (part, matched) in highlight_bytes(text, terms, range) {
        let target = if matched {
            let mark = document().call(Key::CreateElement, &[Arg::literal("mark")]);
            parent.call_void(Key::Append, mark.arg());
            mark
        } else {
            parent
        };
        append_text(target, Arg::bytes(part));
    }
}

fn message(state: &State, text: &'static str) -> (Js, Js) {
    let fragment = state.layout.duplicate();
    fragment.get(Key::LastChild).call(Key::Remove, &[]);
    fragment.get(Key::FirstChild).set_text(text);
    (Js::from_text(text), fragment)
}

fn results(state: &State) -> (Js, Js) {
    let query = state
        .query
        .call(Key::Normalize, &[Arg::literal("NFKC")])
        .call(Key::ToLowerCase, &[])
        .call(Key::ReplaceAll, &[Arg::literal("ς"), Arg::literal("σ")])
        .text();
    let terms = terms(&query);
    if terms.is_empty() {
        return message(state, "Start with a word or phrase.");
    }
    if state.failed {
        let fragment = template("#page-error");
        let heading = document().call(Key::CreateElement, &[Arg::literal("h2")]);
        heading.set_text("Unable to load search.");
        fragment
            .query("h1")
            .call(Key::ReplaceWith, &[heading.arg()]);
        return (Js::from_text("Unable to load search."), fragment);
    }
    let Some(entries) = &state.entries else {
        return message(state, "Loading…");
    };
    let entries = entries.entries();
    let hits = search_terms(entries, &terms);
    if hits.len() == 0 {
        return message(state, "No results. Try another word.");
    }
    let key = Js::construct(Key::Array, &[]);
    let fragment = state.layout.duplicate();
    let count = window()
        .call(Key::String, &[Arg::integer(hits.len() as u32)])
        .call(
            Key::Concat,
            &[Arg::literal(if hits.len() == 1 {
                " result"
            } else {
                " results"
            })],
        );
    fragment
        .get(Key::FirstChild)
        .set(Key::TextContent, count.arg());
    let results = fragment.get(Key::LastChild);
    for hit in hits {
        let entry = state.entry.duplicate();
        let link = entry.get2(Key::FirstChild, Key::FirstChild);
        let href = Js::from_text("/posts/").call(
            Key::Concat,
            &[Arg::string(hit.entry.slug), Arg::literal("/")],
        );
        link.set(Key::Href, href.arg());
        key.call_void(Key::Push, href.arg());
        highlighted(
            link,
            &hit.entry.title,
            &terms,
            0..hit.entry.title.text.len(),
        );
        let excerpt = entry.get(Key::LastChild);
        if hit.excerpt.start > 0 {
            append_text(excerpt, Arg::literal("…"));
        }
        highlighted(excerpt, &hit.entry.body, &terms, hit.excerpt.clone());
        if hit.excerpt.end < hit.entry.body.text.len() {
            append_text(excerpt, Arg::literal("…"));
        }
        results.call_void(Key::Append, entry.arg());
    }
    // The catalog restricts unique slugs to ASCII letters, digits and hyphens;
    // joining their URLs therefore preserves the exact ordered result set.
    (key.call(Key::Join, &[Arg::literal(",")]), fragment)
}
