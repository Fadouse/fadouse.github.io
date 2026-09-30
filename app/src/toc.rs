use core::cell::Cell;

use crate::browser::{self, Arg, Js, Key, document, query, window};

#[derive(Clone, Copy)]
struct Scroll {
    started: f64,
    from: f64,
    to: f64,
}

pub struct Toc {
    headings: Cell<Js>,
    links: Cell<Js>,
    count: Cell<u32>,
    active: Cell<u32>,
    pending: Cell<bool>,
    scroll: Cell<Option<Scroll>>,
}

impl Default for Toc {
    fn default() -> Self {
        Self {
            headings: Cell::new(Js::null()),
            links: Cell::new(Js::null()),
            count: Cell::new(0),
            active: Cell::new(u32::MAX),
            pending: Cell::new(false),
            scroll: Cell::new(None),
        }
    }
}

impl Toc {
    pub fn scroll_to(&self, element: &Js) {
        let from = window().get(Key::ScrollY).numeric();
        let to = (from
            + element
                .call(Key::GetBoundingClientRect, &[])
                .get(Key::Top)
                .numeric()
            - 32.0)
            .max(0.0)
            .min(
                document()
                    .get(Key::DocumentElement)
                    .get(Key::ScrollHeight)
                    .numeric()
                    - window().get(Key::InnerHeight).numeric(),
            );
        self.scroll.set(Some(Scroll {
            started: now(),
            from,
            to,
        }));
        self.request();
    }

    pub fn cancel(&self) {
        self.scroll.set(None);
    }

    pub fn on_page(&self) {
        let links = query("#page-content").call(Key::QuerySelectorAll, &[Arg::literal(".toc a")]);
        // The renderer emits matching desktop and mobile lists, in that order.
        let count = links.get(Key::Length).numeric() as u32 / 2;
        let headings = Js::array(&[]);
        for index in 0..count {
            let id = links
                .call(Key::Item, &[Arg::number(index as f64)])
                .call(Key::GetAttribute, &[Arg::literal("href")])
                .call(Key::Slice, &[Arg::number(1.0)]);
            headings.call(
                Key::Push,
                &[document().call(Key::GetElementById, &[id.arg()]).arg()],
            );
        }
        self.links.replace(links.retain()).release();
        self.headings.replace(headings.retain()).release();
        self.count.set(count);
        self.active.set(u32::MAX);
        self.request();
    }

    pub fn request(&self) {
        if self.count.get() != 0 && !self.pending.replace(true) {
            browser::next_frame(2, 0);
        }
    }

    pub fn update(&self) {
        self.pending.set(false);
        let count = self.count.get();
        if count == 0 {
            return;
        }
        if let Some(scroll) = self.scroll.get() {
            let progress = ((now() - scroll.started) / 180.0).min(1.0);
            let remaining = 1.0 - progress;
            let position =
                scroll.to + (scroll.from - scroll.to) * remaining * remaining * remaining;
            window().call(Key::ScrollTo, &[Arg::number(0.0), Arg::number(position)]);
            if progress < 1.0 {
                self.request();
            } else {
                self.cancel();
            }
        }
        let bottom = window().get(Key::ScrollY).numeric()
            + window().get(Key::InnerHeight).numeric()
            >= document()
                .get(Key::DocumentElement)
                .get(Key::ScrollHeight)
                .numeric()
                - 1.0;
        let mut low = 0;
        let mut high = count;
        if bottom {
            low = count;
        } else {
            // Read geometry before changing attributes; large TOCs need only
            // logarithmically many heading reads per animation frame.
            while low < high {
                let middle = low + (high - low) / 2;
                let top = self
                    .headings
                    .get()
                    .call(Key::At, &[Arg::number(middle as f64)])
                    .call(Key::GetBoundingClientRect, &[])
                    .get(Key::Top)
                    .numeric();
                if top <= 64.0 {
                    low = middle + 1;
                } else {
                    high = middle;
                }
            }
        }
        let active = low.saturating_sub(1);
        let previous = self.active.replace(active);
        if previous == active {
            return;
        }
        for offset in [0, count] {
            if previous != u32::MAX {
                self.links
                    .get()
                    .call(Key::Item, &[Arg::number((offset + previous) as f64)])
                    .remove_attr("aria-current");
            }
            self.links
                .get()
                .call(Key::Item, &[Arg::number((offset + active) as f64)])
                .set_attr("aria-current", "location");
        }
    }
}

fn now() -> f64 {
    window().get(Key::Performance).call(Key::Now, &[]).numeric()
}
