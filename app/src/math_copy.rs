use crate::{
    app,
    browser::{self, Arg, Js, Key, document, window},
    motion,
};
use core::cell::Cell;

#[derive(Default)]
pub struct MathCopy {
    button: Cell<Js>,
    source: Cell<Js>,
    leave: Cell<u32>,
    copy: Cell<u32>,
    restoring: Cell<bool>,
}

impl MathCopy {
    pub fn on_page(&self) {
        self.close();
        let formulas = document().call(
            Key::QuerySelectorAll,
            &[Arg::literal("#page-content .math")],
        );
        if formulas.number(Key::Length) == 0.0 {
            return;
        }
        if self.button.get().is_null() {
            let button = document().call(Key::CreateElement, &[Arg::literal("button")]);
            button.set_attr("type", "button");
            button.set_attr("class", "math-copy");
            button.set_attr("data-copy", "math");
            button.set_attr("aria-label", "Copy LaTeX");
            button.set_attr("aria-hidden", "true");
            button.set_attr("tabindex", "-1");
            button.set_text("Copy LaTeX");
            document()
                .get(Key::Body)
                .call_void(Key::Append, button.arg());
            self.button.set(button.retain());
        }
        for i in 0..formulas.number(Key::Length) as u32 {
            let formula = formulas.item(i);
            if formula.closest("a, button").is_null() {
                formula.set_attr("tabindex", "0");
            }
        }
    }

    fn cancel_leave(&self) {
        self.leave.set(self.leave.get().wrapping_add(1));
    }

    fn origin(&self) -> Js {
        let source = self.source.get();
        if source.is_null() {
            return source;
        }
        let anchor = source.closest("a, button");
        if anchor.is_null() {
            // Return a scoped handle that survives releasing the retained source.
            source.closest(".math")
        } else {
            anchor
        }
    }

    fn inside(&self, element: Js) -> bool {
        if element.is_null() || self.source.get().is_null() {
            return false;
        }
        self.button.get().same(element) || self.origin().call_boolean(Key::Contains, element.arg())
    }

    fn focused(&self) -> bool {
        self.inside(document().get(Key::ActiveElement))
    }

    fn cancel_copy(&self) {
        let token = self.copy.replace(0);
        if token != 0 {
            app().copies.call(Key::Delete, &[Arg::integer(token)]);
        }
    }

    pub fn close(&self) {
        if self.source.get().is_null() {
            return;
        }
        self.cancel_leave();
        self.cancel_copy();
        self.source.set(self.source.get().replacing(Js::null()));
        let button = self.button.get();
        button.remove_attr("data-visible");
        button.set_attr("aria-hidden", "true");
        button.set_attr("tabindex", "-1");
        button.remove_attr("aria-busy");
        button.remove_attr("aria-disabled");
        // Keep the shared control out of cached and departing page content.
        document()
            .get(Key::Body)
            .call_void(Key::Append, button.arg());
    }

    fn show(&self, source: Js) {
        if source.is_null()
            || source
                .query("annotation[encoding='application/x-tex']")
                .is_null()
        {
            return;
        }
        self.cancel_leave();
        if source.same(self.source.get()) {
            return;
        }
        self.cancel_copy();
        self.source.set(self.source.get().replacing(source));
        let button = self.button.get();
        button.remove_attr("aria-hidden");
        button.remove_attr("tabindex");
        button.remove_attr("aria-busy");
        button.remove_attr("aria-disabled");
        button.set_text("Copy LaTeX");
        self.origin().call(
            Key::InsertAdjacentElement,
            &[Arg::literal("afterend"), button.arg()],
        );
        let bounds = source.call(Key::GetBoundingClientRect, &[]);
        let control = button.call(Key::GetBoundingClientRect, &[]);
        let width = control.number(Key::Width);
        let height = control.number(Key::Height);
        let x = (bounds.number(Key::Right) - width).clamp(
            8.0,
            (window().number(Key::InnerWidth) - width - 8.0).max(8.0),
        );
        let above = bounds.number(Key::Top) - height - 6.0;
        let y = if above >= 8.0 {
            above
        } else {
            bounds.number(Key::Bottom) + 6.0
        }
        .clamp(
            8.0,
            (window().number(Key::InnerHeight) - height - 8.0).max(8.0),
        );
        let style = button.get(Key::Style);
        style.set(Key::Left, motion::pixels(x).arg());
        style.set(Key::Top, motion::pixels(y).arg());
        button.set_attr("data-visible", "");
        self.cancel_leave();
    }

    pub fn enter(&self, event: &Js, focus: bool) {
        if self.restoring.get() || !focus && event.get(Key::PointerType).equal_text("touch") {
            return;
        }
        let target = crate::target(event);
        if target.is_null() {
            return;
        }
        if target.same(self.button.get()) {
            self.cancel_leave();
            return;
        }
        let mut source = target.closest("#page-content .math");
        if source.is_null() && focus {
            let anchor = target.closest("#page-content a, #page-content button");
            if !anchor.is_null() {
                source = anchor.query(".math");
            }
        }
        self.show(source);
    }

    pub fn exit(&self, event: &Js, focus: bool) {
        if !focus && event.get(Key::PointerType).equal_text("touch") {
            return;
        }
        if self.source.get().is_null() {
            return;
        }
        let related = event.get(Key::RelatedTarget);
        if self.inside(related) || self.focused() {
            self.cancel_leave();
            return;
        }
        self.cancel_leave();
        browser::delay(120, 3, self.leave.get());
    }

    pub fn timeout(&self, token: u32) {
        if token == self.leave.get() && !self.focused() {
            self.close();
        }
    }

    pub fn pointer_down(&self, event: &Js) {
        if !self.inside(crate::target(event)) {
            self.close();
        }
    }

    pub fn touch(&self, event: &Js, target: Js) -> bool {
        let source = target.closest("#page-content .math");
        if source.is_null()
            || !source.closest("a, button").is_null()
            || !(event.get(Key::PointerType).equal_text("touch")
                || window()
                    .call(Key::MatchMedia, &[Arg::literal("(hover: none)")])
                    .boolean(Key::Matches))
        {
            return false;
        }
        event.call(Key::PreventDefault, &[]);
        self.show(source);
        browser::focus(&self.button.get());
        true
    }

    pub fn keydown(&self, event: &Js) -> bool {
        if !event.get(Key::Key).equal_text("Escape") || self.source.get().is_null() {
            return false;
        }
        event.call(Key::PreventDefault, &[]);
        let origin = self.origin();
        self.close();
        self.restoring.set(true);
        browser::focus(&origin);
        self.restoring.set(false);
        true
    }

    pub fn begin_copy(&self, token: u32) -> Js {
        let source = self.source.get();
        let button = self.button.get();
        if source.is_null() || button.has_attr("aria-busy") {
            return Js::null();
        }
        self.cancel_copy();
        self.copy.set(token);
        button.set_text("Copying…");
        button.set_attr("aria-busy", "true");
        button.set_attr("aria-disabled", "true");
        source
            .query("annotation[encoding='application/x-tex']")
            .get(Key::TextContent)
    }

    pub fn finished(&self, token: u32) -> bool {
        if self.copy.get() != token {
            return false;
        }
        self.button.get().remove_attr("aria-busy");
        self.button.get().remove_attr("aria-disabled");
        true
    }

    pub fn reset_copy(&self, token: u32) {
        if self.copy.get() == token {
            self.copy.set(0);
            self.button.get().set_text("Copy LaTeX");
        }
    }
}
