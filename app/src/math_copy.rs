use crate::{
    app,
    browser::{self, Arg, Js, Key, document, required},
};
use core::cell::Cell;

#[derive(Default)]
pub struct MathCopy {
    panel: Cell<Js>,
    source: Cell<Js>,
    copy: Cell<u32>,
}

impl MathCopy {
    pub fn new() -> Self {
        let panel = required(lit!("#math-popover"));
        Self {
            panel: Cell::new(panel.retain()),
            ..Self::default()
        }
    }

    fn button(&self) -> Js {
        self.panel.get().get(Key::LastChild)
    }

    #[inline(never)]
    fn latex(&self) -> Js {
        self.source
            .get()
            .query(lit!("annotation"))
            .get(Key::TextContent)
    }

    fn origin(&self) -> Js {
        let source = self.source.get();
        let anchor = source.closest(lit!("a,button"));
        if anchor.is_null() { source } else { anchor }
    }

    fn inside(&self, element: Js) -> bool {
        !self.source.get().is_null()
            && (self.panel.get().call_boolean(Key::Contains, element.arg())
                || self.origin().call_boolean(Key::Contains, element.arg()))
    }

    fn cancel_copy(&self) {
        let token = self.copy.replace(0);
        if token != 0 {
            app().copies.call(Key::Delete, &[Arg::integer(token)]);
        }
    }

    pub fn close(&self) {
        let panel = self.panel.get();
        if panel.boolean(Key::Inert) {
            return;
        }
        self.cancel_copy();
        panel.set(Key::Inert, Arg::boolean(true));
        // Keep the anchor through the native popover's CSS exit transition.
        let _ = panel.try_call(Key::HidePopover, &[]);
    }

    pub fn detach(&self) {
        self.close();
        let source = self.source.get();
        if !source.is_null() {
            source.remove_attr(lit!("data-copy-source"));
            self.source.set(source.replacing(Js::null()));
            // The shared control must never enter a cached or departing page.
            document()
                .get(Key::Body)
                .call_void(Key::Append, self.panel.get().arg());
        }
    }

    fn show(&self, source: Js) {
        let panel = self.panel.get();
        if source.same(self.source.get()) && !panel.boolean(Key::Inert) {
            return;
        }
        self.cancel_copy();
        if !self.source.get().is_null() {
            self.source.get().remove_attr(lit!("data-copy-source"));
        }
        self.source.set(self.source.get().replacing(source));
        source.set_attr(lit!("data-copy-source"), lit!(""));
        let button = self.button();
        Self::finished(button);
        button.set_text(lit!("Copy LaTeX"));
        panel
            .get(Key::FirstChild)
            .set(Key::TextContent, self.latex().arg());
        self.origin().call(
            Key::InsertAdjacentElement,
            &[Arg::literal(lit!("afterend")), panel.arg()],
        );
        panel.set(Key::Inert, Arg::boolean(false));
        // Older engines still get the CSS-positioned, non-modal control.
        let _ = panel.try_call(Key::ShowPopover, &[]);
    }

    pub fn focus(&self, event: &Js) {
        let target = crate::target(event);
        if target.is_null() || self.panel.get().call_boolean(Key::Contains, target.arg()) {
            return;
        }
        let anchor = target.closest(lit!("a,button"));
        if !anchor.is_null() {
            let source = anchor.query(lit!(".math"));
            if !source.is_null() {
                self.show(source);
                return;
            }
        }
        if !self.inside(target) {
            self.close();
        }
    }

    pub fn pointer_down(&self, event: &Js) {
        if !self.inside(crate::target(event)) {
            self.close();
        }
    }

    pub fn scroll(&self, event: &Js) {
        if !self
            .panel
            .get()
            .call_boolean(Key::Contains, crate::target(event).arg())
        {
            self.close();
        }
    }

    pub fn activate(&self, event: &Js, target: Js) -> bool {
        if target.is_null() {
            return false;
        }
        let source = target.closest(lit!("#page-content .math"));
        if source.is_null() || !source.closest(lit!("a, button")).is_null() {
            return false;
        }
        event.call(Key::PreventDefault, &[]);
        self.show(source);
        browser::focus(&self.button());
        true
    }

    pub fn keydown(&self, event: &Js) -> bool {
        let key = event.get(Key::Key);
        if key.equal_text(lit!("Enter")) || key.equal_text(lit!(" ")) {
            return self.activate(event, crate::target(event));
        }
        if !key.equal_text(lit!("Escape")) || self.panel.get().boolean(Key::Inert) {
            return false;
        }
        event.call(Key::PreventDefault, &[]);
        // Restore focus before closing so focusin cannot reopen the same formula.
        browser::focus(&self.origin());
        self.close();
        true
    }

    pub fn begin_copy(&self, token: u32) -> Js {
        let button = self.button();
        if self.panel.get().boolean(Key::Inert) || button.has_attr(lit!("aria-busy")) {
            return Js::null();
        }
        self.cancel_copy();
        self.copy.set(token);
        button.set_text(lit!("Copying…"));
        button.set_attr(lit!("aria-busy"), lit!("true"));
        button.set_attr(lit!("aria-disabled"), lit!("true"));
        self.latex()
    }

    pub fn is_button(&self, button: Js) -> bool {
        button.same(self.button())
    }

    #[inline(never)]
    pub fn finished(button: Js) {
        button.remove_attr(lit!("aria-busy"));
        button.remove_attr(lit!("aria-disabled"));
    }

    pub fn reset_copy(&self) {
        self.copy.set(0);
        self.button().set_text(lit!("Copy LaTeX"));
    }
}
