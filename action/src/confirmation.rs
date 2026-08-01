pub(crate) struct ConfirmationService<T> {
    pending: Option<T>,
}

impl<T> ConfirmationService<T> {
    pub(crate) const fn new() -> Self {
        Self { pending: None }
    }

    pub(crate) fn is_waiting(&self) -> bool {
        self.pending.is_some()
    }

    pub(crate) fn pending(&self) -> Option<&T> {
        self.pending.as_ref()
    }

    pub(crate) fn start(&mut self, pending: T) {
        debug_assert!(self.pending.is_none());
        self.pending = Some(pending);
    }

    pub(crate) fn finish(&mut self) -> Option<T> {
        self.pending.take()
    }
}
