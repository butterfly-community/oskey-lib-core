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

    pub(crate) fn request(&mut self, pending: T) -> bool {
        if self.pending.is_some() {
            false
        } else {
            self.pending = Some(pending);
            true
        }
    }

    pub(crate) fn finish(&mut self) -> Option<T> {
        self.pending.take()
    }
}
