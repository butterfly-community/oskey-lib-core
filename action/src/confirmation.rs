use oskey_chain::ConfirmationDetails;

pub(crate) struct PendingConfirmation<T> {
    pub(crate) id: u32,
    pub(crate) action: T,
    pub(crate) details: ConfirmationDetails,
}

pub(crate) struct ConfirmationService<T> {
    next_id: u32,
    pending: Option<PendingConfirmation<T>>,
}

impl<T> ConfirmationService<T> {
    pub(crate) const fn new() -> Self {
        Self {
            next_id: 1,
            pending: None,
        }
    }

    pub(crate) fn is_waiting(&self) -> bool {
        self.pending.is_some()
    }

    pub(crate) fn start(&mut self, action: T, details: ConfirmationDetails) -> Option<u32> {
        if self.pending.is_some() {
            return None;
        }

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.pending = Some(PendingConfirmation {
            id,
            action,
            details,
        });
        Some(id)
    }

    pub(crate) fn details(&self, id: u32) -> Option<&ConfirmationDetails> {
        self.pending
            .as_ref()
            .filter(|pending| pending.id == id)
            .map(|pending| &pending.details)
    }

    pub(crate) fn finish(&mut self, id: u32) -> Option<PendingConfirmation<T>> {
        if self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.id == id)
        {
            self.pending.take()
        } else {
            None
        }
    }

    pub(crate) fn cancel_if(
        &mut self,
        predicate: impl FnOnce(&PendingConfirmation<T>) -> bool,
    ) -> Option<PendingConfirmation<T>> {
        if self.pending.as_ref().is_some_and(predicate) {
            self.pending.take()
        } else {
            None
        }
    }
}
