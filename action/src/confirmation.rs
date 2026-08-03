use alloc::vec::Vec;
use oskey_chain::ConfirmationDetails;

#[derive(Debug, Default, Eq, PartialEq)]
pub struct PreparedResult {
    pub from: Option<[u8; 20]>,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

pub(crate) struct PendingConfirmation<T> {
    pub(crate) id: u32,
    pub(crate) action: T,
    pub(crate) review: ConfirmationDetails,
    pub(crate) prepared: Option<PreparedResult>,
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

    pub(crate) fn start(&mut self, action: T, review: ConfirmationDetails) -> Option<u32> {
        self.resume(PendingConfirmation {
            id: 0,
            action,
            review,
            prepared: None,
        })
    }

    pub(crate) fn get(&self, id: u32) -> Option<(&ConfirmationDetails, Option<&PreparedResult>)> {
        self.pending
            .as_ref()
            .filter(|pending| pending.id == id)
            .map(|pending| (&pending.review, pending.prepared.as_ref()))
    }

    pub(crate) fn resume(&mut self, mut pending: PendingConfirmation<T>) -> Option<u32> {
        if self.pending.is_some() {
            return None;
        }

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        pending.id = id;
        self.pending = Some(pending);
        Some(id)
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
