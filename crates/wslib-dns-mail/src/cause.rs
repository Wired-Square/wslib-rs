use std::sync::Arc;

/// A report entry's typed cause, on the live value only: a serialised report
/// carries the entry's own message and reads back with none, and two entries
/// are equal by what they say, whatever caused them.
#[derive(Debug)]
pub struct Cause<E>(Option<Arc<E>>);

impl<E> Cause<E> {
    pub(crate) fn new(error: E) -> Self {
        Self(Some(Arc::new(error)))
    }

    /// `None` once the entry has been serialised and read back.
    pub fn error(&self) -> Option<&E> {
        self.0.as_deref()
    }
}

impl<E> Default for Cause<E> {
    fn default() -> Self {
        Self(None)
    }
}

impl<E> Clone for Cause<E> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<E> PartialEq for Cause<E> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl<E> Eq for Cause<E> {}
