use std::{cell::RefCell, rc::Rc, time::SystemTime};

use http::HeaderValue;

use crate::date::cached_date_at;

#[derive(Clone, Default)]
pub(super) struct DateCache {
    inner: Rc<RefCell<Option<(HeaderValue, SystemTime)>>>,
}

impl DateCache {
    #[inline]
    pub fn get_date_header_value(&self) -> Option<HeaderValue> {
        let mut inner = self.inner.try_borrow_mut().ok()?;
        cached_date_at(&mut inner, SystemTime::now())
    }
}
