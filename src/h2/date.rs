use std::sync::RwLock;
use std::time::SystemTime;

use http::HeaderValue;

use crate::date::{cached_date_at, is_fresh};

#[derive(Default)]
pub(crate) struct DateCache {
    inner: RwLock<Option<(HeaderValue, SystemTime)>>,
}

impl DateCache {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn get_date_header_value(&self) -> Option<HeaderValue> {
        let now = SystemTime::now();
        {
            let inner = self.inner.read().ok()?;
            if is_fresh(&inner, now) {
                return inner.as_ref().map(|(value, _)| value.clone());
            }
        }
        let mut inner = self.inner.write().ok()?;
        cached_date_at(&mut inner, now)
    }
}
