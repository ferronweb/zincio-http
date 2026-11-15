use std::sync::RwLock;
use std::time::UNIX_EPOCH;

use http::HeaderValue;

#[derive(Default)]
pub(crate) struct DateCache {
    inner: RwLock<Option<(String, std::time::SystemTime)>>,
}

impl DateCache {
    #[allow(dead_code)]
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn get_date_header_value(&self) -> Option<HeaderValue> {
        let now = std::time::SystemTime::now();
        let mut inner = self.inner.read().ok()?;
        if inner.as_ref().is_none_or(|v| {
            v.1.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
                != now.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
        }) {
            drop(inner);
            let value = httpdate::fmt_http_date(now);
            let mut innerw = self.inner.write().ok()?;
            innerw.replace((value, now));
            drop(innerw);
            inner = self.inner.read().ok()?;
        }
        HeaderValue::from_str(inner.as_ref().map(|v| v.0.as_str()).unwrap_or("")).ok()
    }
}
