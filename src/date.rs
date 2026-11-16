use std::time::{SystemTime, UNIX_EPOCH};

use http::HeaderValue;

/// Whether a cached date was formatted in the same wall-clock second as
/// `now`; HTTP dates have second granularity, so only then is it reusable.
#[inline]
pub(crate) fn is_fresh(cache: &Option<(HeaderValue, SystemTime)>, now: SystemTime) -> bool {
    cache.as_ref().is_some_and(|(_, cached_at)| {
        cached_at
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs())
            == now.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
    })
}

/// Returns the cached date for `now`, formatting it first when the cache
/// is empty or stale.
#[inline]
pub(crate) fn cached_date_at(
    cache: &mut Option<(HeaderValue, SystemTime)>,
    now: SystemTime,
) -> Option<HeaderValue> {
    if !is_fresh(cache, now) {
        let value = HeaderValue::from_str(&httpdate::fmt_http_date(now)).ok()?;
        *cache = Some((value, now));
    }
    cache.as_ref().map(|(value, _)| value.clone())
}
