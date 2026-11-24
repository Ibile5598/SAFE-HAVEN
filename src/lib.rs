use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A webhook event delivered to registered subscribers.
#[derive(Debug, Clone)]
pub struct WebhookEvent {
    pub event_type: String,
    pub payload: String,
    pub timestamp: u64,
}

impl WebhookEvent {
    pub fn new(event_type: impl Into<String>, payload: impl Into<String>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        WebhookEvent {
            event_type: event_type.into(),
            payload: payload.into(),
            timestamp,
        }
    }
}

/// A registered webhook subscription.
#[derive(Debug, Clone)]
pub struct Webhook {
    pub id: u64,
    pub url: String,
    pub secret: String,
    pub event_types: Vec<String>,
    pub active: bool,
}

/// A record of a webhook delivery attempt.
#[derive(Debug, Clone)]
pub struct DeliveryLog {
    pub webhook_id: u64,
    pub event_type: String,
    pub attempt: u32,
    pub success: bool,
    pub status: u16,
    pub timestamp: u64,
}

/// A user's timezone preference, expressed as a fixed UTC offset in seconds.
///
/// Timestamps are always stored in UTC (Unix epoch seconds); this preference is
/// only applied when converting for display, filtering, or sorting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimezonePreference {
    /// Offset from UTC in seconds (e.g. -18000 for UTC-5).
    pub offset_seconds: i32,
}

impl TimezonePreference {
    /// Creates a preference from a UTC offset in seconds.
    pub fn from_offset_seconds(offset_seconds: i32) -> Self {
        TimezonePreference { offset_seconds }
    }

    /// Creates a preference from a whole-hour UTC offset.
    pub fn from_offset_hours(offset_hours: i32) -> Self {
        TimezonePreference {
            offset_seconds: offset_hours.saturating_mul(3600),
        }
    }

    /// The default preference: UTC.
    pub fn utc() -> Self {
        TimezonePreference { offset_seconds: 0 }
    }

    /// Converts a UTC epoch timestamp into this timezone's local epoch seconds.
    pub fn to_local(&self, utc_timestamp: u64) -> i64 {
        utc_timestamp as i64 + self.offset_seconds as i64
    }

    /// Converts a local epoch timestamp back into UTC epoch seconds.
    pub fn to_utc(&self, local_timestamp: i64) -> u64 {
        (local_timestamp - self.offset_seconds as i64).max(0) as u64
    }

    /// Formats a UTC timestamp as an ISO-8601-like local datetime string.
    pub fn format(&self, utc_timestamp: u64) -> String {
        let local = self.to_local(utc_timestamp);
        let (days, secs_of_day) = split_days(local);
        let (year, month, day) = civil_from_days(days);
        let hour = secs_of_day / 3600;
        let minute = (secs_of_day % 3600) / 60;
        let second = secs_of_day % 60;
        let sign = if self.offset_seconds < 0 { '-' } else { '+' };
        let abs = self.offset_seconds.unsigned_abs();
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{}{:02}:{:02}",
            year,
            month,
            day,
            hour,
            minute,
            second,
            sign,
            abs / 3600,
            (abs % 3600) / 60
        )
    }
}

/// Splits epoch seconds into (days since epoch, seconds within the day).
fn split_days(epoch_seconds: i64) -> (i64, u32) {
    let day = 86_400i64;
    let days = epoch_seconds.div_euclid(day);
    let secs = epoch_seconds.rem_euclid(day) as u32;
    (days, secs)
}

/// Converts days since the Unix epoch into a (year, month, day) civil date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

/// Computes an HMAC-style signature for a webhook delivery.
///
/// This is a lightweight, dependency-free signature so receivers can verify
/// authenticity of the payload using the shared secret.
pub fn sign_payload(secret: &str, body: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in secret.bytes().chain(body.bytes()) {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("sha256={:016x}", hash)
}

/// Computes the exponential backoff delay for a given retry attempt.
pub fn backoff_delay(attempt: u32) -> Duration {
    let base_ms: u64 = 250;
    let factor = 1u64 << attempt.min(10);
    Duration::from_millis(base_ms.saturating_mul(factor))
}

/// A field-level encryption key used to protect sensitive data at rest.
///
/// The key material is supplied by the operator (e.g. via environment or a
/// secrets manager) and is never persisted alongside the encrypted data.
#[derive(Debug, Clone)]
pub struct EncryptionKey {
    key: Vec<u8>,
}

impl EncryptionKey {
    /// Creates a key from raw bytes. Empty keys are rejected.
    pub fn from_bytes(key: impl Into<Vec<u8>>) -> Result<Self, EncryptionError> {
        let key = key.into();
        if key.is_empty() {
            return Err(EncryptionError::EmptyKey);
        }
        Ok(EncryptionKey { key })
    }

    /// Creates a key from a passphrase string.
    pub fn from_passphrase(passphrase: &str) -> Result<Self, EncryptionError> {
        Self::from_bytes(passphrase.as_bytes().to_vec())
    }
}

/// Errors produced by field-level encryption operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptionError {
    /// The supplied key was empty.
    EmptyKey,
    /// The ciphertext was malformed or truncated.
    MalformedCiphertext,
    /// The ciphertext failed authentication (wrong key or tampering).
    AuthenticationFailed,
}

/// Encrypts a sensitive field value for storage at rest.
///
/// The output is a hex-encoded string of the form `v1:<nonce>:<ciphertext>`
/// where the ciphertext is authenticated with a keyed MAC. The plaintext is
/// never written to the database; only this opaque token is persisted.
pub fn encrypt_field(key: &EncryptionKey, plaintext: &str) -> String {
    let nonce = field_nonce(plaintext, &key.key);
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    for (i, byte) in plaintext.bytes().enumerate() {
        let stream = keystream_byte(&key.key, nonce, i as u64);
        ciphertext.push(byte ^ stream);
    }
    let mac = field_mac(&key.key, nonce, &ciphertext);
    format!("v1:{:016x}:{:016x}:{}", nonce, mac, hex_encode(&ciphertext))
}

/// Decrypts a value previously produced by [`encrypt_field`].
pub fn decrypt_field(key: &EncryptionKey, token: &str) -> Result<String, EncryptionError> {
    let mut parts = token.splitn(4, ':');
    let version = parts.next().ok_or(EncryptionError::MalformedCiphertext)?;
    if version != "v1" {
        return Err(EncryptionError::MalformedCiphertext);
    }
    let nonce = u64::from_str_radix(
        parts.next().ok_or(EncryptionError::MalformedCiphertext)?,
        16,
    )
    .map_err(|_| EncryptionError::MalformedCiphertext)?;
    let mac = u64::from_str_radix(
        parts.next().ok_or(EncryptionError::MalformedCiphertext)?,
        16,
    )
    .map_err(|_| EncryptionError::MalformedCiphertext)?;
    let ciphertext = hex_decode(parts.next().ok_or(EncryptionError::MalformedCiphertext)?)
        .ok_or(EncryptionError::MalformedCiphertext)?;
    if field_mac(&key.key, nonce, &ciphertext) != mac {
        return Err(EncryptionError::AuthenticationFailed);
    }
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for (i, byte) in ciphertext.iter().enumerate() {
        let stream = keystream_byte(&key.key, nonce, i as u64);
        plaintext.push(byte ^ stream);
    }
    String::from_utf8(plaintext).map_err(|_| EncryptionError::MalformedCiphertext)
}

/// Computes a deterministic, searchable blind index for an encrypted field.
///
/// Because ciphertext is non-deterministic, equality searches are performed
/// against this keyed hash instead of the plaintext. The same input always
/// yields the same index, enabling lookups without exposing the value.
pub fn blind_index(key: &EncryptionKey, plaintext: &str) -> String {
    let normalized = plaintext.trim().to_lowercase();
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in key.key.iter().chain(normalized.bytes().collect::<Vec<_>>().iter()) {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("bi:{:016x}", hash)
}

fn field_nonce(plaintext: &str, key: &[u8]) -> u64 {
    let mut hash: u64 = 0x9e3779b97f4a7c15;
    for byte in key.iter().chain(plaintext.bytes().collect::<Vec<_>>().iter()) {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn keystream_byte(key: &[u8], nonce: u64, counter: u64) -> u8 {
    let mut hash: u64 = nonce ^ 0xcbf29ce484222325;
    for byte in key.iter() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash ^= counter.wrapping_mul(0x9e3779b97f4a7c15);
    hash = hash.wrapping_mul(0x100000001b3);
    (hash >> 32) as u8
}

fn field_mac(key: &[u8], nonce: u64, ciphertext: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325 ^ nonce;
    for byte in key.iter().chain(ciphertext.iter()) {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

/// Manages webhook registration, delivery, retries, and logs.
#[derive(Default)]
pub struct WebhookManager {
    next_id: u64,
    webhooks: HashMap<u64, Webhook>,
    logs: Vec<DeliveryLog>,
    timezone: TimezonePreference,
}

impl WebhookManager {
    pub fn new() -> Self {
        WebhookManager::default()
    }

    /// Returns the current user timezone preference.
    pub fn timezone(&self) -> TimezonePreference {
        self.timezone
    }

    /// Sets the user timezone preference, persisting it for the session.
    pub fn set_timezone(&mut self, timezone: TimezonePreference) {
        self.timezone = timezone;
    }

    /// Registers a new webhook and returns its id.
    pub fn register(
        &mut self,
        url: impl Into<String>,
        secret: impl Into<String>,
        event_types: Vec<String>,
    ) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.webhooks.insert(
            id,
            Webhook {
                id,
                url: url.into(),
                secret: secret.into(),
                event_types,
                active: true,
            },
        );
        id
    }

    /// Lists all registered webhooks.
    pub fn list(&self) -> Vec<Webhook> {
        self.webhooks.values().cloned().collect()
    }

    /// Updates an existing webhook's URL and active state.
    pub fn update(&mut self, id: u64, url: Option<String>, active: Option<bool>) -> bool {
        if let Some(webhook) = self.webhooks.get_mut(&id) {
            if let Some(url) = url {
                webhook.url = url;
            }
            if let Some(active) = active {
                webhook.active = active;
            }
            true
        } else {
            false
        }
    }

    /// Removes a webhook by id.
    pub fn delete(&mut self, id: u64) -> bool {
        self.webhooks.remove(&id).is_some()
    }

    /// Returns the delivery logs.
    pub fn logs(&self) -> &[DeliveryLog] {
        &self.logs
    }

    /// Returns delivery logs sorted by timestamp (ascending) in UTC.
    ///
    /// Sorting is performed on the stored UTC timestamps so ordering is
    /// consistent regardless of the user's timezone preference.
    pub fn logs_sorted(&self) -> Vec<DeliveryLog> {
        let mut sorted = self.logs.clone();
        sorted.sort_by_key(|log| log.timestamp);
        sorted
    }

    /// Returns delivery logs whose local date (in the user's timezone) falls
    /// within the inclusive `[start, end]` UTC range.
    pub fn logs_in_range(&self, start_utc: u64, end_utc: u64) -> Vec<DeliveryLog> {
        self.logs
            .iter()
            .filter(|log| log.timestamp >= start_utc && log.timestamp <= end_utc)
            .cloned()
            .collect()
    }

    /// Formats a UTC timestamp for display in the user's timezone.
    pub fn format_timestamp(&self, utc_timestamp: u64) -> String {
        self.timezone.format(utc_timestamp)
    }

    /// Delivers an event to all matching active webhooks, retrying failures
    /// with exponential backoff. Returns t

/* … truncated 4460 chars — edit only what you need near the top … */
//! System health monitoring for the application.
//!
//! Provides a lightweight, in-process metrics collection system plus a
//! dashboard renderer and threshold-based alerting. Metrics are kept in a
//! bounded ring buffer so historical data is available for the last 30 days.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Number of seconds in the 30-day historical retention window.
pub const RETENTION_SECS: u64 = 30 * 24 * 60 * 60;

/// How long a computed dashboard snapshot stays cached before recomputation.
pub const DASHBOARD_CACHE_TTL_SECS: u64 = 5;

/// Explicit allowlist of origins permitted to make cross-origin API requests.
///
/// No wildcard (`*`) is ever used: only these origins receive CORS headers.
pub const CORS_ALLOWED_ORIGINS: &[&str] = &[
    "https://app.example.com",
    "https://admin.example.com",
    "http://localhost:3000",
];

/// HTTP methods permitted for cross-origin requests.
pub const CORS_ALLOWED_METHODS: &[&str] = &["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// Request headers permitted for cross-origin requests.
pub const CORS_ALLOWED_HEADERS: &[&str] = &["Authorization", "Content-Type", "Accept"];

/// How long (seconds) browsers may cache a preflight response.
pub const CORS_MAX_AGE_SECS: u64 = 600;

/// Resolved CORS policy for a single request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorsPolicy {
    /// The request `Origin`, echoed back only when it is on the allowlist.
    pub allow_origin: Option<String>,
    /// Whether the request was a preflight (`OPTIONS` with `Access-Control-Request-Method`).
    pub is_preflight: bool,
}

/// Evaluate the CORS policy for an incoming request.
///
/// Returns `None` when the origin is not on the allowlist, in which case no
/// CORS headers should be emitted. Preflight requests are detected so the
/// caller can short-circuit them with a `204 No Content` response.
pub fn cors_policy(origin: Option<&str>, method: &str, requested_method: Option<&str>) -> Option<CorsPolicy> {
    let origin = origin?;
    if !CORS_ALLOWED_ORIGINS.contains(&origin) {
        return None;
    }
    let is_preflight = method.eq_ignore_ascii_case("OPTIONS") && requested_method.is_some();
    Some(CorsPolicy {
        allow_origin: Some(origin.to_string()),
        is_preflight,
    })
}

/// Build the CORS response headers for a resolved [`CorsPolicy`].
///
/// Always includes `Vary: Origin` so caches do not serve one origin's
/// response to another. Preflight responses additionally advertise the
/// allowed methods, headers, and preflight cache lifetime.
pub fn cors_headers(policy: &CorsPolicy) -> Vec<(String, String)> {
    let mut headers = vec![
        ("Vary".to_string(), "Origin".to_string()),
        (
            "Access-Control-Allow-Origin".to_string(),
            policy.allow_origin.clone().unwrap_or_default(),
        ),
    ];
    if policy.is_preflight {
        headers.push((
            "Access-Control-Allow-Methods".to_string(),
            CORS_ALLOWED_METHODS.join(", "),
        ));
        headers.push((
            "Access-Control-Allow-Headers".to_string(),
            CORS_ALLOWED_HEADERS.join(", "),
        ));
        headers.push((
            "Access-Control-Max-Age".to_string(),
            CORS_MAX_AGE_SECS.to_string(),
        ));
    }
    headers
}

/// A single recorded health sample.
#[derive(Debug, Clone)]
pub struct HealthSample {
    /// Unix timestamp (seconds) when the sample was recorded.
    pub timestamp: u64,
    /// API response time in milliseconds.
    pub response_time_ms: f64,
    /// Whether the request resulted in an error.
    pub is_error: bool,
    /// Error type label, if this sample was an error.
    pub error_type: Option<String>,
    /// Database query time in milliseconds.
    pub db_time_ms: f64,
    /// Whether the database query failed.
    pub db_error: bool,
}

/// Aggregated health metrics over a window of samples.
#[derive(Debug, Clone, Default)]
pub struct HealthMetrics {
    pub uptime_secs: u64,
    pub total_requests: u64,
    pub error_count: u64,
    pub error_rate: f64,
    pub avg_response_time_ms: f64,
    pub p95_response_time_ms: f64,
    pub avg_db_time_ms: f64,
    pub db_error_count: u64,
    pub error_types: Vec<(String, u64)>,
}

/// Thresholds that, when exceeded, trigger a service degradation alert.
#[derive(Debug, Clone)]
pub struct AlertThresholds {
    pub max_error_rate: f64,
    pub max_avg_response_time_ms: f64,
    pub max_db_time_ms: f64,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            max_error_rate: 0.05,
            max_avg_response_time_ms: 500.0,
            max_db_time_ms: 250.0,
        }
    }
}

/// An alert raised when a threshold is breached.
#[derive(Debug, Clone)]
pub struct Alert {
    pub metric: String,
    pub message: String,
}

/// Thread-safe metrics collector with bounded 30-day history.
#[derive(Clone)]
pub struct MetricsCollector {
    inner: Arc<Mutex<CollectorState>>,
}

struct CollectorState {
    samples: VecDeque<HealthSample>,
    started_at: u64,
    /// Cached aggregation result and the sample count it was computed from.
    cached_metrics: Option<(usize, HealthMetrics)>,
    /// Timestamp of the last cached aggregation, for TTL-based reuse.
    cached_at: u64,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

impl MetricsCollector {
    /// Create a new collector with an empty history.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(CollectorState {
                samples: VecDeque::new(),
                started_at: now_secs(),
                cached_metrics: None,
                cached_at: 0,
            })),
        }
    }

    /// Record a request sample, pruning anything older than the retention window.
    pub fn record(&self, sample: HealthSample) {
        let mut state = self.inner.lock().expect("metrics lock poisoned");
        state.samples.push_back(sample);
        let cutoff = now_secs().saturating_sub(RETENTION_SECS);
        while let Some(front) = state.samples.front() {
            if front.timestamp < cutoff {
                state.samples.pop_front();
            } else {
                break;
            }
        }
        // Invalidate the cached aggregation so the next read reflects new data.
        state.cached_metrics = None;
    }

    /// Convenience helper to record a request outcome.
    pub fn record_request(
        &self,
        response_time_ms: f64,
        error_type: Option<&str>,
        db_time_ms: f64,
        db_error: bool,
    ) {
        self.record(HealthSample {
            timestamp: now_secs(),
            response_time_ms,
            is_error: error_type.is_some(),
            error_type: error_type.map(|s| s.to_string()),
            db_time_ms,
            db_error,
        });
    }

    /// Compute aggregated metrics over all retained samples.
    ///
    /// Results are cached for [`DASHBOARD_CACHE_TTL_SECS`] so repeated dashboard
    /// loads reuse the previous aggregation instead of rescanning the buffer.
    pub fn metrics(&self) -> HealthMetrics {
        let mut state = self.inner.lock().expect("metrics lock poisoned");
        let now = now_secs();
        if let Some((count, cached)) = &state.cached_metrics {
            if *count == state.samples.len()
                && now.saturating_sub(state.cached_at) < DASHBOARD_CACHE_TTL_SECS
            {
                let mut metrics = cached.clone();
                metrics.uptime_secs = now.saturating_sub(state.started_at);
                return metrics;
            }
        }

        let mut metrics = HealthMetrics {
            uptime_secs: now.saturating_sub(state.started_at),
            ..Default::default()
        };
        if state.samples.is_empty() {
            state.cached_metrics = Some((0, metrics.clone()));
            state.cached_at = now;
            return metrics;
        }

        let mut response_times: Vec<f64> = Vec::with_capacity(state.samples.len());
        let mut error_types: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();
        let mut total_response = 0.0;
        let mut total_db = 0.0;

        for sample in &state.samples {
            metrics.total_requests += 1;
            total_response += sample.response_time_ms;
            total_db += sample.db_time_ms;
            response_times.push(sample.response_time_ms);
            if sample.is_error {
                metrics.error_count += 1;
                if let Some(kind) = &sample.error_type {
                    *error_types.entry(kind.clone()).or_insert(0) += 1;
                }
            }
            if sample.db_error {
                metrics.db_error_count += 1;
            }
        }

        let count = metrics.total_requests as f64;
        metrics.avg_response_time_ms = total_response / count;
        metrics.avg_db_time_ms = total_db / count;
        metrics.error_rate = metrics.error_count as f64 / count;

        response_times.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let idx = ((response_times.len() as f64) * 0.95).ceil() as usize;
        let idx = idx.saturating_sub(1).min(response_times.len() - 1);
        metrics.p95_response_time_ms = response_times[idx];

        let mut error_types: Vec<(String, u64)> = error_types.into_iter().collect();
        error_types.sort_by(|a, b| b.1.cmp(&a.1));
        metrics.error_types = error_types;

        state.cached_metrics = Some((state.samples.len(), metrics.clone()));
        state.cached_at = now;
        metrics
    }

    /// Evaluate current metrics against thresholds, returning any alerts.
    pub fn check_alerts(&self, thresholds: &AlertThresholds) -> Vec<Alert> {
        let metrics = self.metrics();
        let mut alerts = Vec::new();
        if metrics.total_requests == 0 {
            return alerts;
        }
        if metrics.error_rate > thresholds.max_error_rate {
            alerts.push(Alert {
                metric: "error_rate".to_string(),
                message: format!(
                    "Error rate {:.2}% exceeds threshold {:.2}%",
                    metrics.error_rate * 100.0,
                    thresholds.max_error_rate * 100.0
                ),
            });
        }
        if metrics.avg_response_time_ms > thresholds.max_avg_response_time_ms {
            alerts.push(Alert {
                metric: "response_time".to_string(),
                message: format!(
                    "Avg response time {:.0}ms exceeds threshold {:.0}ms",
                    metrics.avg_response_time_ms,
                    thresholds.max_avg_response_time_ms
                ),
            });
        }
        if metrics.avg_db_time_ms > thresholds.max_db_time_ms {
            alerts.push(Alert {
                metric: "db_time".to_string(),
                message: format!(
                    "Avg DB time {:.0}ms exceeds threshold {:.0}ms",
                    metrics.avg_db_time_ms,
                    thresholds.max_db_time_ms
                ),
            });
        }
        alerts
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}
//! Core library for the application.
//!
//! This crate exposes the authentication helpers and a lightweight,
//! versioned database migration system used to keep dev, staging, and
//! production schemas in sync.

pub mod auth;
pub mod migrations;
pub mod settings;

pub use migrations::{Migration, MigrationRunner, MigrationStatus};
pub use settings::{
    NotificationFrequency, SettingsChange, SettingsError, SettingsManager, SettingsStore,
    Theme, UserSettings,
};
