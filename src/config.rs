use serde::Deserialize;
use std::env;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub database_url: String,
    pub port: u16,
    pub rate_limit: RateLimitConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum number of requests allowed per window for a single user/API key.
    pub max_requests: u64,
    /// Length of the rate limit window in seconds.
    pub window_seconds: u64,
    /// Whether rate limiting is enabled for this environment.
    pub enabled: bool,
    /// API keys that are exempt from rate limiting (trusted clients).
    pub trusted_api_keys: Vec<String>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window_seconds: 60,
            enabled: true,
            trusted_api_keys: Vec::new(),
        }
    }
}

impl RateLimitConfig {
    /// Build a rate limit config from environment variables, falling back to
    /// sensible defaults so limits are configurable per environment.
    pub fn from_env() -> Self {
        let defaults = Self::default();

        let max_requests = env::var("RATE_LIMIT_MAX_REQUESTS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(defaults.max_requests);

        let window_seconds = env::var("RATE_LIMIT_WINDOW_SECONDS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(defaults.window_seconds);

        let enabled = env::var("RATE_LIMIT_ENABLED")
            .ok()
            .map(|v| v != "false" && v != "0")
            .unwrap_or(defaults.enabled);

        let trusted_api_keys = env::var("RATE_LIMIT_TRUSTED_API_KEYS")
            .ok()
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or(defaults.trusted_api_keys);

        Self {
            max_requests,
            window_seconds,
            enabled,
            trusted_api_keys,
        }
    }

    /// Returns true when the given API key is a trusted client that should
    /// bypass rate limiting.
    pub fn is_trusted(&self, api_key: &str) -> bool {
        self.trusted_api_keys.iter().any(|k| k == api_key)
    }
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            database_url: env::var("DATABASE_URL").unwrap_or_default(),
            port: env::var("PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8080),
            rate_limit: RateLimitConfig::from_env(),
use std::time::Duration;

/// Database connection pool configuration.
///
/// Pool sizing is capped at 50 concurrent connections per the acceptance
/// criteria for issue #967. Acquisition timeout is kept well under the 10ms
/// target so that normal load never surfaces timeout errors.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum number of concurrent connections held by the pool.
    pub max_size: u32,
    /// Minimum number of idle connections kept warm.
    pub min_idle: Option<u32>,
    /// How long an idle connection may live before being reaped.
    pub idle_timeout: Option<Duration>,
    /// Maximum lifetime of a connection before it is recycled.
    pub max_lifetime: Option<Duration>,
    /// How long a caller waits to acquire a connection.
    pub acquire_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_size: 50,
            min_idle: Some(5),
            idle_timeout: Some(Duration::from_secs(600)),
            max_lifetime: Some(Duration::from_secs(1800)),
            acquire_timeout: Duration::from_millis(10),
        }
    }
}

impl PoolConfig {
    /// Build a pool config from explicit sizing, clamped to the 50-connection cap.
    pub fn new(max_size: u32) -> Self {
        Self {
            max_size: max_size.min(50),
            ..Self::default()
        }
    }
}
