use std::env;
use std::fmt;

/// How kawa connects to the inference backend.
#[derive(Clone, Debug)]
pub enum Upstream {
    /// HTTP/HTTPS TCP connection (e.g. "http://127.0.0.1:8080")
    Http { url: String },
    /// Unix domain socket (e.g. "unix:///run/vllm/vllm.sock")
    Unix { path: String },
}

impl Upstream {
    fn from_env() -> Self {
        let raw = env::var("UPSTREAM_URL").unwrap_or_else(|_| "http://localhost:8000".into());
        if let Some(path) = raw.strip_prefix("unix://") {
            Upstream::Unix {
                path: path.to_string(),
            }
        } else {
            Upstream::Http { url: raw }
        }
    }
}

impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Upstream::Http { url } => write!(f, "{url}"),
            Upstream::Unix { path } => write!(f, "unix://{path}"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub port: u16,
    pub upstream: Upstream,
    pub enable_pq: bool,
    pub mock_tee: bool,
    #[allow(dead_code)] // parsed from TEE_PLATFORM env, consumed by future platform routing
    pub tee_platform: String,
    pub standalone: bool,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            port: env::var("KAWA_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8443),
            upstream: Upstream::from_env(),
            enable_pq: env::var("ENABLE_PQ").map(|v| v != "false").unwrap_or(true),
            mock_tee: env::var("MOCK_TEE")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            tee_platform: env::var("TEE_PLATFORM").unwrap_or_else(|_| "auto".into()),
            standalone: env::var("KAWA_STANDALONE")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
        }
    }

    pub fn is_standalone(&self) -> bool {
        self.standalone
    }
}
