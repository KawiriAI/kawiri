mod config;
mod protocol;
mod proxy;
mod server;
mod tee;
mod tunnel;

use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("kawa=info".parse()?),
        )
        .init();

    // Version banner — first thing in the log so "is this the right kawa?"
    // is answerable from the very top of any boot output, no scrolling.
    info!(
        "kawa v{} (build target: {})",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::ARCH
    );

    let cfg = config::Config::from_env();
    info!(
        port = cfg.port,
        upstream = %cfg.upstream,
        enable_pq = cfg.enable_pq,
        mock_tee_forced = cfg.mock_tee,
        "kawa starting"
    );

    // Decide attestation mode once, up front. detect_tee_mode itself logs the
    // decision (INFO for real, loud WARN for mock). Mode is then frozen for
    // the process lifetime so clients pinning measurements never see a kawa
    // that "becomes mock" mid-flight.
    let tee_mode = tee::detect_tee_mode(cfg.mock_tee).await;
    server::start_server(cfg, tee_mode).await
}
