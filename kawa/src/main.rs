mod config;
mod protocol;
mod proxy;
mod server;
mod tee;

use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("kawa=info".parse()?),
        )
        .init();

    let cfg = config::Config::from_env();
    info!(
        port = cfg.port,
        upstream = %cfg.upstream,
        enable_pq = cfg.enable_pq,
        mock_tee = cfg.mock_tee,
        "kawa starting"
    );

    server::start_server(cfg).await
}
