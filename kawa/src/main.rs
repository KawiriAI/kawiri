mod config;
mod protocol;
mod proxy;
mod server;
mod tee;

use tracing::{error, info};

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

    // Fail fast on production builds when there's no working TEE backing.
    // Without this, kawa happily binds the port and accepts WebSocket
    // connections only to drop each one mid-handshake when configfs-tsm
    // rejects the report-entry mkdir — the operator sees a generic
    // "connection closed" on the konnect side and has to grep VM logs.
    //
    // Probe by actually creating + removing a sentinel entry. Path
    // existence alone is a weak check: configfs-tsm can be mounted with
    // the `report` subdir present but mkdir underneath still fails
    // (no TSM provider registered, broken hardware, etc.) — exactly the
    // EIO 6 we saw in practice. Doing the same syscall the handshake
    // path will do verifies the *whole* pipeline works.
    //
    // Mock builds skip this — running on TEE-less hosts is the whole
    // point of `--features mock`.
    #[cfg(not(feature = "mock"))]
    {
        const TSM: &str = "/sys/kernel/config/tsm/report";
        let probe = format!("{TSM}/kawa_startup_probe");
        match std::fs::create_dir(&probe) {
            Ok(()) => {
                let _ = std::fs::remove_dir(&probe);
                info!("TEE backing OK ({TSM} accepts report entries)");
            }
            Err(e) => {
                error!(
                    "no working TEE backing: mkdir {probe} failed: {e}. \
                     This is a production kawa build that requires real \
                     SEV-SNP or TDX hardware with the configfs-tsm kernel \
                     driver attached. Run inside a CVM, or rebuild with \
                     `--features mock` for host-side protocol testing."
                );
                std::process::exit(1);
            }
        }
    }

    server::start_server(cfg).await
}
