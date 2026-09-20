//! `zbacs-relay` — run the relay.
//!
//!   zbacs-relay [--bind 0.0.0.0:8787]
//!
//! There is no configuration file and no secret to hand it: the relay holds nothing that needs
//! protecting (spec §7). Self-hosting is a supported deployment, not a special mode (Z-1.R.4).

use std::net::SocketAddr;

use zbacs_relay::{router, Relay};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut bind: SocketAddr = "127.0.0.1:8787".parse()?;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => bind = args.next().ok_or("--bind needs an address")?.parse()?,
            "--help" | "-h" => {
                println!("zbacs-relay [--bind ADDR]   (default 127.0.0.1:8787)");
                return Ok(());
            }
            other => return Err(format!("unknown argument {other}").into()),
        }
    }

    let listener = tokio::net::TcpListener::bind(bind).await?;
    println!("zbacs-relay listening on http://{}", listener.local_addr()?);
    axum::serve(listener, router(Relay::new()))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            println!("\nshutting down");
        })
        .await?;
    Ok(())
}
