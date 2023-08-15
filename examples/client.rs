use std::time::Duration;

use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())
        .expect("could not create endpoint client");

    let conn = client
        .connect_with(
            quinn_plaintext::client_config(),
            "127.0.0.1:1337".parse().unwrap(),
            "plaintext.test",
        )
        .expect("could not create connection future")
        .await
        .expect("could not connect to server");

    warn!("OPENING UNI STREAM");
    let mut send = conn.open_uni().await.unwrap();

    warn!("opened a unidirectional stream");

    send.write_all(b"hello world").await.unwrap();

    info!("wrote bytes!");

    tokio::time::sleep(Duration::from_secs(5)).await;
}
