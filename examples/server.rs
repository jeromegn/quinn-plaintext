use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let server_config = quinn_plaintext::server_config();
    let server = quinn::Endpoint::server(server_config, "127.0.0.1:1337".parse().unwrap())
        .expect("could not create endpoint server");

    info!("server waiting to accept...");
    loop {
        let connecting = server
            .accept()
            .await
            .expect("did not accept a conn!")
            .accept()
            .expect("did not accept a conn!");
        warn!("accepted: {connecting:?}");

        // possibly triggers a "0.5-RTT" handshake
        let (conn, _) = connecting.into_0rtt().expect("into_0rtt failed");

        warn!("completed accept: {conn:?}");

        let mut recv = conn
            .accept_uni()
            .await
            .expect("could not accept uni stream");

        warn!("ACCEPTED UNI STREAM");

        let expected = b"hello world";

        let mut b = vec![0u8; expected.len()];
        recv.read_exact(&mut b).await.expect("could not read data");
        info!(
            "read bytes! message: {}",
            String::from_utf8_lossy(b.as_slice())
        );
    }
}
