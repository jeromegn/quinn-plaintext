use std::sync::Arc;

use bytes::BytesMut;

use quinn_proto::{
    crypto::{self, CryptoError, HeaderKey},
    transport_parameters, ConnectionId, Side, TransportError,
};
use tracing::trace;

pub fn server_config() -> quinn::ServerConfig {
    quinn::ServerConfig::with_crypto(Arc::new(PlaintextServerConfig::new()))
}

pub fn client_config() -> quinn::ClientConfig {
    quinn::ClientConfig::new(Arc::new(PlaintextClientConfig::new()))
}

pub struct PlaintextHeaderKey {
    side: Side,
}

impl PlaintextHeaderKey {
    pub fn new(side: Side) -> Self {
        Self { side }
    }
}

impl HeaderKey for PlaintextHeaderKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        trace!(side = ?self.side, "HeaderKey::decrypt pn_offset: {pn_offset}");
        trace!(side = ?self.side, "packet: {packet:?}");
        // do nothing
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        trace!(side = ?self.side, "HeaderKey::encrypt pn_offset: {pn_offset}");
        trace!(side = ?self.side, "packet: {packet:?}");
        // do nothing
    }

    fn sample_size(&self) -> usize {
        trace!(side = ?self.side, "HeaderKey::sample_size");
        0
    }
}

pub struct PlaintextPacketKey {
    side: Side,
}

impl PlaintextPacketKey {
    fn new(side: Side) -> Self {
        Self { side }
    }
}

pub struct PlaintextClientConfig;

impl PlaintextClientConfig {
    pub fn new() -> Self {
        Self
    }
}

pub struct PlaintextServerConfig;

impl PlaintextServerConfig {
    pub fn new() -> Self {
        Self
    }
}

fn crypto_keys(side: Side) -> crypto::Keys {
    crypto::Keys {
        header: crypto_header_keypair(side),
        packet: crypto_packet_keypair(side),
    }
}

fn crypto_header_keypair(side: Side) -> crypto::KeyPair<Box<dyn crypto::HeaderKey>> {
    crypto::KeyPair {
        local: Box::new(PlaintextHeaderKey::new(side)),
        remote: Box::new(PlaintextHeaderKey::new(side)),
    }
}

fn crypto_packet_keypair(side: Side) -> crypto::KeyPair<Box<dyn crypto::PacketKey>> {
    crypto::KeyPair {
        local: Box::new(PlaintextPacketKey::new(side)),
        remote: Box::new(PlaintextPacketKey::new(side)),
    }
}

/// A plaintext session which does not perform packet encryption/decryption
pub struct PlaintextSession {
    side: Side,
    params: transport_parameters::TransportParameters,
    handshake_data: Option<transport_parameters::TransportParameters>,
    wrote_transporter_params: bool,
    initial_keys: Option<crypto::Keys>,
    handshake_keys: Option<crypto::Keys>,
}

impl PlaintextSession {
    fn new(side: Side, params: transport_parameters::TransportParameters) -> Self {
        Self {
            side,
            params,
            handshake_data: None,
            wrote_transporter_params: false,
            initial_keys: Some(crypto_keys(side)),
            handshake_keys: Some(crypto_keys(side)),
        }
    }
}

// forward all calls to inner except those related to packet encryption/decryption
impl crypto::Session for PlaintextSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, _side: Side) -> crypto::Keys {
        trace!(side = ?self.side, "initial_keys dst_cid: {dst_cid}");
        crypto_keys(self.side)
    }

    fn handshake_data(&self) -> Option<Box<dyn std::any::Any>> {
        trace!(side = ?self.side, "handshake_data");
        self.handshake_data
            .map(|tp| Box::new(tp) as Box<dyn std::any::Any>)
    }

    fn peer_identity(&self) -> Option<Box<dyn std::any::Any>> {
        trace!(side = ?self.side, "peer_identity");
        None
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        trace!(side = ?self.side, "early_crypto");
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        trace!(side = ?self.side, "early_data_accepted");
        Some(false)
    }

    fn is_handshaking(&self) -> bool {
        trace!(side = ?self.side, "is_handshaking");
        self.handshake_data.is_none()
            || !self.wrote_transporter_params
                && (self.initial_keys.is_some() || self.handshake_keys.is_some())
    }

    fn read_handshake(&mut self, mut buf: &[u8]) -> Result<bool, TransportError> {
        trace!(side = ?self.side, "read_handshake {buf:?}");

        if self.handshake_data.is_none() {
            self.handshake_data = Some(
                transport_parameters::TransportParameters::read(self.side, &mut buf)
                    .expect("could not read shit"),
            );
        }
        Ok(true)
    }

    fn transport_parameters(
        &self,
    ) -> Result<Option<transport_parameters::TransportParameters>, TransportError> {
        trace!(side = ?self.side, "transport_parameters");
        Ok(self.handshake_data.clone())
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<crypto::Keys> {
        if self.side.is_client() && !self.wrote_transporter_params {
            self.params.write(buf);
            self.wrote_transporter_params = true;
            trace!("wrote data: {buf:?}");
        }

        trace!(side = ?self.side, "write_handshake");

        match self.initial_keys.take().or_else(|| {
            self.handshake_keys.take().and_then(|k| {
                if self.side.is_server() {
                    if !self.wrote_transporter_params {
                        self.params.write(buf);
                        self.wrote_transporter_params = true;
                        trace!("wrote data: {buf:?}");
                    }
                }
                trace!("taking handshake keys");
                Some(k)
            })
        }) {
            Some(k) => Some(k),
            None => {
                trace!("returning None");
                None
            }
        }
    }

    fn next_1rtt_keys(&mut self) -> Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>> {
        trace!(side = ?self.side, "next_1rtt_keys");
        Some(crypto_packet_keypair(self.side))
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, _header: &[u8], _payload: &[u8]) -> bool {
        trace!(side = ?self.side, "is_valid_retry orig_dst_cid: {orig_dst_cid}");
        true
    }

    fn export_keying_material(
        &self,
        _output: &mut [u8],
        _label: &[u8],
        _context: &[u8],
    ) -> Result<(), crypto::ExportKeyingMaterialError> {
        trace!(side = ?self.side, "export_keying_material");
        Ok(())
    }
}

impl crypto::ClientConfig for PlaintextClientConfig {
    fn start_session(
        self: std::sync::Arc<Self>,
        version: u32,
        server_name: &str,
        params: &transport_parameters::TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, quinn::ConnectError> {
        trace!("ClientConfig::start_session version: {version}, server_name: {server_name}, params: {params:?}");
        Ok(Box::new(PlaintextSession::new(
            Side::Client,
            params.clone(),
        )))
    }
}

impl crypto::ServerConfig for PlaintextServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
        side: Side,
    ) -> Result<crypto::Keys, crypto::UnsupportedVersion> {
        trace!(
            "ServerConfig::initial_keys version: {version}, dst_cid: {dst_cid:?}, side: {side:?}"
        );
        Ok(crypto_keys(side))
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        trace!("ServerConfig::retry_tag version: {version}, orig_dst_cid: {orig_dst_cid:?}, packet: {packet:?}");

        [0u8; 16]
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &transport_parameters::TransportParameters,
    ) -> Box<dyn crypto::Session> {
        trace!("ServerConfig::start_session version: {version}, params: {params:?}");
        Box::new(PlaintextSession::new(Side::Server, params.clone()))
    }
}

// forward all calls to inner except those related to packet encryption/decryption
impl crypto::PacketKey for PlaintextPacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        trace!(side = ?self.side, "PacketKey::encrypt packet: {packet}, header_len: {header_len}");
        let (header, payload_tag) = buf.split_at_mut(header_len);
        trace!(side = ?self.side, "header: {header:?}");
        trace!(side = ?self.side, "payload_tag: {payload_tag:?}");
        // do nothing
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        trace!(side = ?self.side, "PacketKey::decrypt packet: {packet}, header: {header:?}");
        trace!(side = ?self.side, "payload: {:?}", payload.as_ref());
        // do nothing
        Ok(())
    }

    fn tag_len(&self) -> usize {
        trace!(side = ?self.side, "PacketKey::tag_len");
        0
    }

    fn confidentiality_limit(&self) -> u64 {
        trace!(side = ?self.side, "PacketKey::confidentiality_limit");
        u64::MAX
    }

    fn integrity_limit(&self) -> u64 {
        trace!(side = ?self.side, "PacketKey::integrity_limit");
        1 << 36
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test]
    async fn basic_test() {
        let server_config =
            quinn::ServerConfig::with_crypto(Arc::new(PlaintextServerConfig::new()));
        let server = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap())
            .expect("could not create endpoint server");

        let addr = server
            .local_addr()
            .expect("could not get server local addr");

        let test_data = b"hello world";

        let (done_tx, done_rx) = tokio::sync::oneshot::channel();

        let server_fut = async move {
            println!("server waiting to accept...");
            let connecting = server.accept().await.expect("did not accept a conn!");
            println!("accepted: {connecting:?}");
            let conn = connecting
                .await
                .expect("could not complete connection accept");

            println!("completed accept: {conn:?}");

            let mut recv = conn
                .accept_uni()
                .await
                .expect("could not accept uni stream");

            println!("ACCEPTED UNI STREAM");

            let mut b = vec![0u8; test_data.len()];
            recv.read_exact(&mut b)
                .await
                .expect("could not test string");

            done_tx
                .send(())
                .expect("could not tell the client we're done");

            b
        };

        let client_fut = async move {
            let client_config = quinn::ClientConfig::new(Arc::new(PlaintextClientConfig::new()));
            let client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())
                .expect("could not create endpoint client");

            let conn = client
                .connect_with(client_config, addr, "plaintext.test")
                .expect("could not create connection future")
                .await
                .expect("could not connect to server");

            println!("OPENING UNI STREAM");

            let mut send = conn.open_uni().await.unwrap();

            println!("opened a unidirectional stream");

            send.write_all(b"hello world").await.unwrap();
            send.flush().await.unwrap();

            done_rx.await.unwrap();
        };

        let (buf, _) = tokio::join!(server_fut, client_fut);

        assert_eq!(buf, test_data);
    }
}