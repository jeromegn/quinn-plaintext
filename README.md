# quinn-plaintext

Use QUIC without encryption.

Normally, data integrity checks are performed by the cryptography layer. As of 0.2.0, there is checksum added to the tag storage to prevent corrupted data to make it through.

This is not recommended unless there's already encryption w/ the underlying layer (e.g. Wireguard)

## Usage

Basic examples are available under [`examples/`](examples)

### Server

```rust
let server = quinn::Endpoint::server(quinn_plaintext::server_config(), "[::]:0".parse()?)?;
// ...
```

### Client

```rust
let mut client = quinn::Endpoint::client("[::]:0".parse()?)?;
client.set_default_client_config(quinn_plaintext::client_config());
// ...
```