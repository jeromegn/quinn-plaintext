# quinn-plaintext

Use QUIC without encryption.

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