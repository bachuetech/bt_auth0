# Project Title
BT Auth0

## Description
A Rust-based library for launching an authentication flow with Auth0, obtaining an access token and user info in return.

## Usage
See examples for details. Start with auth0_auto.

bt_loger is a hard-dependency, Always build a bt_loger:
```RUST
build_logger("BACHUETECH", "bt_auth0_test", bt_logger::LogLevel::VERBOSE, bt_logger::LogTarget::STD_ERROR);
```

For the auth0 config YAML file use the following structure:
```YAML
dev:
  domain: "example.auth0.com"
  client_id: "client_id_123"
  client_secret: "client_secret_456"
  redirect_port: "3000"
  redirect_server: "http://localhost"
  redirect_path: "/callback"
```

for the encryption keys YAML file use the following structure:
```YAML
dev:
  auth0token: "test_encryption_key"
```

## Version History
* 0.1.0
    * Initial Release

## License
CC-BY-NC-ND-4.0