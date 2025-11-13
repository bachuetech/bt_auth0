# Project Title
BT Auth0

## Description
A Rust-based library for launching an authentication flow with Auth0, obtaining an access token and user info in return.

## Usage
See examples for details. Start with auth0_auto.
```Rust
let answer = auth0_auto(ENV_PROFILE, APPLICATION_NAME, YML_AUTH0_CONFIG, SVR_PREFIX, YML_KEYS, SCOPE, Some(icon_path));
```

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
* 0.2.0
  * Added icon support for auth0_auto, displaying the provided icon (breaking change). 
  * Lowered the wry library version supported to 0.51.2 to enhance compatibility with other frameworks.
  * Rename lib auth0_auto to auth0_easy (breaking change)
* 0.2.1
  * Support multiple ports for Auth0 redirect
  * The maximum number of login retries is set to 10. (Avoid an infinite loop)
* 0.2.2
  * Update Dependencies
* 0.2.3
  * New function with support for auth0_auto with the icon image instead of the path.

## License
CC-BY-NC-ND-4.0