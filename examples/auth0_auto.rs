use bt_auth0::auth0_auto::auth0_auto;
use bt_logger::{build_logger, log_verbose};

fn main(){
    build_logger("BACHUETECH", "bt_auth0_test", bt_logger::LogLevel::VERBOSE, bt_logger::LogTarget::STD_ERROR);

    const ENV_PROFILE: &str = "dev";  
    const APPLICATION_NAME: &str = "BT Auth0 TEST";
    const SVR_PREFIX: &str = "bt-test";
    const YML_AUTH0_CONFIG: &str = include_str!("../.secrets/auth0.yml");
    const YML_KEYS: &str = include_str!("../.secrets/keys.yml");
    const SCOPE: &str = "openid profile email";

    let answer = auth0_auto(ENV_PROFILE, APPLICATION_NAME, YML_AUTH0_CONFIG, SVR_PREFIX, YML_KEYS, SCOPE);
    log_verbose!("main","Auth0 Authentication Answer: {:?}",answer);
}