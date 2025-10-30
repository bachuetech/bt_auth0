use bt_auth0::auth0_easy::auth0_auto;
use bt_logger::{build_logger, log_verbose};

fn main(){
    build_logger("BACHUETECH", "bt_auth0_test", bt_logger::LogLevel::VERBOSE, bt_logger::LogTarget::STD_ERROR);

    const ENV_PROFILE: &str = "dev";  
    const APPLICATION_NAME: &str = "BT Auth0 TEST";
    const SVR_PREFIX: &str = "bt-test";
    const YML_AUTH0_CONFIG: &str = include_str!("../.secrets/auth0.yml");
    const YML_KEYS: &str = include_str!("../.secrets/keys.yml");
    const SCOPE: &str = "openid profile email";

    #[cfg(target_os = "windows")]
    let icon_path = "examples/icons/bachuetech_icon.ico";

    #[cfg(target_os = "linux")]
    let icon_path = "examples/icons/32x32.png";

    #[cfg(target_os = "macos")]
    let icon_path = "examples/icons/icon.icns";

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    let icon_path = "examples/icons/128x128.png";   

    let answer = auth0_auto(ENV_PROFILE, APPLICATION_NAME, YML_AUTH0_CONFIG, SVR_PREFIX, YML_KEYS, SCOPE, Some(icon_path));
    log_verbose!("main","Auth0 Authentication Answer: {:?}",answer);
}