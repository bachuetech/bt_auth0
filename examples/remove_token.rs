use bt_auth0::auth0_tokens::Auth0Token;
use bt_logger::{build_logger, log_verbose};
use bt_secure_storage::secure_storage::SecretVault;

fn main(){
    build_logger("BACHUETECH", "bt_auth0_test", bt_logger::LogLevel::VERBOSE, bt_logger::LogTarget::STD_ERROR, None);
        
    const ENV_PROFILE: &str = "dev";       
    const SVR_PREFIX: &str = "bt-test"; 
    const YML_KEYS: &str = include_str!("../.secrets/keys.yml");

    let vault = SecretVault::new(SVR_PREFIX);
    let at = Auth0Token::retrieve_token_data(ENV_PROFILE, YML_KEYS, &vault); //Retrieve Auth0 Token from Vault
    log_verbose!("main","auth0token {:?}",at);
    let token = at.unwrap();
    log_verbose!("main","Token Removed {:?}", token.remove_token_data(&vault));
}