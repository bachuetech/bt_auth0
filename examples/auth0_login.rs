use bt_auth0::{auth0::launch_auth_flow, auth0_config::Auth0Config, auth0_tokens::Auth0Token};
use bt_logger::{build_logger, log_error, log_fatal, log_verbose};
use bt_secure_storage::secure_storage::SecretVault;


fn main(){
    build_logger("BACHUETECH", "bt_auth0_test", bt_logger::LogLevel::VERBOSE, bt_logger::LogTarget::STD_ERROR);

    const APPLICATION_NAME: &str = "BT Auth0 TEST";
    const ENV_PROFILE: &str = "dev";    
    const SVR_PREFIX: &str = "bt-test";
    const YML_AUTH0_CONFIG: &str = include_str!("../.secrets/auth0.yml");
    const YML_KEYS: &str = include_str!("../.secrets/keys.yml");
    const SCOPE: &str = "openid profile email";
    let yml_config = Auth0Config::get_auth0_config(ENV_PROFILE,YML_AUTH0_CONFIG);


    if let Ok(auth0_config) = yml_config{
        let vault = SecretVault::new(SVR_PREFIX);
        let mut at = Auth0Token::retrieve_token_data(ENV_PROFILE, YML_KEYS, &vault); //Retrieve Auth0 Token from Vault
        while at.is_err(){
            log_verbose!("main","Error retrieving stored token. Error: '{:?}'",at.unwrap_err());
            at = launch_auth_flow(ENV_PROFILE,APPLICATION_NAME, None, &auth0_config,SCOPE,YML_KEYS);
        }

        if at.is_ok(){
            let mut auth0_token = at.unwrap();
            while auth0_token.does_token_expire_in(600) { //If token is about to expire, re-login. 10 minutes left (600) re-login.
                log_verbose!("main","Access Token is about to expire. Login again before token expire");
                let _ = auth0_token.remove_token_data(&vault); //Remove Stored Data, just in case.
                at = launch_auth_flow(ENV_PROFILE,APPLICATION_NAME, None, &auth0_config,SCOPE,YML_KEYS);
                while at.is_err(){
                    log_verbose!("main","Error from Login page. Try login page flow again. Error {:?}",at.unwrap_err());
                    at = launch_auth_flow(ENV_PROFILE,APPLICATION_NAME, None, &auth0_config,SCOPE,YML_KEYS);
                }
                auth0_token = at.unwrap();
            }

            if !auth0_token.is_token_expired(){
                //Valid Token save token data and continue to App
                //if let Err(e) =  auth0_token.store_token_data(&vault){
                //    let _ = auth0_token.remove_token_data(&vault); //Delete Partially saved data. Just in case.
                //    log_warning!("main","unable to save token data due to Error: {}", e);
                //}
                log_verbose!("main","Ready to launch. Token: {:?}",auth0_token);  
                //*** CALL page to start here or functions! ***
            }else{
                //Is this really going to happen?
                let _ = auth0_token.remove_token_data(&vault);//Delete saved data. Just in case.
                log_error!("main","Access Token is Expired. Login Again!");
            }
        }else{
            log_error!("main","Authentication Error: {}", at.unwrap_err());
        }
    }else{
        log_fatal!("main","Cannot initialize Auth0. Error reading YAML Config file. {}",yml_config.unwrap_err())
    }    
}