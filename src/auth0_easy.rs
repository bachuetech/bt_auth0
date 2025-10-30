use std::error::Error;

use bt_logger::{get_error, get_fatal, log_info, log_verbose, log_warning};
use bt_secure_storage::secure_storage::SecretVault;
use tao::window::Icon;

use crate::{auth0::launch_auth_flow, auth0_config::Auth0Config, auth0_tokens::Auth0Token};

/// Loads an icon from a file path and converts it into a format suitable for use as an application icon. 
/// It reads an image file, converts it to RGBA8 format, and then creates an Icon object from the image data.
/// # Parameters
///  * path: A string slice (&str) that represents the file path to the icon image file to be loaded.
/// 
/// # Returns: Result<Icon, Box<dyn Error>>:
///  * On success: Returns Ok(Icon) containing the loaded icon
///  * On failure: Returns Err(Box<dyn Error>) containing the error that occurred during the loading process
fn load_icon(path: &str) -> Result<Icon, Box<dyn Error>> {
    let icon_image = image::open(path)?.into_rgba8();
    let (width, height) = icon_image.dimensions();
    Ok(Icon::from_rgba(icon_image.into_raw(), width, height)?)
}

///The auth0_auto function provides an automated authentication flow for Auth0-based applications. 
///It handles token retrieval from a secret vault, manages token expiration, and automatically re-authenticates when necessary. 
///This function ensures that a valid Auth0 token is available for use by the application.
///
/// #Parameters:
///  * env_profile 	&str 	The environment profile to use for configuration and authentication
///  * application_name 	&str 	The name of the application requesting authentication
///  * yml_auth0_config 	&str 	Content of the YAML configuration file for Auth0 settings
///  * service_prefix 	&str 	Prefix used for identifying secrets in the vault
///  * yml_keys 	&str 	Content of the YAML file containing emcryption keys
///  * scopes 	&str 	Space-separated list of OAuth scopes required for the application
///  * icon_path Option<&str> Option path to the icon, None if no icon.
/// 
/// #Return:
/// A Result: Result<Auth0Token, Box<dyn Error>>
///  * Success: Returns a valid Auth0Token struct containing the authenticated token data
///  * Failure: Returns an error boxed as Box<dyn Error> with detailed error information
pub fn auth0_auto(env_profile: &str, application_name: &str, yml_auth0_config: &str, service_prefix: &str, yml_keys: &str, scopes: &str, icon_path: Option<&str>) 
                    -> Result<Auth0Token, Box<dyn Error>>{
    let app_icon = if icon_path.is_some() { Some(load_icon(icon_path.unwrap())?)}else{None};

    let yml_config = Auth0Config::get_auth0_config(env_profile,yml_auth0_config);

    if let Ok(auth0_config) = yml_config{
        let vault = SecretVault::new(service_prefix);
        let mut at = Auth0Token::retrieve_token_data(env_profile, yml_keys, &vault); //Retrieve Auth0 Token from Vault
        while at.is_err(){
            log_verbose!("auth0_auto","No stored token found: '{:?}'",at.unwrap_err());
            at = launch_auth_flow(env_profile,application_name, app_icon.clone(), &auth0_config,scopes,yml_keys);
        }

        if at.is_ok(){
            let mut auth0_token = at.unwrap();
            while auth0_token.does_token_expire_in(600) { //If token is about to expire, re-login. 10 minutes left (600) re-login.
                log_info!("auth0_auto","Access Token is about to expire. Login again before token expire");
                let _ = auth0_token.remove_token_data(&vault); //Remove Stored Data, just in case.
                at = launch_auth_flow(env_profile,application_name, app_icon.clone(), &auth0_config,scopes,yml_keys);
                while at.is_err(){
                    log_warning!("auth0_auto","Error from Login page. Try login page flow again. Error: {:?}",at.unwrap_err());
                    at = launch_auth_flow(env_profile,application_name, app_icon.clone(), &auth0_config,scopes,yml_keys);
                }
                auth0_token = at.unwrap();
            }

            if !auth0_token.is_token_expired(){
                //Valid Token save token data and continue to App
                if let Err(e) =  auth0_token.store_token_data(&vault){
                    let _ = auth0_token.remove_token_data(&vault); //Delete Partially saved data. Just in case.
                    log_warning!("auth0_auto","unable to save token data due to Error: {}", e);
                }
                return Ok(auth0_token)
            }else{
                //Is this really going to happen?
                let _ = auth0_token.remove_token_data(&vault);//Delete saved data. Just in case.
                return Err(get_error!("auth0_auto","Access Token is Expired. Login Again!").into())
            }
        }else{
            return Err(get_error!("auth0_auto","Authentication Error: {}", at.unwrap_err()).into());
        }
    }else{
        return Err(get_fatal!("auth0_auto","Cannot initialize Auth0. Error reading YAML Config file. {}",yml_config.unwrap_err()).into())
    }        
}