use std::error::Error;

use bt_logger::get_error;
use bt_yaml_utils::get_yaml_from_string;

/// The base URL for Auth0's OAuth authorization endpoint.
/// This constant represents the URL that clients use to redirect users to Auth0 for authentication.
const ENDPOINT_OAUTH_AUTHZ_URL: &str = "/authorize";

/// The base URL for Auth0's device code authorization endpoint.
/// This constant represents the URL that clients use to obtain a device code to authenticate with Auth0.
//const ENDPOINT_DEV_AUTHZ_CODE_URL: &str = "/oauth/device/code";

/// The base URL for Auth0's token endpoint.
/// This constant represents the URL that clients use to exchange an authorization code for an access token.
const ENDPOINT_TOKEN_URL: &str = "/oauth/token";

/// The base URL for Auth0's user info endpoint.
/// This constant represents the URL that clients use to retrieve information about a user after they have authenticated with Auth0.
const ENDPOINT_USER_INFO_URL: &str = "/userinfo";

/// Represents a configuration object for interacting with Auth0.
/// This struct holds the necessary configuration settings to connect to an Auth0 instance, including the domain, client ID, and redirect URI.
#[derive(Debug)]
pub struct Auth0Config {
    domain: String,
    client_id: String,
    client_secret: String,
    redirect_port: Vec<usize>,
    redirect_server: String,
    redirect_path: String,
}

impl Auth0Config {
    /// Creates a new `Auth0Config` instance based on the provided environment profile and YAML configuration file.
    ///
    /// # Parameters
    /// * `env_profile`: The name of the environment profile to use for configuration (e.g. dev, prod).
    /// * `yml_auth0_config`: The contents of the Auth0 YAML configuration file.
    ///
    /// # Returns
    /// A new `Auth0Config` instance if successful, or an error if the configuration could not be read from the YAML file.    
    pub fn get_auth0_config(env_profile: &str, yml_auth0_config: &str) -> Result<Auth0Config,Box<dyn Error>>{
        let config = get_yaml_from_string(yml_auth0_config)?;
        let auth0_redir_port = config[env_profile]["redirect_port"].as_str().ok_or(get_error!("get_auth0_config","No Auth0 Redirect Port in Auth0 YAML config file"))?.to_owned();
        //let auth0_redirect = format!("{}:{}",config[env_profile]["redirect_server"].as_str().unwrap_or("http://localhost").to_owned(),
        //                                            auth0_redir_port);

        Ok(Auth0Config{
            domain: config[env_profile]["domain"].as_str().ok_or(get_error!("get_auth0_config","No Auth0 Domain in Auth0 YAML config file"))?.to_owned(),
            client_id: config[env_profile]["client_id"].as_str().ok_or(get_error!("get_auth0_config","No Auth0 Cliend-ID in Auth0 YAML config file"))?.to_owned(),
            client_secret: config[env_profile]["client_secret"].as_str().ok_or(get_error!("get_auth0_config","No Auth0 Client-secret in Auth0 YAML config file"))?.to_owned(),
            redirect_port: auth0_redir_port.split(',').filter_map(|p| p.trim().parse::<usize>().ok()).collect(),
            redirect_server: config[env_profile]["redirect_server"].as_str().unwrap_or("http://localhost").to_owned(),
            redirect_path: config[env_profile]["redirect_path"].as_str().unwrap_or("/callback").to_owned(), //auth0_redir_port,
            //redirect_uri: format!("{}{}",auth0_redirect, config[env_profile]["redirect_path"].as_str().unwrap_or("/callback").to_owned())
        })
    }
    
    /// Returns the domain of the Auth0 instance.    
    pub fn get_domain(&self) -> String{
        self.domain.clone()
    }

    /// Returns the client ID used to authenticate with the Auth0 instance.    
    pub fn get_client_id(&self) -> String{
        self.client_id.clone()
    }

    /// Returns the client secret used to authenticate with the Auth0 instance.    
    pub fn get_client_secret(&self) -> String{
        self.client_secret.clone()
    }

    /// Returns the port number(s) that clients use for redirects.    
    pub fn get_redirect_port(&self) -> Vec<usize>{ //String{
        self.redirect_port.clone()
    }   

    /// Returns the base URL of the redirect URI, including the scheme and domain.    
    pub fn get_redirect_uri(&self, port: usize) -> String{
        if self.redirect_port.contains(&port){
            format!("{}:{}{}",self.redirect_server,port,self.redirect_path)
        }else{
            format!("Invalid Port {}",port)
        }
    }   

    /// Returns the full URL for the Auth0 OAuth authorization endpoint.
    pub fn get_authorize_url(&self) -> String{
        format!("https://{}{}", self.domain,ENDPOINT_OAUTH_AUTHZ_URL)
    }    

    /// Returns the full URL for the Auth0 token endpoint.    
    pub fn get_token_url(&self) -> String{
        format!("https://{}{}", self.domain,ENDPOINT_TOKEN_URL)
    }

    /// Returns the full URL for the Auth0 user info endpoint.    
    pub fn get_userinfo_url(&self) -> String{
        format!("https://{}{}", self.domain,ENDPOINT_USER_INFO_URL)
    }    
}


#[cfg(test)]
mod auth0_config_tests {
    use std::sync::Once;

    use super::*;
    use bt_logger::{LogLevel, LogTarget, build_logger};

    static INIT: Once = Once::new();
    fn ini_log() {
        INIT.call_once(|| {
            build_logger("BACHUETECH", "UNIT TEST RUST auth0_config_tests", LogLevel::VERBOSE, LogTarget::STD_ERROR, None );     
        });
    }

    // Test for successful configuration creation
    #[test]
    fn test_get_auth0_config_success() {
        ini_log();
        let yaml_config = r#"
dev:
  domain: "example.auth0.com"
  client_id: "client_id_123"
  client_secret: "client_secret_456"
  redirect_port: "3000"
  redirect_server: "http://localhost"
  redirect_path: "/callback"
"#;

        let config = Auth0Config::get_auth0_config("dev", yaml_config).unwrap();

        assert_eq!(config.get_domain(), "example.auth0.com");
        assert_eq!(config.get_client_id(), "client_id_123");
        assert_eq!(config.get_client_secret(), "client_secret_456");
        assert_eq!(config.get_redirect_port(), vec![3000]);
        assert_eq!(config.get_redirect_uri(3000), "http://localhost:3000/callback");
    }

    // Test for missing redirect port
    #[test]
    fn test_get_auth0_config_missing_redirect_port() {
        let yaml_config = r#"
dev:
  domain: "example.auth0.com"
  client_id: "client_id_123"
  client_secret: "client_secret_456"
  redirect_server: "http://localhost"
  redirect_path: "/callback"
"#;

        let result = Auth0Config::get_auth0_config("dev", yaml_config);
        assert!(result.is_err());
    }

    // Test for missing domain
    #[test]
    fn test_get_auth0_config_missing_domain() {
        ini_log();
        let yaml_config = r#"
dev:
  client_id: "client_id_123"
  client_secret: "client_secret_456"
  redirect_port: "3000"
  redirect_server: "http://localhost"
  redirect_path: "/callback"
"#;

        let result = Auth0Config::get_auth0_config("dev", yaml_config);
        assert!(result.is_err());
    }

    // Test for missing client_id
    #[test]
    fn test_get_auth0_config_missing_client_id() {
        ini_log();
        let yaml_config = r#"
dev:
  domain: "example.auth0.com"
  client_secret: "client_secret_456"
  redirect_port: "3000"
  redirect_server: "http://localhost"
  redirect_path: "/callback"
"#;

        let result = Auth0Config::get_auth0_config("dev", yaml_config);
        assert!(result.is_err());
    }

    // Test for missing client_secret
    #[test]
    fn test_get_auth0_config_missing_client_secret() {
        ini_log();
        let yaml_config = r#"
dev:
  domain: "example.auth0.com"
  client_id: "client_id_123"
  redirect_port: "3000"
  redirect_server: "http://localhost"
  redirect_path: "/callback"
"#;

        let result = Auth0Config::get_auth0_config("dev", yaml_config);
        assert!(result.is_err());
    }

    // Test for default redirect path
    #[test]
    fn test_get_auth0_config_default_redirect_path() {
        ini_log();
        let yaml_config = r#"
dev:
  domain: "example.auth0.com"
  client_id: "client_id_123"
  client_secret: "client_secret_456"
  redirect_port: "3000"
  redirect_server: "http://localhost"
"#;

        let config = Auth0Config::get_auth0_config("dev", yaml_config).unwrap();
        assert_eq!(config.get_redirect_uri(3000), "http://localhost:3000/callback");
    }

    // Test for custom redirect path
    #[test]
    fn test_get_auth0_config_custom_redirect_path() {
        ini_log();
        let yaml_config = r#"
dev:
  domain: "example.auth0.com"
  client_id: "client_id_123"
  client_secret: "client_secret_456"
  redirect_port: "3000"
  redirect_server: "http://localhost"
  redirect_path: "/custom"
"#;

        let config = Auth0Config::get_auth0_config("dev", yaml_config).unwrap();
        assert_eq!(config.get_redirect_uri(3000), "http://localhost:3000/custom");
    }

    // Test for default redirect server
    #[test]
    fn test_get_auth0_config_default_redirect_server() {
        ini_log();
        let yaml_config = r#"
dev:
  domain: "example.auth0.com"
  client_id: "client_id_123"
  client_secret: "client_secret_456"
  redirect_port: "3000,4000"
  redirect_path: "/callback"
"#;

        let config = Auth0Config::get_auth0_config("dev", yaml_config).unwrap();
        assert_eq!(config.get_redirect_uri(4000), "http://localhost:4000/callback");
    }

    // Test for authorize URL
    #[test]
    fn test_get_authorize_url() {
        ini_log();
        let yaml_config = r#"
dev:
  domain: "example.auth0.com"
  client_id: "client_id_123"
  client_secret: "client_secret_456"
  redirect_port: "3000"
  redirect_server: "http://localhost"
  redirect_path: "/callback"
"#;

        let config = Auth0Config::get_auth0_config("dev", yaml_config).unwrap();
        assert_eq!(config.get_authorize_url(), "https://example.auth0.com/authorize");
    }

    // Test for token URL
    #[test]
    fn test_get_token_url() {
        ini_log();
        let yaml_config = r#"
dev:
  domain: "example.auth0.com"
  client_id: "client_id_123"
  client_secret: "client_secret_456"
  redirect_port: "3000"
  redirect_server: "http://localhost"
  redirect_path: "/callback"
"#;

        let config = Auth0Config::get_auth0_config("dev", yaml_config).unwrap();
        assert_eq!(config.get_token_url(), "https://example.auth0.com/oauth/token");
    }

    // Test for user info URL
    #[test]
    fn test_get_userinfo_url() {
        ini_log();
        let yaml_config = r#"
dev:
  domain: "example.auth0.com"
  client_id: "client_id_123"
  client_secret: "client_secret_456"
  redirect_port: "3000"
  redirect_server: "http://localhost"
  redirect_path: "/callback"
"#;

        let config = Auth0Config::get_auth0_config("dev", yaml_config).unwrap();
        assert_eq!(config.get_userinfo_url(), "https://example.auth0.com/userinfo");
    }

    // Test for non-existent environment profile
    #[test]
    fn test_get_auth0_config_nonexistent_profile() {
        ini_log();
        let yaml_config = r#"
dev:
  domain: "example.auth0.com"
  client_id: "client_id_123"
  client_secret: "client_secret_456"
  redirect_port: "3000"
  redirect_server: "http://localhost"
  redirect_path: "/callback"
"#;

        let result = Auth0Config::get_auth0_config("prod", yaml_config);
        assert!(result.is_err());
    }
}