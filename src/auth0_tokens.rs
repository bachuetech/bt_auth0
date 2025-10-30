use std::{collections::HashSet, error::Error, fmt};

use bt_logger::get_error;
use bt_secure_storage::secure_storage::{SecretCipher, SecretVault};
use bt_yaml_utils::get_yaml_from_string;
use chrono::Utc;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde_json::{from_str, json, Value};
use tokio::runtime::Runtime;

/// The internal name of the Auth0 service.
const AUTH0_SERVICE_NAME: &str = "auth0token";

/// Represents an Auth0 token.
pub struct Auth0Token{
    access_token: Auth0AccessToken,
    enc_key: String,
    at_nonce: String,
    cipher: SecretCipher,
    user_info: Value,
}

impl fmt::Debug for Auth0Token {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Auth0Token")
            .field("access_token",&self.access_token)
            .field("enc_key", &"***Key***".to_string())
            .field("at_nonce", &"***AT Nonce***".to_string())
            .field("cipher", &"***Cipher***".to_string())
            .field("user_info", &self.user_info)
            .finish()
    }
}

impl Auth0Token {
    /// Creates a new `Auth0Token` instance.
    ///
    /// # Parameters
    /// * `env_profile`: The environment profile used to retrieve the encryption key from the KEYS YAML file (e.g. dev, prod).
    /// * `access_token`: The access token itself.
    /// * `expiration_timestamp`: The timestamp when the access token expires.
    /// * `scope_list`: An optional list of scopes associated with the access token.
    /// * `yml_keys`: A string containing the content of the YAML file with KEYS. Used to retrieve the AUTH0_SERVICE_NAME value to encrypt the access token.
    ///
    /// # Returns
    /// A new `Auth0Token` instance or an error if the encryption key could not be retrieved from the KEYS YAML file.    
    pub fn new(env_profile: &str, access_token: String, expiration_timestamp: usize, scope_list: Option<HashSet<String>>, yml_keys:&str) -> Result<Self, Box<dyn Error>>{
        let yml_keys = get_yaml_from_string(yml_keys)?;
        let int_key = yml_keys[env_profile][AUTH0_SERVICE_NAME].as_str().ok_or(get_error!("new","No Auth0 Encryption Key in KEYS YAML file"))?.to_owned();

        let c = SecretCipher::new();
        let (at,nonce) = c.encrypt_secret(&access_token, &int_key)?;

        Ok(Self{
            access_token: Auth0AccessToken::new(at, expiration_timestamp, scope_list),
            enc_key: int_key,
            at_nonce: nonce,
            cipher: c,
            user_info: json!({}),
        })
    }

    /// Stores the token data in a Secret Vault.
    ///
    /// # Parameters
    /// * `sv`: The Secret Vault used to store the token data.
    ///
    /// # Returns
    /// A result indicating whether the token data was stored successfully or an error occurred.   
    pub fn store_token_data(&self, sv: &SecretVault) -> Result<(), Box<dyn Error>>{
        let nonce_label = format!("{}{}",AUTH0_SERVICE_NAME,"nonce");
        let userinfo_label = format!("{}{}",AUTH0_SERVICE_NAME,"user_info"); 

        sv.store_secret(&nonce_label, &self.at_nonce)?;
        sv.store_secret(&userinfo_label, &self.user_info.to_string())?;
        self.access_token.store_accesstoken_data(sv)?;
        Ok(())
    }

    /// Retrieves the token data from a Secret Vault to return a new Auth0Token
    ///
    /// # Parameters
    /// * `env_profile`: The environment profile used to retrieve the encryption key from the KEYS YAML file.
    /// * `yml_keys`: A string containing the content of the YAML file with the KEYS.
    /// * `sv`: The Secret Vault used to store the token data.
    ///
    /// # Returns
    /// A new `Auth0Token` instance or an error if the encryption key could not be retrieved from the KEYS YAML file or the token data cannot be retrieved from the Secret Vault.    
    pub fn retrieve_token_data(env_profile: &str, yml_keys:&str, sv: &SecretVault) -> Result<Self, Box<dyn Error>>{
        let yml_keys = get_yaml_from_string(yml_keys)?;
        let int_key = yml_keys[env_profile]["auth0token"].as_str().ok_or(get_error!("new","No Auth0 Encryption Key in KEYS YAML file"))?.to_owned();

        let nonce_label = format!("{}{}",AUTH0_SERVICE_NAME,"nonce");
        let userinfo_label = format!("{}{}",AUTH0_SERVICE_NAME,"user_info"); 
        Ok(
            Self{
                access_token: Auth0AccessToken::retrieve_accesstoken_data(sv)?,
                enc_key: int_key,
                at_nonce: sv.retrieve_secret(&nonce_label)?,
                cipher: SecretCipher::new(),
                user_info: from_str(&sv.retrieve_secret(&userinfo_label)?)?,
            }
        )
    }

    /// Removes the token data from a Secret Vault.
    ///
    /// # Parameters
    /// * `sv`: The Secret Vault used to store the token data.
    ///
    /// # Returns
    /// A result indicating whether the token data was removed successfully or an error occurred.    
    pub fn remove_token_data(&self, sv: &SecretVault) -> Result<(), Box<dyn Error>>{
        let nonce_label = format!("{}{}",AUTH0_SERVICE_NAME,"nonce");
        let userinfo_label = format!("{}{}",AUTH0_SERVICE_NAME,"user_info"); 
        let _ = sv.delete_secret(&nonce_label);
        let _ = sv.delete_secret(&userinfo_label);
        self.access_token.remove_access_token_data(sv)
    }

    /// Peeks at the access token.
    ///
    /// # Returns
    /// The access token itself or an error if the access token cannot be peeked at.    
    pub fn peek_access_toke(&self) -> Result<String, Box<dyn Error>>{
        let at = self.cipher.decrypt_secret(self.access_token.peek_token(), &self.at_nonce, &self.enc_key)?;
        Ok(at)
    }

    /// Checks if the access token is expired.
    ///
    /// # Returns
    /// A boolean indicating whether the access token is expired or not.    
    pub fn is_token_expired(&self) -> bool{
        self.access_token.is_expired()
    }

    /// Checks if the access token will expire within a given number of seconds.
    ///
    /// # Parameters
    /// * `seconds`: The number of seconds to check against.
    ///
    /// # Returns
    /// A boolean indicating whether the access token will expire within the given number of seconds or not.    
    pub fn does_token_expire_in(&self, seconds: usize) -> bool{
        self.access_token.does_token_expire_in(seconds)
    }

    /// Checks if the access token has a specific scope.
    ///
    /// # Parameters
    /// * `scope`: The scope to check for.
    ///
    /// # Returns
    /// A boolean indicating whether the access token has the specified scope or not.    
    pub fn has_scope(&self, scope: &str) -> bool{
        self.access_token.has_scope(scope)
    }


    /// Checks if the access token has user info.
    ///
    /// # Returns
    /// A boolean indicating whether the access token has user info or not.    
    pub fn has_user_info(&self) -> bool {
        if self.is_token_expired(){
            return false
        }

        match &self.user_info {
            Value::Object(map) => !map.is_empty(),
            _ => false,
        }
    }

    /// Gets the user info for a specific key.
    ///
    /// # Parameters
    /// * `info_requested`: The key to retrieve the user info for.
    ///
    /// # Returns
    /// The user info for the specified key or an empty string if no user info is available.    
    pub fn get_user_info(&self, info_requested: &str) -> String{
        if self.is_token_expired(){
            return "".to_owned()
        }

        let tmp_value = self.user_info.get(info_requested);
        if tmp_value.is_none(){
            "".to_owned()
        }else{
            tmp_value.unwrap_or_default().to_string()
        }
    }

    /// Refreshes the user info.
    ///
    /// # Parameters
    /// * `userinfo_url`: The URL to retrieve the user info from.
    ///
    /// # Returns
    /// A boolean indicating whether the user info was refreshed successfully or an error occurred.    
    pub fn refresh_userinfo(&mut self, userinfo_url: &str) -> Result<bool, Box<dyn Error>> {
        let rt = Runtime::new()?; 

        let response: Result<Value, Box<dyn Error>>  = rt.block_on(async {
            let client = reqwest::Client::new();

            let r = client.get(userinfo_url)
            .header(AUTHORIZATION, format!("Bearer {}", self.peek_access_toke()?))
            .header(CONTENT_TYPE, "application/json")
            .send()
            .await?;

            if r.status().is_success(){
                let v = r.json().await?;
                return Ok(v)
            }else{
                let status = r.status();
                let text = r.text().await?;
                return Err(get_error!("get_userinfo","Request failed with status {}: {}", status, text).into())
            }
        });

        if response.is_ok(){
            self.user_info = response.unwrap();
            return Ok(self.user_info.is_object());
        }else{
            return Err(get_error!("refresh_userinfo","Cannot unwrap User Info Payload. Error: {}", response.unwrap_err()).into());
        }
    }    
    
}

/// Represents an Auth0 access token.
struct Auth0AccessToken{
    token: String,
    exp_timestamp: usize,
    scopes: HashSet<String>
}

impl fmt::Debug for Auth0AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Auth0AccessToken")
            .field("token",&"***Access Token***".to_string())
            .field("expiration_timestamp", &self.exp_timestamp)
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl Auth0AccessToken {
    /// Creates a new `Auth0AccessToken` instance.
    ///
    /// # Parameters
    /// * `access_token`: The access token itself.
    /// * `expiration_timestamp`: The timestamp when the access token expires.
    /// * `scope_list`: An optional list of scopes associated with the access token.    
    fn new(access_token: String, expiration_timestamp: usize, scope_list: Option<HashSet<String>>) -> Self{
        let sl = if scope_list.is_none() {HashSet::new()}else{scope_list.unwrap()};
        Self { token: access_token, exp_timestamp: expiration_timestamp, scopes: sl }
    }

    /// Stores the access token data in a Secret Vault.
    ///
    /// # Parameters
    /// * `sv`: The Secret Vault used to store the token data.
    ///
    /// # Returns
    /// A result indicating whether the access token data was stored successfully or an error occurred.     
    fn store_accesstoken_data(&self, sv: &SecretVault) -> Result<(), Box<dyn Error>>{
        let at_label = format!("{}{}",AUTH0_SERVICE_NAME,"accesstoken");        
        let exp_ts_label = format!("{}{}",AUTH0_SERVICE_NAME,"expirationtimestamp");         
        let scopes_label = format!("{}{}",AUTH0_SERVICE_NAME,"scopes");

        sv.store_secret(&at_label, &self.token)?;
        sv.store_secret(&exp_ts_label, &self.exp_timestamp.to_string())?;
        sv.store_attribute_set(&scopes_label, &self.scopes)?;

        Ok(())
    }

    /// Retrieves the access token data from a Secret Vault to return a new Auth0AccessToken    
    ///
    /// # Parameters
    /// * `sv`: The Secret Vault used to store the token data.
    ///
    /// # Returns
    /// A new `Auth0AccessToken` instance or an error if the encryption key could not be retrieved from the KEYS YAML file or the token data cannot be retrieved from the Secret Vault.      
    fn retrieve_accesstoken_data(sv: &SecretVault) -> Result<Self, Box<dyn Error>>{
        let at_label = format!("{}{}",AUTH0_SERVICE_NAME,"accesstoken");        
        let exp_ts_label = format!("{}{}",AUTH0_SERVICE_NAME,"expirationtimestamp");         
        let scopes_label = format!("{}{}",AUTH0_SERVICE_NAME,"scopes");

        Ok( Self{
                token: sv.retrieve_secret(&at_label)?,
                exp_timestamp: sv.retrieve_secret(&exp_ts_label)?.parse()?,
                scopes: sv.retrieve_attribute_set(&scopes_label)?,
            }
        )
    }

    /// Removes the token access token data from a Secret Vault.
    ///
    /// # Parameters
    /// * `sv`: The Secret Vault used to store the token data.
    ///
    /// # Returns
    /// A result indicating whether the access token data was removed successfully or an error occurred.     
    fn remove_access_token_data(&self, sv: &SecretVault) -> Result<(), Box<dyn Error>>{
        let at_label = format!("{}{}",AUTH0_SERVICE_NAME,"accesstoken");        
        let exp_ts_label = format!("{}{}",AUTH0_SERVICE_NAME,"expirationtimestamp");         
        let scopes_label = format!("{}{}",AUTH0_SERVICE_NAME,"scopes");   
        sv.delete_secret(&at_label)?;
        let _ = sv.delete_secret(&scopes_label);
        sv.delete_secret(&exp_ts_label)?;        
        Ok(())     
    }

    /// Peeks at the access token.
    ///
    /// # Returns
    /// The access token itself or an error if the access token cannot be peeked at.      
    fn peek_token(&self) -> &str{
        &self.token
    }

    /// Checks if the access token is expired.
    ///
    /// # Returns
    /// A boolean indicating whether the access token is expired or not.    
    fn is_expired(&self) -> bool{
        let now = Utc::now().timestamp() as usize;
        self.exp_timestamp < now
    }

    /// Checks if the access token will expire within a given number of seconds.
    ///
    /// # Parameters
    /// * `seconds`: The number of seconds to check against.

    /// # Returns
    /// A boolean indicating whether the access token will expire within the given number of seconds or not.    
    fn does_token_expire_in(&self, seconds: usize) -> bool{
        let now = Utc::now().timestamp() as usize; 
        self.exp_timestamp < (now  + seconds)
    }

    /// Checks if the access token has a specific scope.
    ///
    /// # Parameters
    /// * `scope`: The scope to check for.
    ///
    /// # Returns
    /// A boolean indicating whether the access token has the specified scope or not.    
    fn has_scope(&self, scope: &str) -> bool{
        if !self.scopes.is_empty(){
            self.scopes.contains(scope)
        }else{
            return false
        }
    }
}


#[cfg(test)]
mod auth0_token_tests {
    use std::sync::Once;

    use super::*;
    use bt_logger::{LogLevel, LogTarget, build_logger};

    static INIT: Once = Once::new();
    fn ini_log() {
        INIT.call_once(|| {
            build_logger("BACHUETECH", "UNIT TEST RUST auth0_config_tests", LogLevel::VERBOSE, LogTarget::STD_ERROR );     
        });
    }

    const VAULT_PREFIX: &str = "bt_test_token_prefix";
    #[test]
    fn test_auth0_token_new_success() {
        ini_log();
        let env_profile = "dev";
        let access_token = "test_access_token".to_string();
        let expiration_timestamp = (Utc::now().timestamp() as usize) + 3600;
        let scope_list = Some(HashSet::new());
        let yml_keys = r#"
dev:
  auth0token: "test_encryption_key"
"#;

        let result = Auth0Token::new(env_profile, access_token, expiration_timestamp, scope_list, yml_keys);
        assert!(result.is_ok());
    }

    #[test]
    fn test_auth0_token_new_missing_key() {
        ini_log();
        let env_profile = "dev";
        let access_token = "test_access_token".to_string();
        let expiration_timestamp = (Utc::now().timestamp() as usize) + 3600;
        let scope_list = Some(HashSet::new());
        let yml_keys = r#"
prod:
  auth0token: "test_encryption_key"
"#;

        let result = Auth0Token::new(env_profile, access_token, expiration_timestamp, scope_list, yml_keys);
        assert!(result.is_err());
    }

    #[test]
    fn test_auth0_token_store_token_data() {
        ini_log();
        let mock_vault = SecretVault::new(VAULT_PREFIX);
        let access_token = "test_access_token".to_string();
        let expiration_timestamp = (Utc::now().timestamp() as usize) + 3600;
        let scope_list = Some(HashSet::new());
        let yml_keys = r#"
dev:
  auth0token: "test_encryption_key"
"#;

        let token = Auth0Token::new("dev", access_token, expiration_timestamp, scope_list, yml_keys).unwrap();
        let result = token.store_token_data(&mock_vault);
        assert!(result.is_ok());
    }

    #[test]
    fn test_auth0_token_retrieve_accesstoken_data() {
        ini_log();
        let mock_vault = SecretVault::new(VAULT_PREFIX);
        let result = Auth0AccessToken::retrieve_accesstoken_data(&mock_vault);
        assert!(result.is_ok());
    }

    #[test]
    fn test_auth0_token_remove_access_token_data() {
        ini_log();
        let mock_vault = SecretVault::new(VAULT_PREFIX);
        let access_token = "test_access_token".to_string();
        let expiration_timestamp = (Utc::now().timestamp() as usize) + 3600;
        let scope_list = Some(HashSet::new());
        let yml_keys = r#"
dev:
  auth0token: "test_encryption_key"
"#;

        let token = Auth0Token::new("dev", access_token, expiration_timestamp, scope_list, yml_keys).unwrap();
        let result = token.remove_token_data(&mock_vault);
        assert!(result.is_ok());
    }

    #[test]
    fn test_auth0_token_peek_token() {
        ini_log();
        let access_token = "test_access_token".to_string();
        let expiration_timestamp = (Utc::now().timestamp() as usize) + 3600;
        let scope_list = Some(HashSet::new());
        let yml_keys = r#"
dev:
  auth0token: "test_encryption_key"
"#;

        let token = Auth0Token::new("dev", access_token.clone(), expiration_timestamp, scope_list, yml_keys).unwrap();
        let access_token_data = token.peek_access_toke().unwrap();
        assert_eq!(access_token_data, access_token);
    }

    #[test]
    fn test_auth0_token_is_expired() {
        ini_log();
        let access_token = "test_access_token".to_string();
        let expiration_timestamp = (Utc::now().timestamp() as usize) - 3600; // Expired
        let scope_list = Some(HashSet::new());
        let yml_keys = r#"
dev:
  auth0token: "test_encryption_key"
"#;

        let token = Auth0Token::new("dev", access_token, expiration_timestamp, scope_list, yml_keys).unwrap();
        assert!(token.is_token_expired());
    }

    #[test]
    fn test_auth0_token_does_token_expire_in() {
        ini_log();
        let access_token = "test_access_token".to_string();
        let expiration_timestamp = (Utc::now().timestamp() as usize) + 100; // Expires in 100 seconds
        let scope_list = Some(HashSet::new());
        let yml_keys = r#"
dev:
  auth0token: "test_encryption_key"
"#;

        let token = Auth0Token::new("dev", access_token, expiration_timestamp, scope_list, yml_keys).unwrap();
        assert!(token.does_token_expire_in(150)); // Should expire in 150 seconds
    }

    #[test]
    fn test_auth0_token_has_scope() {
        ini_log();
        let mut scopes = HashSet::new();
        scopes.insert("read".to_string());
        let access_token = "test_access_token".to_string();
        let expiration_timestamp = (Utc::now().timestamp() as usize) + 3600;
        let scope_list = Some(scopes);
        let yml_keys = r#"
dev:
  auth0token: "test_encryption_key"
"#;

        let token = Auth0Token::new("dev", access_token, expiration_timestamp, scope_list, yml_keys).unwrap();
        assert!(token.has_scope("read"));
        assert!(!token.has_scope("write"));
    }

    #[test]
    fn test_auth0_token_new_with_scopes() {
        ini_log();
        let mut scopes = HashSet::new();
        scopes.insert("read".to_string());
        scopes.insert("write".to_string());
        let access_token = "test_access_token".to_string();
        let expiration_timestamp = (Utc::now().timestamp() as usize) + 3600;
        let scope_list = Some(scopes);
        let yml_keys = r#"
dev:
  auth0token: "test_encryption_key"
"#;

        let token = Auth0Token::new("dev", access_token, expiration_timestamp, scope_list, yml_keys).unwrap();
        assert!(token.has_scope("read"));
        assert!(token.has_scope("write"));
    }

    #[test]
    fn test_auth0_token_has_scope_empty_scopes() {
        ini_log();
        let access_token = "test_access_token".to_string();
        let expiration_timestamp = (Utc::now().timestamp() as usize) + 3600;
        let scope_list = Some(HashSet::new());
        let yml_keys = r#"
dev:
  auth0token: "test_encryption_key"
"#;

        let token = Auth0Token::new("dev", access_token, expiration_timestamp, scope_list, yml_keys).unwrap();
        assert!(!token.has_scope("read"));
    }

    #[test]
    fn test_auth0_token_new_no_scopes() {
        ini_log();
        let access_token = "test_access_token".to_string();
        let expiration_timestamp = (Utc::now().timestamp() as usize) + 3600;
        let scope_list = None;
        let yml_keys = r#"
dev:
  auth0token: "test_encryption_key"
"#;

        let token = Auth0Token::new("dev", access_token, expiration_timestamp, scope_list, yml_keys).unwrap();
        assert!(!token.has_scope("read"));
    }

    #[test]
    fn test_auth0_token_debug_format() {
        ini_log();
        let access_token = "test_access_token".to_string();
        let expiration_timestamp = (Utc::now().timestamp() as usize) + 3600;
        let scope_list = Some(HashSet::new());
        let yml_keys = r#"
dev:
  auth0token: "test_encryption_key"
"#;

        let token = Auth0Token::new("dev", access_token, expiration_timestamp, scope_list, yml_keys).unwrap();
        let debug_str = format!("{:?}", token);
        assert!(debug_str.contains("***Access Token***"));
    }

    #[test]
    fn test_auth0_access_token_debug_format() {
        ini_log();
        let access_token = "test_access_token".to_string();
        let expiration_timestamp = (Utc::now().timestamp() as usize) + 3600;
        let scope_list = Some(HashSet::new());
        let yml_keys = r#"
dev:
  auth0token: "test_encryption_key"
"#;

        let token = Auth0Token::new("dev", access_token, expiration_timestamp, scope_list, yml_keys).unwrap();
        let debug_str = format!("{:?}", token);
        assert!(debug_str.contains("Auth0AccessToken"));
    }

    #[test]
    fn test_auth0_token_new_with_invalid_timestamp() {
        ini_log();
        let access_token = "test_access_token".to_string();
        let expiration_timestamp = 0; // Invalid timestamp
        let scope_list = Some(HashSet::new());
        let yml_keys = r#"
dev:
  auth0token: "test_encryption_key"
"#;

        let token = Auth0Token::new("dev", access_token, expiration_timestamp, scope_list, yml_keys).unwrap();
        assert!(token.is_token_expired());
    }

    #[test]
    fn test_auth0_token_new_with_future_timestamp() {
        ini_log();
        let access_token = "test_access_token".to_string();
        let expiration_timestamp = (Utc::now().timestamp() as usize) + 3600; // Future timestamp
        let scope_list = Some(HashSet::new());
        let yml_keys = r#"
dev:
  auth0token: "test_encryption_key"
"#;

        let token = Auth0Token::new("dev", access_token, expiration_timestamp, scope_list, yml_keys).unwrap();
        assert!(!token.is_token_expired());
    }

     #[test]
    fn test_auth0_token_new_with_multiple_scopes() {
        ini_log();
        let mut scopes = HashSet::new();
        scopes.insert("read".to_string());
        scopes.insert("write".to_string());
        scopes.insert("delete".to_string());
        let access_token = "test_access_token".to_string();
        let expiration_timestamp = (Utc::now().timestamp() as usize) + 3600;
        let scope_list = Some(scopes);
        let yml_keys = r#"
dev:
  auth0token: "test_encryption_key"
"#;

        let token = Auth0Token::new("dev", access_token, expiration_timestamp, scope_list, yml_keys).unwrap();
        assert!(token.has_scope("read"));
        assert!(token.has_scope("write"));
        assert!(token.has_scope("delete"));
    }
}