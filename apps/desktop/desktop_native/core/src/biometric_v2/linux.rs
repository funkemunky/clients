//! This file implements Polkit based system unlock.
//!
//! # Security
//! This section describes the assumed security model and security guarantees achieved. In the
//! required security guarantee is that a locked vault - a running app - cannot be unlocked when the
//! device (user-space) is compromised in this state.
//!
//! When first unlocking the app, the app sends the user-key to this module, which holds it in
//! secure memory, protected by memfd_secret. This makes it inaccessible to other processes, even if
//! they compromise root, a kernel compromise has circumventable best-effort protections. While the
//! app is running this key is held in memory, even if locked. When unlocking, the app will prompt
//! the user via `polkit` to get a yes/no decision on whether to release the key to the app.

use std::{collections::HashMap, sync::Arc};

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use futures::future::{BoxFuture, FutureExt};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use zbus::Connection;
use zbus_polkit::policykit1::{AuthorityProxy, CheckAuthorizationFlags, Subject};

use crate::{
    password::{self, PASSWORD_NOT_FOUND},
    secure_memory::{encrypted_memory_store::EncryptedMemoryStore, SecureMemoryStore as _},
};

const KEYCHAIN_SERVICE_NAME: &str = "BitwardenBiometricsV2";

trait LinuxBiometricBackend: Send + Sync {
    fn authenticate(&self) -> BoxFuture<'_, Result<bool>>;
    fn authenticate_available(&self) -> BoxFuture<'_, Result<bool>>;
    fn set_secret<'a>(
        &'a self,
        service: &'static str,
        account: &'a str,
        secret: String,
    ) -> BoxFuture<'a, Result<()>>;
    fn get_secret<'a>(
        &'a self,
        service: &'static str,
        account: &'a str,
    ) -> BoxFuture<'a, Result<String>>;
    fn delete_secret<'a>(
        &'a self,
        service: &'static str,
        account: &'a str,
    ) -> BoxFuture<'a, Result<()>>;
    fn has_secret<'a>(
        &'a self,
        service: &'static str,
        account: &'a str,
    ) -> BoxFuture<'a, Result<bool>>;
}

struct SystemLinuxBiometricBackend;

impl LinuxBiometricBackend for SystemLinuxBiometricBackend {
    fn authenticate(&self) -> BoxFuture<'_, Result<bool>> {
        polkit_authenticate_bitwarden_policy().boxed()
    }

    fn authenticate_available(&self) -> BoxFuture<'_, Result<bool>> {
        polkit_is_bitwarden_policy_available().boxed()
    }

    fn set_secret<'a>(
        &'a self,
        service: &'static str,
        account: &'a str,
        secret: String,
    ) -> BoxFuture<'a, Result<()>> {
        async move { password::set_password(service, account, &secret).await }.boxed()
    }

    fn get_secret<'a>(
        &'a self,
        service: &'static str,
        account: &'a str,
    ) -> BoxFuture<'a, Result<String>> {
        async move { password::get_password(service, account).await }.boxed()
    }

    fn delete_secret<'a>(
        &'a self,
        service: &'static str,
        account: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        async move { password::delete_password(service, account).await }.boxed()
    }

    fn has_secret<'a>(
        &'a self,
        service: &'static str,
        account: &'a str,
    ) -> BoxFuture<'a, Result<bool>> {
        async move {
            let keyring = oo7::Keyring::new().await?;
            let attributes = HashMap::from([("service", service), ("account", account)]);
            let items = keyring.search_items(&attributes).await?;
            Ok(!items.is_empty())
        }
        .boxed()
    }
}

/// Biometric lock system using Polkit for authentication and secure memory to hold the key on
/// Linux.
pub struct BiometricLockSystem {
    // The userkeys that are held in memory MUST be protected from memory dumping attacks, to
    // ensure locked vaults cannot be unlocked
    secure_memory: Arc<Mutex<EncryptedMemoryStore<String>>>,
    backend: Arc<dyn LinuxBiometricBackend>,
}

impl BiometricLockSystem {
    /// Creates a new biometric lock system with secure memory storage.
    pub fn new() -> Self {
        Self {
            secure_memory: Arc::new(Mutex::new(EncryptedMemoryStore::default())),
            backend: Arc::new(SystemLinuxBiometricBackend),
        }
    }

    #[cfg(test)]
    fn new_with_backend(backend: Arc<dyn LinuxBiometricBackend>) -> Self {
        Self {
            secure_memory: Arc::new(Mutex::new(EncryptedMemoryStore::default())),
            backend,
        }
    }
}

impl Default for BiometricLockSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl super::BiometricTrait for BiometricLockSystem {
    async fn authenticate(&self, _hwnd: Vec<u8>, _message: String) -> Result<bool> {
        self.backend.authenticate().await
    }

    async fn authenticate_available(&self) -> Result<bool> {
        self.backend.authenticate_available().await
    }

    async fn enroll_persistent(&self, user_id: &str, key: &[u8]) -> Result<()> {
        set_keychain_entry(self.backend.as_ref(), user_id, key).await
    }

    async fn provide_key(&self, user_id: &str, key: &[u8]) {
        self.secure_memory
            .lock()
            .await
            .put(user_id.to_string(), key);
    }

    async fn unlock(&self, user_id: &String, _hwnd: Vec<u8>) -> Result<Vec<u8>> {
        if !self.backend.authenticate().await? {
            return Err(anyhow!("Authentication failed"));
        }

        if let Some(key) = self.secure_memory.lock().await.get(user_id)? {
            return Ok(key);
        }

        let key = get_keychain_entry(self.backend.as_ref(), user_id).await?;
        self.secure_memory
            .lock()
            .await
            .put(user_id.to_string(), &key);
        Ok(key)
    }

    async fn unlock_available(&self, user_id: &String) -> Result<bool> {
        let has_key = self.secure_memory.lock().await.has(user_id)
            || has_keychain_entry(self.backend.as_ref(), user_id).await?;
        Ok(has_key && self.backend.authenticate_available().await.unwrap_or(false))
    }

    async fn has_persistent(&self, user_id: &str) -> Result<bool> {
        has_keychain_entry(self.backend.as_ref(), user_id).await
    }

    async fn unenroll(&self, user_id: &String) -> Result<(), anyhow::Error> {
        self.secure_memory.lock().await.remove(user_id);
        delete_keychain_entry(self.backend.as_ref(), user_id).await?;
        Ok(())
    }
}

async fn set_keychain_entry(
    backend: &dyn LinuxBiometricBackend,
    user_id: &str,
    key: &[u8],
) -> Result<()> {
    info!(
        "[Polkit] Saving persistent biometric unlock key to Secret Service for user {}",
        user_id
    );

    backend
        .set_secret(KEYCHAIN_SERVICE_NAME, user_id, encode_keychain_entry(key))
        .await?;

    let stored_key = get_keychain_entry(backend, user_id).await?;
    if stored_key != key {
        return Err(anyhow!(
            "Secret Service verification failed after saving persistent biometric unlock key"
        ));
    }

    info!(
        "[Polkit] Persistent biometric unlock key saved to Secret Service for user {}",
        user_id
    );
    Ok(())
}

async fn get_keychain_entry(backend: &dyn LinuxBiometricBackend, user_id: &str) -> Result<Vec<u8>> {
    decode_keychain_entry(&backend.get_secret(KEYCHAIN_SERVICE_NAME, user_id).await?)
}

fn encode_keychain_entry(key: &[u8]) -> String {
    BASE64_STANDARD.encode(key)
}

fn decode_keychain_entry(entry: &str) -> Result<Vec<u8>> {
    BASE64_STANDARD.decode(entry).map_err(|e| anyhow!(e))
}

async fn delete_keychain_entry(backend: &dyn LinuxBiometricBackend, user_id: &str) -> Result<()> {
    backend
        .delete_secret(KEYCHAIN_SERVICE_NAME, user_id)
        .await
        .or_else(|e| {
            if e.to_string() == PASSWORD_NOT_FOUND {
                debug!(
                    "[Polkit] No keychain entry found for user {}, nothing to delete",
                    user_id
                );
                Ok(())
            } else {
                Err(e)
            }
        })
}

async fn has_keychain_entry(backend: &dyn LinuxBiometricBackend, user_id: &str) -> Result<bool> {
    let result = backend.has_secret(KEYCHAIN_SERVICE_NAME, user_id).await;

    match result {
        Ok(has_secret) => Ok(has_secret),
        Err(e) => {
            warn!(
                "[Polkit] Error checking keychain entry for user {}: {}",
                user_id, e
            );
            Err(e)
        }
    }
}

/// Perform a polkit authorization against the bitwarden unlock policy. Note: This relies on no
/// custom rules in the system skipping the authorization check, in which case this counts as UV /
/// authentication.
async fn polkit_authenticate_bitwarden_policy() -> Result<bool> {
    debug!("[Polkit] Authenticating / performing UV");

    let connection = Connection::system().await?;
    let proxy = AuthorityProxy::new(&connection).await?;

    // Use system-bus-name instead of unix-process to avoid PID namespace issues in
    // sandboxed environments (e.g., Flatpak). When using unix-process with a PID from
    // inside the sandbox, polkit cannot validate it against the host PID namespace.
    //
    // By using system-bus-name, polkit queries D-Bus for the connection's credentials,
    // which includes the correct host PID and UID, avoiding namespace mismatches.
    //
    // If D-Bus unique name is not available, fall back to the traditional unix-process
    // approach for compatibility with non-sandboxed environments.
    let subject = if let Some(bus_name) = connection.unique_name() {
        use zbus::zvariant::{OwnedValue, Str};
        let mut subject_details = std::collections::HashMap::new();
        subject_details.insert(
            "name".to_string(),
            OwnedValue::from(Str::from(bus_name.as_str())),
        );
        Subject {
            subject_kind: "system-bus-name".to_string(),
            subject_details,
        }
    } else {
        // Fallback: use unix-process with PID (may not work in sandboxed environments)
        Subject::new_for_owner(std::process::id(), None, None)?
    };

    let details = std::collections::HashMap::new();
    let authorization_result = proxy
        .check_authorization(
            &subject,
            "com.bitwarden.Bitwarden.unlock",
            &details,
            CheckAuthorizationFlags::AllowUserInteraction.into(),
            "",
        )
        .await;

    match authorization_result {
        Ok(result) => Ok(result.is_authorized),
        Err(e) => {
            warn!("[Polkit] Error performing authentication: {:?}", e);
            Ok(false)
        }
    }
}

async fn polkit_is_bitwarden_policy_available() -> Result<bool> {
    let connection = Connection::system().await?;
    let proxy = AuthorityProxy::new(&connection).await?;
    let actions = proxy.enumerate_actions("en").await?;
    for action in actions {
        if action.action_id == "com.bitwarden.Bitwarden.unlock" {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex as StdMutex,
    };

    use super::*;
    use crate::biometric_v2::BiometricTrait;

    #[derive(Default)]
    struct FakeLinuxBiometricBackend {
        authenticate_result: AtomicBool,
        authenticate_available_result: AtomicBool,
        authenticate_calls: AtomicUsize,
        get_secret_calls: AtomicUsize,
        secrets: StdMutex<HashMap<(String, String), String>>,
    }

    impl FakeLinuxBiometricBackend {
        fn available() -> Arc<Self> {
            Arc::new(Self {
                authenticate_result: AtomicBool::new(true),
                authenticate_available_result: AtomicBool::new(true),
                authenticate_calls: AtomicUsize::new(0),
                get_secret_calls: AtomicUsize::new(0),
                secrets: StdMutex::new(HashMap::new()),
            })
        }

        fn set_authenticate_result(&self, result: bool) {
            self.authenticate_result.store(result, Ordering::SeqCst);
        }

        fn set_authenticate_available_result(&self, result: bool) {
            self.authenticate_available_result
                .store(result, Ordering::SeqCst);
        }

        fn authenticate_calls(&self) -> usize {
            self.authenticate_calls.load(Ordering::SeqCst)
        }

        fn get_secret_calls(&self) -> usize {
            self.get_secret_calls.load(Ordering::SeqCst)
        }

        fn secret_for(&self, service: &str, account: &str) -> Option<String> {
            self.secrets
                .lock()
                .expect("fake secret store mutex should not be poisoned")
                .get(&(service.to_string(), account.to_string()))
                .cloned()
        }
    }

    impl LinuxBiometricBackend for FakeLinuxBiometricBackend {
        fn authenticate(&self) -> BoxFuture<'_, Result<bool>> {
            async move {
                self.authenticate_calls.fetch_add(1, Ordering::SeqCst);
                Ok(self.authenticate_result.load(Ordering::SeqCst))
            }
            .boxed()
        }

        fn authenticate_available(&self) -> BoxFuture<'_, Result<bool>> {
            async move { Ok(self.authenticate_available_result.load(Ordering::SeqCst)) }.boxed()
        }

        fn set_secret<'a>(
            &'a self,
            service: &'static str,
            account: &'a str,
            secret: String,
        ) -> BoxFuture<'a, Result<()>> {
            async move {
                self.secrets
                    .lock()
                    .expect("fake secret store mutex should not be poisoned")
                    .insert((service.to_string(), account.to_string()), secret);
                Ok(())
            }
            .boxed()
        }

        fn get_secret<'a>(
            &'a self,
            service: &'static str,
            account: &'a str,
        ) -> BoxFuture<'a, Result<String>> {
            async move {
                self.get_secret_calls.fetch_add(1, Ordering::SeqCst);
                self.secrets
                    .lock()
                    .expect("fake secret store mutex should not be poisoned")
                    .get(&(service.to_string(), account.to_string()))
                    .cloned()
                    .ok_or_else(|| anyhow!(PASSWORD_NOT_FOUND))
            }
            .boxed()
        }

        fn delete_secret<'a>(
            &'a self,
            service: &'static str,
            account: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            async move {
                let removed = self
                    .secrets
                    .lock()
                    .expect("fake secret store mutex should not be poisoned")
                    .remove(&(service.to_string(), account.to_string()));
                removed
                    .map(|_| ())
                    .ok_or_else(|| anyhow!(PASSWORD_NOT_FOUND))
            }
            .boxed()
        }

        fn has_secret<'a>(
            &'a self,
            service: &'static str,
            account: &'a str,
        ) -> BoxFuture<'a, Result<bool>> {
            async move {
                Ok(self
                    .secrets
                    .lock()
                    .expect("fake secret store mutex should not be poisoned")
                    .contains_key(&(service.to_string(), account.to_string())))
            }
            .boxed()
        }
    }

    #[test]
    fn keychain_entry_round_trips_binary_key() {
        let key = [0, 1, 2, 3, 127, 128, 253, 254, 255];
        let encoded = encode_keychain_entry(&key);
        let decoded = decode_keychain_entry(&encoded).unwrap();

        assert_eq!(decoded, key);
    }

    #[test]
    fn keychain_entry_round_trips_empty_key() {
        let key = [];
        let encoded = encode_keychain_entry(&key);
        let decoded = decode_keychain_entry(&encoded).unwrap();

        assert_eq!(decoded, key);
    }

    #[test]
    fn keychain_entry_rejects_invalid_base64() {
        assert!(decode_keychain_entry("not valid base64!").is_err());
    }

    #[tokio::test]
    async fn enroll_persistent_sets_and_retrieves_secret_service_entry() {
        let backend = FakeLinuxBiometricBackend::available();
        let lock_system = BiometricLockSystem::new_with_backend(backend.clone());
        let user_id = "test_user_biometric_v2_linux";
        let key = [0, 1, 2, 3, 127, 128, 253, 254, 255];

        lock_system.enroll_persistent(user_id, &key).await.unwrap();

        assert!(lock_system.has_persistent(user_id).await.unwrap());
        assert_eq!(
            backend
                .secret_for(KEYCHAIN_SERVICE_NAME, user_id)
                .expect("secret should be saved"),
            encode_keychain_entry(&key)
        );
        assert_eq!(
            get_keychain_entry(backend.as_ref(), user_id).await.unwrap(),
            key
        );
    }

    #[tokio::test]
    async fn unlock_available_after_restart_requires_secret_service_key_and_polkit_policy() {
        let backend = FakeLinuxBiometricBackend::available();
        let user_id = String::from("test_user_biometric_v2_linux");
        let key = [1, 2, 3, 4];

        BiometricLockSystem::new_with_backend(backend.clone())
            .enroll_persistent(&user_id, &key)
            .await
            .unwrap();

        let restarted_lock_system = BiometricLockSystem::new_with_backend(backend.clone());
        assert!(restarted_lock_system
            .unlock_available(&user_id)
            .await
            .unwrap());

        backend.set_authenticate_available_result(false);
        assert!(!restarted_lock_system
            .unlock_available(&user_id)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn unlock_after_restart_reads_secret_service_key_after_polkit_authentication() {
        let backend = FakeLinuxBiometricBackend::available();
        let user_id = String::from("test_user_biometric_v2_linux");
        let key = [0, 1, 2, 3, 127, 128, 253, 254, 255];

        BiometricLockSystem::new_with_backend(backend.clone())
            .enroll_persistent(&user_id, &key)
            .await
            .unwrap();

        let restarted_lock_system = BiometricLockSystem::new_with_backend(backend.clone());
        let secret_reads_before_unlock = backend.get_secret_calls();

        let unlocked_key = restarted_lock_system
            .unlock(&user_id, Vec::new())
            .await
            .unwrap();

        assert_eq!(unlocked_key, key);
        assert_eq!(backend.authenticate_calls(), 1);
        assert_eq!(backend.get_secret_calls(), secret_reads_before_unlock + 1);

        let secret_reads_after_first_unlock = backend.get_secret_calls();
        let unlocked_key = restarted_lock_system
            .unlock(&user_id, Vec::new())
            .await
            .unwrap();

        assert_eq!(unlocked_key, key);
        assert_eq!(backend.authenticate_calls(), 2);
        assert_eq!(backend.get_secret_calls(), secret_reads_after_first_unlock);
    }

    #[tokio::test]
    async fn unlock_after_restart_fails_when_polkit_authentication_is_denied() {
        let backend = FakeLinuxBiometricBackend::available();
        let user_id = String::from("test_user_biometric_v2_linux");
        let key = [1, 2, 3, 4];

        BiometricLockSystem::new_with_backend(backend.clone())
            .enroll_persistent(&user_id, &key)
            .await
            .unwrap();

        backend.set_authenticate_result(false);
        let restarted_lock_system = BiometricLockSystem::new_with_backend(backend.clone());
        let secret_reads_before_unlock = backend.get_secret_calls();

        let result = restarted_lock_system.unlock(&user_id, Vec::new()).await;

        assert_eq!(result.unwrap_err().to_string(), "Authentication failed");
        assert_eq!(backend.authenticate_calls(), 1);
        assert_eq!(backend.get_secret_calls(), secret_reads_before_unlock);
    }

    #[tokio::test]
    #[ignore]
    async fn test_polkit_authenticate() {
        let result = polkit_authenticate_bitwarden_policy().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[ignore]
    async fn test_secret_service_persistent_enroll_has_unenroll() {
        let user_id = String::from("test_user_biometric_v2_linux");
        let key = [0, 1, 2, 3, 127, 128, 253, 254, 255];
        let lock_system = BiometricLockSystem::new();

        let _ = lock_system.unenroll(&user_id).await;

        assert!(!lock_system.has_persistent(&user_id).await.unwrap());

        lock_system.enroll_persistent(&user_id, &key).await.unwrap();

        assert!(lock_system.has_persistent(&user_id).await.unwrap());
        assert_eq!(
            get_keychain_entry(lock_system.backend.as_ref(), &user_id)
                .await
                .unwrap(),
            key
        );

        lock_system.unenroll(&user_id).await.unwrap();

        assert!(!lock_system.has_persistent(&user_id).await.unwrap());
    }
}
