use arc_swap::ArcSwap;
use derive_more::{Deref, DerefMut};
use log::debug;
use parking_lot::Mutex;
use serde_json::Value;
use stack_string::StackString;
use std::{collections::HashMap, sync::Arc};
use uuid::Uuid;

use auth_server_lib::session::Session;

use crate::errors::ServiceError as Error;

type SessionData = HashMap<StackString, Value>;

#[derive(Deref, DerefMut, Debug, Default, Clone)]
pub struct SessionDataMap(HashMap<Uuid, (StackString, Arc<Mutex<SessionData>>)>);

impl SessionDataMap {
    #[must_use]
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn add_session(&mut self, session: &Session) {
        self.insert(
            session.get_id(),
            (
                session.get_secret_key().into(),
                Arc::new(Mutex::new(HashMap::new())),
            ),
        );
    }

    pub fn remove_session(&mut self, session_id: Uuid) {
        self.remove(&session_id);
    }
}

#[derive(Deref, DerefMut, Debug, Default, Clone)]
pub struct SessionDataCache(Arc<ArcSwap<SessionDataMap>>);

impl SessionDataCache {
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(ArcSwap::new(Arc::new(SessionDataMap::new()))))
    }

    #[must_use]
    pub fn has_session(&self, session_id: Uuid) -> bool {
        self.load().contains_key(&session_id)
    }

    #[must_use]
    pub fn add_session(&self, session: &Session) -> Arc<SessionDataMap> {
        let mut session_data_cache =
            Arc::try_unwrap(self.load_full()).unwrap_or_else(|a| (*a).clone());
        session_data_cache.add_session(session);
        self.swap(Arc::new(session_data_cache))
    }

    #[must_use]
    pub fn remove_session(&self, session_id: Uuid) -> Arc<SessionDataMap> {
        let mut session_data_cache =
            Arc::try_unwrap(self.load_full()).unwrap_or_else(|a| (*a).clone());
        session_data_cache.remove(&session_id);
        self.swap(Arc::new(session_data_cache))
    }

    /// # Errors
    /// Returns `Error::BadRequest` if `secret_key` doesn't match secret from
    /// session data
    pub fn get_data(
        &self,
        session_id: Uuid,
        secret_key: impl AsRef<str>,
        session_key: impl AsRef<str>,
    ) -> Result<Option<Value>, Error> {
        if let Some((secret, session_map)) = self.load_full().get(&session_id) {
            if secret != secret_key.as_ref() {
                return Err(Error::BadSecret);
            }
            debug!("got cache");
            if let Some(value) = session_map.lock().get(session_key.as_ref()) {
                return Ok(Some(value.clone()));
            }
        }
        Ok(None)
    }

    /// # Errors
    /// Returns `Error::BadRequest` if `secret_key` doesn't match session secret
    /// key
    pub fn set_data(
        &self,
        session_id: Uuid,
        secret_key: impl Into<StackString>,
        session_key: impl Into<StackString>,
        session_value: &Value,
    ) -> Result<Arc<SessionDataMap>, Error> {
        let secret_key = secret_key.into();
        let session_key = session_key.into();
        let mut session_data_cache =
            Arc::try_unwrap(self.load_full()).unwrap_or_else(|a| (*a).clone());
        if let Some((secret, session_map)) = session_data_cache.get_mut(&session_id) {
            if secret != &secret_key {
                return Err(Error::BadSecret);
            }
            *session_map.lock().entry(session_key).or_default() = session_value.clone();
        } else {
            let mut session_map = HashMap::new();
            session_map.insert(session_key, session_value.clone());
            session_data_cache.insert(session_id, (secret_key, Arc::new(Mutex::new(session_map))));
        }
        Ok(self.swap(Arc::new(session_data_cache)))
    }

    /// # Errors
    /// Return `Error:BadRequest` if `secret_key` doesn't match session secret
    /// key
    pub fn remove_data(
        &self,
        session_id: Uuid,
        secret_key: impl AsRef<str>,
        session_key: impl AsRef<str>,
    ) -> Result<Option<Value>, Error> {
        let mut result = None;
        let mut session_data_cache =
            Arc::try_unwrap(self.load_full().clone()).unwrap_or_else(|a| (*a).clone());
        if let Some((secret, session_map)) = session_data_cache.get_mut(&session_id) {
            if secret != secret_key.as_ref() {
                return Err(Error::BadSecret);
            }
            result = session_map.lock().remove(session_key.as_ref());
        }
        self.store(Arc::new(session_data_cache));
        Ok(result)
    }
}
