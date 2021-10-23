use arc_swap::ArcSwap;
use derive_more::{Deref, DerefMut};
use im::HashMap;
use log::debug;
use serde_json::Value;
use stack_string::StackString;
use std::sync::Arc;
use uuid::Uuid;

use auth_server_lib::session::Session;

use crate::errors::ServiceError as Error;

#[derive(Deref, DerefMut, Debug, Default, Clone)]
pub struct SessionDataMap(HashMap<Uuid, (StackString, HashMap<StackString, Value>)>);

impl SessionDataMap {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn from_map(cache: HashMap<Uuid, (StackString, HashMap<StackString, Value>)>) -> Self {
        Self(cache)
    }

    pub fn add_session(&mut self, session: &Session) {
        self.insert(session.id, (session.secret_key.clone(), HashMap::new()));
    }

    pub fn remove_session(&mut self, session_id: Uuid) {
        self.remove(&session_id);
    }
}

#[derive(Deref, DerefMut, Debug, Default, Clone)]
pub struct SessionDataCache(Arc<ArcSwap<SessionDataMap>>);

impl SessionDataCache {
    pub fn new() -> Self {
        Self(Arc::new(ArcSwap::new(Arc::new(SessionDataMap::new()))))
    }

    pub fn add_session(&self, session: &Session) {
        let mut session_data_cache = (*self.load().clone()).clone();
        session_data_cache.add_session(session);
        self.store(Arc::new(session_data_cache));
    }

    pub fn remove_session(&self, session_id: Uuid) {
        let mut session_data_cache = (*self.load().clone()).clone();
        session_data_cache.remove(&session_id);
        self.store(Arc::new(session_data_cache));
    }

    pub fn get_data(
        &self,
        session_id: Uuid,
        secret_key: &str,
        session_key: &str,
    ) -> Result<Option<Value>, Error> {
        if let Some((secret, session_map)) = self.load().get(&session_id) {
            if secret != secret_key {
                return Err(Error::BadRequest("Bad Secret".into()));
            }
            debug!("got cache");
            if let Some(value) = session_map.get(session_key) {
                return Ok(Some(value.clone()));
            }
        }
        Ok(None)
    }

    pub fn set_data(
        &self,
        session_id: Uuid,
        secret_key: &str,
        session_key: &str,
        session_value: &Value,
    ) -> Result<(), Error> {
        let mut session_data_cache = (*self.load().clone()).clone();
        if let Some((secret, session_map)) = session_data_cache.get_mut(&session_id) {
            if secret != secret_key {
                return Err(Error::BadRequest("Bad Secret".into()));
            }
            *session_map.entry(session_key.into()).or_default() = session_value.clone();
        } else {
            let mut session_map = HashMap::new();
            session_map.insert(session_key.into(), session_value.clone());
            session_data_cache.insert(session_id, (secret_key.into(), session_map));
        }
        self.store(Arc::new(session_data_cache));
        Ok(())
    }

    pub fn remove_data(
        &self,
        session_id: Uuid,
        secret_key: &str,
        session_key: &str,
    ) -> Result<(), Error> {
        let mut session_data_cache = (*self.load().clone()).clone();
        if let Some((secret, session_map)) = session_data_cache.get_mut(&session_id) {
            if secret != secret_key {
                return Err(Error::BadRequest("Bad Secret".into()));
            }
            session_map.remove(session_key);
        }
        self.store(Arc::new(session_data_cache));
        Ok(())
    }
}
