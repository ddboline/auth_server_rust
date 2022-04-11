#![allow(clippy::too_many_lines)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]

pub mod auth_user_config;
pub mod config;
pub mod date_time_wrapper;
pub mod invitation;
pub mod pgpool;
pub mod session;
pub mod session_data;
pub mod toml_entry;
pub mod user;

pub use postgres_query::extract::Error as QueryError;
use stack_string::{StackString, MAX_INLINE};
pub use tokio_postgres::Error as PostgresError;

use lazy_static::lazy_static;
use rand::{
    distributions::{Alphanumeric, DistString, Distribution},
    thread_rng,
};
use smallvec::SmallVec;
use tokio::sync::Mutex;

lazy_static! {
    pub static ref AUTH_APP_MUTEX: Mutex<()> = Mutex::new(());
}

#[must_use]
pub fn get_random_string(n: usize) -> StackString {
    let mut rng = thread_rng();
    if n > MAX_INLINE {
        Alphanumeric.sample_string(&mut rng, n).into()
    } else {
        let buf: SmallVec<[u8; MAX_INLINE]> =
            (0..n).map(|_| Alphanumeric.sample(&mut rng)).collect();
        StackString::from_utf8_lossy(&buf[0..n])
    }
}
