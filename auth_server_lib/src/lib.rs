#![allow(clippy::too_many_lines)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]

pub mod auth_user_config;
pub mod config;
pub mod date_time_wrapper;
pub mod errors;
pub mod invitation;
pub mod pgpool;
pub mod session;
pub mod session_data;
pub mod toml_entry;
pub mod user;

use rand::{
    distr::{Alphanumeric, Distribution, SampleString},
    rng as thread_rng,
};
use smallvec::SmallVec;
use stack_string::{MAX_INLINE, StackString};
use std::sync::LazyLock;
use tokio::sync::Mutex;

pub static AUTH_APP_MUTEX: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[must_use]
pub fn get_random_string(n: usize) -> StackString {
    let mut rng = thread_rng();
    if n > MAX_INLINE {
        Alphanumeric.sample_string(&mut rng, n).into()
    } else {
        let buf: SmallVec<[u8; MAX_INLINE]> = Alphanumeric.sample_iter(&mut rng).take(n).collect();
        StackString::from_utf8_lossy(&buf[0..n])
    }
}
