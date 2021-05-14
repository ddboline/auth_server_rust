#![allow(clippy::must_use_candidate)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::unseparated_literal_suffix)]

pub mod auth_user_config;
pub mod config;
pub mod pgpool;
pub mod static_files;
pub mod user;
pub mod session;

use lazy_static::lazy_static;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use tokio::sync::Mutex;

lazy_static! {
    pub static ref AUTH_APP_MUTEX: Mutex<()> = Mutex::new(());
}

pub fn get_random_string(n: usize) -> String {
    let mut rng = thread_rng();
    (0..n)
        .map(|_| char::from(rng.sample(Alphanumeric)))
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
