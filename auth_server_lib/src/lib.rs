#![allow(clippy::must_use_candidate)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::unseparated_literal_suffix)]

pub mod auth;
pub mod auth_user_config;
pub mod claim;
pub mod config;
pub mod pgpool;
pub mod static_files;
pub mod token;
pub mod user;

use rand::{thread_rng, Rng};

pub fn get_random_string(n: usize) -> String {
    let mut rng = thread_rng();
    (0..)
        .filter_map(|_| {
            let c: char = (rng.gen::<u8>() & 0x7f).into();
            match c {
                ' '..='~' => Some(c),
                _ => None,
            }
        })
        .take(n)
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
