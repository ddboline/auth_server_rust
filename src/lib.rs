#![allow(clippy::must_use_candidate)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::unseparated_literal_suffix)]

pub mod app;
pub mod auth;
pub mod claim;
pub mod config;
pub mod errors;
pub mod google_openid;
pub mod invitation;
pub mod logged_user;
pub mod pgpool;
pub mod routes;
pub mod ses_client;
pub mod static_files;
pub mod stdout_channel;
pub mod token;
pub mod user;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
