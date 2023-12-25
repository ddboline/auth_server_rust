use argon2::{
    password_hash::{Error as ArgonError, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};
use futures::Stream;
use once_cell::sync::Lazy;
use postgres_query::{client::GenericClient, query, Error as PqError, FromSqlRow};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use stack_string::StackString;
use uuid::Uuid;

use authorized_users::AuthorizedUser;

use crate::{
    date_time_wrapper::DateTimeWrapper,
    errors::AuthServerError as Error,
    get_random_string,
    pgpool::{PgPool, PgTransaction},
};

static ARGON: Lazy<Argon> = Lazy::new(|| Argon::new().expect("Failed to init Argon"));
static FAKE_PASSWORD: Lazy<StackString> = Lazy::new(|| {
    ARGON
        .hash_password("password")
        .expect("Failed to generate password")
});
static ALTERNATE_FAKE: Lazy<StackString> = Lazy::new(|| {
    ARGON
        .hash_password("fake password")
        .expect("Failed to generate password")
});

struct Argon(Argon2<'static>);

impl Argon {
    fn new() -> Result<Self, ArgonError> {
        Ok(Self(Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15360, 2, 1, None)?,
        )))
    }

    fn hash_password(&self, plain: impl AsRef<[u8]>) -> Result<StackString, Error> {
        let salt = SaltString::generate(thread_rng());
        self.0
            .hash_password(plain.as_ref(), &salt)
            .map(StackString::from_display)
            .map_err(Into::into)
    }

    fn verify_password(&self, hashed: &str, password: impl AsRef<[u8]>) -> Result<(), ArgonError> {
        self.0
            .verify_password(password.as_ref(), &PasswordHash::new(hashed)?)
    }
}

#[derive(FromSqlRow, Serialize, Deserialize, PartialEq, Debug, Eq)]
pub struct User {
    pub email: StackString,
    // password here is always the hashed password
    password: StackString,
    pub created_at: DateTimeWrapper,
}

impl User {
    /// # Errors
    /// Returns error if hashing fails
    pub fn from_details(
        email: impl Into<StackString>,
        password: impl AsRef<str>,
    ) -> Result<Self, Error> {
        ARGON.hash_password(password.as_ref()).map(|password| Self {
            email: email.into(),
            password,
            created_at: DateTimeWrapper::now(),
        })
    }

    /// # Errors
    /// Returns error if hashing fails
    pub fn set_password(&mut self, password: impl AsRef<str>) -> Result<(), Error> {
        self.password = ARGON.hash_password(password.as_ref())?;
        Ok(())
    }

    /// # Errors
    /// Returns error if parsing password hash fails
    pub fn verify_password(&self, password: impl AsRef<[u8]>) -> Result<bool, Error> {
        ARGON
            .verify_password(&self.password, password)
            .map(|()| true)
            .or_else(|e| match e {
                ArgonError::Password => Ok(false),
                e => Err(e.into()),
            })
    }

    /// # Errors
    /// Returns error if parsing hash fails
    pub fn fake_verify(password: impl AsRef<str>) -> Result<bool, Error> {
        let password = if password.as_ref() == FAKE_PASSWORD.as_str() {
            ALTERNATE_FAKE.as_str()
        } else {
            password.as_ref()
        };
        ARGON
            .verify_password(&FAKE_PASSWORD, password)
            .map(|()| unreachable!())
            .or_else(|e| match e {
                ArgonError::Password => Ok(false),
                e => Err(e.into()),
            })
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn get_authorized_users(
        pool: &PgPool,
    ) -> Result<impl Stream<Item = Result<Self, PqError>>, Error> {
        let query = query!("SELECT * FROM users");
        let conn = pool.get().await?;
        query.fetch_streaming(&conn).await.map_err(Into::into)
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn get_number_users(pool: &PgPool) -> Result<i64, Error> {
        let query = query!("SELECT count(*) FROM users");
        let conn = pool.get().await?;
        let (count,) = query.fetch_one(&conn).await?;
        Ok(count)
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn get_by_email(
        email: impl AsRef<str>,
        pool: &PgPool,
    ) -> Result<Option<Self>, Error> {
        let mut conn = pool.get().await?;
        let tran = conn.transaction().await?;
        let conn: &PgTransaction = &tran;
        let result = Self::get_by_email_conn(email, conn).await?;
        tran.commit().await?;
        Ok(result)
    }

    async fn get_by_email_conn<C>(email: impl AsRef<str>, conn: &C) -> Result<Option<Self>, Error>
    where
        C: GenericClient + Sync,
    {
        let email = email.as_ref();
        let query = query!("SELECT * FROM users WHERE email = $email", email = email);
        query.fetch_opt(&conn).await.map_err(Into::into)
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn insert(&self, pool: &PgPool) -> Result<(), Error> {
        let mut conn = pool.get().await?;
        let tran = conn.transaction().await?;
        let conn: &PgTransaction = &tran;
        self.insert_conn(conn).await?;
        tran.commit().await?;
        Ok(())
    }

    async fn insert_conn<C>(&self, conn: &C) -> Result<(), Error>
    where
        C: GenericClient + Sync,
    {
        let query = query!(
            "
            INSERT INTO users (email, password, created_at)
            VALUES ($email, $password, $created_at)",
            email = self.email,
            password = self.password,
            created_at = self.created_at
        );
        query.execute(&conn).await?;
        Ok(())
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn update(&self, pool: &PgPool) -> Result<(), Error> {
        let mut conn = pool.get().await?;
        let tran = conn.transaction().await?;
        let conn: &PgTransaction = &tran;
        self.update_conn(conn).await?;
        tran.commit().await?;
        Ok(())
    }

    async fn update_conn<C>(&self, conn: &C) -> Result<(), Error>
    where
        C: GenericClient + Sync,
    {
        let query = query!(
            "UPDATE users set password = $password WHERE email = $email",
            password = self.password,
            email = self.email,
        );
        query.execute(&conn).await?;
        Ok(())
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn upsert(&self, pool: &PgPool) -> Result<(), Error> {
        let mut conn = pool.get().await?;
        let tran = conn.transaction().await?;
        let conn: &PgTransaction = &tran;
        if Self::get_by_email_conn(&self.email, conn).await?.is_some() {
            self.update_conn(conn).await?;
        } else {
            self.insert_conn(conn).await?;
        }
        tran.commit().await?;
        Ok(())
    }

    /// # Errors
    /// Returns error if db query fails
    pub async fn delete(&self, pool: &PgPool) -> Result<(), Error> {
        let mut conn = pool.get().await?;
        let tran = conn.transaction().await?;
        let conn: &PgTransaction = &tran;
        self.delete_conn(conn).await?;
        tran.commit().await?;
        Ok(())
    }

    async fn delete_conn<C>(&self, conn: &C) -> Result<(), Error>
    where
        C: GenericClient + Sync,
    {
        let query = query!("DELETE FROM users WHERE email = $email", email = self.email);
        query.execute(&conn).await?;
        Ok(())
    }
}

impl From<User> for AuthorizedUser {
    fn from(user: User) -> Self {
        Self {
            email: user.email,
            session: Uuid::new_v4(),
            secret_key: get_random_string(16),
        }
    }
}

#[cfg(test)]
mod tests {
    use futures::TryStreamExt;
    use log::debug;
    use stack_string::format_sstr;

    use crate::{
        config::Config,
        date_time_wrapper::DateTimeWrapper,
        errors::AuthServerError as Error,
        get_random_string,
        pgpool::PgPool,
        user::{Argon, User},
        AUTH_APP_MUTEX,
    };

    #[tokio::test]
    async fn test_create_delete_user() -> Result<(), Error> {
        let _lock = AUTH_APP_MUTEX.lock().await;
        let config = Config::init_config()?;
        let pool = PgPool::new(&config.database_url);

        let email = format_sstr!("{}@localhost", get_random_string(32));

        assert_eq!(User::get_by_email(&email, &pool).await?, None);

        let password = get_random_string(32);
        let user = User::from_details(&email, &password)?;
        println!("{}", user.password);

        user.insert(&pool).await?;
        let mut db_user = User::get_by_email(&email, &pool).await?.unwrap();
        debug!("{:?}", db_user);
        assert!(db_user.verify_password(&password)?);

        let password = get_random_string(32);
        db_user.set_password(&password)?;
        db_user.upsert(&pool).await?;

        let db_user = User::get_by_email(&email, &pool).await?.unwrap();
        debug!("{:?}", db_user);
        assert!(db_user.verify_password(&password)?);

        db_user.delete(&pool).await?;
        assert_eq!(User::get_by_email(&email, &pool).await?, None);
        Ok(())
    }

    #[test]
    fn test_verify_argon2() -> Result<(), Error> {
        let user = User {
            email: "test@localhost".into(),
            password: "$argon2id$v=19$m=15360,t=2,\
                       p=1$kCY9hyy6ZE3c71Np$kLz4pb6M5IbBz7jLgwG+xxFudnPPvSAWVC5muM/jh8E"
                .into(),
            created_at: DateTimeWrapper::now(),
        };
        assert!(user.verify_password("password").unwrap());
        Ok(())
    }

    #[tokio::test]
    async fn test_get_authorized_users_get_number_users() -> Result<(), Error> {
        let _lock = AUTH_APP_MUTEX.lock().await;
        let config = Config::init_config()?;
        let pool = PgPool::new(&config.database_url);
        let count = User::get_number_users(&pool).await? as usize;
        let users: Vec<_> = User::get_authorized_users(&pool)
            .await?
            .try_collect()
            .await?;
        debug!("{:?}", users);
        assert_eq!(count, users.len());
        Ok(())
    }

    #[test]
    fn test_argon2() -> Result<(), Error> {
        let argon = Argon::new().unwrap();
        let password = "password";
        let hash = argon.hash_password(password).unwrap();
        assert_eq!(argon.verify_password(&hash, password), Ok(()));
        Ok(())
    }
}
