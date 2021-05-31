use http::{header::SET_COOKIE, status::StatusCode};
use rweb::{
    hyper::{Body, Response},
    openapi::{self, Entity, ResponseEntity, Responses},
    Json, Reply,
};
use serde::Serialize;

use crate::errors::ServiceError as Error;

pub struct JsonResponse<T>
where
    T: Serialize + Entity + Send,
{
    data: T,
    cookie: Option<String>,
    status: StatusCode,
}

impl<T> JsonResponse<T>
where
    T: Serialize + Entity + Send,
{
    pub fn new(data: T) -> Self {
        Self {
            data,
            cookie: None,
            status: StatusCode::OK,
        }
    }
    pub fn with_cookie(mut self, cookie: String) -> Self {
        self.cookie = Some(cookie);
        self
    }
    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }
}

impl<T> Reply for JsonResponse<T>
where
    T: Serialize + Entity + Send,
{
    fn into_response(self) -> Response<Body> {
        let reply = rweb::reply::json(&self.data);
        let reply = rweb::reply::with_status(reply, self.status);
        #[allow(clippy::option_if_let_else)]
        if let Some(header) = self.cookie {
            let reply = rweb::reply::with_header(reply, SET_COOKIE, header);
            reply.into_response()
        } else {
            reply.into_response()
        }
    }
}

impl<T> Entity for JsonResponse<T>
where
    T: Serialize + Entity + Send,
{
    fn describe() -> openapi::Schema {
        Result::<T, Error>::describe()
    }
}

impl<T> ResponseEntity for JsonResponse<T>
where
    T: Serialize + Entity + Send,
{
    fn describe_responses() -> Responses {
        Result::<Json<T>, Error>::describe_responses()
    }
}
