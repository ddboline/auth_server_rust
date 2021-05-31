use http::header::SET_COOKIE;
use rweb::{
    hyper::{Body, Response},
    openapi::{self, Entity, ResponseEntity, Responses},
    Json, Reply,
};
use serde::Serialize;
use std::borrow::Cow;
use std::marker::PhantomData;

use crate::errors::ServiceError as Error;
use crate::response_description_trait::{DefaultDescription, ResponseDescriptionTrait};
use crate::status_code_trait::{StatusCodeOk, StatusCodeTrait};

pub struct JsonResponse<T, S = StatusCodeOk, D = DefaultDescription>
where
    T: Serialize + Entity + Send,
    S: StatusCodeTrait,
    D: ResponseDescriptionTrait,
{
    data: T,
    cookie: Option<String>,
    phantom_s: PhantomData<S>,
    phantom_d: PhantomData<D>,
}

impl<T, S, D> JsonResponse<T, S, D>
where
    T: Serialize + Entity + Send,
    S: StatusCodeTrait,
    D: ResponseDescriptionTrait,
{
    pub fn new(data: T) -> Self {
        Self {
            data,
            cookie: None,
            phantom_s: PhantomData,
            phantom_d: PhantomData,
        }
    }
    pub fn with_cookie(mut self, cookie: String) -> Self {
        self.cookie = Some(cookie);
        self
    }
}

impl<T, S, D> Reply for JsonResponse<T, S, D>
where
    T: Serialize + Entity + Send,
    S: StatusCodeTrait,
    D: ResponseDescriptionTrait,
{
    fn into_response(self) -> Response<Body> {
        let reply = rweb::reply::json(&self.data);
        let reply = rweb::reply::with_status(reply, S::status_code());
        #[allow(clippy::option_if_let_else)]
        if let Some(header) = self.cookie {
            let reply = rweb::reply::with_header(reply, SET_COOKIE, header);
            reply.into_response()
        } else {
            reply.into_response()
        }
    }
}

impl<T, S, D> Entity for JsonResponse<T, S, D>
where
    T: Serialize + Entity + Send,
    S: StatusCodeTrait,
    D: ResponseDescriptionTrait,
{
    fn describe() -> openapi::Schema {
        Result::<T, Error>::describe()
    }
}

impl<T, S, D> ResponseEntity for JsonResponse<T, S, D>
where
    T: Serialize + Entity + Send,
    S: StatusCodeTrait,
    D: ResponseDescriptionTrait,
{
    fn describe_responses() -> Responses {
        let mut responses = Result::<Json<T>, Error>::describe_responses();
        let old_code: Cow<'static, str> = "200".into();
        let new_code: Cow<'static, str> = S::status_code().as_u16().to_string().into();
        if let Some(mut old) = responses.remove(&old_code) {
            old.description = D::description().into();
            responses.insert(new_code, old);
        }
        responses
    }
}
