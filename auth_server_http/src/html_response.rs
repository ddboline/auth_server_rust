use http::{
    header::{CONTENT_TYPE, SET_COOKIE},
    status::StatusCode,
};
use indexmap::IndexMap;
use rweb::{
    hyper::{Body, Response},
    openapi::{self, Entity, MediaType, ObjectOrReference, ResponseEntity, Responses},
    Reply,
};
use stack_string::StackString;
use std::borrow::Cow;

use crate::errors::ServiceError as Error;

pub struct HtmlResponse<T>
where
    T: Send,
    Body: From<T>,
{
    data: T,
    cookie: Option<String>,
    status: StatusCode,
    content_type: Option<String>,
}

impl<T> HtmlResponse<T>
where
    T: Send,
    Body: From<T>,
{
    pub fn new(data: T) -> Self {
        Self {
            data,
            cookie: None,
            status: StatusCode::OK,
            content_type: None,
        }
    }
    pub fn with_cookie(mut self, cookie: &str) -> Self {
        self.cookie = Some(cookie.into());
        self
    }
    pub fn with_status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }
    pub fn with_content_type(mut self, content_type: &str) -> Self {
        self.content_type = Some(content_type.into());
        self
    }
}

impl<T> Reply for HtmlResponse<T>
where
    T: Send,
    Body: From<T>,
{
    fn into_response(self) -> Response<Body> {
        let reply = rweb::reply::html(self.data);
        let reply = rweb::reply::with_status(reply, self.status);
        let content_type = self
            .content_type
            .unwrap_or("text/html; charset=utf-8".into());
        let reply = rweb::reply::with_header(reply, CONTENT_TYPE, content_type);
        #[allow(clippy::option_if_let_else)]
        if let Some(header) = self.cookie {
            let reply = rweb::reply::with_header(reply, SET_COOKIE, header);
            reply.into_response()
        } else {
            reply.into_response()
        }
    }
}

impl<T> Entity for HtmlResponse<T>
where
    T: Send,
    Body: From<T>,
{
    fn describe() -> openapi::Schema {
        Result::<StackString, Error>::describe()
    }
}

impl<T> ResponseEntity for HtmlResponse<T>
where
    T: Send,
    Body: From<T>,
{
    fn describe_responses() -> Responses {
        let mut content = IndexMap::new();
        content.insert(
            Cow::Borrowed("text/html"),
            MediaType {
                schema: Some(ObjectOrReference::Object(Self::describe())),
                examples: None,
                encoding: Default::default(),
            },
        );

        let mut map = IndexMap::new();
        map.insert(
            Cow::Borrowed("200"),
            openapi::Response {
                content,
                ..Default::default()
            },
        );
        map
    }
}
