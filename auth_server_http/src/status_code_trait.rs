use rweb::http::StatusCode;

pub trait StatusCodeTrait: Send + Sync {
    fn status_code() -> StatusCode;
}

pub struct StatusCodeOk {}

impl StatusCodeTrait for StatusCodeOk {
    fn status_code() -> StatusCode {
        StatusCode::OK
    }
}

pub struct StatusCodeCreated {}

impl StatusCodeTrait for StatusCodeCreated {
    fn status_code() -> StatusCode {
        StatusCode::CREATED
    }
}
