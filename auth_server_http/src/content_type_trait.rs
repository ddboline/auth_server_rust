pub trait ContentTypeTrait: Send + Sync {
    fn content_type() -> &'static str;
    fn content_type_header() -> &'static str;
}
pub struct ContentTypeHtml {}

impl ContentTypeTrait for ContentTypeHtml {
    fn content_type() -> &'static str {
        "text/html"
    }
    fn content_type_header() -> &'static str {
        "text/html; charset=utf-8"
    }
}

pub struct ContentTypeCss {}

impl ContentTypeTrait for ContentTypeCss {
    fn content_type() -> &'static str {
        "text/css"
    }
    fn content_type_header() -> &'static str {
        "text/css; charset=utf-8"
    }
}

pub struct ContentTypeJs {}

impl ContentTypeTrait for ContentTypeJs {
    fn content_type() -> &'static str {
        "text/javascript"
    }
    fn content_type_header() -> &'static str {
        "text/javascript; charset=utf-8"
    }
}
