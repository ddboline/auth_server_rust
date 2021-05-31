pub trait ResponseDescriptionTrait: Send + Sync {
    fn description() -> &'static str;
}

pub struct DefaultDescription {}

impl ResponseDescriptionTrait for DefaultDescription {
    fn description() -> &'static str {
        ""
    }
}
