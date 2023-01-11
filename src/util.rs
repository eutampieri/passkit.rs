use serde::{Deserialize, Serialize};

pub fn is_false(value: &bool) -> bool {
    !(*value)
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Empty {}
