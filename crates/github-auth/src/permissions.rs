use crate::Result;
pub struct Permissions {}

impl Permissions {
    pub fn from_permission_list(_permissions: &[String]) -> Result<Self> {
        // TODO!
        Ok(Permissions {})
    }
}
