use alloc::string::ToString;

pub mod client_state;
pub mod error;

use crate::core::ics02_client::client_type::ClientType;

pub(crate) const LOCALHOST_CLIENT_TYPE: &str = "09-localhost";

pub fn client_type() -> ClientType {
    ClientType::new(LOCALHOST_CLIENT_TYPE.to_string())
}
