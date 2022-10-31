use crate::core::ics02_client::client_type::ClientType;

pub mod client_state;
pub mod consensus_state;
pub mod error;
pub mod header;
pub mod help;
pub mod misbehaviour;
mod state_machine;

pub(crate) const GRANDPA_CLIENT_TYPE: &str = "10-grandpa";

pub fn client_type() -> ClientType {
    ClientType::new(GRANDPA_CLIENT_TYPE)
}
