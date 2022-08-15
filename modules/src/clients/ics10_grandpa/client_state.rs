use crate::alloc::string::ToString;
use alloc::vec::Vec;
use core::convert::{TryFrom, TryInto};
use core::str::FromStr;
use core::time::Duration;

// mock grandpa as tendermint
use ibc_proto::ibc::lightclients::grandpa::v1::ClientState as RawClientState;

use super::help::BlockHeader;
use super::help::Commitment;
use super::help::ValidatorSet;

use crate::clients::ics10_grandpa::error::Error;
use crate::clients::ics10_grandpa::header::Header;
use crate::core::ics02_client::client_state::AnyClientState;
use crate::core::ics02_client::client_type::ClientType;
use crate::core::ics24_host::identifier::ChainId;
use crate::Height;
use serde::{Deserialize, Serialize};
use tendermint_proto::Protobuf;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ClientState {
    pub chain_id: ChainId,
    /// block_number is height?
    pub latest_height: u32,
    /// Block height when the client was frozen due to a misbehaviour
    pub frozen_height: Option<Height>,
    pub latest_commitment: Commitment,
    pub validator_set: ValidatorSet,
}

impl ClientState {
    pub fn new(
        chain_id: ChainId,
        latest_height: u32,
        latest_commitment: Commitment,
        validator_set: ValidatorSet,
    ) -> Result<Self, Error> {
        let client_state = ClientState {
            chain_id,
            latest_height,
            latest_commitment,
            validator_set,
            frozen_height: None,
        };

        Ok(client_state)
    }

    pub fn with_header(self, h: Header) -> Self {
        // TODO: Clarify which fields should update.
        ClientState {
            latest_height: h.height().revision_number() as u32,
            ..self
        }
    }

    /// Get the refresh time to ensure the state does not expire
    pub fn refresh_time(&self) -> Option<Duration> {
        //TODO
        Some(Duration::new(3, 0))
    }

    /// Check if the state is expired when `elapsed` time has passed since the latest consensus
    /// state timestamp
    pub fn expired(&self, elapsed: Duration) -> bool {
        //TODO
        false
    }

    pub fn latest_height(&self) -> Height {
        Height::new(8888, self.latest_height as u64).unwrap()
    }
}

impl Protobuf<RawClientState> for ClientState {}

impl crate::core::ics02_client::client_state::ClientState for ClientState {
    type UpgradeOptions = ();

    fn chain_id(&self) -> ChainId {
        self.chain_id.clone()
    }

    fn client_type(&self) -> ClientType {
        ClientType::Grandpa
    }

    fn latest_height(&self) -> Height {
        Height::new(8888, self.latest_height as u64).unwrap()
    }

    fn frozen_height(&self) -> Option<Height> {
        self.frozen_height
    }

    fn upgrade(
        self,
        upgrade_height: Height,
        upgrade_options: Self::UpgradeOptions,
        chain_id: ChainId,
    ) -> Self {
        todo!()
    }

    fn wrap_any(self) -> AnyClientState {
        AnyClientState::Grandpa(self)
    }
}

impl TryFrom<RawClientState> for ClientState {
    type Error = Error;

    fn try_from(raw: RawClientState) -> Result<Self, Self::Error> {
        let frozen_height = raw
            .frozen_height
            .and_then(|raw_height| raw_height.try_into().ok());

        Ok(Self {
            chain_id: ChainId::from_str(raw.chain_id.as_str())
                .map_err(|_| Error::invalid_chain_id())?,
            latest_height: raw.latest_height,
            frozen_height,
            latest_commitment: raw
                .latest_commitment
                .ok_or_else(Error::empty_latest_commitment)?
                .into(),
            validator_set: raw
                .validator_set
                .ok_or_else(Error::empty_validator_set)?
                .into(),
        })
    }
}

use ibc_proto::ibc::core::client::v1::Height as RawHeight;

impl From<ClientState> for RawClientState {
    fn from(value: ClientState) -> Self {
        Self {
            chain_id: value.chain_id.to_string(),
            latest_height: value.latest_height,
            frozen_height: Some(value.frozen_height.map(|height| height.into()).unwrap_or(
                RawHeight {
                    revision_number: 0,
                    revision_height: 0,
                },
            )),
            latest_commitment: Some(value.latest_commitment.into()),
            validator_set: Some(value.validator_set.into()),
        }
    }
}
