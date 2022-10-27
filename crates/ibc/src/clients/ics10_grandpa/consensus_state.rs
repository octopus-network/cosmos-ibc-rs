use crate::prelude::*;

use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::lightclients::grandpa::v1::ConsensusState as RawConsensusState;
use ibc_proto::protobuf::Protobuf;
use serde::{Deserialize, Serialize};
//use tendermint::{hash::Algorithm, Hash};
use tendermint::Time;
use tendermint_proto::google::protobuf as tpb;

use super::help::Commitment;
use crate::clients::ics10_grandpa::error::Error;
use crate::clients::ics10_grandpa::header::Header;
use crate::core::ics02_client::client_type::ClientType;
use crate::core::ics02_client::error::Error as Ics02Error;
use crate::core::ics23_commitment::commitment::CommitmentRoot;
use crate::timestamp::Timestamp;

pub const GRANDPA_CONSENSUS_STATE_TYPE_URL: &str = "/ibc.lightclients.grandpa.v1.ConsensusState";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusState {
    /// commitment used to verify mmr proof
    pub commitment: Commitment,
    /// timestamp
    pub timestamp: Time,
    /// the state trie merkle root that used to verify storage proof
    pub state_root: CommitmentRoot,
}

impl ConsensusState {
    pub fn new(commitment: Commitment, state_root: CommitmentRoot, timestamp: Time) -> Self {
        Self {
            commitment,
            timestamp,
            state_root,
        }
    }
}

impl Default for ConsensusState {
    fn default() -> Self {
        Self {
            commitment: Commitment::default(),
            state_root: CommitmentRoot::from(vec![0]),
            timestamp: Time::from_unix_timestamp(0, 0).unwrap(),
        }
    }
}

impl crate::core::ics02_client::consensus_state::ConsensusState for ConsensusState {
    fn client_type(&self) -> ClientType {
        ClientType::Grandpa
    }

    fn root(&self) -> &CommitmentRoot {
        &self.state_root
    }

    fn timestamp(&self) -> Timestamp {
        self.timestamp.into()
    }
}

impl Protobuf<RawConsensusState> for ConsensusState {}

impl TryFrom<RawConsensusState> for ConsensusState {
    type Error = Error;

    fn try_from(raw: RawConsensusState) -> Result<Self, Self::Error> {
        let ibc_proto::google::protobuf::Timestamp { seconds, nanos } = raw
            .timestamp
            .ok_or_else(|| Error::invalid_raw_consensus_state("missing timestamp".into()))?;
        // FIXME: shunts like this are necessary due to
        // https://github.com/informalsystems/tendermint-rs/issues/1053
        let proto_timestamp = tpb::Timestamp { seconds, nanos };
        let timestamp = proto_timestamp
            .try_into()
            .map_err(|e| Error::invalid_raw_consensus_state(format!("invalid timestamp: {}", e)))?;

        Ok(Self {
            commitment: raw
                .commitment
                .ok_or_else(Error::empty_latest_commitment)?
                .into(),
            state_root: raw
                .state_root
                .ok_or_else(|| {
                    Error::invalid_raw_consensus_state("missing commitment root".into())
                })?
                .hash
                .into(),
            timestamp,
        })
    }
}

impl From<ConsensusState> for RawConsensusState {
    fn from(value: ConsensusState) -> Self {
        // FIXME: shunts like this are necessary due to
        // https://github.com/informalsystems/tendermint-rs/issues/1053
        let tpb::Timestamp { seconds, nanos } = value.timestamp.into();
        let timestamp = ibc_proto::google::protobuf::Timestamp { seconds, nanos };

        RawConsensusState {
            commitment: Some(value.commitment.into()),
            timestamp: Some(timestamp),
            state_root: Some(ibc_proto::ibc::core::commitment::v1::MerkleRoot {
                hash: value.state_root.into_vec(),
            }),
        }
    }
}

impl Protobuf<Any> for ConsensusState {}

impl TryFrom<Any> for ConsensusState {
    type Error = Ics02Error;

    fn try_from(raw: Any) -> Result<Self, Self::Error> {
        use bytes::Buf;
        use core::ops::Deref;
        use prost::Message;

        fn decode_consensus_state<B: Buf>(buf: B) -> Result<ConsensusState, Error> {
            RawConsensusState::decode(buf)
                .map_err(Error::decode)?
                .try_into()
        }

        match raw.type_url.as_str() {
            GRANDPA_CONSENSUS_STATE_TYPE_URL => {
                decode_consensus_state(raw.value.deref()).map_err(Into::into)
            }
            _ => Err(Ics02Error::unknown_consensus_state_type(raw.type_url)),
        }
    }
}

impl From<ConsensusState> for Any {
    fn from(consensus_state: ConsensusState) -> Self {
        Any {
            type_url: GRANDPA_CONSENSUS_STATE_TYPE_URL.to_string(),
            value: Protobuf::<RawConsensusState>::encode_vec(&consensus_state)
                .expect("encoding to `Any` from `TmConsensusState`"),
        }
    }
}

impl From<Header> for ConsensusState {
    fn from(header: Header) -> Self {
        Self {
            commitment: header.mmr_root.signed_commitment.commitment.unwrap(),
            state_root: CommitmentRoot::from_bytes(&header.block_header.state_root),
            timestamp: header.timestamp,
        }
    }
}
