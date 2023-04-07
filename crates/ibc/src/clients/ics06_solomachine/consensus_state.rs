use crate::prelude::*;

use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::lightclients::solomachine::v2::ConsensusState as RawConsensusState;
use ibc_proto::protobuf::Protobuf;

use crate::clients::ics06_solomachine::error::Error;
use crate::core::ics02_client::error::ClientError;
use crate::core::ics23_commitment::commitment::CommitmentRoot;
use crate::timestamp::Timestamp;
use cosmos_sdk_proto::{
    self,
    traits::{Message, MessageExt},
};

pub const SOLOMACHINE_CONSENSUS_STATE_TYPE_URL: &str =
    "/ibc.lightclients.solomachine.v2.ConsensusState";

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PublicKey(pub tendermint::PublicKey);

impl PublicKey {
    /// Protobuf [`Any`] type URL for Ed25519 public keys
    pub const ED25519_TYPE_URL: &'static str = "/cosmos.crypto.ed25519.PubKey";

    /// Protobuf [`Any`] type URL for secp256k1 public keys
    pub const SECP256K1_TYPE_URL: &'static str = "/cosmos.crypto.secp256k1.PubKey";

    /// Get the type URL for this [`PublicKey`].
    pub fn type_url(&self) -> &'static str {
        match &self.0 {
            tendermint::PublicKey::Ed25519(_) => Self::ED25519_TYPE_URL,
            tendermint::PublicKey::Secp256k1(_) => Self::SECP256K1_TYPE_URL,
            // `tendermint::PublicKey` is `non_exhaustive`
            _ => unreachable!("unknown pubic key type"),
        }
    }

    /// Convert this [`PublicKey`] to a Protobuf [`Any`] type.
    pub fn to_any(&self) -> Result<Any, Error> {
        let value = match self.0 {
            tendermint::PublicKey::Ed25519(_) => {
                cosmos_sdk_proto::cosmos::crypto::secp256k1::PubKey {
                    key: self.to_bytes(),
                }
                .to_bytes()
                .map_err(|_| Error::Unknown)?
            }
            tendermint::PublicKey::Secp256k1(_) => {
                cosmos_sdk_proto::cosmos::crypto::secp256k1::PubKey {
                    key: self.to_bytes(),
                }
                .to_bytes()
                .map_err(|_| Error::Unknown)?
            }
            _ => return Err(Error::Unknown.into()),
        };

        Ok(Any {
            type_url: self.type_url().to_owned(),
            value,
        })
    }

    /// Serialize this [`PublicKey`] as a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}

impl TryFrom<Any> for PublicKey {
    type Error = Error;

    fn try_from(any: Any) -> Result<PublicKey, Self::Error> {
        PublicKey::try_from(&any)
    }
}

impl TryFrom<&Any> for PublicKey {
    type Error = Error;

    fn try_from(any: &Any) -> Result<PublicKey, Self::Error> {
        match any.type_url.as_str() {
            Self::ED25519_TYPE_URL => {
                cosmos_sdk_proto::cosmos::crypto::ed25519::PubKey::decode(&*any.value)
                    .map_err(|_| Error::Unknown)?
                    .try_into()
            }
            Self::SECP256K1_TYPE_URL => {
                cosmos_sdk_proto::cosmos::crypto::secp256k1::PubKey::decode(&*any.value)
                    .map_err(|_| Error::Unknown)?
                    .try_into()
            }
            _other => Err(Error::Unknown.into()),
        }
    }
}

impl TryFrom<cosmos_sdk_proto::cosmos::crypto::ed25519::PubKey> for PublicKey {
    type Error = Error;

    fn try_from(
        public_key: cosmos_sdk_proto::cosmos::crypto::ed25519::PubKey,
    ) -> Result<PublicKey, Self::Error> {
        tendermint::public_key::PublicKey::from_raw_ed25519(&public_key.key)
            .map(Into::into)
            .ok_or_else(|| Error::Unknown.into())
    }
}

impl TryFrom<cosmos_sdk_proto::cosmos::crypto::secp256k1::PubKey> for PublicKey {
    type Error = Error;

    fn try_from(
        public_key: cosmos_sdk_proto::cosmos::crypto::secp256k1::PubKey,
    ) -> Result<PublicKey, Self::Error> {
        tendermint::public_key::PublicKey::from_raw_secp256k1(&public_key.key)
            .map(Into::into)
            .ok_or_else(|| Error::Unknown.into())
    }
}

impl From<PublicKey> for Any {
    fn from(public_key: PublicKey) -> Any {
        // This is largely a workaround for `tendermint::PublicKey` being
        // marked `non_exhaustive`.
        public_key.to_any().expect("unsupported algorithm")
    }
}

impl From<tendermint::PublicKey> for PublicKey {
    fn from(pk: tendermint::PublicKey) -> PublicKey {
        PublicKey(pk)
    }
}

impl From<PublicKey> for tendermint::PublicKey {
    fn from(pk: PublicKey) -> tendermint::PublicKey {
        pk.0
    }
}

#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusState {
    pub public_key: PublicKey,
    pub diversifier: String,
    pub timestamp: u64,
    pub root: CommitmentRoot,
}

impl ConsensusState {
    pub fn new(timestamp: u64) -> Self {
        let pk = PublicKey(
            tendermint::PublicKey::from_raw_secp256k1(&hex_literal::hex!(
                "02c88aca653727db28e0ade87497c1f03b551143dedfd4db8de71689ad5e38421c"
            ))
            .unwrap(),
        );
        Self {
            public_key: pk,
            diversifier: "oct".to_string(),
            timestamp,
            root: CommitmentRoot::from_bytes(&pk.to_bytes()),
        }
    }
}

impl crate::core::ics02_client::consensus_state::ConsensusState for ConsensusState {
    fn root(&self) -> &CommitmentRoot {
        &self.root
    }

    fn timestamp(&self) -> Timestamp {
        Timestamp::from_nanoseconds(self.timestamp).unwrap()
    }
}

impl Protobuf<RawConsensusState> for ConsensusState {}

impl TryFrom<RawConsensusState> for ConsensusState {
    type Error = Error;

    fn try_from(raw: RawConsensusState) -> Result<Self, Self::Error> {
        let pk = raw.public_key.unwrap().try_into().unwrap();
        Ok(Self {
            public_key: pk,
            diversifier: raw.diversifier,
            timestamp: raw.timestamp,
            root: CommitmentRoot::from_bytes(&pk.to_bytes()),
        })
    }
}

impl From<ConsensusState> for RawConsensusState {
    fn from(value: ConsensusState) -> Self {
        RawConsensusState {
            public_key: Some(value.public_key.into()),
            diversifier: value.diversifier,
            timestamp: value.timestamp,
        }
    }
}

impl Protobuf<Any> for ConsensusState {}

impl TryFrom<Any> for ConsensusState {
    type Error = ClientError;

    fn try_from(raw: Any) -> Result<Self, Self::Error> {
        use bytes::Buf;
        use core::ops::Deref;

        fn decode_consensus_state<B: Buf>(buf: B) -> Result<ConsensusState, Error> {
            RawConsensusState::decode(buf)
                .map_err(Error::Decode)?
                .try_into()
        }

        match raw.type_url.as_str() {
            SOLOMACHINE_CONSENSUS_STATE_TYPE_URL => {
                decode_consensus_state(raw.value.deref()).map_err(Into::into)
            }
            _ => Err(Error::Unknown.into()),
        }
    }
}

impl From<ConsensusState> for Any {
    fn from(consensus_state: ConsensusState) -> Self {
        Any {
            type_url: SOLOMACHINE_CONSENSUS_STATE_TYPE_URL.to_string(),
            value: Protobuf::<RawConsensusState>::encode_vec(&consensus_state)
                .expect("encoding to `Any` from `SmConsensusState`"),
        }
    }
}
