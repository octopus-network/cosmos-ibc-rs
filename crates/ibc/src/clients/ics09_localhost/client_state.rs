use crate::prelude::*;

use crate::alloc::string::ToString;
use crate::clients::ics09_localhost::error::Error;
use crate::core::ics02_client::client_state::{ClientState as Ics2ClientState, UpdatedState};
use crate::core::ics02_client::client_type::ClientType;
use crate::core::ics02_client::consensus_state::ConsensusState;
use crate::core::ics02_client::error::ClientError;
use crate::core::ics23_commitment::commitment::{
    CommitmentPrefix, CommitmentProofBytes, CommitmentRoot,
};
use crate::core::ics24_host::identifier::{ChainId, ClientId};
use crate::core::ics24_host::Path;
use core::time::Duration;
use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::core::commitment::v1::MerkleProof as RawMerkleProof;
use ibc_proto::{
    ibc::lightclients::localhost::v1::ClientState as RawLHClientState, protobuf::Protobuf,
};

// use crate::core::ics23_commitment::merkle::{apply_prefix, MerkleProof};
use crate::core::ValidationContext;
use crate::Height;
use prost::Message;

use crate::core::context::ContextError;

use super::client_type as lh_client_type;

pub const LOCALHOST_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.localhost.v1.ClientState";

/// ClientState defines a loopback (localhost) client. It requires (read-only)
/// access to keys outside the client prefix.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientState {
    /// self chain ID
    pub chain_id: ChainId,
    /// self latest block height
    pub latest_height: Height,
}

impl ClientState {
    pub fn new(chain_id: ChainId, latest_height: Height) -> Self {
        Self {
            chain_id,
            latest_height,
        }
    }
}

impl Ics2ClientState for ClientState {
    /// Return the chain identifier which this client is serving (i.e., the client is verifying
    /// consensus states from this chain).
    fn chain_id(&self) -> ChainId {
        self.chain_id.clone()
    }

    /// Type of client associated with this state (eg. Tendermint)
    fn client_type(&self) -> ClientType {
        lh_client_type()
    }

    /// Latest height the client was updated to
    fn latest_height(&self) -> Height {
        self.latest_height
    }

    /// Check if the given proof has a valid height for the client
    fn validate_proof_height(&self, _proof_height: Height) -> Result<(), ClientError> {
        todo!()
    }

    /// Assert that the client is not frozen
    fn confirm_not_frozen(&self) -> Result<(), ClientError> {
        todo!()
    }

    /// Check if the state is expired when `elapsed` time has passed since the latest consensus
    /// state timestamp
    fn expired(&self, _elapsed: Duration) -> bool {
        todo!()
    }

    /// Helper function to verify the upgrade client procedure.
    /// Resets all fields except the blockchain-specific ones,
    /// and updates the given fields.
    fn zero_custom_fields(&mut self) {}

    fn initialise(&self, _consensus_state: Any) -> Result<Box<dyn ConsensusState>, ClientError> {
        todo!()
    }

    fn check_header_and_update_state(
        &self,
        _ctx: &dyn ValidationContext,
        _client_id: ClientId,
        _header: Any,
    ) -> Result<UpdatedState, ClientError> {
        // height := clienttypes.GetSelfHeight(ctx)
        // cs.LatestHeight = height

        // clientStore.Set(host.ClientStateKey(), clienttypes.MustMarshalClientState(cdc, &cs))

        // return []exported.Height{height}
        todo!()
    }

    fn check_misbehaviour_and_update_state(
        &self,
        _ctx: &dyn ValidationContext,
        _client_id: ClientId,
        _misbehaviour: Any,
    ) -> Result<Box<dyn Ics2ClientState>, ContextError> {
        // return false ,
        // error local host can check misbehaviour
        todo!()
    }

    /// Verify the upgraded client and consensus states and validate proofs
    /// against the given root.
    ///
    /// NOTE: proof heights are not included as upgrade to a new revision is
    /// expected to pass only on the last height committed by the current
    /// revision. Clients are responsible for ensuring that the planned last
    /// height of the current revision is somehow encoded in the proof
    /// verification process. This is to ensure that no premature upgrades
    /// occur, since upgrade plans committed to by the counterparty may be
    /// cancelled or modified before the last planned height.
    fn verify_upgrade_client(
        &self,
        _upgraded_client_state: Any,
        _upgraded_consensus_state: Any,
        _proof_upgrade_client: RawMerkleProof,
        _proof_upgrade_consensus_state: RawMerkleProof,
        _root: &CommitmentRoot,
    ) -> Result<(), ClientError> {
        // return errorsmod.Wrap(clienttypes.ErrInvalidUpgradeClient, "cannot upgrade localhost client")
        todo!()
    }

    // Update the client state and consensus state in the store with the upgraded ones.
    fn update_state_with_upgrade_client(
        &self,
        _upgraded_client_state: Any,
        _upgraded_consensus_state: Any,
    ) -> Result<UpdatedState, ClientError> {
        // return errorsmod.Wrap(clienttypes.ErrUpdateClientFailed, "cannot update localhost client with a proposal")
        todo!()
    }

    // Verify_membership is a generic proof verification method which verifies a
    // proof of the existence of a value at a given Path.
    fn verify_membership(
        &self,
        _prefix: &CommitmentPrefix,
        _proof: &CommitmentProofBytes,
        _root: &CommitmentRoot,
        _path: Path,
        _value: Vec<u8>,
    ) -> Result<(), ClientError> {
        // ensure the proof provided is the expected sentinel localhost client proof
        // if !bytes.Equal(proof, SentinelProof) {
        // 	return errorsmod.Wrapf(commitmenttypes.ErrInvalidProof, "expected %s, got %s", string(SentinelProof), string(proof))
        // }

        // merklePath, ok := path.(commitmenttypes.MerklePath)
        // if !ok {
        // 	return errorsmod.Wrapf(ibcerrors.ErrInvalidType, "expected %T, got %T", commitmenttypes.MerklePath{}, path)
        // }

        // if len(merklePath.GetKeyPath()) != 2 {
        // 	return errorsmod.Wrapf(host.ErrInvalidPath, "path must be of length 2: %s", merklePath.GetKeyPath())
        // }

        // // The commitment prefix (eg: "ibc") is omitted when operating on the core IBC store
        // bz := store.Get([]byte(merklePath.KeyPath[1]))
        // if bz == nil {
        // 	return errorsmod.Wrapf(clienttypes.ErrFailedMembershipVerification, "value not found for path %s", path)
        // }

        // if !bytes.Equal(bz, value) {
        // 	return errorsmod.Wrapf(clienttypes.ErrFailedMembershipVerification, "value provided does not equal value stored at path: %s", path)
        // }

        // return nil
        todo!()
    }

    // Verify_non_membership is a generic proof verification method which
    // verifies the absence of a given commitment.
    fn verify_non_membership(
        &self,
        _prefix: &CommitmentPrefix,
        _proof: &CommitmentProofBytes,
        _root: &CommitmentRoot,
        _path: Path,
    ) -> Result<(), ClientError> {
        // ensure the proof provided is the expected sentinel localhost client proof
        // if !bytes.Equal(proof, SentinelProof) {
        // 	return errorsmod.Wrapf(commitmenttypes.ErrInvalidProof, "expected %s, got %s", string(SentinelProof), string(proof))
        // }

        // merklePath, ok := path.(commitmenttypes.MerklePath)
        // if !ok {
        // 	return errorsmod.Wrapf(ibcerrors.ErrInvalidType, "expected %T, got %T", commitmenttypes.MerklePath{}, path)
        // }

        // if len(merklePath.GetKeyPath()) != 2 {
        // 	return errorsmod.Wrapf(host.ErrInvalidPath, "path must be of length 2: %s", merklePath.GetKeyPath())
        // }

        // // The commitment prefix (eg: "ibc") is omitted when operating on the core IBC store
        // if store.Has([]byte(merklePath.KeyPath[1])) {
        // 	return errorsmod.Wrapf(clienttypes.ErrFailedNonMembershipVerification, "value found for path %s", path)
        // }

        // return nil
        todo!()
    }
}

fn downcast_local_host_client_state(cs: &dyn Ics2ClientState) -> Result<&ClientState, ClientError> {
    cs.as_any()
        .downcast_ref::<ClientState>()
        .ok_or_else(|| ClientError::ClientArgsTypeMismatch {
            client_type: lh_client_type(),
        })
}

impl Protobuf<RawLHClientState> for ClientState {}

impl TryFrom<RawLHClientState> for ClientState {
    type Error = Error;
    fn try_from(raw: RawLHClientState) -> Result<Self, Self::Error> {
        let chain_id = ChainId::from_string(raw.chain_id.as_str());

        let latest_height = raw
            .height
            .ok_or(Error::MissingLatestHeight)?
            .try_into()
            .map_err(|_| Error::MissingLatestHeight)?;

        Ok(Self {
            chain_id,
            latest_height,
        })
    }
}

impl From<ClientState> for RawLHClientState {
    fn from(value: ClientState) -> Self {
        Self {
            chain_id: value.chain_id.to_string(),
            height: Some(value.latest_height.into()),
        }
    }
}

impl Protobuf<Any> for ClientState {}

impl TryFrom<Any> for ClientState {
    type Error = ClientError;

    fn try_from(raw: Any) -> Result<Self, Self::Error> {
        use bytes::Buf;
        use core::ops::Deref;

        fn decode_client_state<B: Buf>(buf: B) -> Result<ClientState, Error> {
            RawLHClientState::decode(buf)
                .map_err(Error::Decode)?
                .try_into()
        }

        match raw.type_url.as_str() {
            LOCALHOST_CLIENT_STATE_TYPE_URL => {
                decode_client_state(raw.value.deref()).map_err(Into::into)
            }
            _ => Err(ClientError::UnknownClientStateType {
                client_state_type: raw.type_url,
            }),
        }
    }
}

impl From<ClientState> for Any {
    fn from(client_state: ClientState) -> Self {
        Any {
            type_url: LOCALHOST_CLIENT_STATE_TYPE_URL.to_string(),
            value: Protobuf::<RawLHClientState>::encode_vec(&client_state)
                .expect("encoding to `Any` from `RawLocalHostClientState`"),
        }
    }
}

#[cfg(test)]
mod tests {}
