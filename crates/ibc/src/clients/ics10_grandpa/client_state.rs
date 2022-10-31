use core::convert::{TryFrom, TryInto};
use core::str::FromStr;
use core::time::Duration;

use prost::Message;
use serde::{Deserialize, Serialize};

use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::core::client::v1::Height as RawHeight;
use ibc_proto::ibc::core::commitment::v1::MerkleProof;
use ibc_proto::ibc::lightclients::grandpa::v1::ClientState as RawGpClientState;
use ibc_proto::ics23::commitment_proof::Proof::Exist;

use super::help::Commitment;
use super::help::ValidatorSet;

use crate::clients::ics10_grandpa::consensus_state::ConsensusState as GpConsensusState;
use crate::clients::ics10_grandpa::error::Error;
use crate::clients::ics10_grandpa::header::Header as GpHeader;
use crate::clients::ics10_grandpa::help::BlockHeader;
use crate::core::ics02_client::client_state::{
    ClientState as Ics2ClientState, UpdatedState, UpgradeOptions as CoreUpgradeOptions,
};
use crate::core::ics02_client::client_type::ClientType;
use crate::core::ics02_client::consensus_state::ConsensusState;
use crate::core::ics02_client::context::ClientReader;
use crate::core::ics02_client::error::Error as Ics02Error;
use crate::core::ics03_connection::connection::ConnectionEnd;
use crate::core::ics04_channel::channel::ChannelEnd;
use crate::core::ics04_channel::commitment::{AcknowledgementCommitment, PacketCommitment};
use crate::core::ics04_channel::context::ChannelReader;
use crate::core::ics04_channel::packet::Sequence;
use crate::core::ics23_commitment::commitment::{
    CommitmentPrefix, CommitmentProofBytes, CommitmentRoot,
};
use crate::clients::ics10_grandpa::state_machine::read_proof_check;
use crate::core::ics24_host::identifier::{ChainId, ChannelId, ClientId, ConnectionId, PortId};
use crate::core::ics24_host::path::{
    AcksPath, ChannelEndsPath, ClientConsensusStatePath, ClientStatePath, CommitmentsPath,
    ConnectionsPath, ReceiptsPath, SeqRecvsPath,
};
use crate::core::ics24_host::Path;
use crate::prelude::*;
use crate::timestamp::Timestamp;
use crate::Height;
use beefy_light_client::mmr;
use codec::{Decode, Encode};
use frame_support::{storage::storage_prefix, Blake2_128Concat, StorageHasher};
use ibc_proto::protobuf::Protobuf;

pub const GRANDPA_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.grandpa.v1.ClientState";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientState {
    pub chain_id: ChainId,
    /// block_number is height?
    pub latest_height: u64,
    /// Block height when the client was frozen due to a misbehaviour
    pub frozen_height: Option<Height>,
    pub latest_commitment: Commitment,
    pub validator_set: ValidatorSet,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowUpdate {
    pub after_expiry: bool,
    pub after_misbehaviour: bool,
}

impl ClientState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainId,
        latest_height: u64,
        latest_commitment: Commitment,
        validator_set: ValidatorSet,
    ) -> Result<ClientState, Error> {
        // todo(davirain)
        let client_state = ClientState {
            chain_id,
            latest_height,
            latest_commitment,
            validator_set,
            frozen_height: None,
        };

        Ok(client_state)
    }

    pub fn latest_height(&self) -> Height {
        // todo(davirian)
        Height::new(0, self.latest_height).unwrap()
    }

    pub fn with_header(self, h: GpHeader) -> Result<Self, Error> {
        // // TODO: Clarify which fields should update.
        Ok(ClientState {
            latest_height: h.height().revision_number(),
            ..self
        })
    }

    pub fn with_frozen_height(self, h: Height) -> Result<Self, Error> {
        Ok(Self {
            frozen_height: Some(h),
            ..self
        })
    }

    /// Get the refresh time to ensure the state does not expire
    pub fn refresh_time(&self) -> Option<Duration> {
        //TODO(davirian) need to
        Some(Duration::new(3, 0))
    }

    /// Verify the time and height delays
    pub fn verify_delay_passed(
        current_time: Timestamp,
        current_height: Height,
        processed_time: Timestamp,
        processed_height: Height,
        delay_period_time: Duration,
        delay_period_blocks: u64,
    ) -> Result<(), Error> {
        let earliest_time =
            (processed_time + delay_period_time).map_err(Error::timestamp_overflow)?;
        if !(current_time == earliest_time || current_time.after(&earliest_time)) {
            return Err(Error::not_enough_time_elapsed(current_time, earliest_time));
        }

        let earliest_height = processed_height.add(delay_period_blocks);
        if current_height < earliest_height {
            return Err(Error::not_enough_blocks_elapsed(
                current_height,
                earliest_height,
            ));
        }

        Ok(())
    }

    /// Verify that the client is at a sufficient height and unfrozen at the given height
    pub fn verify_height(&self, height: Height) -> Result<(), Error> {
        // todo(davirian) need to handle unwrap()
        if Height::new(0, self.latest_height).unwrap() < height {
            return Err(Error::insufficient_height(self.latest_height(), height));
        }

        match self.frozen_height {
            Some(frozen_height) if frozen_height <= height => {
                Err(Error::client_frozen(frozen_height, height))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeOptions {
    pub unbonding_period: Duration,
}

impl CoreUpgradeOptions for UpgradeOptions {}

impl Ics2ClientState for ClientState {
    fn chain_id(&self) -> ChainId {
        self.chain_id.clone()
    }

    fn client_type(&self) -> ClientType {
        ClientType::Grandpa
    }

    fn latest_height(&self) -> Height {
        // todo(davirain)
        Height::new(0, self.latest_height).unwrap()
    }

    fn frozen_height(&self) -> Option<Height> {
        self.frozen_height.clone()
    }

    fn upgrade(
        &mut self,
        _upgrade_height: Height,
        _upgrade_options: &dyn CoreUpgradeOptions,
        _chain_id: ChainId,
    ) {
        // todo(davirian) need to do
    }

    fn expired(&self, _elapsed: Duration) -> bool {
        // TODO(davirian) need to be set
        false
    }

    fn initialise(&self, consensus_state: Any) -> Result<Box<dyn ConsensusState>, Ics02Error> {
        GpConsensusState::try_from(consensus_state).map(GpConsensusState::into_box)
    }

    fn check_header_and_update_state(
        &self,
        _ctx: &dyn ClientReader,
        _client_id: ClientId,
        header: Any,
    ) -> Result<UpdatedState, Ics02Error> {
        // todo(davirian)
        let client_state = downcast_gp_client_state(self)?.clone();
        let header = GpHeader::try_from(header)?;

        Ok(UpdatedState {
            client_state: client_state.with_header(header.clone())?.into_box(),
            consensus_state: GpConsensusState::from(header).into_box(),
        })
    }

    fn verify_upgrade_and_update_state(
        &self,
        _consensus_state: Any,
        _proof_upgrade_client: MerkleProof,
        _proof_upgrade_consensus_state: MerkleProof,
    ) -> Result<UpdatedState, Ics02Error> {
        // todo(davirian) tendermint have not implement
        unimplemented!()
    }

    fn verify_client_consensus_state(
        &self,
        height: Height,
        prefix: &CommitmentPrefix,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        client_id: &ClientId,
        consensus_height: Height,
        expected_consensus_state: &dyn ConsensusState,
    ) -> Result<(), Ics02Error> {
        let client_state = downcast_gp_client_state(self)?;
        client_state.verify_height(height)?;

        let path = ClientConsensusStatePath {
            client_id: client_id.clone(),
            epoch: consensus_height.revision_number(),
            height: consensus_height.revision_height(),
        };
        let value = expected_consensus_state
            .encode_vec()
            .map_err(Ics02Error::invalid_any_consensus_state)?;

        verify_membership(client_state, prefix, proof, root, path, value)
    }

    fn verify_connection_state(
        &self,
        height: Height,
        prefix: &CommitmentPrefix,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        connection_id: &ConnectionId,
        expected_connection_end: &ConnectionEnd,
    ) -> Result<(), Ics02Error> {
        let client_state = downcast_gp_client_state(self)?;
        client_state.verify_height(height)?;

        let path = ConnectionsPath(connection_id.clone());
        let value = expected_connection_end
            .encode_vec()
            .map_err(Ics02Error::invalid_connection_end)?;
        verify_membership(client_state, prefix, proof, root, path, value)
    }

    fn verify_channel_state(
        &self,
        height: Height,
        prefix: &CommitmentPrefix,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        port_id: &PortId,
        channel_id: &ChannelId,
        expected_channel_end: &ChannelEnd,
    ) -> Result<(), Ics02Error> {
        let client_state = downcast_gp_client_state(self)?;
        client_state.verify_height(height)?;

        let path = ChannelEndsPath(port_id.clone(), channel_id.clone());
        let value = expected_channel_end
            .encode_vec()
            .map_err(Ics02Error::invalid_channel_end)?;
        verify_membership(client_state, prefix, proof, root, path, value)
    }

    fn verify_client_full_state(
        &self,
        height: Height,
        prefix: &CommitmentPrefix,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        client_id: &ClientId,
        expected_client_state: Any,
    ) -> Result<(), Ics02Error> {
        let client_state = downcast_gp_client_state(self)?;
        client_state.verify_height(height)?;

        let path = ClientStatePath(client_id.clone());
        let value = expected_client_state.encode_to_vec();
        verify_membership(client_state, prefix, proof, root, path, value)
    }

    fn verify_packet_data(
        &self,
        ctx: &dyn ChannelReader,
        height: Height,
        connection_end: &ConnectionEnd,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
        commitment: PacketCommitment,
    ) -> Result<(), Ics02Error> {
        let client_state = downcast_gp_client_state(self)?;
        client_state.verify_height(height)?;
        verify_delay_passed(ctx, height, connection_end)?;

        let commitment_path = CommitmentsPath {
            port_id: port_id.clone(),
            channel_id: channel_id.clone(),
            sequence,
        };

        verify_membership(
            client_state,
            connection_end.counterparty().prefix(),
            proof,
            root,
            commitment_path,
            commitment.into_vec(),
        )
    }

    fn verify_packet_acknowledgement(
        &self,
        ctx: &dyn ChannelReader,
        height: Height,
        connection_end: &ConnectionEnd,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
        ack: AcknowledgementCommitment,
    ) -> Result<(), Ics02Error> {
        let client_state = downcast_gp_client_state(self)?;
        client_state.verify_height(height)?;
        verify_delay_passed(ctx, height, connection_end)?;

        let ack_path = AcksPath {
            port_id: port_id.clone(),
            channel_id: channel_id.clone(),
            sequence,
        };
        verify_membership(
            client_state,
            connection_end.counterparty().prefix(),
            proof,
            root,
            ack_path,
            ack.into_vec(),
        )
    }

    fn verify_next_sequence_recv(
        &self,
        ctx: &dyn ChannelReader,
        height: Height,
        connection_end: &ConnectionEnd,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<(), Ics02Error> {
        let client_state = downcast_gp_client_state(self)?;
        client_state.verify_height(height)?;
        verify_delay_passed(ctx, height, connection_end)?;

        let mut seq_bytes = Vec::new();
        Message::encode(&u64::from(sequence), &mut seq_bytes).expect("buffer size too small");
        // u64::from(sequence)
        //     .encode(&mut seq_bytes)
        //     .expect("buffer size too small");

        let seq_path = SeqRecvsPath(port_id.clone(), channel_id.clone());

        verify_membership(
            client_state,
            connection_end.counterparty().prefix(),
            proof,
            root,
            seq_path,
            seq_bytes,
        )
    }

    fn verify_packet_receipt_absence(
        &self,
        ctx: &dyn ChannelReader,
        height: Height,
        connection_end: &ConnectionEnd,
        proof: &CommitmentProofBytes,
        root: &CommitmentRoot,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<(), Ics02Error> {
        let client_state = downcast_gp_client_state(self)?;
        client_state.verify_height(height)?;
        verify_delay_passed(ctx, height, connection_end)?;

        let receipt_path = ReceiptsPath {
            port_id: port_id.clone(),
            channel_id: channel_id.clone(),
            sequence,
        };
        verify_non_membership(
            client_state,
            connection_end.counterparty().prefix(),
            proof,
            root,
            receipt_path,
        )
    }
}

impl Protobuf<RawGpClientState> for ClientState {}

impl TryFrom<RawGpClientState> for ClientState {
    type Error = Error;

    fn try_from(raw: RawGpClientState) -> Result<Self, Self::Error> {
        let frozen_height = raw
            .frozen_height
            .and_then(|raw_height| raw_height.try_into().ok());

        Ok(Self {
            chain_id: ChainId::from_str(raw.chain_id.as_str())
                .map_err(|_| Error::invalid_chain_id())?,
            latest_height: raw.latest_height as u64,
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

impl From<ClientState> for RawGpClientState {
    fn from(value: ClientState) -> Self {
        Self {
            chain_id: value.chain_id.to_string(),
            latest_height: value.latest_height as u32,
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

impl Protobuf<Any> for ClientState {}

impl TryFrom<Any> for ClientState {
    type Error = Ics02Error;

    fn try_from(raw: Any) -> Result<Self, Self::Error> {
        use bytes::Buf;
        use core::ops::Deref;

        fn decode_client_state<B: Buf>(buf: B) -> Result<ClientState, Error> {
            RawGpClientState::decode(buf)
                .map_err(Error::decode)?
                .try_into()
        }

        match raw.type_url.as_str() {
            GRANDPA_CLIENT_STATE_TYPE_URL => {
                decode_client_state(raw.value.deref()).map_err(Into::into)
            }
            _ => Err(Ics02Error::unknown_client_state_type(raw.type_url)),
        }
    }
}

impl From<ClientState> for Any {
    fn from(client_state: ClientState) -> Self {
        Any {
            type_url: GRANDPA_CLIENT_STATE_TYPE_URL.to_string(),
            value: Protobuf::<RawGpClientState>::encode_vec(&client_state)
                .expect("encoding to `Any` from `RawGpClientState`"),
        }
    }
}

fn verify_header(
    block_header: BlockHeader,
    mmr_leaf: Vec<u8>,
    mmr_leaf_proof: Vec<u8>,
) -> Result<(), Ics02Error> {
    let block_number = block_header.block_number as u64;
    let mmr_leaf: Vec<u8> = Decode::decode(&mut &mmr_leaf[..])
        .map_err(|e| Ics02Error::client_specific(e.to_string()))?;
    let mmr_leaf: mmr::MmrLeaf =
        Decode::decode(&mut &*mmr_leaf).map_err(|e| Ics02Error::client_specific(e.to_string()))?;

    // check mmr leaf
    if mmr_leaf.parent_number_and_hash.1.is_empty() {
        return Err(Ics02Error::client_specific(
            "empty_mmr_leaf_parent_hash_mmr_root".to_string(),
        ));
    }

    // decode mmr leaf proof
    let mmr_leaf_proof = beefy_light_client::mmr::MmrLeafProof::decode(&mut &mmr_leaf_proof[..])
        .map_err(|_| Ics02Error::client_specific("decode_mmr_proof error".to_string()))?;

    if block_number > mmr_leaf_proof.leaf_count {
        return Err(Ics02Error::client_specific(
            "invalid_mmr_leaf_proof".to_string(),
        ));
    }

    // verfiy block header
    if block_header.parent_hash != mmr_leaf.parent_number_and_hash.1.to_vec() {
        return Err(Ics02Error::client_specific(
            "header_hash_not_match".to_string(),
        ));
    }

    Ok(())
}

fn verify_membership(
    _client_state: &ClientState,
    _prefix: &CommitmentPrefix,
    proof: &CommitmentProofBytes,
    root: &CommitmentRoot,
    path: impl Into<Path>,
    value: Vec<u8>,
) -> Result<(), Ics02Error> {
    // TODO(we need prefix)??
    // let merkle_path = apply_prefix(prefix, vec![path.into().to_string()]);
    let (key, storage_name) = match path.into() {
        Path::ClientType(_) => unimplemented!(),
        Path::ClientState(value) => (value.to_string().as_bytes().to_vec(), "ClientStates"),
        Path::ClientConsensusState(value) => {
            (value.to_string().as_bytes().to_vec(), "ConsensusStates")
        }
        Path::ClientConnections(_) => unimplemented!(),
        Path::Connections(value) => (value.to_string().as_bytes().to_vec(), "Connections"),
        Path::Ports(_) => unimplemented!(),
        Path::ChannelEnds(value) => (value.to_string().as_bytes().to_vec(), "Channels"),
        Path::SeqSends(_) => unimplemented!(),
        Path::SeqRecvs(value) => (value.to_string().as_bytes().to_vec(), "NextSequenceRecv"),
        Path::SeqAcks(_) => unimplemented!(),
        Path::Commitments(value) => (value.to_string().as_bytes().to_vec(), "PacketCommitment"),
        Path::Acks(value) => (value.to_string().as_bytes().to_vec(), "Acknowledgements"),
        Path::Receipts(value) => (value.to_string().as_bytes().to_vec(), "PacketReceipt"),
        Path::Upgrade(_) => unimplemented!(),
    };

    let storage_result = get_storage_via_proof(root, proof, key, storage_name)?;

    if storage_result != value {
        Err(Ics02Error::client_specific(
            "verify membership error".to_string(),
        ))
    } else {
        Ok(())
    }
}

fn verify_non_membership(
    _client_state: &ClientState,
    _prefix: &CommitmentPrefix,
    proof: &CommitmentProofBytes,
    root: &CommitmentRoot,
    path: impl Into<Path>,
) -> Result<(), Ics02Error> {
    // TODO(we need prefix)??
    // let merkle_path = apply_prefix(prefix, vec![path.into().to_string()]);

    let (key, storage_name) = match path.into() {
        Path::ClientType(_) => unimplemented!(),
        Path::ClientState(value) => (value.to_string().as_bytes().to_vec(), "ClientStates"),
        Path::ClientConsensusState(value) => {
            (value.to_string().as_bytes().to_vec(), "ConsensusStates")
        }
        Path::ClientConnections(_) => unimplemented!(),
        Path::Connections(value) => (value.to_string().as_bytes().to_vec(), "Connections"),
        Path::Ports(_) => unimplemented!(),
        Path::ChannelEnds(value) => (value.to_string().as_bytes().to_vec(), "Channels"),
        Path::SeqSends(_) => unimplemented!(),
        Path::SeqRecvs(value) => (value.to_string().as_bytes().to_vec(), "NextSequenceRecv"),
        Path::SeqAcks(_) => unimplemented!(),
        Path::Commitments(value) => (value.to_string().as_bytes().to_vec(), "PacketCommitment"),
        Path::Acks(value) => (value.to_string().as_bytes().to_vec(), "Acknowledgements"),
        Path::Receipts(value) => (value.to_string().as_bytes().to_vec(), "PacketReceipt"),
        Path::Upgrade(_) => unimplemented!(),
    };

    let storage_result = get_storage_via_proof(root, proof, key, storage_name);

    // TODO(is or not correct)
    if storage_result.is_err() {
        Ok(())
    } else {
        Err(Ics02Error::client_specific(
            "verify non membership error".to_string(),
        ))
    }
}
/// Reconstruct on-chain storage value by proof, key(path), and state root
fn get_storage_via_proof(
    root: &CommitmentRoot,
    proof: &CommitmentProofBytes,
    keys: Vec<u8>,
    storage_name: &str,
) -> Result<Vec<u8>, Ics02Error> {
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ReadProofU8 {
        pub at: String,
        pub proof: Vec<Vec<u8>>,
    }

    let merkel_proof = MerkleProof::try_from(proof.clone())
        .map_err(|e| Ics02Error::client_specific(e.to_string()))?;
    let merkel_proof = merkel_proof.proofs[0]
        .proof
        .clone()
        .ok_or(Ics02Error::client_specific("empty proof".to_string()))?;
    let storage_proof = match merkel_proof {
        Exist(exist_proof) => {
            let proof_str = String::from_utf8(exist_proof.value)
                .map_err(|e| Ics02Error::client_specific(e.to_string()))?;
            let storage_proof: ReadProofU8 = serde_json::from_str(&proof_str)
                .map_err(|e| Ics02Error::client_specific(e.to_string()))?;
            storage_proof
        }
        _ => unimplemented!(),
    };

    let storage_keys = storage_map_final_key(keys, storage_name);
    let state_root = root.clone().into_vec();
    let state_root = vector_to_array::<u8, 32>(state_root);

    let storage_result = read_proof_check::<sp_runtime::traits::BlakeTwo256>(
        sp_core::H256::from(state_root),
        sp_trie::StorageProof::new(storage_proof.proof),
        &storage_keys,
    )
    .map_err(|_| Ics02Error::client_specific("Read Proof Check Error".to_string()))?
    .ok_or(Ics02Error::client_specific("empty proof".to_string()))?;

    let storage_result = <Vec<u8> as Decode>::decode(&mut &storage_result[..])
        .map_err(|e| Ics02Error::client_specific(e.to_string()))?;

    Ok(storage_result)
}

/// Calculate the storage's final key
fn storage_map_final_key(key: Vec<u8>, storage_name: &str) -> Vec<u8> {
    // Migrate from: https://github.com/paritytech/substrate/blob/32b71896df8a832e7c139a842e46710e4d3f70cd/frame/support/src/storage/generator/map.rs?_pjax=%23js-repo-pjax-container%2C%20div%5Bitemtype%3D%22http%3A%2F%2Fschema.org%2FSoftwareSourceCode%22%5D%20main%2C%20%5Bdata-pjax-container%5D#L66
    let key_hashed: &[u8] = &Blake2_128Concat::hash(&Encode::encode(&key));
    let storage_prefix = storage_prefix("Ibc".as_bytes(), storage_name.as_bytes());
    let mut final_key = Vec::with_capacity(storage_prefix.len() + key_hashed.as_ref().len());
    final_key.extend_from_slice(&storage_prefix);
    final_key.extend_from_slice(key_hashed.as_ref());

    final_key
}

/// A hashing function for packet commitments
fn hash(value: String) -> String {
    let r = sp_io::hashing::sha2_256(value.as_bytes());

    let mut tmp = String::new();
    for item in r.iter() {
        tmp.push_str(&format!("{:02x}", item));
    }

    tmp
}

fn vector_to_array<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}

fn verify_delay_passed(
    ctx: &dyn ChannelReader,
    height: Height,
    connection_end: &ConnectionEnd,
) -> Result<(), Ics02Error> {
    let current_timestamp = ctx.host_timestamp();
    let current_height = ctx.host_height();

    let client_id = connection_end.client_id();
    let processed_time = ctx
        .client_update_time(client_id, height)
        .map_err(|_| Error::processed_time_not_found(client_id.clone(), height))?;
    let processed_height = ctx
        .client_update_height(client_id, height)
        .map_err(|_| Error::processed_height_not_found(client_id.clone(), height))?;

    let delay_period_time = connection_end.delay_period();
    let delay_period_height = ctx.block_delay(delay_period_time);

    ClientState::verify_delay_passed(
        current_timestamp,
        current_height,
        processed_time,
        processed_height,
        delay_period_time,
        delay_period_height,
    )
    .map_err(|e| e.into())
}

fn downcast_gp_client_state(cs: &dyn Ics2ClientState) -> Result<&ClientState, Ics02Error> {
    cs.as_any()
        .downcast_ref::<ClientState>()
        .ok_or_else(|| Ics02Error::client_args_type_mismatch(ClientType::Grandpa))
}

fn downcast_gp_consensus_state(cs: &dyn ConsensusState) -> Result<GpConsensusState, Ics02Error> {
    cs.as_any()
        .downcast_ref::<GpConsensusState>()
        .ok_or_else(|| Ics02Error::client_args_type_mismatch(ClientType::Grandpa))
        .map(Clone::clone)
}
