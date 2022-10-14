use super::client::ClientSettings;
use crate::config::ChainConfig;
use crate::error::Error;
// use crate::event::monitor::{EventMonitor, EventReceiver, TxMonitorCmd};
use crate::event::beefy_monitor::{BeefyMonitor, BeefyReceiver};
use crate::event::substrate_mointor::{EventMonitor, EventReceiver, TxMonitorCmd};
use crate::keyring::{KeyEntry, KeyRing};
use crate::light_client::grandpa::LightClient as GPLightClient;
use crate::util::retry::{retry_with_index, RetryResult};
use tracing::{debug, error, info, trace, warn};

use crate::chain::endpoint::ChainEndpoint;
use crate::chain::endpoint::ChainStatus;
use crate::chain::endpoint::HealthCheck;
use crate::chain::requests::QueryPacketEventDataRequest;
use crate::chain::requests::QueryTxRequest;
use crate::chain::requests::{
    IncludeProof, QueryBlockRequest, QueryClientStateRequest, QueryHeight,
    QueryHostConsensusStateRequest, QueryPacketAcknowledgementRequest,
    QueryPacketCommitmentRequest, QueryPacketReceiptRequest, QueryUpgradedClientStateRequest,
    QueryUpgradedConsensusStateRequest,
};
use crate::chain::tracking::{TrackedMsgs, TrackingId};
use alloc::sync::Arc;
use codec::{Decode, Encode};
use core::fmt::Debug;
use core::{future::Future, str::FromStr, time::Duration};
use ibc::core::ics02_client::msgs::update_client::MsgUpdateAnyClient;
use ibc::core::ics04_channel::events::WriteAcknowledgement;
use ibc::tx_msg::Msg;
use ibc::{
    clients::{
        ics07_tendermint::header::Header as tHeader,
        ics10_grandpa::{
            client_state::ClientState as GPClientState,
            consensus_state::ConsensusState as GPConsensusState,
            header::Header as GPHeader,
            help::{BlockHeader, MmrLeaf, MmrLeafProof},
        },
    },
    core::{
        ics02_client::{
            client_consensus::{AnyConsensusState, AnyConsensusStateWithHeight},
            client_state::{AnyClientState, IdentifiedAnyClientState},
            client_type::ClientType,
        },
        ics03_connection::connection::{ConnectionEnd, Counterparty, IdentifiedConnectionEnd},
        ics04_channel::{
            channel::{ChannelEnd, IdentifiedChannelEnd},
            packet::{Packet, PacketMsgType, Receipt, Sequence},
        },
        ics23_commitment::commitment::CommitmentPrefix,
        ics24_host::identifier::{ChainId, ChannelId, ClientId, ConnectionId, PortId},
    },
    events::{IbcEvent, WithBlockDataType},
    signer::Signer,
    Height, Height as ICSHeight,
};
use subxt::rpc::ClientT;

use crate::chain::requests::QueryChannelClientStateRequest;
use crate::chain::requests::QueryChannelRequest;
use crate::chain::requests::QueryChannelsRequest;
use crate::chain::requests::QueryClientConnectionsRequest;
use crate::chain::requests::QueryClientStatesRequest;
use crate::chain::requests::QueryConnectionChannelsRequest;
use crate::chain::requests::QueryConnectionRequest;
use crate::chain::requests::QueryConnectionsRequest;
use crate::chain::requests::QueryConsensusStateRequest;
use crate::chain::requests::QueryConsensusStatesRequest;
use crate::chain::requests::QueryNextSequenceReceiveRequest;
use crate::chain::requests::QueryPacketAcknowledgementsRequest;
use crate::chain::requests::QueryPacketCommitmentsRequest;
use crate::chain::requests::QueryUnreceivedAcksRequest;
use crate::chain::requests::QueryUnreceivedPacketsRequest;
use ibc::core::ics23_commitment::merkle::MerkleProof;
use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::core::channel::v1::PacketState;

use ibc::clients::ics10_grandpa::help::SignedCommitment;
use ibc::clients::ics10_grandpa::help::ValidatorMerkleProof;
use ibc::core::ics23_commitment::commitment::CommitmentRoot;
use jsonrpsee::rpc_params;
use octopusxt::MyConfig;
use retry::delay::Fixed;
use semver::Version;
use sp_core::ByteArray;
use std::thread::{self, sleep};
use subxt::{
    self, rpc::NumberOrHex, storage::StorageEntry, storage::StorageKeyPrefix, BlockNumber, Client,
    ClientBuilder, PairSigner,
};

use tendermint::abci::{Code, Log};

use crate::account::Balance;
use crate::denom::DenomTrace;
use anyhow::Result;
use beefy_light_client::{commitment, mmr};
use ibc::clients::ics10_grandpa::help::Commitment;
use ibc::clients::ics10_grandpa::help::MmrRoot;

use ibc::core::ics04_channel::events::SendPacket;
use ibc::core::ics24_host::path::{
    AcksPath, ChannelEndsPath, ClientConsensusStatePath, ClientStatePath, CommitmentsPath,
    ConnectionsPath, ReceiptsPath, SeqRecvsPath,
};
use ics23::InnerOp;
use octopusxt::ibc_node::ibc::storage;
use octopusxt::ibc_node::RuntimeApi;
use octopusxt::update_client_state::update_client_state;
use octopusxt::SubstrateNodeTemplateExtrinsicParams;

use serde::{Deserialize, Serialize};
use sp_core::sr25519;
use sp_core::{hexdisplay::HexDisplay, Bytes, Pair, H256};
use sp_runtime::{traits::IdentifyAccount, AccountId32, MultiSigner};
use tendermint::abci::transaction;
use tendermint::time::Time;
use tendermint_light_client::types::Validator;
use tendermint_proto::Protobuf;
use tendermint_rpc::endpoint::broadcast::tx_sync::Response as TxResponse;
use tokio::runtime::Runtime as TokioRuntime;

const MAX_QUERY_TIMES: u64 = 100;
pub const REVISION_NUMBER: u64 = 8888;

/// A struct used to start a Substrate chain instance in relayer
#[derive(Debug)]
pub struct SubstrateChain {
    client: Client<MyConfig>,
    config: ChainConfig,
    websocket_url: String,
    keybase: KeyRing,
    rt: Arc<TokioRuntime>,
}

impl SubstrateChain {
    pub fn config(&self) -> &ChainConfig {
        &self.config
    }

    /// Run a future to completion on the Tokio runtime.
    fn block_on<F: Future>(&self, f: F) -> F::Output {
        self.rt.block_on(f)
    }

    fn retry_wapper<O, Op>(&self, operation: Op) -> Result<O, retry::Error<String>>
    where
        Op: FnOnce() -> Result<O> + Copy,
    {
        retry_with_index(Fixed::from_millis(200), |current_try| {
            if current_try > MAX_QUERY_TIMES {
                return RetryResult::Err("did not succeed within tries".to_string());
            }

            let result = operation();

            match result {
                Ok(v) => RetryResult::Ok(v),
                Err(_) => RetryResult::Retry("Fail to retry".to_string()),
            }
        })
    }

    /// Subscribe Events
    fn subscribe_ibc_events(&self) -> Result<Vec<IbcEvent>> {
        tracing::trace!("in substrate: [subscribe_ibc_events]");

        self.block_on(octopusxt::subscribe_ibc_event(self.client.clone()))
    }

    /// get latest block height
    fn get_latest_height(&self) -> Result<u64> {
        tracing::trace!("in substrate: [get_latest_height]");

        self.block_on(octopusxt::get_latest_height(self.client.clone()))
    }

    /// get connectionEnd by connection_identifier
    fn query_connection_end(&self, connection_identifier: &ConnectionId) -> Result<ConnectionEnd> {
        tracing::trace!("in substrate: [query_connection_end]");

        self.block_on(octopusxt::query_connection_end(
            connection_identifier,
            self.client.clone(),
        ))
    }

    /// query channelEnd  by port_identifier, and channel_identifier
    fn query_channel_end(&self, port_id: &PortId, channel_id: &ChannelId) -> Result<ChannelEnd> {
        tracing::trace!("in substrate: [query_channel_end]");

        self.block_on(octopusxt::query_channel_end(
            port_id,
            channel_id,
            self.client.clone(),
        ))
    }

    /// get packet receipt by port_id, channel_id and sequence
    fn _get_packet_receipt(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        seq: &Sequence,
    ) -> Result<Receipt> {
        tracing::trace!("in substrate: [get_packet_receipt]");

        self.block_on(octopusxt::get_packet_receipt(
            port_id,
            channel_id,
            seq,
            self.client.clone(),
        ))
    }

    /// get send packet event by port_id, channel_id and sequence
    fn get_send_packet_event(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        seq: &Sequence,
    ) -> Result<Packet> {
        tracing::trace!("in substrate: [get_send_packet_event]");

        self.block_on(octopusxt::get_send_packet_event(
            port_id,
            channel_id,
            seq,
            self.client.clone(),
        ))
    }

    // TODO(davirain) need add query height
    /// get client_state by client_id
    fn query_client_state(&self, client_id: &ClientId) -> Result<AnyClientState> {
        tracing::trace!("in substrate: [query_client_state]");

        self.block_on(octopusxt::query_client_state(
            client_id,
            self.client.clone(),
        ))
    }

    // TODO(davirain) need add query height
    /// Performs a query to retrieve the consensus state for a specified height
    /// `consensus_height` that the specified light client stores.
    fn query_client_consensus(
        &self,
        client_id: &ClientId,
        consensus_height: &ICSHeight,
    ) -> Result<AnyConsensusState> {
        tracing::trace!("in substrate: [query_client_consensus]");

        self.block_on(octopusxt::query_client_consensus(
            client_id,
            consensus_height,
            self.client.clone(),
        ))
    }

    fn get_consensus_state_with_height(
        &self,
        client_id: &ClientId,
    ) -> Result<Vec<(Height, AnyConsensusState)>> {
        tracing::trace!("in substrate: [get_consensus_state_with_height]");

        self.block_on(octopusxt::get_consensus_state_with_height(
            &client_id,
            self.client.clone(),
        ))
    }

    fn get_unreceipt_packet(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequences: &[Sequence],
    ) -> Result<Vec<u64>> {
        tracing::trace!("in substrate: [get_unreceipt_packet]");

        self.block_on(octopusxt::get_unreceipt_packet(
            port_id,
            channel_id,
            sequences.to_vec(),
            self.client.clone(),
        ))
    }

    fn get_clients(&self) -> Result<Vec<IdentifiedAnyClientState>> {
        tracing::trace!("in substrate: [get_clients]");

        self.block_on(octopusxt::get_clients(self.client.clone()))
    }

    fn get_connections(&self) -> Result<Vec<IdentifiedConnectionEnd>> {
        tracing::trace!("in substrate: [get_connections]");

        self.block_on(octopusxt::get_connections(self.client.clone()))
    }

    fn get_channels(&self) -> Result<Vec<IdentifiedChannelEnd>> {
        tracing::trace!("in substrate: [get_channels]");

        self.block_on(octopusxt::get_channels(self.client.clone()))
    }

    fn get_commitment_packet_state(&self) -> Result<Vec<PacketState>> {
        tracing::trace!("in substrate: [get_commitment_packet_state]");

        self.block_on(octopusxt::get_commitment_packet_state(self.client.clone()))
    }

    /// get packet commitment by port_id, channel_id and sequence
    fn get_packet_commitment(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: &Sequence,
    ) -> Result<Vec<u8>> {
        tracing::trace!("in substrate: [get_packet_commitment]");

        self.block_on(octopusxt::get_packet_commitment(
            port_id,
            channel_id,
            sequence,
            self.client.clone(),
        ))
    }

    fn get_acknowledge_packet_state(&self) -> Result<Vec<PacketState>> {
        tracing::trace!("in substrate: [get_acknowledge_packet_state]");

        self.block_on(octopusxt::get_acknowledge_packet_state(self.client.clone()))
    }

    /// get connection_identifier vector by client_identifier
    fn get_client_connections(&self, client_id: &ClientId) -> Result<Vec<ConnectionId>> {
        tracing::trace!("in substrate: [get_client_connections]");

        self.block_on(octopusxt::get_client_connections(
            client_id,
            self.client.clone(),
        ))
    }

    fn get_connection_channels(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<Vec<IdentifiedChannelEnd>> {
        tracing::trace!("in substrate: [get_connection_channels]");

        self.block_on(octopusxt::get_connection_channels(
            connection_id,
            self.client.clone(),
        ))
    }

    /// The function to submit IBC request to a Substrate chain
    /// This function handles most of the IBC reqeusts, except the MMR root update
    fn deliever(&self, msgs: Vec<Any>) -> Result<H256> {
        info!("in substrate: [deliever]");

        let result = self.block_on(octopusxt::deliver(msgs, self.client.clone()))?;

        Ok(result)
    }

    fn raw_transfer(&self, msgs: Vec<Any>) -> Result<H256> {
        tracing::trace!("in substrate: [raw_transfer]");

        let result = self.block_on(octopusxt::raw_transfer(msgs, self.client.clone()))?;

        Ok(result)
    }

    fn get_write_ack_packet_event(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: &Sequence,
    ) -> Result<WriteAcknowledgement> {
        tracing::trace!("in substrate: [get_send_packet_event]");

        self.block_on(octopusxt::ibc_rpc::get_write_ack_packet_event(
            port_id,
            channel_id,
            sequence,
            self.client.clone(),
        ))
    }

    fn get_ibc_send_packet_event(
        &self,
        request: QueryPacketEventDataRequest,
    ) -> Result<Vec<IbcEvent>, Error> {
        let mut result_event = vec![];

        for sequence in &request.sequences {
            let packet = self
                .get_send_packet_event(
                    &request.source_port_id,
                    &request.source_channel_id,
                    sequence,
                )
                .map_err(|e| Error::get_send_packet_event_error(e.to_string()))?;

            result_event.push(IbcEvent::SendPacket(SendPacket {
                height: match request.height {
                    QueryHeight::Latest => unimplemented!(),
                    QueryHeight::Specific(value) => value,
                },
                packet,
            }));
        }
        Ok(result_event)
    }

    fn get_ibc_write_acknowledgement_event(
        &self,
        request: QueryPacketEventDataRequest,
    ) -> Result<Vec<IbcEvent>, Error> {
        let mut result_event = vec![];

        for sequence in &request.sequences {
            let write_ack = self
                .get_write_ack_packet_event(
                    &request.source_port_id,
                    &request.source_channel_id,
                    sequence,
                )
                .map_err(|_| Error::get_write_ack_packet_event_error())?;

            result_event.push(IbcEvent::WriteAcknowledgement(write_ack));
        }

        Ok(result_event)
    }

    /// Retrieve the storage proof according to storage keys
    /// And convert the proof to IBC compatible type
    fn generate_storage_proof<F: StorageEntry>(
        &self,
        storage_entry: &F,
        height: &Height,
        storage_name: &str,
    ) -> Result<MerkleProof, Error>
    where
        <F as StorageEntry>::Value: Serialize + Debug,
    {
        let generate_storage_proof = async {
            let client = self.client.clone();

            let height = NumberOrHex::Number(height.revision_height());

            let block_hash: H256 = client
                .rpc()
                .block_hash(Some(BlockNumber::from(height)))
                .await
                .map_err(|_| Error::get_block_hash_error())?
                .ok_or_else(Error::empty_hash)?;

            let storage_key = storage_entry.key().final_key(StorageKeyPrefix::new::<F>());
            tracing::trace!("in substrate: [generate_storage_proof] >> height: {:?}, block_hash: {:?}, storage key: {:?}, storage_name = {:?}",
                height, block_hash, storage_key, storage_name);

            let params = rpc_params![vec![storage_key], block_hash];

            #[derive(Debug, PartialEq, Serialize, Deserialize)]
            #[serde(rename_all = "camelCase")]
            pub struct ReadProof_ {
                pub at: String,
                pub proof: Vec<Bytes>,
            }

            let storage_proof: ReadProof_ = client
                .rpc()
                .client
                .request("state_getReadProof", params)
                .await
                .map_err(|_| Error::get_read_proof_error())?;

            tracing::trace!(
                "in substrate: [generate_storage_proof] >> storage_proof : {:?}",
                storage_proof
            );

            #[derive(Debug, PartialEq, Serialize, Deserialize)]
            #[serde(rename_all = "camelCase")]
            pub struct ReadProofU8 {
                pub at: String,
                pub proof: Vec<Vec<u8>>,
            }
            let storage_proof_ = ReadProofU8 {
                at: storage_proof.at,
                proof: storage_proof
                    .proof
                    .iter()
                    .map(|val| val.clone().0)
                    .collect::<Vec<Vec<u8>>>(),
            };
            tracing::trace!(
                "in substrate: [generate_storage_proof] >> storage_proof_ : {:?}",
                storage_proof_
            );

            let storage_proof_str =
                serde_json::to_string(&storage_proof_).map_err(Error::invalid_serde_json_error)?;
            tracing::trace!(
                "in substrate: [generate_storage_proof] >> storage_proof_str: {:?}",
                storage_proof_str
            );

            Ok(storage_proof_str)
        };

        let storage_proof = self.block_on(generate_storage_proof)?;

        Ok(compose_ibc_merkle_proof(storage_proof))
    }

    fn _key(&self) -> Result<KeyEntry, Error> {
        self.keybase()
            .get_key(&self.config.key_name)
            .map_err(Error::key_base)
    }

    fn query_packet_commitment(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: &Sequence,
    ) -> Result<Vec<u8>> {
        self.block_on(octopusxt::ibc_rpc::get_packet_commitment(
            port_id,
            channel_id,
            sequence,
            self.client.clone(),
        ))
    }

    fn query_packet_receipt(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: &Sequence,
    ) -> Result<Vec<u8>> {
        self.block_on(octopusxt::ibc_rpc::get_packet_receipt_vec(
            port_id,
            channel_id,
            sequence,
            self.client.clone(),
        ))
    }

    fn query_next_sequence_receive(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<Sequence> {
        self.block_on(octopusxt::ibc_rpc::get_next_sequence_recv(
            port_id,
            channel_id,
            self.client.clone(),
        ))
    }

    fn query_packet_acknowledgement(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: &Sequence,
    ) -> Result<Vec<u8>> {
        self.block_on(octopusxt::ibc_rpc::get_packet_ack(
            port_id,
            channel_id,
            sequence,
            self.client.clone(),
        ))
    }
}

impl ChainEndpoint for SubstrateChain {
    type LightBlock = GPHeader;
    type Header = GPHeader;
    type ConsensusState = AnyConsensusState;
    type ClientState = AnyClientState;
    type LightClient = GPLightClient;

    fn bootstrap(config: ChainConfig, rt: Arc<TokioRuntime>) -> Result<Self, Error> {
        tracing::info!("in Substrate: [bootstrap function]");

        let websocket_url = format!("{}", config.websocket_addr);

        // Initialize key store and load key
        let keybase = KeyRing::new(config.key_store_type, &config.account_prefix, &config.id)
            .map_err(Error::key_base)?;

        let client = async {
            ClientBuilder::new()
                .set_url(websocket_url.clone())
                .build::<MyConfig>()
                .await
                .map_err(|_| Error::substrate_build_client())
        };

        let client = rt
            .clone()
            .block_on(client)
            .map_err(|_| Error::substrate_build_client())?;

        let chain = Self {
            client,
            config,
            websocket_url,
            rt,
            keybase,
        };

        Ok(chain)
    }

    fn init_light_client(&self) -> Result<Self::LightClient, Error> {
        tracing::debug!("in substrate: [init_light_client]");
        use subxt::sp_core::Public;

        let config = self.config.clone();

        let public_key = async {
            let client = self.client.clone();

            let api =
                client.to_runtime_api::<RuntimeApi<MyConfig, SubstrateNodeTemplateExtrinsicParams<MyConfig>>>();

            let authorities = api
                .storage()
                .beefy()
                .authorities(None)
                .await
                .map_err(|_| Error::authorities())?;

            tracing::info!("authorities length : {:?}", authorities.len());

            let result: Vec<String> = authorities
                .into_iter()
                .map(|val| format!("0x{}", HexDisplay::from(&val.to_raw_vec())))
                .collect();
            tracing::info!("authorities member: {:?}", result);
            Ok(result)
        };
        let public_key = self.block_on(public_key)?;

        let initial_public_keys = public_key;
        let light_client = GPLightClient::from_config(
            &config,
            self.websocket_url.clone(),
            self.rt.clone(),
            initial_public_keys,
        );
        Ok(light_client)
    }

    fn init_event_monitor(
        &self,
        rt: Arc<TokioRuntime>,
    ) -> Result<(EventReceiver, TxMonitorCmd), Error> {
        debug!(
            "in substrate: [init_event_mointor] >> websocket addr: {:?}",
            self.config.websocket_addr.clone()
        );

        let (mut event_monitor, event_receiver, monitor_tx) = EventMonitor::new(
            self.config.id.clone(),
            self.client.clone(),
            self.config.websocket_addr.clone(),
            rt,
        )
        .map_err(Error::event_monitor)?;

        event_monitor.subscribe().map_err(Error::event_monitor)?;

        thread::spawn(move || event_monitor.run());

        Ok((event_receiver, monitor_tx))
    }

    fn init_beefy_monitor(
        &self,
        rt: Arc<TokioRuntime>,
    ) -> Result<(BeefyReceiver, TxMonitorCmd), Error> {
        tracing::debug!(
            "in substrate: [init_beefy_mointor] >> websocket addr: {:?}",
            self.config.websocket_addr.clone()
        );

        let (mut beefy_monitor, beefy_receiver, monitor_tx) = BeefyMonitor::new(
            self.config.id.clone(),
            self.client.clone(),
            self.config.websocket_addr.clone(),
            rt,
        )
        .map_err(Error::event_monitor)?;

        beefy_monitor.subscribe().map_err(Error::event_monitor)?;

        thread::spawn(move || beefy_monitor.run());
        debug!("in substrate: [init_beefy_mointor] >> beefy monitor is running ...");

        Ok((beefy_receiver, monitor_tx))
    }

    fn id(&self) -> &ChainId {
        tracing::trace!("in substrate: [id]");

        &self.config().id
    }

    fn shutdown(self) -> Result<(), Error> {
        info!("in substrate: [shutdown]");

        Ok(())
    }

    fn health_check(&self) -> Result<HealthCheck, Error> {
        Ok(HealthCheck::Healthy)
    }

    fn keybase(&self) -> &KeyRing {
        trace!("in substrate: [keybase]");
        &self.keybase
    }

    fn keybase_mut(&mut self) -> &mut KeyRing {
        trace!("in substrate: [keybase_mut]");
        &mut self.keybase
    }

    fn send_messages_and_wait_commit(
        &mut self,
        proto_msgs: TrackedMsgs,
    ) -> Result<Vec<IbcEvent>, Error> {
        info!(
            "in substrate: [send_messages_and_wait_commit], proto_msgs={:?}",
            proto_msgs.tracking_id
        );
        use ibc::applications::transfer::msgs::transfer::TYPE_URL as TRANSFER_TYPE_URL;

        match proto_msgs.tracking_id {
            TrackingId::Uuid(_) => {
                sleep(Duration::from_secs(4));
                let result = self
                    .deliever(proto_msgs.messages().to_vec())
                    .map_err(|e| Error::deliver_error(e))?;
                debug!(
                    "in substrate: [send_messages_and_wait_commit] >> extrics_hash  : {:?}",
                    result
                );
            }
            TrackingId::Static(value) => match value {
                "ft-transfer" => {
                    let result = self
                        .raw_transfer(proto_msgs.messages().to_vec())
                        .map_err(|_| Error::ics20_transfer())?;
                    debug!(
                        "in substrate: [send_messages_and_wait_commit] >> extrics_hash  : {:?}",
                        result
                    );
                }
                _ => {
                    sleep(Duration::from_secs(4));
                    let result = self
                        .deliever(proto_msgs.messages().to_vec())
                        .map_err(|e| Error::deliver_error(e))?;
                    debug!(
                        "in substrate: [send_messages_and_wait_commit] >> extrics_hash  : {:?}",
                        result
                    );
                }
            },
        }

        let ibc_event = self
            .subscribe_ibc_events()
            .map_err(|_| Error::subscribe_ibc_events())?;

        Ok(ibc_event)
    }

    fn send_messages_and_wait_check_tx(
        &mut self,
        proto_msgs: TrackedMsgs,
    ) -> Result<Vec<TxResponse>, Error> {
        debug!(
            "in substrate: [send_messages_and_wait_check_tx], proto_msgs={:?}",
            proto_msgs.tracking_id
        );

        match proto_msgs.tracking_id {
            TrackingId::Uuid(_) => {
                sleep(Duration::from_secs(4));
                let result = self
                    .deliever(proto_msgs.messages().to_vec())
                    .map_err(|e| Error::deliver_error(e))?;
                debug!(
                    "in substrate: [send_messages_and_wait_commit] >> extrics_hash  : {:?}",
                    result
                );
            }
            TrackingId::Static(value) => match value {
                "ft-transfer" => {
                    let result = self
                        .raw_transfer(proto_msgs.messages().to_vec())
                        .map_err(|_| Error::ics20_transfer())?;

                    debug!(
                        "in substrate: [send_messages_and_wait_commit] >> extrics_hash  : {:?}",
                        result
                    );
                }
                _ => {
                    sleep(Duration::from_secs(4));
                    let result = self
                        .deliever(proto_msgs.messages().to_vec())
                        .map_err(|e| Error::deliver_error(e))?;
                    debug!(
                        "in substrate: [send_messages_and_wait_commit] >> extrics_hash  : {:?}",
                        result
                    );
                }
            },
        }

        let json = "\"ChYKFGNvbm5lY3Rpb25fb3Blbl9pbml0\"";
        let tx_re = TxResponse {
            code: Code::default(),
            data: serde_json::from_str(json).map_err(Error::invalid_serde_json_error)?,
            log: Log::from("test_test"),
            hash: transaction::Hash::new([0u8; 32]),
        };

        Ok(vec![tx_re])
    }

    fn get_signer(&mut self) -> Result<Signer, Error> {
        trace!("In Substraet: [get signer]");
        crate::time!("get_signer");

        /// Public key type for Runtime
        pub type PublicFor<P> = <P as Pair>::Public;

        /// formats public key as accountId as hex
        fn format_account_id<P: Pair>(public_key: PublicFor<P>) -> String
        where
            PublicFor<P>: Into<MultiSigner>,
        {
            format!(
                "0x{}",
                HexDisplay::from(&public_key.into().into_account().as_ref())
            )
        }

        // Get the key from key seed file
        let key = self
            .keybase()
            .get_key(&self.config.key_name)
            .map_err(|e| Error::key_not_found(self.config.key_name.clone(), e))?;

        let private_seed = key.mnemonic;

        let (pair, _seed) = sr25519::Pair::from_phrase(&private_seed, None).unwrap();
        let public_key = pair.public();

        let account_id = format_account_id::<sr25519::Pair>(public_key);
        let account = AccountId32::from_str(&account_id).unwrap();
        let encode_account = AccountId32::encode(&account);
        let hex_account = hex::encode(encode_account);

        Ok(Signer::from_str(&account_id).unwrap())
    }

    fn config(&self) -> ChainConfig {
        self.config.clone()
    }

    fn get_key(&mut self) -> Result<KeyEntry, Error> {
        tracing::trace!("in substrate: [get_key]");
        crate::time!("get_key");

        // Get the key from key seed file
        let key = self
            .keybase()
            .get_key(&self.config.key_name)
            .map_err(|e| Error::key_not_found(self.config.key_name.clone(), e))?;

        Ok(key)
    }

    fn add_key(&mut self, key_name: &str, key: KeyEntry) -> Result<(), Error> {
        self.keybase_mut()
            .add_key(key_name, key)
            .map_err(Error::key_base)?;

        Ok(())
    }

    fn ibc_version(&self) -> Result<Option<Version>, Error> {
        Ok(None)
    }

    fn query_balance(&self, key_name: Option<String>) -> std::result::Result<Balance, Error> {
        // todo(davirain) add mock balance
        Ok(Balance {
            amount: String::default(),
            denom: String::default(),
        })
    }

    fn query_denom_trace(&self, hash: String) -> std::result::Result<DenomTrace, Error> {
        // todo(daviarin) add mock denom trace
        Ok(DenomTrace {
            /// The chain of port/channel identifiers used for tracing the source of the coin.
            path: String::default(),
            /// The base denomination for that coin
            base_denom: String::default(),
        })
    }

    fn query_commitment_prefix(&self) -> Result<CommitmentPrefix, Error> {
        tracing::trace!("in substrate: [query_commitment_prefix]");

        // TODO - do a real chain query
        CommitmentPrefix::try_from(self.config().store_prefix.as_bytes().to_vec())
            .map_err(|_| Error::invalid_commitment_prefix())
    }

    fn query_application_status(&self) -> Result<ChainStatus, Error> {
        tracing::trace!("in substrate: [query_status]");

        let height = self
            .retry_wapper(|| self.get_latest_height())
            .map_err(Error::retry_error)?;

        let latest_height = Height::new(REVISION_NUMBER, height).expect("REVISION_NUMBER");

        Ok(ChainStatus {
            height: latest_height,
            timestamp: Default::default(),
        })
    }

    fn query_clients(
        &self,
        _request: QueryClientStatesRequest,
    ) -> Result<Vec<IdentifiedAnyClientState>, Error> {
        tracing::trace!("in substrate: [query_clients]");

        let result = self
            .retry_wapper(|| self.get_clients())
            .map_err(Error::retry_error)?;

        Ok(result)
    }

    fn query_client_state(
        &self,
        request: QueryClientStateRequest,
        include_proof: IncludeProof,
    ) -> Result<(AnyClientState, Option<MerkleProof>), Error> {
        tracing::trace!("in substrate: [query_client_state]");

        let QueryClientStateRequest { client_id, height } = request;

        let query_height = match height {
            QueryHeight::Latest => {
                let height = self
                    .get_latest_height()
                    .map_err(|_| Error::query_latest_height())?;
                Height::new(REVISION_NUMBER, height).expect(&REVISION_NUMBER.to_string())
            }
            QueryHeight::Specific(value) => value,
        };

        let result = self
            .retry_wapper(|| self.query_client_state(&client_id))
            .map_err(Error::retry_error)?;

        let client_state_path = ClientStatePath(client_id.clone())
            .to_string()
            .as_bytes()
            .to_vec();

        let storage_entry = storage::ClientStates(&client_state_path);

        match include_proof {
            IncludeProof::Yes => Ok((
                result,
                Some(self.generate_storage_proof(&storage_entry, &query_height, "ClientStates")?),
            )),
            IncludeProof::No => Ok((result, None)),
        }
    }

    fn query_consensus_state(
        &self,
        request: QueryConsensusStateRequest,
        include_proof: IncludeProof,
    ) -> Result<(AnyConsensusState, Option<MerkleProof>), Error> {
        tracing::trace!("in substrate: [query_consensus_state]");

        // query_height to amit to search chain height
        let QueryConsensusStateRequest {
            client_id,
            consensus_height,
            query_height,
        } = request;

        let result = self
            .retry_wapper(|| self.query_client_consensus(&client_id, &consensus_height))
            .map_err(Error::retry_error)?;

        // search key
        let client_consensus_state_path = ClientConsensusStatePath {
            client_id: client_id.clone(),
            epoch: consensus_height.revision_number(),
            height: consensus_height.revision_height(),
        }
        .to_string()
        .as_bytes()
        .to_vec();

        let storage_entry = storage::ConsensusStates(&client_consensus_state_path);

        match include_proof {
            IncludeProof::Yes => Ok((
                result,
                Some(self.generate_storage_proof(
                    &storage_entry,
                    &consensus_height,
                    "ConsensusStates",
                )?),
            )),
            IncludeProof::No => Ok((result, None)),
        }
    }

    fn query_consensus_states(
        &self,
        request: QueryConsensusStatesRequest,
    ) -> Result<Vec<AnyConsensusStateWithHeight>, Error> {
        tracing::trace!("in substrate: [query_consensus_states]");

        let request_client_id =
            ClientId::from_str(request.client_id.as_str()).map_err(Error::identifier)?;

        let result = self
            .retry_wapper(|| self.get_consensus_state_with_height(&request_client_id))
            .map_err(Error::retry_error)?;

        let consensus_state: Vec<(Height, AnyConsensusState)> = result;

        let mut any_consensus_state_with_height = vec![];
        for (height, consensus_state) in consensus_state.into_iter() {
            let tmp = AnyConsensusStateWithHeight {
                height,
                consensus_state,
            };
            any_consensus_state_with_height.push(tmp.clone());

            tracing::trace!(
                "in substrate: [query_consensus_state] >> any_consensus_state_with_height: {:?}",
                tmp
            );
        }

        any_consensus_state_with_height.sort_by(|a, b| a.height.cmp(&b.height));

        Ok(any_consensus_state_with_height)
    }

    fn query_upgraded_client_state(
        &self,
        request: QueryUpgradedClientStateRequest,
    ) -> Result<(AnyClientState, MerkleProof), Error> {
        tracing::trace!("in substrate: [query_upgraded_client_state]");

        todo!()
    }

    fn query_upgraded_consensus_state(
        &self,
        request: QueryUpgradedConsensusStateRequest,
    ) -> Result<(AnyConsensusState, MerkleProof), Error> {
        tracing::trace!("in substrate: [query_upgraded_consensus_state]");

        todo!()
    }

    fn query_connections(
        &self,
        _request: QueryConnectionsRequest,
    ) -> Result<Vec<IdentifiedConnectionEnd>, Error> {
        tracing::trace!("in substrate: [query_connections]");

        let result = self
            .retry_wapper(|| self.get_connections())
            .map_err(Error::retry_error)?;

        Ok(result)
    }

    fn query_client_connections(
        &self,
        request: QueryClientConnectionsRequest,
    ) -> Result<Vec<ConnectionId>, Error> {
        tracing::trace!("in substrate: [query_client_connections]");

        let client_id =
            ClientId::from_str(request.client_id.as_str()).map_err(Error::identifier)?;

        let result = self
            .retry_wapper(|| self.get_client_connections(&client_id))
            .map_err(Error::retry_error)?;

        Ok(result)
    }

    fn query_connection(
        &self,
        request: QueryConnectionRequest,
        include_proof: IncludeProof,
    ) -> Result<(ConnectionEnd, Option<MerkleProof>), Error> {
        tracing::trace!("in substrate: [query_connection]");
        // sleep(Duration::from_secs(6));

        let QueryConnectionRequest {
            connection_id,
            height,
        } = request;

        let connection_end = self
            .retry_wapper(|| self.query_connection_end(&connection_id))
            .map_err(Error::retry_error)?;

        // update ConnectionsPath key
        let connections_path = ConnectionsPath(connection_id.clone())
            .to_string()
            .as_bytes()
            .to_vec();
        let storage_entry = storage::Connections(&connections_path);

        match include_proof {
            IncludeProof::Yes => {
                let query_height = match height {
                    QueryHeight::Latest => {
                        let height = self
                            .get_latest_height()
                            .map_err(|_| Error::query_latest_height())?;
                        Height::new(REVISION_NUMBER, height).expect(&REVISION_NUMBER.to_string())
                    }
                    QueryHeight::Specific(value) => value,
                };

                Ok((
                    connection_end,
                    Some(self.generate_storage_proof(
                        &storage_entry,
                        &query_height,
                        "Connections",
                    )?),
                ))
            }
            IncludeProof::No => Ok((connection_end, None)),
        }
    }

    fn query_connection_channels(
        &self,
        request: QueryConnectionChannelsRequest,
    ) -> Result<Vec<IdentifiedChannelEnd>, Error> {
        tracing::trace!("in substrate: [query_connection_channels] ");

        let result = self
            .retry_wapper(|| self.get_connection_channels(&request.connection_id))
            .map_err(Error::retry_error)?;

        Ok(result)
    }

    fn query_channels(
        &self,
        _request: QueryChannelsRequest,
    ) -> Result<Vec<IdentifiedChannelEnd>, Error> {
        tracing::trace!("in substrate: [query_channels]");

        let result = self
            .retry_wapper(|| self.get_channels())
            .map_err(Error::retry_error)?;

        Ok(result)
    }

    fn query_channel(
        &self,
        request: QueryChannelRequest,
        include_proof: IncludeProof,
    ) -> Result<(ChannelEnd, Option<MerkleProof>), Error> {
        tracing::trace!("in substrate: [query_channel]");

        // sleep(Duration::from_secs(6));

        let QueryChannelRequest {
            port_id,
            channel_id,
            height,
        } = request;

        let channel_end = self
            .retry_wapper(|| self.query_channel_end(&port_id, &channel_id))
            .map_err(Error::retry_error)?;

        // use channel_end path as key
        let channel_end_path = ChannelEndsPath(port_id.clone(), channel_id.clone())
            .to_string()
            .as_bytes()
            .to_vec();
        let storage_entry = storage::Channels(&channel_end_path);

        match include_proof {
            IncludeProof::Yes => {
                let query_height = match height {
                    QueryHeight::Latest => {
                        let height = self
                            .get_latest_height()
                            .map_err(|_| Error::query_latest_height())?;
                        Height::new(REVISION_NUMBER, height).expect(&REVISION_NUMBER.to_string())
                    }
                    QueryHeight::Specific(value) => value,
                };

                Ok((
                    channel_end,
                    Some(self.generate_storage_proof(&storage_entry, &query_height, "Channels")?),
                ))
            }
            IncludeProof::No => Ok((channel_end, None)),
        }
    }

    fn query_channel_client_state(
        &self,
        _request: QueryChannelClientStateRequest,
    ) -> Result<Option<IdentifiedAnyClientState>, Error> {
        tracing::trace!("in substrate: [query_channel_client_state]");

        todo!()
    }

    fn query_packet_commitment(
        &self,
        request: QueryPacketCommitmentRequest,
        include_proof: IncludeProof,
    ) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
        let QueryPacketCommitmentRequest {
            port_id,
            channel_id,
            sequence,
            height,
        } = request;

        let packet_commit = self
            .retry_wapper(|| self.query_packet_commitment(&port_id, &channel_id, &sequence))
            .map_err(Error::retry_error)?;

        let packet_commits_path = CommitmentsPath {
            port_id: port_id.clone(),
            channel_id: channel_id.clone(),
            sequence: sequence.clone(),
        }
        .to_string()
        .as_bytes()
        .to_vec();

        let storage_entry = storage::PacketCommitment(&packet_commits_path);

        match include_proof {
            IncludeProof::Yes => {
                let query_height = match height {
                    QueryHeight::Latest => {
                        let height = self
                            .get_latest_height()
                            .map_err(|_| Error::query_latest_height())?;
                        Height::new(REVISION_NUMBER, height).expect(&REVISION_NUMBER.to_string())
                    }
                    QueryHeight::Specific(value) => value,
                };
                Ok((
                    packet_commit,
                    Some(self.generate_storage_proof(
                        &storage_entry,
                        &query_height,
                        "PacketCommitment",
                    )?),
                ))
            }
            IncludeProof::No => Ok((packet_commit, None)),
        }
    }

    fn query_packet_commitments(
        &self,
        _request: QueryPacketCommitmentsRequest,
    ) -> Result<(Vec<Sequence>, ICSHeight), Error> {
        tracing::trace!("in substrate: [query_packet_commitments]");

        let packet_commitments = self
            .retry_wapper(|| self.get_commitment_packet_state())
            .map_err(Error::retry_error)?
            .into_iter()
            .map(|value| Sequence::from(value.sequence))
            .collect();

        let height = self
            .retry_wapper(|| self.get_latest_height())
            .map_err(Error::retry_error)?;

        let latest_height = Height::new(REVISION_NUMBER, height).expect("REVISION_NUMBER");

        Ok((packet_commitments, latest_height))
    }

    fn query_packet_receipt(
        &self,
        request: QueryPacketReceiptRequest,
        include_proof: IncludeProof,
    ) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
        let QueryPacketReceiptRequest {
            port_id,
            channel_id,
            sequence,
            height,
        } = request;

        let packet_receipt = self
            .retry_wapper(|| self.query_packet_receipt(&port_id, &channel_id, &sequence))
            .map_err(Error::retry_error)?;

        let packet_receipt_path = ReceiptsPath {
            port_id: port_id.clone(),
            channel_id: channel_id.clone(),
            sequence: sequence.clone(),
        }
        .to_string()
        .as_bytes()
        .to_vec();

        let storage_entry = storage::PacketReceipt(&packet_receipt_path);

        match include_proof {
            IncludeProof::Yes => {
                let query_height = match height {
                    QueryHeight::Latest => {
                        let height = self
                            .get_latest_height()
                            .map_err(|_| Error::query_latest_height())?;
                        Height::new(REVISION_NUMBER, height).expect(&REVISION_NUMBER.to_string())
                    }
                    QueryHeight::Specific(value) => value,
                };
                Ok((
                    packet_receipt,
                    Some(self.generate_storage_proof(
                        &storage_entry,
                        &query_height,
                        "PacketReceipt",
                    )?),
                ))
            }
            IncludeProof::No => Ok((packet_receipt, None)),
        }
    }

    fn query_unreceived_packets(
        &self,
        request: QueryUnreceivedPacketsRequest,
    ) -> Result<Vec<Sequence>, Error> {
        tracing::trace!("in substrate: [query_unreceived_packets]");

        let port_id = PortId::from_str(request.port_id.as_str()).map_err(Error::identifier)?;
        let channel_id =
            ChannelId::from_str(request.channel_id.as_str()).map_err(Error::identifier)?;
        let sequences = request
            .packet_commitment_sequences
            .into_iter()
            .map(Sequence::from)
            .collect::<Vec<_>>();

        let result = self
            .retry_wapper(|| self.get_unreceipt_packet(&port_id, &channel_id, &sequences))
            .map_err(Error::retry_error)?
            .into_iter()
            .map(|value| Sequence::from(value))
            .collect();

        Ok(result)
    }

    fn query_packet_acknowledgement(
        &self,
        request: QueryPacketAcknowledgementRequest,
        include_proof: IncludeProof,
    ) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
        let QueryPacketAcknowledgementRequest {
            port_id,
            channel_id,
            sequence,
            height,
        } = request;

        let packet_acknowledgement = self
            .retry_wapper(|| self.query_packet_acknowledgement(&port_id, &channel_id, &sequence))
            .map_err(Error::retry_error)?;

        let packet_acknowledgement_path = AcksPath {
            port_id: port_id.clone(),
            channel_id: channel_id.clone(),
            sequence: sequence.clone(),
        }
        .to_string()
        .as_bytes()
        .to_vec();

        let storage_entry = storage::Acknowledgements(&packet_acknowledgement_path);

        match include_proof {
            IncludeProof::Yes => {
                let query_height = match height {
                    QueryHeight::Latest => {
                        let height = self
                            .get_latest_height()
                            .map_err(|_| Error::query_latest_height())?;
                        Height::new(REVISION_NUMBER, height).expect(&REVISION_NUMBER.to_string())
                    }
                    QueryHeight::Specific(value) => value,
                };
                Ok((
                    packet_acknowledgement,
                    Some(self.generate_storage_proof(
                        &storage_entry,
                        &query_height,
                        "Acknowledgements",
                    )?),
                ))
            }
            IncludeProof::No => Ok((packet_acknowledgement, None)),
        }
    }

    fn query_packet_acknowledgements(
        &self,
        _request: QueryPacketAcknowledgementsRequest,
    ) -> Result<(Vec<Sequence>, ICSHeight), Error> {
        tracing::trace!("in substrate: [query_packet_acknowledgements]");

        let packet_acknowledgements = self
            .retry_wapper(|| self.get_acknowledge_packet_state())
            .map_err(Error::retry_error)?
            .into_iter()
            .map(|value| Sequence::from(value.sequence))
            .collect();

        let height = self
            .retry_wapper(|| self.get_latest_height())
            .map_err(Error::retry_error)?;

        let latest_height = Height::new(REVISION_NUMBER, height).expect("REVISION_NUMBER");

        Ok((packet_acknowledgements, latest_height))
    }

    fn query_unreceived_acknowledgements(
        &self,
        request: QueryUnreceivedAcksRequest,
    ) -> Result<Vec<Sequence>, Error> {
        tracing::trace!("in substrate: [query_unreceived_acknowledgements] ");

        let port_id = PortId::from_str(request.port_id.as_str()).map_err(Error::identifier)?;
        let channel_id =
            ChannelId::from_str(request.channel_id.as_str()).map_err(Error::identifier)?;
        let sequences = request
            .packet_ack_sequences
            .into_iter()
            .map(Sequence::from)
            .collect::<Vec<_>>();

        let mut unreceived_seqs = vec![];

        for seq in sequences {
            let cmt = self.retry_wapper(|| self.get_packet_commitment(&port_id, &channel_id, &seq));

            // if packet commitment still exists on the original sending chain, then packet ack is unreceived
            // since processing the ack will delete the packet commitment
            if let Ok(_) = cmt {
                unreceived_seqs.push(seq);
            }
        }

        Ok(unreceived_seqs)
    }

    fn query_next_sequence_receive(
        &self,
        request: QueryNextSequenceReceiveRequest,
        include_proof: IncludeProof,
    ) -> Result<(Sequence, Option<MerkleProof>), Error> {
        tracing::trace!("in substrate: [query_next_sequence_receive] ");

        let QueryNextSequenceReceiveRequest {
            port_id,
            channel_id,
            height,
        } = request;

        let next_sequence_receive = self
            .retry_wapper(|| self.query_next_sequence_receive(&port_id, &channel_id))
            .map_err(Error::retry_error)?;

        let next_sequence_receive_path = SeqRecvsPath(port_id.clone(), channel_id.clone())
            .to_string()
            .as_bytes()
            .to_vec();

        let storage_entry = storage::NextSequenceRecv(&next_sequence_receive_path);

        match include_proof {
            IncludeProof::Yes => {
                let query_height = match height {
                    QueryHeight::Latest => {
                        let height = self
                            .get_latest_height()
                            .map_err(|_| Error::query_latest_height())?;
                        Height::new(REVISION_NUMBER, height).expect(&REVISION_NUMBER.to_string())
                    }
                    QueryHeight::Specific(value) => value,
                };
                Ok((
                    next_sequence_receive,
                    Some(self.generate_storage_proof(
                        &storage_entry,
                        &query_height,
                        "NextSequenceRecv",
                    )?),
                ))
            }
            IncludeProof::No => Ok((next_sequence_receive, None)),
        }
    }

    fn query_txs(&self, request: QueryTxRequest) -> Result<Vec<IbcEvent>, Error> {
        tracing::trace!("in substrate: [query_txs]");

        match request {
            // Todo: Related to https://github.com/octopus-network/ibc-rs/issues/88
            QueryTxRequest::Packet(request) => {
                let mut result: Vec<IbcEvent> = vec![];
                if request.sequences.is_empty() {
                    return Ok(result);
                }

                match request.event_id {
                    WithBlockDataType::SendPacket => {
                        let mut send_packet_event = self.get_ibc_send_packet_event(request)?;
                        result.append(&mut send_packet_event);
                    }

                    WithBlockDataType::WriteAck => {
                        let mut ack_event = self.get_ibc_write_acknowledgement_event(request)?;
                        result.append(&mut ack_event);
                    }

                    _ => unimplemented!(),
                }

                Ok(result)
            }

            QueryTxRequest::Client(request) => {
                use ibc::core::ics02_client::events::Attributes;

                // Todo: the client event below is mock
                // replace it with real client event replied from a Substrate chain
                let result: Vec<IbcEvent> = vec![IbcEvent::UpdateClient(
                    ibc::core::ics02_client::events::UpdateClient::from(Attributes {
                        height: match request.query_height {
                            QueryHeight::Latest => {
                                let height = self
                                    .get_latest_height()
                                    .map_err(|_| Error::query_latest_height())?;
                                Height::new(REVISION_NUMBER, height)
                                    .expect(&REVISION_NUMBER.to_string())
                            }
                            QueryHeight::Specific(value) => value.clone(),
                        },
                        client_id: request.client_id,
                        client_type: ClientType::Grandpa,
                        consensus_height: request.consensus_height,
                    }),
                )];

                Ok(result)
            }

            QueryTxRequest::Transaction(_tx) => {
                // tracing::trace!("in substrate: [query_txs]: Transaction: {:?}", tx);
                // Todo: https://github.com/octopus-network/ibc-rs/issues/98
                let result: Vec<IbcEvent> = vec![];
                Ok(result)
            }
        }
    }

    fn query_blocks(
        &self,
        _request: QueryBlockRequest,
    ) -> Result<(Vec<IbcEvent>, Vec<IbcEvent>), Error> {
        tracing::trace!("in substrate: [query_block]");

        Ok((vec![], vec![]))
    }

    fn query_host_consensus_state(
        &self,
        request: QueryHostConsensusStateRequest,
    ) -> Result<AnyConsensusState, Error> {
        tracing::trace!("in substrate: [query_host_consensus_state]");

        Ok(AnyConsensusState::Grandpa(GPConsensusState::default()))
    }

    fn build_client_state(
        &self,
        height: ICSHeight,
        _dst_config: ClientSettings,
    ) -> Result<Self::ClientState, Error> {
        tracing::trace!("in substrate: [build_client_state]");

        let public_key = async {
            let client = self.client.clone();

            let api =
                client.to_runtime_api::<RuntimeApi<MyConfig, SubstrateNodeTemplateExtrinsicParams<MyConfig>>>();

            let authorities = api
                .storage()
                .beefy()
                .authorities(None)
                .await
                .map_err(|_| Error::authorities())?;

            let result: Vec<String> = authorities
                .into_iter()
                .map(|val| format!("0x{}", HexDisplay::from(&val.to_raw_vec())))
                .collect();

            Ok(result)
        };
        let public_key = self.block_on(public_key)?;

        let beefy_light_client = beefy_light_client::new(public_key);

        // Build client state
        let client_state = GPClientState::new(
            self.id().clone(),
            height.revision_height() as u32,
            Commitment::default(),
            beefy_light_client.validator_set.into(),
        )
        .map_err(Error::ics10)?;

        Ok(AnyClientState::Grandpa(client_state))
    }

    fn build_consensus_state(
        &self,
        light_block: Self::LightBlock,
    ) -> Result<Self::ConsensusState, Error> {
        tracing::trace!(
            "in substrate: [build_consensus_state] light_block:{:?}",
            light_block
        );
        //build consensus state from header
        let commitment = light_block.mmr_root.signed_commitment.commitment.unwrap();
        let state_root = CommitmentRoot::from_bytes(&light_block.block_header.state_root);
        let consensue_state = GPConsensusState::new(commitment, state_root, light_block.timestamp);
        Ok(AnyConsensusState::Grandpa(consensue_state))
    }

    fn build_header(
        &self,
        trusted_height: ICSHeight,
        target_height: ICSHeight,
        client_state: &AnyClientState,
        _light_client: &mut Self::LightClient,
    ) -> Result<(Self::Header, Vec<Self::Header>), Error> {
        tracing::trace!("in substrate [build_header]");

        assert!(trusted_height.revision_height() < target_height.revision_height());

        let grandpa_client_state = match client_state {
            AnyClientState::Grandpa(state) => state,
            _ => unimplemented!(),
        };

        // assert trust_height <= grandpa_client_state height
        if trusted_height.revision_height() > grandpa_client_state.latest_height as u64 {
            return Err(Error::trust_height_miss_match_client_state_height(
                trusted_height.revision_height(),
                grandpa_client_state.latest_height as u64,
            ));
        }

        let beefy_light_client::commitment::Commitment {
            payload,
            block_number,
            validator_set_id,
        } = grandpa_client_state.clone().latest_commitment.into();
        let mmr_root_height = block_number;
        let target_height = target_height.revision_height() as u32;

        // build target height header
        let future = async {
            let client = self.client.clone();

            //build mmr root
            let mmr_root = if target_height > mmr_root_height {
                tracing::trace!(
                    "in substrate [build_header] target_height > mmr_root_height, target_height = {:?},  mmr_root_height = {:?}, need to build new mmr root",
                    target_height,mmr_root_height
                );
                // subscribe beefy justification and get signed commitment
                let raw_signed_commitment = octopusxt::ibc_rpc::subscribe_beefy(client.clone())
                    .await
                    .map_err(|_| Error::get_signed_commitment())?;

                // decode signed commitment
                let signed_commmitment: beefy_light_client::commitment::SignedCommitment =
                    Decode::decode(&mut &raw_signed_commitment.0[..]).unwrap();
                tracing::trace!(
                    "in substrate [build_header] decode signed commitment : {:?},",
                    signed_commmitment
                );
                // get commitment
                let beefy_light_client::commitment::Commitment {
                    payload,
                    block_number,
                    validator_set_id,
                } = signed_commmitment.commitment.clone();
                tracing::trace!(
                    "in substrate [build_header] new mmr root block_number : {:?},",
                    block_number
                );
                // build validator proof
                let validator_merkle_proofs: Vec<ValidatorMerkleProof> =
                    octopusxt::update_client_state::build_validator_proof(
                        client.clone(),
                        block_number,
                    )
                    .await
                    .map_err(|_| Error::get_validator_merkle_proof())?;

                // build mmr proof
                let api =
                    client.clone().to_runtime_api::<RuntimeApi<MyConfig, SubstrateNodeTemplateExtrinsicParams<MyConfig>>>();
                // get block hash
                let block_hash: Option<H256> = api
                    .client
                    .rpc()
                    .block_hash(Some(BlockNumber::from(block_number)))
                    .await
                    .map_err(|_| Error::get_block_hash_error())?;
                // create proof
                let mmr_leaf_and_mmr_leaf_proof = octopusxt::ibc_rpc::get_mmr_leaf_and_mmr_proof(
                    Some(BlockNumber::from(target_height - 1)),
                    block_hash,
                    client.clone(),
                )
                .await
                .map_err(|_| Error::get_mmr_leaf_and_mmr_proof_error())?;

                // build new mmr root
                MmrRoot {
                    signed_commitment: signed_commmitment.into(),
                    validator_merkle_proofs: validator_merkle_proofs,
                    mmr_leaf: mmr_leaf_and_mmr_leaf_proof.1,
                    mmr_leaf_proof: mmr_leaf_and_mmr_leaf_proof.2,
                }
            } else {
                tracing::trace!(
                    "in substrate [build_header] target_height <= mmr_root_height, mmr_root_height = {:?}, target_height = {:?}, just get mmr leaf and proof",
                    mmr_root_height,
                    target_height
                );

                let api =
                client.clone().to_runtime_api::<RuntimeApi<MyConfig, SubstrateNodeTemplateExtrinsicParams<MyConfig>>>();
                // get block hash
                let block_hash: Option<H256> = api
                    .client
                    .rpc()
                    .block_hash(Some(BlockNumber::from(mmr_root_height)))
                    .await
                    .map_err(|_| Error::get_block_hash_error())?;

                tracing::trace!(
                    "in substrate [build_header] >> block_hash = {:?}",
                    block_hash
                );
                // build mmr proof
                let (block_hash, mmr_leaf, mmr_leaf_proof) =
                    octopusxt::ibc_rpc::get_mmr_leaf_and_mmr_proof(
                        Some(BlockNumber::from(target_height - 1)),
                        block_hash,
                        client.clone(),
                    )
                    .await
                    .map_err(|_| Error::get_mmr_leaf_and_mmr_proof_error())?;
                tracing::trace!(
                    "in substrate [build_header] >> block_hash = {:?}",
                    block_hash
                );

                // build signed_commitment
                let signed_commitment = SignedCommitment {
                    commitment: Some(grandpa_client_state.latest_commitment.clone()),
                    signatures: vec![],
                };
                tracing::trace!("in substrate [build_header] build signed_commitment by grandpa_client_state.latest_commitment: {:?}",signed_commitment);
                MmrRoot {
                    signed_commitment: signed_commitment,
                    validator_merkle_proofs: vec![ValidatorMerkleProof::default()],
                    mmr_leaf: mmr_leaf,
                    mmr_leaf_proof: mmr_leaf_proof,
                }
            };

            // get block header
            let block_header = octopusxt::ibc_rpc::get_header_by_block_number(
                Some(BlockNumber::from(target_height)),
                client.clone(),
            )
            .await
            .map_err(|_| Error::get_header_by_block_number_error())?;
            // let block_header = block_header.unwrap();
            tracing::trace!(
                "in substrate [build_header] block_header: {:?}",
                block_header
            );

            // //TODO:[test] log mmr leaf
            // tracing::trace!("in substrate [build_header] ---------------------test[begin]-----------------------");
            // let mmr_leaf: Vec<u8> = Decode::decode(&mut &mmr_root.mmr_leaf.clone()[..]).unwrap();
            // tracing::trace!("in substrate [build_header] test_mmr_leaf decode to Vec<u8>: {:?}",mmr_leaf);
            // let mmr_leaf: beefy_light_client::mmr::MmrLeaf =
            //     Decode::decode(&mut &*mmr_leaf).unwrap();
            // tracing::trace!("in substrate [build_header] test_mmr_leaf to data struct: {:?}",mmr_leaf);

            // //TODO:[test] log mmr leaf proof
            // let mmr_leaf_proof = beefy_light_client::mmr::MmrLeafProof::decode(
            //     &mut &mmr_root.mmr_leaf_proof.clone()[..],
            // )
            // .unwrap();
            // tracing::trace!("in substrate [build_header]  block_header.block_number:{:?},mmr root heigh:{:?},mmr_leaf.parent_number:{:?},mmr_leaf_proof.leaf_index{:?},mmr_leaf_proof.leaf_count: {:?}",block_header.block_number,block_number,mmr_leaf.parent_number_and_hash.0,mmr_leaf_proof.leaf_index, mmr_leaf_proof.leaf_count);

            // // log mmr leaf
            // tracing::trace!("in substrate [build_header] block_header.parent_hash: {:?}",block_header.parent_hash);
            // tracing::trace!("in substrate [build_header] mmr_leaf.parent_number_and_hash.1.to_vec(): {:?}",mmr_leaf.parent_number_and_hash.1.to_vec());
            // // verfiy block header
            // if block_header.parent_hash != mmr_leaf.parent_number_and_hash.1.to_vec() {
            //     tracing::trace!("in substrate [build_header] header.block_header.parent_hash != mmr_leaf.parent_number_and_hash.1.to_vec()");
            // } else {
            //     tracing::trace!("in substrate [build_header] header.block_header.parent_hash == mmr_leaf.parent_number_and_hash.1.to_vec()");
            // }

            // let beefy_header =
            //     beefy_light_client::header::Header::try_from(block_header.clone()).unwrap();
            // let header_hash = beefy_header.hash();
            // tracing::trace!("in substrate [build_header] header_hash: {:?}",header_hash);
            // tracing::trace!("in substrate [build_header] mmr_leaf.parent_number_and_hash.1: {:?}",mmr_leaf.parent_number_and_hash.1);
            // if header_hash != mmr_leaf.parent_number_and_hash.1 {
            //     tracing::trace!("in substrate [build_header] header_hash != mmr_leaf.parent_number_and_hash.1");
            // } else {
            //     tracing::trace!("in substrate [build_header]header_hash == mmr_leaf.parent_number_and_hash.1");
            // }

            // tracing::trace!("in substrate [build_header] ---------------------test[end]-----------------------");

            //build timestamp
            let timestamp = Time::from_unix_timestamp(0, 0).unwrap();
            tracing::trace!(
                "in substrate: [build_header] >> timestamp = {:?}",
                timestamp
            );

            // build header
            let grandpa_header = GPHeader {
                mmr_root: mmr_root,
                block_header: block_header,
                timestamp: timestamp,
            };

            tracing::trace!(
                "in substrate: [build_header] >> grandpa_header = {:?}",
                grandpa_header
            );
            Ok(grandpa_header)
        };

        let header = self.block_on(future)?;
        Ok((header, vec![]))
    }

    /// add new api websocket_url
    fn websocket_url(&self) -> Result<String, Error> {
        tracing::trace!("in substrate: [websocket_url]");

        Ok(self.websocket_url.clone())
    }

    /// add new api update_mmr_root
    fn update_mmr_root(&mut self, client_id: ClientId, header: GPHeader) -> Result<(), Error> {
        tracing::trace!("[update_mmr_root] client_id = {:?} ", client_id,);

        let MmrRoot {
            signed_commitment,
            validator_merkle_proofs,
            mmr_leaf,
            mmr_leaf_proof,
        } = header.mmr_root.clone();

        let new_mmr_root_height = signed_commitment.clone().commitment.unwrap().block_number;
        tracing::trace!(
            "[update_mmr_root] mmr root height = {:?}",
            new_mmr_root_height
        );
        let client_state = self.query_client_state(&client_id).unwrap();
        let gp_client_state = match client_state {
            AnyClientState::Grandpa(value) => value,
            _ => unimplemented!(),
        };

        let beefy_light_client::commitment::Commitment {
            payload,
            block_number,
            validator_set_id,
        } = gp_client_state.latest_commitment.clone().into();

        tracing::trace!(
            "[update_mmr_root] mmr root height in client state is: ({:?}) and  new mmr root height is ({:?})!",
            block_number,new_mmr_root_height
        );

        if block_number >= new_mmr_root_height {
            tracing::trace!(
                "[update_mmr_root]mmr root height in client state ({:?}) >= new mmr root height({:?}), Don't need to update!",
                block_number,new_mmr_root_height
            );
            return Err(Error::update_client_state_error());
        }

        let mut msgs = vec![];

        let signer = self.get_signer().unwrap();
        use ibc::core::ics02_client::header::AnyHeader;
        msgs.push(
            MsgUpdateAnyClient {
                header: AnyHeader::Grandpa(header),
                signer: signer,
                client_id: client_id,
            }
            .to_any(),
        );

        let tm = TrackedMsgs::new_static(msgs, "update client");
        tracing::trace!("in substrate: [update_mmr_root] >> msgs = {:?}", tm);

        let events = self.send_messages_and_wait_commit(tm);
        tracing::trace!("in substrate: [update_mmr_root] >> events = {:?}", events);

        Ok(())
    }
}

/// send Update client state request
pub async fn send_update_state_request(
    client: Client<MyConfig>,
    pair_signer: PairSigner<MyConfig, sr25519::Pair>,
    chain_id: ChainId,
    client_id: ClientId,
    mmr_root: MmrRoot,
) -> Result<H256, Box<dyn std::error::Error>> {
    tracing::info!("in substrate: [send_update_state_request]");

    let api = client
        .to_runtime_api::<RuntimeApi<MyConfig, SubstrateNodeTemplateExtrinsicParams<MyConfig>>>();

    let encode_client_id = client_id.as_bytes().to_vec();
    let encode_mmr_root = <MmrRoot as Encode>::encode(&mmr_root);

    let result = api
        .tx()
        .ibc()
        .update_client_state(encode_client_id, encode_mmr_root)?
        .sign_and_submit_default(&pair_signer)
        .await?;

    tracing::info!("update client state result: {:?}", result);

    Ok(result)
}
// Todo: to create a new type in `commitment_proof::Proof`
/// Compose merkle proof according to ibc proto
pub fn compose_ibc_merkle_proof(proof: String) -> MerkleProof {
    use ics23::{commitment_proof, ExistenceProof, InnerOp};
    tracing::trace!("in substrate: [compose_ibc_merkle_proof]");

    let _inner_op = InnerOp {
        hash: 0,
        prefix: vec![0],
        suffix: vec![0],
    };

    let proof = commitment_proof::Proof::Exist(ExistenceProof {
        key: vec![0],
        value: proof.as_bytes().to_vec(),
        leaf: None,
        path: vec![_inner_op],
    });

    let parsed = ics23::CommitmentProof { proof: Some(proof) };
    let mproofs: Vec<ics23::CommitmentProof> = vec![parsed];
    MerkleProof { proofs: mproofs }
}
pub fn get_dummy_merkle_proof() -> MerkleProof {
    let parsed = ics23::CommitmentProof { proof: None };
    let mproofs: Vec<ics23::CommitmentProof> = vec![parsed];
    MerkleProof { proofs: mproofs }
}

use feignhttp::get;
#[get("https://github.com/livelybug/ibc-rs/blob/dev/modules/tests/support/signed_header.json")]
async fn get_singed_header() -> feignhttp::Result<String> {}

pub async fn get_dummy_ics07_header() -> tHeader {
    use tendermint::block::signed_header::SignedHeader;
    let singed_header = get_singed_header().await.unwrap();
    let shdr = serde_json::from_str::<SignedHeader>(&singed_header)
    .unwrap();

    // Build a set of validators.
    // Below are test values inspired form `test_validator_set()` in tendermint-rs.
    use subtle_encoding::hex;
    use tendermint::validator::Info as ValidatorInfo;
    use tendermint::PublicKey;

    let v1: ValidatorInfo = ValidatorInfo::new(
        PublicKey::from_raw_ed25519(
            &hex::decode_upper("F349539C7E5EF7C49549B09C4BFC2335318AB0FE51FBFAA2433B4F13E816F4A7")
                .unwrap(),
        )
        .unwrap(),
        281_815_u64.try_into().unwrap(),
    );

    use tendermint::validator::Set as ValidatorSet;
    let vs = ValidatorSet::new(vec![v1.clone()], Some(v1));

    tHeader {
        signed_header: shdr,
        validator_set: vs.clone(),
        trusted_height: Height::new(REVISION_NUMBER, 1).expect("REVISION_NUMBER"),
        trusted_validator_set: vs,
    }
}

#[test]
fn test_compose_ibc_merkle_proof() {
    use core::convert::TryFrom;
    use ibc_proto::ibc::core::commitment::v1::MerkleProof as RawMerkleProof;
    use ibc_proto::ics23::commitment_proof::Proof::Exist;
    use serde::{Deserialize, Serialize};

    let ibc_proof = compose_ibc_merkle_proof("proof".to_string());
    let merkel_proof = RawMerkleProof::try_from(ibc_proof).unwrap();
    let _merkel_proof = merkel_proof.proofs[0].proof.clone().unwrap();

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ReadProofU8 {
        pub at: String,
        pub proof: Vec<Vec<u8>>,
    }

    match _merkel_proof {
        Exist(_exist_proof) => {
            let _proof_str = String::from_utf8(_exist_proof.value).unwrap();
            assert_eq!(_proof_str, "proof".to_string());
        }
        _ => unimplemented!(),
    };
}
