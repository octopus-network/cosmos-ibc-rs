use crate::core::ics03_connection::connection::ConnectionEnd;
use crate::core::ics04_channel::channel::ChannelEnd;
use crate::core::ics04_channel::context::ChannelReader;
use crate::core::ics04_channel::error::ChannelError;
use crate::core::ics04_channel::msgs::acknowledgement::Acknowledgement;
use crate::core::ics04_channel::packet::{Packet, Sequence};
use crate::prelude::*;
use crate::proofs::Proofs;
use crate::Height;

/// Entry point for verifying all proofs bundled in any ICS4 message for channel protocols.
pub fn verify_channel_proofs<Ctx: ChannelReader>(
    ctx: &Ctx,
    height: Height,
    channel_end: &ChannelEnd,
    connection_end: &ConnectionEnd,
    expected_chan: &ChannelEnd,
    proofs: &Proofs,
) -> Result<(), ChannelError> {
    // This is the client which will perform proof verification.
    let client_id = connection_end.client_id().clone();

    let client_state = ctx.client_state(&client_id)?;

    // The client must not be frozen.
    if client_state.is_frozen() {
        return Err(ChannelError::FrozenClient { client_id });
    }

    let consensus_state = ctx.client_consensus_state(&client_id, &proofs.height())?;

    // Verify the proof for the channel state against the expected channel end.
    // A counterparty channel id of None in not possible, and is checked by validate_basic in msg.
    client_state
        .verify_channel_state(
            height,
            connection_end.counterparty().prefix(),
            proofs.object_proof(),
            consensus_state.root(),
            channel_end.counterparty().port_id(),
            channel_end
                .counterparty()
                .channel_id()
                .ok_or(ChannelError::InvalidCounterpartyChannelId)?,
            expected_chan,
        )
        .map_err(ChannelError::VerifyChannelFailed)
}

/// Entry point for verifying all proofs bundled in a ICS4 packet recv. message.
pub fn verify_packet_recv_proofs<Ctx: ChannelReader>(
    ctx: &Ctx,
    height: Height,
    packet: &Packet,
    connection_end: &ConnectionEnd,
    proofs: &Proofs,
) -> Result<(), ChannelError> {
    let client_id = connection_end.client_id();
    let client_state = ctx.client_state(client_id)?;

    // The client must not be frozen.
    if client_state.is_frozen() {
        return Err(ChannelError::FrozenClient {
            client_id: client_id.clone(),
        });
    }

    let consensus_state = ctx.client_consensus_state(client_id, &proofs.height())?;

    let commitment = ctx.packet_commitment(
        &packet.data,
        &packet.timeout_height,
        &packet.timeout_timestamp,
    );

    // Verify the proof for the packet against the chain store.
    client_state
        .verify_packet_data(
            ctx,
            height,
            connection_end,
            proofs.object_proof(),
            consensus_state.root(),
            &packet.source_port,
            &packet.source_channel,
            packet.sequence,
            commitment,
        )
        .map_err(|e| ChannelError::PacketVerificationFailed {
            sequence: packet.sequence,
            client_error: e,
        })?;

    Ok(())
}

/// Entry point for verifying all proofs bundled in an ICS4 packet ack message.
pub fn verify_packet_acknowledgement_proofs<Ctx: ChannelReader>(
    ctx: &Ctx,
    height: Height,
    packet: &Packet,
    acknowledgement: Acknowledgement,
    connection_end: &ConnectionEnd,
    proofs: &Proofs,
) -> Result<(), ChannelError> {
    let client_id = connection_end.client_id();
    let client_state = ctx.client_state(client_id)?;

    // The client must not be frozen.
    if client_state.is_frozen() {
        return Err(ChannelError::FrozenClient {
            client_id: client_id.clone(),
        });
    }

    let consensus_state = ctx.client_consensus_state(client_id, &proofs.height())?;

    let ack_commitment = ctx.ack_commitment(&acknowledgement);

    // Verify the proof for the packet against the chain store.
    client_state
        .verify_packet_acknowledgement(
            ctx,
            height,
            connection_end,
            proofs.object_proof(),
            consensus_state.root(),
            &packet.destination_port,
            &packet.destination_channel,
            packet.sequence,
            ack_commitment,
        )
        .map_err(|e| ChannelError::PacketVerificationFailed {
            sequence: packet.sequence,
            client_error: e,
        })?;

    Ok(())
}

/// Entry point for verifying all timeout proofs.
pub fn verify_next_sequence_recv<Ctx: ChannelReader>(
    ctx: &Ctx,
    height: Height,
    connection_end: &ConnectionEnd,
    packet: Packet,
    seq: Sequence,
    proofs: &Proofs,
) -> Result<(), ChannelError> {
    let client_id = connection_end.client_id();
    let client_state = ctx.client_state(client_id)?;

    // The client must not be frozen.
    if client_state.is_frozen() {
        return Err(ChannelError::FrozenClient {
            client_id: client_id.clone(),
        });
    }

    let consensus_state = ctx.client_consensus_state(client_id, &proofs.height())?;

    // Verify the proof for the packet against the chain store.
    client_state
        .verify_next_sequence_recv(
            ctx,
            height,
            connection_end,
            proofs.object_proof(),
            consensus_state.root(),
            &packet.destination_port,
            &packet.destination_channel,
            packet.sequence,
        )
        .map_err(|e| ChannelError::PacketVerificationFailed {
            sequence: seq,
            client_error: e,
        })?;

    Ok(())
}

pub fn verify_packet_receipt_absence<Ctx: ChannelReader>(
    ctx: &Ctx,
    height: Height,
    connection_end: &ConnectionEnd,
    packet: Packet,
    proofs: &Proofs,
) -> Result<(), ChannelError> {
    let client_id = connection_end.client_id();
    let client_state = ctx.client_state(client_id)?;

    // The client must not be frozen.
    if client_state.is_frozen() {
        return Err(ChannelError::FrozenClient {
            client_id: client_id.clone(),
        });
    }

    let consensus_state = ctx.client_consensus_state(client_id, &proofs.height())?;

    // Verify the proof for the packet against the chain store.
    client_state
        .verify_packet_receipt_absence(
            ctx,
            height,
            connection_end,
            proofs.object_proof(),
            consensus_state.root(),
            &packet.destination_port,
            &packet.destination_channel,
            packet.sequence,
        )
        .map_err(|e| ChannelError::PacketVerificationFailed {
            sequence: packet.sequence,
            client_error: e,
        })?;

    Ok(())
}
