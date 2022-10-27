use alloc::string::String;
use alloc::string::ToString;

use crate::core::ics02_client::error::Error as Ics02Error;
use crate::core::ics24_host::error::ValidationError;
use crate::core::ics24_host::identifier::ClientId;
use crate::timestamp::Timestamp;
use crate::timestamp::TimestampOverflowError;
use crate::Height;
use flex_error::{define_error, DisplayOnly, TraceError};
define_error! {
     #[derive(Debug, PartialEq, Eq)]
    Error{
        Dummy
            |_| { format_args!("dummy error") },

        Decode
            [ TraceError<prost::DecodeError> ]
            | _ | { "decode error" },

        MissingLatestHeight
            | _ | { "missing latest height" },

        MissingHeight
            | _ | { "missing height" },

        InvalidChainIdentifier
            [ ValidationError ]
            | _ | { "invalid chain identifier" },

        MissingFrozenHeight
            | _ | { "missing frozen height" },

        InvalidRawConsensusState
            { reason: String }
            | _ | { "invalid raw client consensus state" },

        InvalidRawMisbehaviour
            { reason: String }
            | _ | { "invalid raw misbehaviour" },
        InvalidRawHeader
            { reason: String }
            | _ | { "invalid raw header" },

        Encode
            [ TraceError<prost::EncodeError> ]
            | _ | { "encode error" },

        EmptyCommitment
            | _ | { "empty commitment"},

        InvalidSignedCommitment
            | _ | { "invalid Signed Commitment" },

        InvalidValidatorMerkleProof
            | _ | { "invalid Validator Merkle Proof" },

        InvalidMmrLeaf
            | _ | { "invalid Mmr Leaf" },

        InvalidMmrLeafProof
            | _ | { "invalid Mmr Lead Proof" },

        InvalidCommitment
            | _ | { "Invalid commitment"},

        InvalidStorageProof
            | _ | { "invalid storage Proof" },

        GetStorageByProofErr
            {
                e: String,
            }
            | e | {
                format_args!("failed to get storage by proof: {0}", e)
            },

        InvalidChainId
            | _ | { "invalid chain id" },

        EmptyBlockHeader
            | _ | { "empty block header" },

        EmptyLatestCommitment
            | _ | { "empty latest commitment" },

        EmptyValidatorSet
            | _ | { "empty validator set" },

        EmptyMmrLeaf
            | _ | { "empty mmr leaf" },

        EmptyMmrLeafProof
            | _ | { "empty mmr leaf proof" },

        EmptyMmrRoot
            | _ | { "empty mmr root" },

        EmptyTimestamp
            | _ | { "empty timestamp" },

        EmptySignedCommitment
            | _ | { "empty signed commitment" },

        InvalidConvertHash
            | _ | { "invalid convert hash" },

        InvalidConvertSignature
            | _ | { "invalid convert signature" },

        EmptyParentNumberAndHash
            | _ | { "empty parent and hash" },

        EmptyBeefyNextAuthoritySet
            | _ | { "empty next authority set" },

        InvalidCodecDecode
            [ DisplayOnly<codec::Error> ]
            |_| { "invalid codec decode" },

        InvalidMmrRoot
            { reason: String }
            |e| { format_args!("invalid mmr root, failed basic validation: {}", e.reason) },

        ProcessedTimeNotFound
            {
                client_id: ClientId,
                height: Height,
            }
            | e | {
                format_args!(
                    "Processed time for the client {0} at height {1} not found",
                    e.client_id, e.height)
            },

        ProcessedHeightNotFound
            {
                client_id: ClientId,
                height: Height,
            }
            | e | {
                format_args!(
                    "Processed height for the client {0} at height {1} not found",
                    e.client_id, e.height)
            },

        InsufficientHeight
            {
                latest_height: Height,
                target_height: Height,
            }
            | e | {
                format_args!("the height is insufficient: latest_height={0} target_height={1}", e.latest_height, e.target_height)
            },

        ClientFrozen
            {
                frozen_height: Height,
                target_height: Height,
            }
            | e | {
                format_args!("the client is frozen: frozen_height={0} target_height={1}", e.frozen_height, e.target_height)
            },

        NotEnoughTimeElapsed
            {
                current_time: Timestamp,
                earliest_time: Timestamp,
            }
            | e | {
                format_args!("not enough time elapsed, current timestamp {0} is still less than earliest acceptable timestamp {1}", e.current_time, e.earliest_time)
            },

        NotEnoughBlocksElapsed
            {
                current_height: Height,
                earliest_height: Height,
            }
            | e | {
                format_args!("not enough blocks elapsed, current height {0} is still less than earliest acceptable height {1}", e.current_height, e.earliest_height)
            },

        TimestampOverflow
            [ TimestampOverflowError ]
            |_| { "timestamp overflowed" },

    }
}

impl From<Error> for Ics02Error {
    fn from(e: Error) -> Self {
        Self::client_specific(e.to_string())
    }
}
