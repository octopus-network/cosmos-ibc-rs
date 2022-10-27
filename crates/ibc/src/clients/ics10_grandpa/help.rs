use crate::clients::ics10_grandpa::error::Error;
use alloc::vec;
use alloc::vec::Vec;
use beefy_light_client::mmr::MmrLeafVersion;
use beefy_merkle_tree::Hash;
use codec::{Decode, Encode};
use core::convert::TryFrom;
use serde::{Deserialize, Serialize};

use ibc_proto::ibc::lightclients::grandpa::v1::BlockHeader as RawBlockHeader;
use ibc_proto::ibc::lightclients::grandpa::v1::Commitment as RawCommitment;
use ibc_proto::ibc::lightclients::grandpa::v1::InnerSignature;
use ibc_proto::ibc::lightclients::grandpa::v1::MmrLeaf as RawMmrLeaf;
use ibc_proto::ibc::lightclients::grandpa::v1::MmrLeafProof as RawMmrLeafProof;
use ibc_proto::ibc::lightclients::grandpa::v1::ParentNumberAndHash as RawParentNumberAndHash;
use ibc_proto::ibc::lightclients::grandpa::v1::Signature as RawSignature;
use ibc_proto::ibc::lightclients::grandpa::v1::SignedCommitment as RawSignedCommitment;
use ibc_proto::ibc::lightclients::grandpa::v1::ValidatorMerkleProof as RawValidatorMerkleProof;
use ibc_proto::ibc::lightclients::grandpa::v1::ValidatorSet as RawValidatorSet;

use crate::Height;
use alloc::string::ToString;
use beefy_light_client::commitment::known_payload_ids::MMR_ROOT_ID;
use beefy_light_client::commitment::Commitment as BeefyCommitment;
use beefy_light_client::commitment::Payload;
use beefy_light_client::ValidatorMerkleProof as BeefyValidatorMerkleProof;
use beefy_light_client::{commitment, header, mmr, validator_set};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct Commitment {
    /// block height
    pub block_number: u32,
    /// mmr root
    pub payload: Payload,
    ///validator_set_id
    pub validator_set_id: u64,
}

impl Default for Commitment {
    fn default() -> Self {
        Self {
            block_number: 0,
            payload: Payload(vec![]),
            validator_set_id: 0,
        }
    }
}

impl From<BeefyCommitment> for Commitment {
    fn from(value: BeefyCommitment) -> Self {
        Self {
            block_number: value.block_number,
            payload: value.payload.into(),
            validator_set_id: value.validator_set_id,
        }
    }
}

impl From<Commitment> for BeefyCommitment {
    fn from(value: Commitment) -> Self {
        Self {
            payload: value.payload.into(),
            block_number: value.block_number,
            validator_set_id: value.validator_set_id,
        }
    }
}

impl From<RawCommitment> for Commitment {
    fn from(raw: RawCommitment) -> Self {
        Self {
            block_number: raw.block_number,
            payload: Payload::new(MMR_ROOT_ID, raw.payload),
            validator_set_id: raw.validator_set_id,
        }
    }
}
impl From<Commitment> for RawCommitment {
    fn from(value: Commitment) -> Self {
        Self {
            block_number: value.block_number,
            payload: value
                .payload
                .get_raw(&MMR_ROOT_ID)
                .map(|value| value.clone())
                .unwrap_or_default(),
            validator_set_id: value.validator_set_id,
        }
    }
}

/// A typedef for validator set id.
pub type ValidatorSetId = u64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct ValidatorSet {
    /// Id of the next set.
    ///
    /// Id is required to correlate BEEFY signed commitments with the validator set.
    /// Light Client can easily verify that the commitment witness it is getting is
    /// produced by the latest validator set.
    pub id: ValidatorSetId,

    /// Number of validators in the set.
    ///
    /// Some BEEFY Light Clients may use an interactive protocol to verify only subset
    /// of signatures. We put set length here, so that these clients can verify the minimal
    /// number of required signatures.
    pub len: u32,
    /// Merkle Root Hash build from BEEFY AuthorityIds.
    ///
    /// This is used by Light Clients to confirm that the commitments are signed by the correct
    /// validator set. Light Clients using interactive protocol, might verify only subset of
    /// signatures, hence don't require the full list here (will receive inclusion proofs).
    pub root: Vec<u8>,
}

impl From<validator_set::BeefyNextAuthoritySet> for ValidatorSet {
    fn from(value: validator_set::BeefyNextAuthoritySet) -> Self {
        Self {
            id: value.id,
            len: value.len,
            root: Vec::from(value.root),
        }
    }
}

impl From<ValidatorSet> for validator_set::BeefyNextAuthoritySet {
    fn from(value: ValidatorSet) -> Self {
        Self {
            id: value.id,
            len: value.len,
            root: Hash::try_from(value.root).unwrap_or([0; 32]),
        }
    }
}
impl From<RawValidatorSet> for ValidatorSet {
    fn from(raw: RawValidatorSet) -> Self {
        Self {
            id: raw.id,
            len: raw.len,
            root: raw.root,
        }
    }
}

impl From<ValidatorSet> for RawValidatorSet {
    fn from(value: ValidatorSet) -> Self {
        Self {
            id: value.id,
            len: value.len,
            root: value.root,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct MmrLeaf {
    //// Version of the leaf format.
    //// Can be used to enable future format migrations and compatibility.
    pub version: u32,
    //// Current block parent number and hash.
    pub parent_number_and_hash: ParentNumberAndHash,
    //// A merkle root of the next BEEFY authority set.
    pub beefy_next_authority_set: ValidatorSet,
    //// A merkle root of all registered parachain heads.
    pub leaf_extra: Vec<u8>,
}

impl From<mmr::MmrLeaf> for MmrLeaf {
    fn from(value: mmr::MmrLeaf) -> Self {
        Self {
            version: value.version.0 as u32,
            parent_number_and_hash: ParentNumberAndHash {
                parent_header_number: value.parent_number_and_hash.0,
                parent_header_hash: Vec::from(value.parent_number_and_hash.1),
            },
            beefy_next_authority_set: ValidatorSet::from(value.beefy_next_authority_set),
            leaf_extra: Vec::from(value.leaf_extra),
        }
    }
}

impl TryFrom<MmrLeaf> for mmr::MmrLeaf {
    type Error = Error;

    fn try_from(value: MmrLeaf) -> Result<Self, Self::Error> {
        Ok(Self {
            version: MmrLeafVersion(value.version as u8),
            parent_number_and_hash: (
                value.parent_number_and_hash.parent_header_number,
                Hash::try_from(value.parent_number_and_hash.parent_header_hash)
                    .map_err(|_| Error::invalid_convert_hash())?,
            ),
            beefy_next_authority_set: validator_set::BeefyNextAuthoritySet::from(
                value.beefy_next_authority_set,
            ),
            leaf_extra: value.leaf_extra,
        })
    }
}

impl TryFrom<RawMmrLeaf> for MmrLeaf {
    type Error = Error;
    fn try_from(raw: RawMmrLeaf) -> Result<Self, Self::Error> {
        Ok(Self {
            version: raw.version,
            parent_number_and_hash: raw
                .parent_number_and_hash
                .ok_or_else(Error::empty_parent_number_and_hash)?
                .into(),
            beefy_next_authority_set: raw
                .beefy_next_authority_set
                .ok_or_else(Error::empty_beefy_next_authority_set)?
                .into(),
            leaf_extra: raw.leaf_extra,
        })
    }
}

impl From<MmrLeaf> for RawMmrLeaf {
    fn from(value: MmrLeaf) -> Self {
        Self {
            version: value.version,
            parent_number_and_hash: Some(value.parent_number_and_hash.into()),
            beefy_next_authority_set: Some(value.beefy_next_authority_set.into()),
            leaf_extra: value.leaf_extra,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct ParentNumberAndHash {
    pub parent_header_number: u32,
    /// header hash
    pub parent_header_hash: Vec<u8>,
}

impl From<RawParentNumberAndHash> for ParentNumberAndHash {
    fn from(raw: RawParentNumberAndHash) -> Self {
        Self {
            parent_header_number: raw.block_number,
            parent_header_hash: raw.mmr_root,
        }
    }
}

impl From<ParentNumberAndHash> for RawParentNumberAndHash {
    fn from(value: ParentNumberAndHash) -> Self {
        Self {
            block_number: value.parent_header_number,
            mmr_root: value.parent_header_hash,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
pub struct SignedCommitment {
    pub commitment: Option<Commitment>,
    pub signatures: Vec<Option<Signature>>,
}

impl SignedCommitment {
    pub fn from_height(height: Height) -> SignedCommitment {
        SignedCommitment {
            commitment: Some(Commitment {
                block_number: height.revision_height() as u32,
                payload: Payload(vec![]),
                validator_set_id: 0,
            }),
            signatures: vec![],
        }
    }
}

impl From<commitment::SignedCommitment> for SignedCommitment {
    fn from(value: commitment::SignedCommitment) -> Self {
        Self {
            commitment: Some(Commitment::from(value.commitment)),
            signatures: value
                .signatures
                .into_iter()
                .map(|value| {
                    if value.is_none() {
                        None
                    } else {
                        Some(Signature::from(value.unwrap()))
                    }
                }) // todo unwrap , cannot remove because map
                .collect(),
        }
    }
}

impl TryFrom<SignedCommitment> for commitment::SignedCommitment {
    type Error = Error;

    fn try_from(value: SignedCommitment) -> Result<Self, Self::Error> {
        Ok(Self {
            commitment: value.commitment.ok_or_else(Error::empty_commitment)?.into(),
            signatures: value
                .signatures
                .into_iter()
                .map(|value| {
                    if value.is_none() {
                        None
                    } else {
                        Some(value.unwrap().try_into().unwrap())
                    }
                }) // todo unwrap , cannot remove because map
                .collect(),
        })
    }
}

impl TryFrom<RawSignedCommitment> for SignedCommitment {
    type Error = Error;

    fn try_from(raw: RawSignedCommitment) -> Result<Self, Self::Error> {
        Ok(Self {
            commitment: Some(raw.commitment.ok_or_else(Error::empty_commitment)?.into()),
            signatures: raw
                .signatures
                .into_iter()
                .map(|value| {
                    if value.inner_signature.is_none() {
                        None
                    } else {
                        Some(value.inner_signature.unwrap().into())
                    }
                })
                .collect(),
        })
    }
}

impl TryFrom<SignedCommitment> for RawSignedCommitment {
    type Error = Error;
    fn try_from(value: SignedCommitment) -> Result<Self, Self::Error> {
        Ok(Self {
            commitment: Some(value.commitment.ok_or_else(Error::empty_commitment)?.into()),
            signatures: value
                .signatures
                .into_iter()
                .map(|value| {
                    if value.is_none() {
                        InnerSignature {
                            inner_signature: None,
                        }
                    } else {
                        InnerSignature {
                            inner_signature: Some(value.unwrap().into()),
                        }
                    }
                })
                .collect(),
        })
    }
}

impl Default for SignedCommitment {
    fn default() -> Self {
        Self {
            commitment: Some(Commitment::default()),
            signatures: vec![],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Decode, Encode, Default)]
pub struct Signature {
    pub signature: Vec<u8>,
}

impl From<commitment::Signature> for Signature {
    fn from(value: commitment::Signature) -> Self {
        Self {
            signature: Vec::from(value.0),
        }
    }
}

impl TryFrom<Signature> for commitment::Signature {
    type Error = Error;

    fn try_from(value: Signature) -> Result<Self, Self::Error> {
        Ok(Self(
            <[u8; 65]>::try_from(value.signature)
                .map_err(|_| Error::invalid_convert_signature())?,
        ))
    }
}

impl From<RawSignature> for Signature {
    fn from(raw: RawSignature) -> Self {
        Self {
            signature: raw.signature,
        }
    }
}

impl From<Signature> for RawSignature {
    fn from(value: Signature) -> Self {
        Self {
            signature: value.signature,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Decode, Encode, Default)]
pub struct ValidatorMerkleProof {
    //// Proof items (does not contain the leaf hash, nor the root obviously).
    ////
    //// This vec contains all inner node hashes necessary to reconstruct the root hash given the
    //// leaf hash.
    pub proof: Vec<Vec<u8>>,
    //// Number of leaves in the original tree.
    ////
    //// This is needed to detect a case where we have an odd number of leaves that "get promoted"
    //// to upper layers.
    //// pub number_of_leaves: usize,
    pub number_of_leaves: u32,
    //// Index of the leaf the proof is for (0-based).
    //// pub leaf_index: usize,
    pub leaf_index: u32,
    //// Leaf content.
    ////pub leaf: Vec<u8>,
    pub leaf: Vec<u8>,
}

impl From<BeefyValidatorMerkleProof> for ValidatorMerkleProof {
    fn from(value: BeefyValidatorMerkleProof) -> Self {
        let proof: Vec<Vec<u8>> = value.proof.into_iter().map(Vec::from).collect();
        Self {
            proof,
            number_of_leaves: value.number_of_leaves as u32,
            leaf_index: value.leaf_index as u32,
            leaf: value.leaf,
        }
    }
}

impl From<ValidatorMerkleProof> for BeefyValidatorMerkleProof {
    fn from(value: ValidatorMerkleProof) -> Self {
        let mut proofs = vec![];
        for item in value.proof {
            let proof = Hash::try_from(item).unwrap_or([0; 32]);
            proofs.push(proof);
        }

        Self {
            proof: proofs,
            number_of_leaves: value.number_of_leaves as usize,
            leaf_index: value.leaf_index as usize,
            leaf: value.leaf,
        }
    }
}

impl From<RawValidatorMerkleProof> for ValidatorMerkleProof {
    fn from(raw: RawValidatorMerkleProof) -> Self {
        Self {
            proof: raw.proof,
            number_of_leaves: raw.number_of_leaves,
            leaf_index: raw.leaf_index,
            leaf: raw.leaf,
        }
    }
}

impl From<ValidatorMerkleProof> for RawValidatorMerkleProof {
    fn from(value: ValidatorMerkleProof) -> Self {
        Self {
            proof: value.proof,
            number_of_leaves: value.number_of_leaves,
            leaf_index: value.leaf_index,
            leaf: value.leaf,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Decode, Encode)]
pub struct MmrLeafProof {
    //// The index of the leaf the proof is for.
    pub leaf_index: u64,
    //// Number of leaves in MMR, when the proof was generated.
    pub leaf_count: u64,
    //// Proof elements (hashes of siblings of inner nodes on the path to the leaf).
    pub items: Vec<Vec<u8>>,
}

impl From<mmr::MmrLeafProof> for MmrLeafProof {
    fn from(value: mmr::MmrLeafProof) -> Self {
        let items = value.items.into_iter().map(Vec::from).collect();
        Self {
            leaf_index: value.leaf_index,
            leaf_count: value.leaf_count,
            items,
        }
    }
}

impl From<MmrLeafProof> for mmr::MmrLeafProof {
    fn from(value: MmrLeafProof) -> Self {
        Self {
            leaf_index: value.leaf_index,
            leaf_count: value.leaf_count,
            items: value
                .items
                .into_iter()
                .map(|value| Hash::try_from(value).unwrap_or_default()) // todo unwrap , cannot remove because map
                .collect(),
        }
    }
}

impl From<RawMmrLeafProof> for MmrLeafProof {
    fn from(raw: RawMmrLeafProof) -> Self {
        Self {
            leaf_index: raw.leaf_index,
            leaf_count: raw.leaf_count,
            items: raw.items,
        }
    }
}

impl From<MmrLeafProof> for RawMmrLeafProof {
    fn from(value: MmrLeafProof) -> Self {
        Self {
            leaf_index: value.leaf_index,
            leaf_count: value.leaf_count,
            items: value.items,
        }
    }
}

impl Default for MmrLeafProof {
    fn default() -> Self {
        Self {
            leaf_index: 0,
            leaf_count: 0,
            items: vec![vec![0u8; 32], vec![0u8; 32]],
        }
    }
}

/// Block Header
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Decode, Encode, Default)]
pub struct BlockHeader {
    //// The parent hash.
    pub parent_hash: Vec<u8>,
    //// The block number.
    #[codec(compact)]
    pub block_number: u32,
    //// The state trie merkle root
    pub state_root: Vec<u8>,
    //// The merkle root of the extrinsics.
    pub extrinsics_root: Vec<u8>,
    //// A chain-specific digest of data useful for light clients or referencing auxiliary data.
    pub digest: Vec<u8>,
}

impl BlockHeader {
    pub fn hash(&self) -> Result<Hash, Error> {
        let beefy_header = header::Header::try_from(self.clone())?;
        Ok(beefy_header.hash())
    }
}

impl From<header::Header> for BlockHeader {
    fn from(value: header::Header) -> Self {
        Self {
            parent_hash: Vec::from(value.parent_hash),
            block_number: value.number,
            state_root: Vec::from(value.state_root),
            extrinsics_root: Vec::from(value.extrinsics_root),
            digest: value.digest.encode(),
        }
    }
}

impl TryFrom<BlockHeader> for header::Header {
    type Error = Error;

    fn try_from(value: BlockHeader) -> Result<Self, Self::Error> {
        let digest =
            header::Digest::decode(&mut &value.digest[..]).map_err(Error::invalid_codec_decode)?;
        Ok(Self {
            parent_hash: Hash::try_from(value.parent_hash)
                .map_err(|_| Error::invalid_convert_hash())?,
            number: value.block_number,
            state_root: Hash::try_from(value.state_root)
                .map_err(|_| Error::invalid_convert_hash())?,
            extrinsics_root: Hash::try_from(value.extrinsics_root)
                .map_err(|_| Error::invalid_convert_hash())?,
            digest,
        })
    }
}

impl From<RawBlockHeader> for BlockHeader {
    fn from(raw: RawBlockHeader) -> Self {
        Self {
            parent_hash: raw.parent_hash,
            block_number: raw.block_number,
            state_root: raw.state_root,
            extrinsics_root: raw.extrinsics_root,
            digest: raw.digest,
        }
    }
}

impl From<BlockHeader> for RawBlockHeader {
    fn from(value: BlockHeader) -> Self {
        Self {
            parent_hash: value.parent_hash,
            block_number: value.block_number,
            state_root: value.state_root,
            extrinsics_root: value.extrinsics_root,
            digest: value.digest,
        }
    }
}

use ibc_proto::ibc::lightclients::grandpa::v1::MmrRoot as RawMmrRoot;
// #[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Encode, Decode, Default)]
pub struct MmrRoot {
    pub signed_commitment: SignedCommitment,
    pub validator_merkle_proofs: Vec<ValidatorMerkleProof>,
    pub mmr_leaf: Vec<u8>,
    pub mmr_leaf_proof: Vec<u8>,
}
impl TryFrom<RawMmrRoot> for MmrRoot {
    type Error = Error;

    fn try_from(raw: RawMmrRoot) -> Result<Self, Self::Error> {
        Ok(Self {
            signed_commitment: raw
                .signed_commitment
                .ok_or_else(Error::empty_signed_commitment)?
                .try_into()
                .map_err(|_| Error::invalid_mmr_root("signed mmr root conversion".to_string()))?,

            validator_merkle_proofs: raw
                .validator_merkle_proofs
                .into_iter()
                .map(|proof| proof.into())
                .collect(),
            mmr_leaf: raw.mmr_leaf,
            mmr_leaf_proof: raw.mmr_leaf_proof,
        })
    }
}

impl TryFrom<MmrRoot> for RawMmrRoot {
    type Error = Error;
    fn try_from(value: MmrRoot) -> Result<Self, Self::Error> {
        Ok(Self {
            signed_commitment: Some(value.signed_commitment.try_into()?),
            validator_merkle_proofs: value
                .validator_merkle_proofs
                .into_iter()
                .map(|proof| proof.into())
                .collect(),
            mmr_leaf: value.mmr_leaf,
            mmr_leaf_proof: value.mmr_leaf_proof,
        })
    }
}
