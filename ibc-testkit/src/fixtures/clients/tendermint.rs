use core::str::FromStr;
use core::time::Duration;

use ibc::clients::tendermint::client_state::ClientState as TmClientState;
use ibc::clients::tendermint::types::error::{Error as ClientError, Error};
use ibc::clients::tendermint::types::proto::v1::{ClientState as RawTmClientState, Fraction};
#[cfg(feature = "serde")]
use ibc::clients::tendermint::types::Header;
use ibc::clients::tendermint::types::{
    AllowUpdate, ClientState as ClientStateType, TrustThreshold,
};
use ibc::core::client::types::proto::v1::Height as RawHeight;
use ibc::core::client::types::Height;
use ibc::core::commitment_types::specs::ProofSpecs;
use ibc::core::host::types::identifiers::ChainId;
use ibc::core::primitives::prelude::*;
use tendermint::block::Header as TmHeader;

/// Returns a dummy tendermint `ClientState` by given `frozen_height`, for testing purposes only!
pub fn dummy_tm_client_state_from_raw(
    frozen_height: RawHeight,
) -> Result<TmClientState<tendermint::crypto::default::signature::Verifier>, Error> {
    ClientStateType::try_from(dummy_raw_tm_client_state(frozen_height)).map(TmClientState::from)
}

/// Returns a dummy tendermint `ClientState` from a `TmHeader`, for testing purposes only!
pub fn dummy_tm_client_state_from_header(
    tm_header: TmHeader,
) -> TmClientState<tendermint::crypto::default::signature::Verifier> {
    let chain_id = ChainId::from_str(tm_header.chain_id.as_str()).expect("Never fails");
    let client_state = ClientStateType::new(
        chain_id.clone(),
        Default::default(),
        Duration::from_secs(64000),
        Duration::from_secs(128000),
        Duration::from_millis(3000),
        Height::new(chain_id.revision_number(), u64::from(tm_header.height)).expect("Never fails"),
        Default::default(),
        Default::default(),
        AllowUpdate {
            after_expiry: false,
            after_misbehaviour: false,
        },
    )
    .expect("Never fails");

    TmClientState::from(client_state)
}

/// Returns a dummy tendermint `RawTmClientState` by given `frozen_height`, for testing purposes only!
pub fn dummy_raw_tm_client_state(frozen_height: RawHeight) -> RawTmClientState {
    #[allow(deprecated)]
    RawTmClientState {
        chain_id: ChainId::new("ibc-0").expect("Never fails").to_string(),
        trust_level: Some(Fraction {
            numerator: 1,
            denominator: 3,
        }),
        trusting_period: Some(Duration::from_secs(64000).into()),
        unbonding_period: Some(Duration::from_secs(128000).into()),
        max_clock_drift: Some(Duration::from_millis(3000).into()),
        latest_height: Some(Height::new(0, 10).expect("Never fails").into()),
        proof_specs: ProofSpecs::default().into(),
        upgrade_path: Default::default(),
        frozen_height: Some(frozen_height),
        allow_update_after_expiry: false,
        allow_update_after_misbehaviour: false,
    }
}

#[derive(typed_builder::TypedBuilder, Debug)]
pub struct ClientStateConfig {
    pub chain_id: ChainId,
    #[builder(default)]
    pub trust_level: TrustThreshold,
    #[builder(default = Duration::from_secs(64000))]
    pub trusting_period: Duration,
    #[builder(default = Duration::from_secs(128000))]
    pub unbonding_period: Duration,
    #[builder(default = Duration::from_millis(3000))]
    max_clock_drift: Duration,
    pub latest_height: Height,
    #[builder(default)]
    pub proof_specs: ProofSpecs,
    #[builder(default)]
    pub upgrade_path: Vec<String>,
    #[builder(default = AllowUpdate { after_expiry: false, after_misbehaviour: false })]
    allow_update: AllowUpdate,
}

impl TryFrom<ClientStateConfig>
    for TmClientState<tendermint::crypto::default::signature::Verifier>
{
    type Error = ClientError;

    fn try_from(config: ClientStateConfig) -> Result<Self, Self::Error> {
        let client_state = ClientStateType::new(
            config.chain_id,
            config.trust_level,
            config.trusting_period,
            config.unbonding_period,
            config.max_clock_drift,
            config.latest_height,
            config.proof_specs,
            config.upgrade_path,
            config.allow_update,
        )?;

        Ok(TmClientState::from(client_state))
    }
}

#[cfg(feature = "serde")]
pub fn dummy_tendermint_header() -> tendermint::block::Header {
    use tendermint::block::signed_header::SignedHeader;

    serde_json::from_str::<SignedHeader>(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/json/signed_header.json"
    )))
    .expect("Never fails")
    .header
}

// TODO: This should be replaced with a ::default() or ::produce().
// The implementation of this function comprises duplicate code (code borrowed from
// `tendermint-rs` for assembling a Header).
// See https://github.com/informalsystems/tendermint-rs/issues/381.
//
// The normal flow is:
// - get the (trusted) signed header and the `trusted_validator_set` at a `trusted_height`
// - get the `signed_header` and the `validator_set` at latest height
// - build the ics07 Header
// For testing purposes this function does:
// - get the `signed_header` from a .json file
// - create the `validator_set` with a single validator that is also the proposer
// - assume a `trusted_height` of 1 and no change in the validator set since height 1,
//   i.e. `trusted_validator_set` = `validator_set`
#[cfg(feature = "serde")]
pub fn dummy_ics07_header() -> Header {
    use subtle_encoding::hex;
    use tendermint::block::signed_header::SignedHeader;
    use tendermint::validator::{Info as ValidatorInfo, Set as ValidatorSet};
    use tendermint::PublicKey;

    // Build a SignedHeader from a JSON file.
    let shdr = serde_json::from_str::<SignedHeader>(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/json/signed_header.json"
    )))
    .expect("Never fails");

    // Build a set of validators.
    // Below are test values inspired form `test_validator_set()` in tendermint-rs.
    let v1: ValidatorInfo = ValidatorInfo::new(
        PublicKey::from_raw_ed25519(
            &hex::decode_upper("F349539C7E5EF7C49549B09C4BFC2335318AB0FE51FBFAA2433B4F13E816F4A7")
                .expect("Never fails"),
        )
        .expect("Never fails"),
        281_815_u64.try_into().expect("Never fails"),
    );

    let vs = ValidatorSet::new(vec![v1.clone()], Some(v1));

    Header {
        signed_header: shdr,
        validator_set: vs.clone(),
        trusted_height: Height::min(0),
        trusted_next_validator_set: vs,
    }
}

#[cfg(all(test, feature = "serde"))]
mod tests {

    use ibc::primitives::proto::Any;

    use super::*;

    #[test]
    fn tm_client_state_conversions_healthy() {
        // check client state creation path from a proto type
        let tm_client_state_from_raw = dummy_tm_client_state_from_raw(RawHeight {
            revision_number: 0,
            revision_height: 0,
        });
        assert!(tm_client_state_from_raw.is_ok());

        let any_from_tm_client_state = Any::from(
            tm_client_state_from_raw
                .as_ref()
                .expect("Never fails")
                .clone(),
        );
        let tm_client_state_from_any = ClientStateType::try_from(any_from_tm_client_state);
        assert!(tm_client_state_from_any.is_ok());
        assert_eq!(
            tm_client_state_from_raw.expect("Never fails"),
            tm_client_state_from_any.expect("Never fails").into()
        );

        // check client state creation path from a tendermint header
        let tm_header = dummy_tendermint_header();
        let tm_client_state_from_header = dummy_tm_client_state_from_header(tm_header);
        let any_from_header = Any::from(tm_client_state_from_header.clone());
        let tm_client_state_from_any = ClientStateType::try_from(any_from_header);
        assert!(tm_client_state_from_any.is_ok());
        assert_eq!(
            tm_client_state_from_header,
            tm_client_state_from_any.expect("Never fails").into()
        );
    }

    #[test]
    fn tm_client_state_malformed_with_frozen_height() {
        let tm_client_state_from_raw = dummy_tm_client_state_from_raw(RawHeight {
            revision_number: 0,
            revision_height: 10,
        });
        match tm_client_state_from_raw {
            Err(Error::FrozenHeightNotAllowed) => {}
            _ => panic!("Expected to fail with FrozenHeightNotAllowed error"),
        }
    }
}
