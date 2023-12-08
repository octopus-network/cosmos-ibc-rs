use ibc_client_tendermint_types::error::{Error, IntoResult};
use ibc_client_tendermint_types::{ConsensusState as ConsensusStateType, Header as TmHeader};
use ibc_core_client::context::ClientExecutionContext;
use ibc_core_client::types::error::ClientError;
use ibc_core_host::types::identifiers::ClientId;
use ibc_core_host::types::path::ClientConsensusStatePath;
use ibc_primitives::prelude::*;
use tendermint_light_client_verifier::types::{TrustedBlockState, UntrustedBlockState};
use tendermint_light_client_verifier::Verifier;

use super::ClientState;
use crate::consensus_state::ConsensusState as TmConsensusState;
use crate::context::{CommonContext, ValidationContext as TmValidationContext};

impl<V> ClientState<V>
where
    V: Clone + Default + tendermint::crypto::signature::Verifier,
{
    pub fn verify_header<ClientValidationContext>(
        &self,
        ctx: &ClientValidationContext,
        client_id: &ClientId,
        header: TmHeader,
    ) -> Result<(), ClientError>
    where
        ClientValidationContext: TmValidationContext,
    {
        // Checks that the header fields are valid.
        header.validate_basic()?;

        // The tendermint-light-client crate though works on heights that are assumed
        // to have the same revision number. We ensure this here.
        header.verify_chain_id_version_matches_height(&self.0.chain_id())?;

        // Delegate to tendermint-light-client, which contains the required checks
        // of the new header against the trusted consensus state.
        {
            let trusted_state =
                {
                    let trusted_client_cons_state_path = ClientConsensusStatePath::new(
                        client_id.clone(),
                        header.trusted_height.revision_number(),
                        header.trusted_height.revision_height(),
                    );
                    let trusted_consensus_state: TmConsensusState = ctx
                        .consensus_state(&trusted_client_cons_state_path)?
                        .try_into()
                        .map_err(|err| ClientError::Other {
                            description: err.to_string(),
                        })?;

                    header.check_trusted_next_validator_set(trusted_consensus_state.inner())?;

                    TrustedBlockState {
                        chain_id: &self.0.chain_id.to_string().try_into().map_err(|e| {
                            ClientError::Other {
                                description: format!("failed to parse chain id: {}", e),
                            }
                        })?,
                        header_time: trusted_consensus_state.timestamp(),
                        height: header.trusted_height.revision_height().try_into().map_err(
                            |_| ClientError::ClientSpecific {
                                description: Error::InvalidHeaderHeight {
                                    height: header.trusted_height.revision_height(),
                                }
                                .to_string(),
                            },
                        )?,
                        next_validators: &header.trusted_next_validator_set,
                        next_validators_hash: trusted_consensus_state.next_validators_hash(),
                    }
                };

            let untrusted_state = UntrustedBlockState {
                signed_header: &header.signed_header,
                validators: &header.validator_set,
                // NB: This will skip the
                // VerificationPredicates::next_validators_match check for the
                // untrusted state.
                next_validators: None,
            };

            let options = self.0.as_light_client_options()?;
            let now = ctx.host_timestamp()?.into_tm_time().ok_or_else(|| {
                ClientError::ClientSpecific {
                    description: "host timestamp is not a valid TM timestamp".to_string(),
                }
            })?;

            // main header verification, delegated to the tendermint-light-client crate.
            self.0
                .verifier
                .verify_update_header(untrusted_state, trusted_state, &options, now)
                .into_result()?;
        }

        Ok(())
    }

    pub fn check_for_misbehaviour_update_client<ClientValidationContext>(
        &self,
        ctx: &ClientValidationContext,
        client_id: &ClientId,
        header: TmHeader,
    ) -> Result<bool, ClientError>
    where
        ClientValidationContext: TmValidationContext,
    {
        let maybe_existing_consensus_state = {
            let path_at_header_height = ClientConsensusStatePath::new(
                client_id.clone(),
                header.height().revision_number(),
                header.height().revision_height(),
            );

            ctx.consensus_state(&path_at_header_height).ok()
        };

        match maybe_existing_consensus_state {
            Some(existing_consensus_state) => {
                let existing_consensus_state: TmConsensusState = existing_consensus_state
                    .try_into()
                    .map_err(|err| ClientError::Other {
                        description: err.to_string(),
                    })?;

                let header_consensus_state =
                    TmConsensusState::from(ConsensusStateType::from(header.clone()));

                // There is evidence of misbehaviour if the stored consensus state
                // is different from the new one we received.
                Ok(existing_consensus_state != header_consensus_state)
            }
            None => {
                // If no header was previously installed, we ensure the monotonicity of timestamps.

                // 1. for all headers, the new header needs to have a larger timestamp than
                //    the “previous header”
                {
                    let maybe_prev_cs = ctx.prev_consensus_state(client_id, &header.height())?;

                    if let Some(prev_cs) = maybe_prev_cs {
                        // New header timestamp cannot occur *before* the
                        // previous consensus state's height
                        let prev_cs: TmConsensusState =
                            prev_cs.try_into().map_err(|err| ClientError::Other {
                                description: err.to_string(),
                            })?;

                        if header.signed_header.header().time <= prev_cs.timestamp() {
                            return Ok(true);
                        }
                    }
                }

                // 2. if a header comes in and is not the “last” header, then we also ensure
                //    that its timestamp is less than the “next header”
                if header.height() < self.0.latest_height {
                    let maybe_next_cs = ctx.next_consensus_state(client_id, &header.height())?;

                    if let Some(next_cs) = maybe_next_cs {
                        // New (untrusted) header timestamp cannot occur *after* next
                        // consensus state's height
                        let next_cs: TmConsensusState =
                            next_cs.try_into().map_err(|err| ClientError::Other {
                                description: err.to_string(),
                            })?;

                        if header.signed_header.header().time >= next_cs.timestamp() {
                            return Ok(true);
                        }
                    }
                }

                Ok(false)
            }
        }
    }

    pub fn prune_oldest_consensus_state<E>(
        &self,
        ctx: &mut E,
        client_id: &ClientId,
    ) -> Result<(), ClientError>
    where
        E: ClientExecutionContext + CommonContext,
    {
        let mut heights = ctx.consensus_state_heights(client_id)?;

        heights.sort();

        for height in heights {
            let client_consensus_state_path = ClientConsensusStatePath::new(
                client_id.clone(),
                height.revision_number(),
                height.revision_height(),
            );
            let consensus_state =
                CommonContext::consensus_state(ctx, &client_consensus_state_path)?;
            let tm_consensus_state: TmConsensusState =
                consensus_state
                    .try_into()
                    .map_err(|err| ClientError::Other {
                        description: err.to_string(),
                    })?;

            let host_timestamp =
                ctx.host_timestamp()?
                    .into_tm_time()
                    .ok_or_else(|| ClientError::Other {
                        description: String::from("host timestamp is not a valid TM timestamp"),
                    })?;
            let tm_consensus_state_timestamp = tm_consensus_state.timestamp();
            let tm_consensus_state_expiry = (tm_consensus_state_timestamp
                + self.0.trusting_period)
                .map_err(|_| ClientError::Other {
                    description: String::from(
                        "Timestamp overflow error occurred while attempting to parse TmConsensusState",
                    ),
                })?;

            if tm_consensus_state_expiry > host_timestamp {
                break;
            } else {
                let client_id = client_id.clone();

                ctx.delete_consensus_state(client_consensus_state_path)?;
                ctx.delete_update_time(client_id.clone(), height)?;
                ctx.delete_update_height(client_id, height)?;
            }
        }

        Ok(())
    }
}
