use core::time::Duration;

use ibc_proto::ibc::core::connection::v1::MsgConnectionOpenInit as RawMsgConnectionOpenInit;
use ibc_proto::protobuf::Protobuf;

use crate::core::ics03_connection::connection::Counterparty;
use crate::core::ics03_connection::error::ConnectionError;
use crate::core::ics03_connection::version::Version;
use crate::core::ics24_host::identifier::ClientId;
use crate::core::Msg;
use crate::prelude::*;
use crate::signer::Signer;

pub(crate) const TYPE_URL: &str = "/ibc.core.connection.v1.MsgConnectionOpenInit";

/// Per our convention, this message is sent to chain A.
/// The handler will check proofs of chain B.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct MsgConnectionOpenInit {
    /// ClientId on chain A that the connection is being opened for
    pub client_id_on_a: ClientId,
    pub counterparty: Counterparty,
    pub version: Option<Version>,
    pub delay_period: Duration,
    pub signer: Signer,
}

impl Msg for MsgConnectionOpenInit {
    type Raw = RawMsgConnectionOpenInit;

    fn type_url(&self) -> String {
        TYPE_URL.to_string()
    }
}

/// This module encapsulates the workarounds we need to do to implement
/// `BorshSerialize` and `BorshDeserialize` on `MsgConnectionOpenInit`
#[cfg(feature = "borsh")]
mod borsh_impls {
    use borsh::io::{self, Read};
    use borsh::{BorshDeserialize, BorshSerialize};

    use super::*;

    #[derive(BorshSerialize, BorshDeserialize)]
    pub struct InnerMsgConnectionOpenInit {
        /// ClientId on chain A that the connection is being opened for
        pub client_id_on_a: ClientId,
        pub counterparty: Counterparty,
        pub version: Option<Version>,
        pub delay_period_nanos: u64,
        pub signer: Signer,
    }

    impl BorshSerialize for MsgConnectionOpenInit {
        fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
            let delay_period_nanos: u64 =
                self.delay_period.as_nanos().try_into().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("Duration too long: {} nanos", self.delay_period.as_nanos()),
                    )
                })?;

            let inner = InnerMsgConnectionOpenInit {
                client_id_on_a: self.client_id_on_a.clone(),
                counterparty: self.counterparty.clone(),
                version: self.version.clone(),
                delay_period_nanos,
                signer: self.signer.clone(),
            };

            inner.serialize(writer)
        }
    }

    impl BorshDeserialize for MsgConnectionOpenInit {
        fn deserialize_reader<R: Read>(reader: &mut R) -> borsh::io::Result<Self> {
            let inner = InnerMsgConnectionOpenInit::deserialize_reader(reader)?;

            Ok(MsgConnectionOpenInit {
                client_id_on_a: inner.client_id_on_a,
                counterparty: inner.counterparty,
                version: inner.version,
                delay_period: Duration::from_nanos(inner.delay_period_nanos),
                signer: inner.signer,
            })
        }
    }
}

impl Protobuf<RawMsgConnectionOpenInit> for MsgConnectionOpenInit {}

impl TryFrom<RawMsgConnectionOpenInit> for MsgConnectionOpenInit {
    type Error = ConnectionError;

    fn try_from(msg: RawMsgConnectionOpenInit) -> Result<Self, Self::Error> {
        let counterparty: Counterparty = msg
            .counterparty
            .ok_or(ConnectionError::MissingCounterparty)?
            .try_into()?;

        counterparty.verify_empty_connection_id()?;

        Ok(Self {
            client_id_on_a: msg
                .client_id
                .parse()
                .map_err(ConnectionError::InvalidIdentifier)?,
            counterparty,
            version: msg.version.map(|version| version.try_into()).transpose()?,
            delay_period: Duration::from_nanos(msg.delay_period),
            signer: msg.signer.into(),
        })
    }
}

impl From<MsgConnectionOpenInit> for RawMsgConnectionOpenInit {
    fn from(ics_msg: MsgConnectionOpenInit) -> Self {
        RawMsgConnectionOpenInit {
            client_id: ics_msg.client_id_on_a.as_str().to_string(),
            counterparty: Some(ics_msg.counterparty.into()),
            version: ics_msg.version.map(|version| version.into()),
            delay_period: ics_msg.delay_period.as_nanos() as u64,
            signer: ics_msg.signer.to_string(),
        }
    }
}

#[cfg(test)]
pub mod test_util {
    use ibc_proto::ibc::core::connection::v1::{
        MsgConnectionOpenInit as RawMsgConnectionOpenInit, Version as RawVersion,
    };

    use crate::core::ics03_connection::connection::Counterparty;
    use crate::core::ics03_connection::msgs::conn_open_init::MsgConnectionOpenInit;
    use crate::core::ics03_connection::msgs::test_util::get_dummy_raw_counterparty;
    use crate::core::ics03_connection::version::Version;
    use crate::core::ics24_host::identifier::ClientId;
    use crate::prelude::*;
    use crate::test_utils::get_dummy_bech32_account;

    /// Extends the implementation with additional helper methods.
    impl MsgConnectionOpenInit {
        /// Returns a new `MsgConnectionOpenInit` with dummy values.
        pub fn new_dummy() -> Self {
            MsgConnectionOpenInit::try_from(get_dummy_raw_msg_conn_open_init()).unwrap()
        }

        /// Setter for `client_id`. Amenable to chaining, since it consumes the input message.
        pub fn with_client_id(self, client_id: ClientId) -> Self {
            MsgConnectionOpenInit {
                client_id_on_a: client_id,
                ..self
            }
        }

        /// Setter for `counterparty`. Amenable to chaining, since it consumes the input message.\
        pub fn with_counterparty_conn_id(self, counterparty_conn_id: u64) -> Self {
            let counterparty =
                Counterparty::try_from(get_dummy_raw_counterparty(Some(counterparty_conn_id)))
                    .unwrap();
            MsgConnectionOpenInit {
                counterparty,
                ..self
            }
        }

        pub fn with_version(self, identifier: Option<&str>) -> Self {
            let version = match identifier {
                Some(v) => Version::try_from(RawVersion {
                    identifier: v.to_string(),
                    features: vec![],
                })
                .unwrap()
                .into(),
                None => None,
            };
            MsgConnectionOpenInit { version, ..self }
        }
    }

    /// Returns a dummy message, for testing only.
    /// Other unit tests may import this if they depend on a MsgConnectionOpenInit.
    pub fn get_dummy_raw_msg_conn_open_init() -> RawMsgConnectionOpenInit {
        RawMsgConnectionOpenInit {
            client_id: ClientId::default().to_string(),
            counterparty: Some(get_dummy_raw_counterparty(None)),
            version: Some(Version::default().into()),
            delay_period: 0,
            signer: get_dummy_bech32_account(),
        }
    }
}

#[cfg(test)]
mod tests {
    use ibc_proto::ibc::core::connection::v1::{
        Counterparty as RawCounterparty, MsgConnectionOpenInit as RawMsgConnectionOpenInit,
    };
    use test_log::test;

    use super::MsgConnectionOpenInit;
    use crate::core::ics03_connection::msgs::conn_open_init::test_util::get_dummy_raw_msg_conn_open_init;
    use crate::core::ics03_connection::msgs::test_util::get_dummy_raw_counterparty;
    use crate::prelude::*;

    #[test]
    fn parse_connection_open_init_msg() {
        #[derive(Clone, Debug, PartialEq)]
        struct Test {
            name: String,
            raw: RawMsgConnectionOpenInit,
            want_pass: bool,
        }

        let default_init_msg = get_dummy_raw_msg_conn_open_init();

        let tests: Vec<Test> = vec![
            Test {
                name: "Good parameters".to_string(),
                raw: default_init_msg.clone(),
                want_pass: true,
            },
            Test {
                name: "Bad client id, name too short".to_string(),
                raw: RawMsgConnectionOpenInit {
                    client_id: "client".to_string(),
                    ..default_init_msg.clone()
                },
                want_pass: false,
            },
            Test {
                name: "Bad destination connection id, name too long".to_string(),
                raw: RawMsgConnectionOpenInit {
                    counterparty: Some(RawCounterparty {
                        connection_id:
                            "abcdefghijksdffjssdkflweldflsfladfsfwjkrekcmmsdfsdfjflddmnopqrstu"
                                .to_string(),
                        ..get_dummy_raw_counterparty(None)
                    }),
                    ..default_init_msg
                },
                want_pass: false,
            },
        ]
        .into_iter()
        .collect();

        for test in tests {
            let msg = MsgConnectionOpenInit::try_from(test.raw.clone());

            assert_eq!(
                test.want_pass,
                msg.is_ok(),
                "MsgConnOpenInit::new failed for test {}, \nmsg {:?} with error {:?}",
                test.name,
                test.raw,
                msg.err(),
            );
        }
    }

    #[test]
    fn to_and_from() {
        let raw = get_dummy_raw_msg_conn_open_init();
        let msg = MsgConnectionOpenInit::try_from(raw.clone()).unwrap();
        let raw_back = RawMsgConnectionOpenInit::from(msg.clone());
        let msg_back = MsgConnectionOpenInit::try_from(raw_back.clone()).unwrap();
        assert_eq!(raw, raw_back);
        assert_eq!(msg, msg_back);

        // Check if handler sets counterparty connection id to `None`
        // in case relayer passes `MsgConnectionOpenInit` message with it set to `Some(_)`.
        let raw_with_counterpary_conn_id_some = get_dummy_raw_msg_conn_open_init();
        let msg_with_counterpary_conn_id_some =
            MsgConnectionOpenInit::try_from(raw_with_counterpary_conn_id_some).unwrap();
        let raw_with_counterpary_conn_id_some_back =
            RawMsgConnectionOpenInit::from(msg_with_counterpary_conn_id_some.clone());
        let msg_with_counterpary_conn_id_some_back =
            MsgConnectionOpenInit::try_from(raw_with_counterpary_conn_id_some_back.clone())
                .unwrap();
        assert_eq!(
            raw_with_counterpary_conn_id_some_back
                .counterparty
                .unwrap()
                .connection_id,
            "".to_string()
        );
        assert_eq!(
            msg_with_counterpary_conn_id_some,
            msg_with_counterpary_conn_id_some_back
        );
    }

    /// Test that borsh serialization/deserialization works well with delay periods up to u64::MAX
    #[cfg(feature = "borsh")]
    #[test]
    fn test_borsh() {
        let mut raw = get_dummy_raw_msg_conn_open_init();
        raw.delay_period = u64::MAX;
        let msg = MsgConnectionOpenInit::try_from(raw.clone()).unwrap();

        let serialized = borsh::to_vec(&msg).unwrap();

        let msg_deserialized =
            <MsgConnectionOpenInit as borsh::BorshDeserialize>::try_from_slice(&serialized)
                .unwrap();

        assert_eq!(msg, msg_deserialized);
    }
}
