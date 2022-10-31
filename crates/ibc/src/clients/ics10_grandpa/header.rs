use alloc::format;
use alloc::string::ToString;
use core::fmt::{Display, Error as FmtError, Formatter};

use bytes::Buf;
use ibc_proto::google::protobuf::Any;
use ibc_proto::ibc::lightclients::grandpa::v1::Header as RawHeader;
use ibc_proto::protobuf::Protobuf;
use prost::Message;
use serde_derive::{Deserialize, Serialize};

use super::help::BlockHeader;
use super::help::MmrRoot;
use crate::clients::ics10_grandpa::error::Error;
use crate::core::ics02_client::client_type::ClientType;
use crate::core::ics02_client::error::Error as Ics02Error;
use crate::timestamp::Timestamp;
use crate::Height;
use tendermint::Time;
use tendermint_proto::google::protobuf as tpb;

use super::client_type as gp_client_type;

pub const GRANDPA_HEADER_TYPE_URL: &str = "/ibc.lightclients.grandpa.v1.Header";

/// Tendermint consensus header
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Header {
    pub block_header: BlockHeader,
    pub mmr_root: MmrRoot,
    //// timestamp
    pub timestamp: Time,
}

impl Default for Header {
    fn default() -> Self {
        Self {
            block_header: BlockHeader::default(),
            mmr_root: MmrRoot::default(),
            timestamp: Time::from_unix_timestamp(0, 0).unwrap(),
        }
    }
}

impl core::fmt::Debug for Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(f, " Header {{...}}")
    }
}

impl Display for Header {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(f, "Header {{ ... }}")
    }
}

impl Header {
    pub fn height(&self) -> Height {
        Height::new(0, self.block_header.block_number as u64).unwrap()
    }

    pub fn compatible_with(&self, _other_header: &Header) -> bool {
        // todo
        true
    }
}

impl crate::core::ics02_client::header::Header for Header {
    fn client_type(&self) -> ClientType {
        gp_client_type()
    }

    fn height(&self) -> Height {
        self.height()
    }

    fn timestamp(&self) -> Timestamp {
        self.timestamp.into()
    }
}

impl Protobuf<RawHeader> for Header {}

impl TryFrom<RawHeader> for Header {
    type Error = Error;

    fn try_from(raw: RawHeader) -> Result<Self, Self::Error> {
        let ibc_proto::google::protobuf::Timestamp { seconds, nanos } = raw
            .timestamp
            .ok_or_else(|| Error::invalid_raw_header("missing timestamp".into()))?;

        let proto_timestamp = tpb::Timestamp { seconds, nanos };
        let timestamp = proto_timestamp
            .try_into()
            .map_err(|e| Error::invalid_raw_header(format!("invalid timestamp: {}", e)))?;

        Ok(Self {
            block_header: raw
                .block_header
                .ok_or_else(Error::empty_block_header)?
                .into(),
            mmr_root: raw.mmr_root.ok_or_else(Error::empty_mmr_root)?.try_into()?,
            timestamp,
        })
    }
}

impl Protobuf<Any> for Header {}

impl TryFrom<Any> for Header {
    type Error = Ics02Error;

    fn try_from(raw: Any) -> Result<Self, Ics02Error> {
        use core::ops::Deref;

        fn decode_header<B: Buf>(buf: B) -> Result<Header, Error> {
            RawHeader::decode(buf).map_err(Error::decode)?.try_into()
        }

        match raw.type_url.as_str() {
            GRANDPA_HEADER_TYPE_URL => decode_header(raw.value.deref()).map_err(Into::into),
            _ => Err(Ics02Error::unknown_header_type(raw.type_url)),
        }
    }
}

impl From<Header> for Any {
    fn from(header: Header) -> Self {
        Any {
            type_url: GRANDPA_HEADER_TYPE_URL.to_string(),
            value: Protobuf::<RawHeader>::encode_vec(&header)
                .expect("encoding to `Any` from `TmHeader`"),
        }
    }
}

pub fn decode_header<B: Buf>(buf: B) -> Result<Header, Error> {
    RawHeader::decode(buf).map_err(Error::decode)?.try_into()
}

impl From<Header> for RawHeader {
    fn from(value: Header) -> Self {
        let tpb::Timestamp { seconds, nanos } = value.timestamp.into();
        let timestamp = ibc_proto::google::protobuf::Timestamp { seconds, nanos };
        let mmr_root = value.mmr_root.try_into().unwrap();
        RawHeader {
            block_header: Some(value.block_header.into()),
            mmr_root: Some(mmr_root),
            timestamp: Some(timestamp),
        }
    }
}
