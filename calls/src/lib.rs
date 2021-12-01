mod codegen;
// pub use codegen::astar::*;


use codec::{Decode, Encode};

// #[derive(Eq, PartialEq, Encode, Decode)]
// pub struct ParachainId(u32);

#[derive(Encode, Decode)]
pub struct MessageQueueChain(pub subxt::sp_core::H256);

#[subxt::subxt(runtime_metadata_path = "metadata_file/metadata.scale")]
pub mod ibc_node {
    // #[subxt(substitute_type = "polkadot_parachain::primitives::Id")]
    // use crate::ParachainId;

    // #[subxt(substitute_type = "polkadot_core_primitives::InboundHrmpMessage")]
    // use crate::ibc_node::runtime_types::polkadot_core_primitives::InboundHrmpMessage;
    //
    #[subxt(substitute_type = "cumulus_pallet_parachain_system::MessageQueueChain")]
    use crate::MessageQueueChain;

}



const _: () = {
    use ibc_node::runtime_types::polkadot_parachain::primitives::Id;

    impl PartialEq for Id {
        fn eq(&self, other: &Self) -> bool {
            self.0 == other.0
        }
    }

    impl Eq for Id {

    }

    impl PartialOrd for Id {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            self.0.partial_cmp(&other.0)
        }
    }

    impl Ord for Id {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.0.cmp(&other.0)
        }
    }
};

impl ibc_node::runtime_types::pallet_ibc::event::primitive::Height {
    pub fn to_ibc_height(self) -> ibc::Height {
        ibc::Height {
            revision_number: self.revision_number,
            revision_height: self.revision_height,
        }
    }
}

impl ibc_node::runtime_types::pallet_ibc::event::primitive::Packet {
    pub fn to_ibc_packet(self) -> ibc::ics04_channel::packet::Packet {
        todo!()
    }
    
}

impl  ibc_node::runtime_types::pallet_ibc::event::primitive::ConnectionId {
    pub fn to_ibc_connection_id(self) -> ibc::ics24_host::identifier::ConnectionId {
        todo!()
    }
}

impl ibc_node::runtime_types::pallet_ibc::event::primitive::ChannelId {
    pub fn to_ibc_channel_id(self) -> ibc::ics24_host::identifier::ChannelId {
        todo!()
    }
}

impl ibc_node::runtime_types::pallet_ibc::event::primitive::PortId {
    pub fn to_ibc_port_id(self) -> ibc::ics24_host::identifier::PortId {
        todo!()
    }
}


impl ibc_node::runtime_types::pallet_ibc::event::primitive::ClientId {
    pub fn to_ibc_client_id(self) -> ibc::ics24_host::identifier::ClientId {
        todo!()
    }
}


impl ibc_node::runtime_types::pallet_ibc::event::primitive::ClientTy {
    pub fn to_ibc_client_type(self) -> ibc::ics02_client::client_type::ClientType {
        todo!()
    }
}



// // #![feature(associated_type_bounds)]
// #![allow(unused_imports)]
//
// use pallet_balances::AccountData;
// use pallet_ibc::Event;
// use sp_core::H256;
// use sp_runtime::generic::Header;
// use sp_runtime::traits::{BlakeTwo256, IdentifyAccount, Verify};
// use sp_runtime::{MultiSignature, OpaqueExtrinsic};
// use substrate_subxt::{
//     balances::{Balances, BalancesEventTypeRegistry},
//     contracts::{Contracts, ContractsEventTypeRegistry},
//     extrinsic::DefaultExtra,
//     register_default_type_sizes,
//     session::{Session, SessionEventTypeRegistry},
//     staking::{Staking, StakingEventTypeRegistry},
//     system::{System, SystemEventTypeRegistry},
//     BasicSessionKeys, EventTypeRegistry, Runtime,
// };
//
// pub mod ibc;
// pub mod template;
//
// #[derive(Debug, Clone, Eq, PartialEq)]
// pub struct NodeRuntime;
//
// impl Runtime for NodeRuntime {
//     type Signature = MultiSignature;
//     type Extra = DefaultExtra<Self>;
//
//     fn register_type_sizes(event_type_registry: &mut EventTypeRegistry<Self>) {
//         event_type_registry.with_system();
//         event_type_registry.with_balances();
//         event_type_registry.with_staking();
//         event_type_registry.with_session();
//         event_type_registry.register_type_size::<H256>("H256");
//         event_type_registry.register_type_size::<u64>("TAssetBalance");
//         event_type_registry.register_type_size::<pallet_ibc::event::primitive::Height>("Height");
//         event_type_registry
//             .register_type_size::<pallet_ibc::event::primitive::ClientType>("ClientType");
//         event_type_registry
//             .register_type_size::<pallet_ibc::event::primitive::ClientId>("ClientId");
//         event_type_registry
//             .register_type_size::<pallet_ibc::event::primitive::ConnectionId>("ConnectionId");
//         event_type_registry
//             .register_type_size::<pallet_ibc::event::primitive::PortId>("PortId");
//         event_type_registry
//             .register_type_size::<pallet_ibc::event::primitive::ChannelId>("ChannelId");
//         event_type_registry
//             .register_type_size::<pallet_ibc::event::primitive::Packet>("Packet");
//         register_default_type_sizes(event_type_registry);
//     }
// }
//
// impl System for NodeRuntime {
//     type Index = u32;
//     type BlockNumber = u32;
//     type Hash = sp_core::H256;
//     type Hashing = BlakeTwo256;
//     type AccountId = <<MultiSignature as Verify>::Signer as IdentifyAccount>::AccountId;
//     type Address = sp_runtime::MultiAddress<Self::AccountId, u32>;
//     type Header = Header<Self::BlockNumber, BlakeTwo256>;
//     type Extrinsic = OpaqueExtrinsic;
//     type AccountData = AccountData<<Self as Balances>::Balance>;
// }
//
// impl Balances for NodeRuntime {
//     type Balance = u128;
// }
//
// impl Session for NodeRuntime {
//     type ValidatorId = <Self as System>::AccountId;
//     type Keys = BasicSessionKeys;
// }
// impl Staking for NodeRuntime {}
//
// impl Contracts for NodeRuntime {}
//
// impl ibc::Ibc for NodeRuntime {}
//
// impl template::TemplateModule for NodeRuntime {}
