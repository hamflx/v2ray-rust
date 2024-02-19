use crate::config::{BlackHoleConfig, DirectConfig, VmessConfig};
use crate::proxy::blackhole::BlackHoleStreamBuilder;
use crate::proxy::direct::DirectStreamBuilder;
use crate::proxy::vmess::vmess_option::VmessOption;
use crate::proxy::vmess::VmessBuilder;
use crate::proxy::{Address, ChainableStreamBuilder, ProtocolType};

pub trait ToChainableStreamBuilder: Sync + Send {
    fn to_chainable_stream_builder(&self, addr: Option<Address>)
        -> Box<dyn ChainableStreamBuilder>;
    fn tag(&self) -> &str;
    fn clone_box(&self) -> Box<dyn ToChainableStreamBuilder>;
    fn get_protocol_type(&self) -> ProtocolType;
    fn get_addr(&self) -> Option<Address> {
        None
    }
}
impl Clone for Box<dyn ToChainableStreamBuilder> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

impl ToChainableStreamBuilder for VmessConfig {
    fn to_chainable_stream_builder(
        &self,
        addr: Option<Address>,
    ) -> Box<dyn ChainableStreamBuilder> {
        Box::new(VmessBuilder {
            vmess_option: VmessOption {
                uuid: self.uuid,
                alter_id: 0,
                addr: addr.unwrap(),
                security_num: self.security_num,
                is_udp: false,
            },
        })
    }

    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    fn clone_box(&self) -> Box<dyn ToChainableStreamBuilder> {
        Box::new(self.clone())
    }

    fn get_protocol_type(&self) -> ProtocolType {
        ProtocolType::Vmess
    }

    fn get_addr(&self) -> Option<Address> {
        Some(self.addr.clone())
    }
}

impl ToChainableStreamBuilder for BlackHoleConfig {
    fn to_chainable_stream_builder(
        &self,
        _addr: Option<Address>,
    ) -> Box<dyn ChainableStreamBuilder> {
        Box::new(BlackHoleStreamBuilder)
    }

    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    fn clone_box(&self) -> Box<dyn ToChainableStreamBuilder> {
        Box::new(self.clone())
    }

    fn get_protocol_type(&self) -> ProtocolType {
        ProtocolType::Blackhole
    }
}
impl ToChainableStreamBuilder for DirectConfig {
    fn to_chainable_stream_builder(
        &self,
        _addr: Option<Address>,
    ) -> Box<dyn ChainableStreamBuilder> {
        Box::new(DirectStreamBuilder)
    }

    fn tag(&self) -> &str {
        self.tag.as_str()
    }

    fn clone_box(&self) -> Box<dyn ToChainableStreamBuilder> {
        Box::new(self.clone())
    }

    fn get_protocol_type(&self) -> ProtocolType {
        ProtocolType::Direct
    }
}
