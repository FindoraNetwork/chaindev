use nix::unistd;
use once_cell::sync::Lazy;
use ruc::*;
use serde::{Deserialize, Serialize};
use std::{env, fmt, fs};

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////

/// Allocate ports based on this trait
pub trait NodePorts:
    Clone + Default + Send + Sync + Serialize + for<'a> Deserialize<'a>
{
    /// Reserved ports defined both by the Tendermint and the APP
    fn reserved() -> Vec<u16> {
        let mut ret = Self::app_reserved();
        ret.extend_from_slice(&Self::sys_reserved());
        ret
    }
    /// Reserved ports defined by the Tendermint
    fn sys_reserved() -> [u16; 3] {
        // - p2p, owned by TM
        // - rpc, owned by TM
        // - abci, owned by APP
        [26656, 26657, 26658]
    }
    /// Reserved ports defined by the APP
    fn app_reserved() -> Vec<u16>;
    /// Set actual ports to the instance
    fn set_all_ports(&mut self, ports: &[u16]);
    /// Get actual ports from the instance
    fn get_all_ports(&self) -> Vec<u16>;
    /// The p2p listening port in the Tendermint side
    fn get_sys_p2p(&self) -> u16;
    /// The rpc listening port in the Tendermint side
    fn get_sys_rpc(&self) -> u16;
    /// The ABCI listening port in the APP side
    fn get_sys_abci(&self) -> u16;
}

pub trait NodeOptsGenerator<Node>:
    Clone + Default + Send + Sync + Serialize + for<'a> Deserialize<'a>
{
    fn app_opts(&self, n: &Node, extra: &str) -> String;
    fn tendermint_opts(&self, n: &Node, extra: &str) -> String;
}

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////

// global shared paths should not be used to avoid confusion
// when multiple users share a same physical machine
pub(crate) static GLOBAL_BASE_DIR: Lazy<String> = Lazy::new(|| {
    let ret = env::var("CHAIN_DEV_GLOBAL_BASE_DIR").unwrap_or_else(|_| {
        format!(
            "/tmp/__CHAIN_DEV__/{}/{}/__D_DEV__",
            unistd::gethostname().unwrap().into_string().unwrap(),
            unistd::User::from_uid(unistd::getuid())
                .unwrap()
                .unwrap()
                .name
        )
    });
    pnk!(fs::create_dir_all(&ret));
    ret
});

///////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////

pub(crate) const ENV_NAME_DEFAULT: &str = "DEFAULT";

pub(crate) const PRESET_POWER: u32 = 1_000_000_000;

pub(crate) const MB: i64 = 1024 * 1024;
pub(crate) const GB: i64 = 1024 * MB;

pub(crate) type NodeId = u32;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EnvName {
    #[serde(rename = "env_name")]
    name: String,
}

impl Default for EnvName {
    fn default() -> Self {
        Self {
            name: ENV_NAME_DEFAULT.to_owned(),
        }
    }
}

impl fmt::Display for EnvName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.name)
    }
}

impl From<String> for EnvName {
    fn from(name: String) -> Self {
        Self { name }
    }
}

impl From<&str> for EnvName {
    fn from(n: &str) -> Self {
        Self { name: n.to_owned() }
    }
}

impl AsRef<str> for EnvName {
    fn as_ref(&self) -> &str {
        &self.name
    }
}
