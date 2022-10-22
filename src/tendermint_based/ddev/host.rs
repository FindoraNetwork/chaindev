use super::remote::Remote;
use once_cell::sync::Lazy;
use ruc::*;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, env, path::PathBuf, thread};

static DEFAULT_SSH_USER: Lazy<String> =
    Lazy::new(|| pnk!(env::var("USER"), "$USER not defined!"));
static DEFAULT_SSH_PRIVKEY_PATH: Lazy<PathBuf> = Lazy::new(|| {
    PathBuf::from(format!(
        "{}/.ssh/id_rsa",
        pnk!(env::var("HOME"), "$HOME not defined!")
    ))
});

// ip, domain, ...
pub type HostAddr = String;

pub type HostMap = BTreeMap<HostAddr, Host>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Host {
    pub(super) meta: HostMeta,

    // weight used when allocating nodes
    pub(super) weight: u64,

    // how many nodes have been created
    pub(super) node_cnt: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct HostMeta {
    pub(super) addr: HostAddr,
    pub(super) ssh_user: String,
    pub(super) ssh_port: u16,
    pub(super) ssh_local_privkey: PathBuf,
}

#[derive(Debug, Clone)]
pub(super) enum HostOS {
    Linux,
    MacOS,
    FreeBSD,
    Unknown(String),
}

/// "ssh_remote_addr#ssh_user#ssh_remote_port#weight#ssh_local_privkey,..."
pub fn param_parse_hosts(hosts: &str) -> Result<BTreeMap<HostAddr, Host>> {
    let hosts = hosts
        .trim_matches(|c| c == ' ' || c == '\t')
        .split(',')
        .map(|h| h.split('#').collect::<Vec<_>>())
        .collect::<Vec<_>>();

    if hosts.iter().any(|h| h.is_empty()) || hosts.iter().any(|h| h.len() > 5) {
        return Err(eg!("invalid length"));
    }

    let mut hosts = hosts
        .into_iter()
        .map(|h| {
            if 1 == h.len() {
                Ok(Host {
                    meta: HostMeta {
                        addr: h[0].to_owned(),
                        ssh_user: DEFAULT_SSH_USER.clone(),
                        ssh_port: 22,
                        ssh_local_privkey: DEFAULT_SSH_PRIVKEY_PATH.clone(),
                    },
                    weight: 0,
                    node_cnt: 0,
                })
            } else if 2 == h.len() {
                Ok(Host {
                    meta: HostMeta {
                        addr: h[0].to_owned(),
                        ssh_user: h[1].to_owned(),
                        ssh_port: 22,
                        ssh_local_privkey: DEFAULT_SSH_PRIVKEY_PATH.clone(),
                    },
                    weight: 0,
                    node_cnt: 0,
                })
            } else if 3 == h.len() {
                h[2].parse::<u16>().c(d!()).map(|p| Host {
                    meta: HostMeta {
                        addr: h[0].to_owned(),
                        ssh_user: h[1].to_owned(),
                        ssh_port: p,
                        ssh_local_privkey: DEFAULT_SSH_PRIVKEY_PATH.clone(),
                    },
                    weight: 0,
                    node_cnt: 0,
                })
            } else {
                h[2].parse::<u16>().c(d!()).and_then(|p| {
                    h[3].parse::<u64>().c(d!()).map(|w| Host {
                        meta: HostMeta {
                            addr: h[0].to_owned(),
                            ssh_user: h[1].to_owned(),
                            ssh_port: p,
                            ssh_local_privkey: alt!(
                                5 == h.len(),
                                PathBuf::from(h[4]),
                                DEFAULT_SSH_PRIVKEY_PATH.clone()
                            ),
                        },
                        weight: w,
                        node_cnt: 0,
                    })
                })
            }
        })
        .collect::<Result<Vec<Host>>>()
        .c(d!())?;

    if hosts.iter().any(|h| 0 == h.weight) {
        hosts = thread::scope(|s| {
            hosts
                .into_iter()
                .map(|mut h| {
                    s.spawn(|| {
                        h.weight = Remote::from(&h.meta).get_hosts_weight().c(d!())?;
                        Ok(h)
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .flat_map(|h| h.join())
                .collect::<Result<Vec<_>>>()
        })
        .c(d!())?;
    }

    let ret = hosts
        .into_iter()
        .map(|h| (h.meta.addr.clone(), h))
        .collect::<BTreeMap<_, _>>();

    if ret.is_empty() {
        Err(eg!("No valid hosts found!"))
    } else {
        Ok(ret)
    }
}
