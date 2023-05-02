//!
//! Distributed version.
//!

mod host;
mod remote;

use host::{HostMeta, HostOS};
use once_cell::sync::Lazy;
use rand::random;
use remote::Remote;
use ruc::{cmd, *};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::{collections::BTreeMap, fmt, fs, io::ErrorKind, path::PathBuf, thread};
use tendermint::{
    config::{
        NodeKey, PrivValidatorKey as TmValidatorKey, TendermintConfig as TmConfig,
    },
    validator::Info as TmValidator,
    vote::Power as TmPower,
};
use toml_edit::{value as toml_value, Array, Document};
use vsdb::MapxRaw;

pub use super::common::*;
pub use host::{Host, HostAddr, HostAddrRef, Hosts};

static GLOBAL_BASE_DIR: Lazy<String> = Lazy::new(|| format!("{}/__D_DEV__", &*BASE_DIR));

#[macro_export]
macro_rules! check_errlist {
    ($errlist: expr) => {{
        if $errlist.is_empty() {
            Ok(())
        } else {
            Err(eg!("{:?}", $errlist))
        }
    }};
    (@$errlist: expr) => {{
        if !$errlist.is_empty() {
            return Err(eg!("{:?}", $errlist));
        }
    }};
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EnvCfg<A, C, P, U>
where
    A: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    P: NodePorts,
    U: CustomOps,
{
    /// The name of this env
    pub name: EnvName,

    /// Which operation to trigger/call
    pub op: Op<A, C, P, U>,
}

impl<A, C, P, U> EnvCfg<A, C, P, U>
where
    A: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    P: NodePorts,
    U: CustomOps,
{
    pub fn exec<S>(&self, s: S) -> Result<()>
    where
        S: NodeOptsGenerator<Node<P>, EnvMeta<C, Node<P>>>,
    {
        match &self.op {
            Op::Create(envopts) => Env::<C, P, S>::create(self, envopts, s).c(d!()),
            Op::Destroy => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|env| env.destroy().c(d!())),
            Op::DestroyAll => Env::<C, P, S>::destroy_all().c(d!()),
            Op::Start => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.start(None).c(d!())),
            Op::StartAll => Env::<C, P, S>::start_all().c(d!()),
            Op::Stop => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|env| env.stop().c(d!())),
            Op::StopAll => Env::<C, P, S>::stop_all().c(d!()),
            Op::PushNode => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.push_node().c(d!())),
            Op::PopNode => Env::<C, P, S>::load_env_by_cfg(self)
                .c(d!())
                .and_then(|mut env| env.kick_node().c(d!())),
            Op::Show => Env::<C, P, S>::load_env_by_cfg(self).c(d!()).map(|env| {
                env.show();
            }),
            Op::ShowAll => Env::<C, P, S>::show_all().c(d!()),
            Op::List => Env::<C, P, S>::list_all().c(d!()),
            Op::HostPutFile {
                local_path,
                remote_path,
                hosts,
            } => {
                if let Some(hosts) = hosts {
                    remote::put_file_to_hosts(
                        hosts,
                        local_path.as_str(),
                        remote_path.as_deref(),
                    )
                    .c(d!())
                } else {
                    Env::<C, P, S>::load_env_by_cfg(self)
                        .c(d!())
                        .and_then(|env| {
                            env.hosts_put_file(
                                local_path.as_str(),
                                remote_path.as_deref(),
                            )
                            .c(d!())
                        })
                }
            }
            Op::HostGetFile {
                remote_path,
                local_base_dir,
                hosts,
            } => {
                if let Some(hosts) = hosts {
                    remote::get_file_from_hosts(
                        hosts,
                        remote_path.as_str(),
                        local_base_dir.as_deref(),
                    )
                    .c(d!())
                } else {
                    Env::<C, P, S>::load_env_by_cfg(self)
                        .c(d!())
                        .and_then(|env| {
                            env.hosts_get_file(
                                remote_path.as_str(),
                                local_base_dir.as_deref(),
                            )
                            .c(d!())
                        })
                }
            }
            Op::HostExec {
                cmd,
                script_path,
                hosts,
            } => {
                if let Some(hosts) = hosts {
                    remote::exec_cmds_on_hosts(
                        hosts,
                        cmd.as_deref(),
                        script_path.as_deref(),
                    )
                    .c(d!())
                } else {
                    Env::<C, P, S>::load_env_by_cfg(self)
                        .c(d!())
                        .and_then(|env| {
                            env.hosts_exec(cmd.as_deref(), script_path.as_deref())
                                .c(d!())
                        })
                }
            }
            Op::NodeCollectLogs { local_base_dir } => {
                Env::<C, P, S>::load_env_by_cfg(self)
                    .c(d!())
                    .and_then(|env| {
                        env.nodes_collect_logs(local_base_dir.as_deref()).c(d!())
                    })
            }
            Op::Custom(custom_op) => custom_op.exec(&self.name).c(d!()),
            Op::Nil(_) => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct EnvMeta<C, N>
where
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    N: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
{
    /// the name of this env
    #[serde(flatten)]
    pub name: EnvName,

    /// data path of this env
    #[serde(rename = "env_home_dir")]
    pub home: String,

    #[serde(rename = "remote_hosts")]
    pub hosts: Hosts,

    #[serde(rename = "app_bin_path")]
    pub app_bin: String,

    pub app_extra_opts: String,

    #[serde(rename = "tendermint_bin_path")]
    pub tendermint_bin: String,

    pub tendermint_extra_opts: String,

    /// seconds between two blocks
    #[serde(rename = "block_interval_in_seconds")]
    pub block_itv_secs: BlockItv,

    #[serde(rename = "bootstrap_nodes")]
    pub bootstraps: BTreeMap<NodeId, N>,

    #[serde(rename = "validator_or_full_nodes")]
    pub nodes: BTreeMap<NodeId, N>,

    /// the contents of `genesis.json` of all nodes
    #[serde(rename = "tendermint_genesis")]
    pub genesis: Option<JsonValue>,

    pub custom_data: C,

    // the latest/max id of current nodes
    pub(crate) next_node_id: NodeId,
}

impl<C, P> EnvMeta<C, Node<P>>
where
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    P: NodePorts,
{
    pub fn get_env_list() -> Result<Vec<EnvName>> {
        let mut list = vec![];

        let data_dir = format!("{}/envs", &*GLOBAL_BASE_DIR);
        fs::create_dir_all(&data_dir).c(d!())?;

        for entry in fs::read_dir(&data_dir).c(d!())? {
            let entry = entry.c(d!())?;
            let path = entry.path();
            if path.is_dir() {
                let env = path.file_name().c(d!())?.to_string_lossy().into_owned();
                list.push(env.into());
            }
        }

        list.sort();

        Ok(list)
    }

    pub fn load_env_by_name<S>(cfg_name: &EnvName) -> Result<Option<Env<C, P, S>>>
    where
        S: NodeOptsGenerator<Node<P>, EnvMeta<C, Node<P>>>,
    {
        let p = format!("{}/envs/{}/config.json", &*GLOBAL_BASE_DIR, cfg_name);
        match fs::read_to_string(p) {
            Ok(d) => Ok(serde_json::from_str(&d).c(d!())?),
            Err(e) => match e.kind() {
                ErrorKind::NotFound => Ok(None),
                _ => Err(eg!(e)),
            },
        }
    }

    pub fn get_addrports_any_node(&self) -> (HostAddrRef, Vec<u16>) {
        let node = pnk!(self.nodes.values().next());
        let addr = node.host.addr.as_str();
        let ports = node.ports.get_port_list();
        (addr, ports)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct Env<C, P, S>
where
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    P: NodePorts,
    S: NodeOptsGenerator<Node<P>, EnvMeta<C, Node<P>>>,
{
    pub meta: EnvMeta<C, Node<P>>,

    #[serde(rename = "node_options_generator")]
    pub node_opts_generator: S,
}

impl<C, P, S> Env<C, P, S>
where
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    P: NodePorts,
    S: NodeOptsGenerator<Node<P>, EnvMeta<C, Node<P>>>,
{
    // - initilize a new env
    // - `genesis.json` will be created
    fn create<A, U>(cfg: &EnvCfg<A, C, P, U>, opts: &EnvOpts<A, C>, s: S) -> Result<()>
    where
        A: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
        U: CustomOps,
    {
        let home = format!("{}/envs/{}", &*GLOBAL_BASE_DIR, &cfg.name);

        if opts.force_create {
            omit!(
                Env::<C, P, S>::load_env_by_cfg(cfg)
                    .c(d!())
                    .and_then(|env| env.destroy().c(d!()))
            );
            omit!(fs::remove_dir_all(&home).c(d!()).and_then(|_| {
                let errlist = thread::scope(|s| {
                    opts.hosts
                        .as_ref()
                        .values()
                        .map(|h| {
                            let remote = Remote::from(h);
                            let cmd = format!("rm -rf {}", &home);
                            s.spawn(move || info!(remote.exec_cmd(&cmd), &h.meta.addr))
                        })
                        .collect::<Vec<_>>()
                        .into_iter()
                        .flat_map(|h| h.join())
                        .filter(|t| t.is_err())
                        .collect::<Vec<_>>()
                });
                check_errlist!(errlist)
            }));
        }

        if fs::metadata(&home).is_ok()
            || thread::scope(|s| {
                opts.hosts
                    .as_ref()
                    .values()
                    .map(|h| {
                        let remote = Remote::from(h);
                        let cmd = format!(r"\ls {}/*", &home);
                        s.spawn(move || remote.exec_cmd(&cmd))
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .flat_map(|h| h.join())
                    .collect::<Vec<_>>()
            })
            .iter()
            .any(|ret| ret.is_ok())
        {
            return Err(eg!("Another env with the same name exists!"));
        }

        let mut env = Env {
            meta: EnvMeta {
                name: cfg.name.clone(),
                home,
                hosts: opts.hosts.clone(),
                app_bin: opts.app_bin_path.clone(),
                app_extra_opts: opts.app_extra_opts.clone(),
                tendermint_bin: opts.tendermint_bin_path.clone(),
                tendermint_extra_opts: opts.tendermint_extra_opts.clone(),
                block_itv_secs: opts.block_itv_secs,
                nodes: Default::default(),
                bootstraps: Default::default(),
                genesis: None,
                custom_data: opts.custom_data.clone(),
                next_node_id: Default::default(),
            },
            node_opts_generator: s,
        };

        fs::create_dir_all(&env.meta.home).c(d!()).and_then(|_| {
            let errlist = thread::scope(|s| {
                env.meta
                    .hosts
                    .as_ref()
                    .values()
                    .map(|h| {
                        let remote = Remote::from(h);
                        let cmd = format!("mkdir -p {}", &env.meta.home);
                        s.spawn(move || info!(remote.exec_cmd(&cmd), &h.meta.addr))
                    })
                    .collect::<Vec<_>>()
                    .into_iter()
                    .flat_map(|h| h.join())
                    .filter(|t| t.is_err())
                    .collect::<Vec<_>>()
            });
            check_errlist!(errlist)
        })?;

        macro_rules! add_initial_nodes {
            ($kind: tt) => {{
                let id = env.next_node_id();
                env.alloc_resources(id, Kind::$kind).c(d!())?;
            }};
        }

        add_initial_nodes!(Bootstrap);
        for _ in 0..opts.initial_validator_num {
            add_initial_nodes!(Node);
        }

        env.gen_genesis(&opts.app_state)
            .c(d!())
            .and_then(|_| env.apply_genesis(None).c(d!()))
            .and_then(|_| env.start(None).c(d!()))
    }

    // start one or all nodes
    fn start(&mut self, n: Option<NodeId>) -> Result<()> {
        let ids = n.map(|id| vec![id]).unwrap_or_else(|| {
            self.meta
                .bootstraps
                .keys()
                .chain(self.meta.nodes.keys())
                .copied()
                .collect()
        });

        self.update_peer_cfg()
            .c(d!())
            .and_then(|_| self.write_cfg().c(d!()))?;

        let errlist = thread::scope(|s| {
            let mut hdrs = vec![];
            for i in ids.iter() {
                let hdr = s.spawn(|| {
                    if let Some(n) = self.meta.nodes.get(i) {
                        n.start(self).c(d!())
                    } else if let Some(n) = self.meta.bootstraps.get(i) {
                        n.start(self).c(d!())
                    } else {
                        Err(eg!("not exist"))
                    }
                });
                hdrs.push(hdr);
            }
            hdrs.into_iter()
                .flat_map(|h| h.join())
                .filter(|t| t.is_err())
                .collect::<Vec<_>>()
        });

        check_errlist!(errlist)
    }

    // start all existing ENVs
    fn start_all() -> Result<()> {
        for env in Self::get_env_list().c(d!())?.iter() {
            Self::load_env_by_name(env)
                .c(d!())?
                .c(d!("BUG: env not found!"))?
                .start(None)
                .c(d!())?;
        }
        Ok(())
    }

    // - stop all processes
    // - release all occupied ports
    fn stop(&self) -> Result<()> {
        let errlist = thread::scope(|s| {
            self.meta
                .nodes
                .values()
                .chain(self.meta.bootstraps.values())
                .map(|n| s.spawn(|| info!(n.stop(), &n.host.addr)))
                .collect::<Vec<_>>()
                .into_iter()
                .flat_map(|h| h.join())
                .filter(|t| t.is_err())
                .collect::<Vec<_>>()
        });

        check_errlist!(errlist)
    }

    // stop all existing ENVs
    fn stop_all() -> Result<()> {
        for env in Self::get_env_list().c(d!())?.iter() {
            Self::load_env_by_name(env)
                .c(d!())?
                .c(d!("BUG: env not found!"))?
                .stop()
                .c(d!())?;
        }
        Ok(())
    }

    // destroy all nodes
    // - stop all running processes
    // - delete the data of every nodes
    fn destroy(&self) -> Result<()> {
        info_omit!(self.stop());

        sleep_ms!(10);

        let errlist = thread::scope(|s| {
            self.meta
                .bootstraps
                .values()
                .chain(self.meta.nodes.values())
                .map(|n| s.spawn(|| n.clean().c(d!())))
                .collect::<Vec<_>>()
                .into_iter()
                .flat_map(|h| h.join())
                .filter(|t| t.is_err())
                .collect::<Vec<_>>()
        });

        check_errlist!(@errlist);

        fs::remove_dir_all(&self.meta.home).c(d!())?;

        let errlist = thread::scope(|s| {
            self.meta
                .hosts
                .as_ref()
                .values()
                .map(|h| {
                    s.spawn(move || {
                        let remote = Remote::from(h);
                        let cmd = format!("rm -rf {}", &self.meta.home);
                        info!(remote.exec_cmd(&cmd), &h.meta.addr)
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .flat_map(|h| h.join())
                .filter(|t| t.is_err())
                .collect::<Vec<_>>()
        });

        check_errlist!(errlist)
    }

    // destroy all existing ENVs
    fn destroy_all() -> Result<()> {
        let mut hosts = BTreeMap::new();
        for env in Self::get_env_list().c(d!())?.iter() {
            let mut env = Self::load_env_by_name(env)
                .c(d!())?
                .c(d!("BUG: env not found!"))?;
            env.destroy().c(d!())?;
            hosts.append(env.meta.hosts.as_mut());
        }
        fs::remove_dir_all(&*GLOBAL_BASE_DIR)
            .c(d!())
            .and_then(|_| {
                hosts
                    .values()
                    .map(|h| {
                        let remote = Remote::from(h);
                        let cmd = format!("rm -rf {}", &*GLOBAL_BASE_DIR);
                        info!(remote.exec_cmd(&cmd), &h.meta.addr)
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .map(|_| ())
    }

    // bootstrap nodes are kept by system for now,
    // so only the other nodes can be added on demand
    fn push_node(&mut self) -> Result<()> {
        let id = self.next_node_id();
        let kind = Kind::Node;
        self.alloc_resources(id, kind)
            .c(d!())
            .and_then(|_| self.apply_genesis(Some(id)).c(d!()))
            .and_then(|_| self.start(Some(id)).c(d!()))
    }

    // bootstrap nodes and the first fullnode can not be removed.
    fn kick_node(&mut self) -> Result<()> {
        self.meta
            .nodes
            .keys()
            .skip(1)
            .rev()
            .copied()
            .next()
            .c(d!("at least one Full Node should be kept!"))
            .and_then(|k| self.meta.nodes.remove(&k).c(d!()))
            .and_then(|n| {
                self.meta
                    .hosts
                    .as_mut()
                    .get_mut(&n.host.addr)
                    .unwrap()
                    .node_cnt -= 1;
                n.stop().c(d!()).and_then(|_| n.clean().c(d!()))
            })
            .and_then(|_| self.write_cfg().c(d!()))
    }

    fn show(&self) {
        println!("{}", pnk!(serde_json::to_string_pretty(self)));
    }

    // show the details of all existing ENVs
    fn show_all() -> Result<()> {
        for (idx, env) in Self::get_env_list().c(d!())?.iter().enumerate() {
            println!("\x1b[31;01m====== ENV No.{} ======\x1b[00m", idx);
            Self::load_env_by_name(env)
                .c(d!())?
                .c(d!("BUG: env not found!"))?
                .show();
            println!();
        }
        Ok(())
    }

    // list the names of all existing ENVs
    fn list_all() -> Result<()> {
        let list = Self::get_env_list().c(d!())?;

        if list.is_empty() {
            eprintln!("\x1b[31;01mNo existing env!\x1b[00m");
        } else {
            println!("\x1b[31;01mEnv list:\x1b[00m");
            list.into_iter().for_each(|env| {
                println!("  {}", env);
            });
        }

        Ok(())
    }

    #[inline(always)]
    fn hosts_put_file(&self, local_path: &str, remote_path: Option<&str>) -> Result<()> {
        remote::put_file_to_hosts(&self.meta.hosts, local_path, remote_path).c(d!())
    }

    #[inline(always)]
    fn hosts_get_file(
        &self,
        remote_path: &str,
        local_base_dir: Option<&str>,
    ) -> Result<()> {
        remote::get_file_from_hosts(&self.meta.hosts, remote_path, local_base_dir)
            .c(d!())
    }

    #[inline(always)]
    fn hosts_exec(&self, cmd: Option<&str>, script_path: Option<&str>) -> Result<()> {
        remote::exec_cmds_on_hosts(&self.meta.hosts, cmd, script_path).c(d!())
    }

    #[inline(always)]
    fn nodes_collect_logs(&self, local_base_dir: Option<&str>) -> Result<()> {
        remote::collect_logs_from_nodes(self, local_base_dir).c(d!())
    }

    // 1. allocate host and ports
    // 2. change configs: ports, bootstrap address, etc.
    // 3. write new configs of tendermint to local/remote disk
    // 4. insert new node to the meta of env
    fn alloc_resources(&mut self, id: NodeId, kind: Kind) -> Result<()> {
        // 1.
        let (host, ports) = self.alloc_hosts_ports(&kind).c(d!())?;
        let remote = Remote::from(&host);

        // 2.
        let home = format!("{}/{}", self.meta.home, id);
        remote.exec_cmd(&format!("mkdir -p {}", &home)).c(d!())?;

        let cfgfile = format!("{}/config/config.toml", &home);
        let role_mark = match kind {
            Kind::Node => "node",
            Kind::Bootstrap => "bootstrap",
        };

        let cmd = format!(
            "{} init {} --home {}",
            &self.meta.tendermint_bin, role_mark, &home
        );
        let mut cfg = remote
            .exec_cmd(&cmd)
            .c(d!())
            .and_then(|_| remote.read_file(&cfgfile).c(d!()))
            .and_then(|c| c.parse::<Document>().c(d!()))?;

        cfg["proxy_app"] =
            toml_value(format!("tcp://{}:{}", &host.addr, ports.get_sys_abci()));

        let remote_os = remote.hosts_os().c(d!())?;
        match remote_os {
            HostOS::Linux | HostOS::MacOS => {
                cfg["rpc"]["laddr"] =
                    toml_value(format!("tcp://{}:{}", &host.addr, ports.get_sys_rpc()));
            }
            _ => return Err(eg!("Unsupported OS: {:?}!", remote_os)),
        }

        let mut arr = Array::new();
        arr.push("*");
        cfg["rpc"]["cors_allowed_origins"] = toml_value(arr);
        cfg["rpc"]["max_open_connections"] = toml_value(10_0000);

        cfg["p2p"]["pex"] = toml_value(true);
        cfg["p2p"]["seed_mode"] = toml_value(false);
        cfg["p2p"]["addr_book_strict"] = toml_value(false);
        cfg["p2p"]["allow_duplicate_ip"] = toml_value(true);
        cfg["p2p"]["persistent_peers_max_dial_period"] = toml_value("30s");
        cfg["p2p"]["flush_throttle_timeout"] = toml_value("0ms");
        cfg["p2p"]["send_rate"] = toml_value(GB);
        cfg["p2p"]["recv_rate"] = toml_value(GB);
        cfg["p2p"]["max_packet_msg_payload_size"] = toml_value(MB);
        cfg["p2p"]["laddr"] =
            toml_value(format!("tcp://{}:{}", &host.addr, ports.get_sys_p2p()));

        cfg["consensus"]["timeout_propose"] = toml_value("32s");
        cfg["consensus"]["timeout_propose_delta"] = toml_value("500ms");
        cfg["consensus"]["timeout_prevote"] = toml_value("0s");
        cfg["consensus"]["timeout_prevote_delta"] = toml_value("500ms");
        cfg["consensus"]["timeout_precommit"] = toml_value("0s");
        cfg["consensus"]["timeout_precommit_delta"] = toml_value("500ms");
        let block_itv = self
            .meta
            .block_itv_secs
            .to_millisecond()
            .c(d!())?
            .to_string()
            + "ms";
        cfg["consensus"]["timeout_commit"] = toml_value(&block_itv);
        cfg["consensus"]["skip_timeout_commit"] = toml_value(false);
        cfg["consensus"]["create_empty_blocks"] = toml_value(true);
        cfg["consensus"]["create_empty_blocks_interval"] = toml_value(&block_itv);

        cfg["mempool"]["recheck"] = toml_value(false);
        cfg["mempool"]["broadcast"] = toml_value(true);
        cfg["mempool"]["size"] = toml_value(1_000_000);
        cfg["mempool"]["cache_size"] = toml_value(2_000_000);
        cfg["mempool"]["max_txs_bytes"] = toml_value(10 * GB);
        cfg["mempool"]["max_tx_bytes"] = toml_value(5 * MB);
        cfg["mempool"]["ttl-num-blocks"] = toml_value(16);

        cfg["moniker"] = toml_value(format!("{}-{}", &self.meta.name, id));

        match kind {
            Kind::Node => {
                cfg["p2p"]["max_num_inbound_peers"] = toml_value(40);
                cfg["p2p"]["max_num_outbound_peers"] = toml_value(10);
                cfg["tx_index"]["indexer"] = toml_value("null");
            }
            Kind::Bootstrap => {
                cfg["p2p"]["max_num_inbound_peers"] = toml_value(400);
                cfg["p2p"]["max_num_outbound_peers"] = toml_value(100);
                cfg["tx_index"]["indexer"] = toml_value("kv");
                cfg["tx_index"]["index_all_keys"] = toml_value(true);
            }
        }
        let cfg = cfg.to_string();

        // 3.
        remote.write_file(&cfgfile, cfg.as_bytes()).c(d!())?;

        // 4.
        let tm_id = TmConfig::parse_toml(&cfg)
            .map_err(|e| eg!(e))
            .and_then(|cfg| {
                remote
                    .read_file(PathBuf::from(&home).join(cfg.node_key_file))
                    .c(d!())
            })
            .and_then(|contents| NodeKey::parse_json(contents).map_err(|e| eg!(e)))?
            .node_id()
            .to_string()
            .to_lowercase();
        let node = Node {
            id,
            tm_id,
            home: format!("{}/{}", &self.meta.home, id),
            kind,
            host,
            ports,
        };

        match kind {
            Kind::Node => self.meta.nodes.insert(id, node),
            Kind::Bootstrap => self.meta.bootstraps.insert(id, node),
        };

        Ok(())
    }

    fn update_peer_cfg(&self) -> Result<()> {
        let errlist = thread::scope(|s| {
            let mut hdrs = vec![];
            for n in self
                .meta
                .nodes
                .values()
                .chain(self.meta.bootstraps.values())
            {
                let hdr = s.spawn(|| {
                    let remote = Remote::from(&n.host);
                    let cfgfile = format!("{}/config/config.toml", &n.home);
                    let mut cfg = remote
                        .read_file(&cfgfile)
                        .c(d!())
                        .and_then(|c| c.parse::<Document>().c(d!()))?;
                    cfg["p2p"]["persistent_peers"] = toml_value(
                        self.meta
                            .nodes
                            .values()
                            .chain(self.meta.bootstraps.values())
                            .filter(|peer| peer.id != n.id)
                            .map(|n| {
                                format!(
                                    "{}@{}:{}",
                                    &n.tm_id,
                                    &n.host.addr,
                                    n.ports.get_sys_p2p()
                                )
                            })
                            .collect::<Vec<_>>()
                            .join(","),
                    );
                    remote
                        .write_file(&cfgfile, cfg.to_string().as_bytes())
                        .c(d!())
                });
                hdrs.push(hdr);
            }

            hdrs.into_iter()
                .flat_map(|hdr| hdr.join())
                .filter(|t| t.is_err())
                .collect::<Vec<_>>()
        });

        check_errlist!(errlist)
    }

    // Allocate unique IDs for nodes within the scope of an env
    fn next_node_id(&mut self) -> NodeId {
        let ret = self.meta.next_node_id;
        self.meta.next_node_id += 1;
        ret
    }

    // Generate a new `genesis.json`
    // based on the collection of initial validators.
    fn gen_genesis<A>(&mut self, app_state: &A) -> Result<()>
    where
        A: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    {
        let tmp_id = NodeId::MAX;
        let tmp_home = format!("{}/{}", &self.meta.home, tmp_id);

        let parse = |n: &Node<P>| {
            let cfgfile = format!("{}/config/config.toml", &n.home);
            let remote = Remote::from(&n.host);
            remote
                .read_file(cfgfile)
                .c(d!())
                .and_then(|f| TmConfig::parse_toml(f).map_err(|e| eg!(e)))
                .and_then(|cfg| {
                    cfg.priv_validator_key_file
                        .as_ref()
                        .c(d!())
                        .and_then(|f| {
                            remote.read_file(PathBuf::from(&n.home).join(f)).c(d!())
                        })
                        .and_then(|c| TmValidatorKey::parse_json(c).map_err(|e| eg!(e)))
                })
                .map(|key| TmValidator::new(key.pub_key, TmPower::from(PRESET_POWER)))
        };
        let gen = |genesis_file: String| {
            thread::scope(|s| {
                self.meta
                    .nodes
                    .values()
                    .map(|n| s.spawn(|| parse(n)))
                    .collect::<Vec<_>>()
                    .into_iter()
                    .flat_map(|h| h.join())
                    .collect::<Result<Vec<_>>>()
            })
            .and_then(|vs| serde_json::to_value(vs).c(d!()))
            .and_then(|mut vs| {
                vs.as_array_mut()
                    .c(d!())?
                    .iter_mut()
                    .enumerate()
                    .for_each(|(i, v)| {
                        v["power"] = JsonValue::String(PRESET_POWER.to_string());
                        v["name"] = JsonValue::String(format!("NODE_{}", i));
                    });

                fs::read_to_string(format!("{}/{}", tmp_home, genesis_file))
                    .c(d!())
                    .and_then(|g| serde_json::from_str::<JsonValue>(&g).c(d!()))
                    .and_then(|mut g| {
                        g["consensus_params"]["block"]["time_iota_ms"] =
                            serde_json::to_value("1000").c(d!())?;
                        g["app_hash"] = serde_json::to_value("").c(d!())?;
                        g["app_state"] =
                            serde_json::to_value(app_state.clone()).c(d!())?;
                        g["validators"] = vs;
                        g["genesis_time"] = JsonValue::String(
                            // '2022-xxx' --> '1022-xxx'
                            // avoid waiting time between hosts
                            // due to different time shift
                            // when the chain is starting first time
                            g["genesis_time"].as_str().unwrap().replacen('2', "1", 1),
                        );
                        g["consensus_params"]["block"]["max_bytes"] =
                            serde_json::to_value((MB * 10).to_string()).unwrap();
                        self.meta.genesis = Some(g);
                        Ok(())
                    })
            })
        };

        cmd::exec_output(&format!(
            "{} init validator --home {}",
            &self.meta.tendermint_bin, &tmp_home
        ))
        .c(d!())
        .and_then(|_| {
            TmConfig::load_toml_file(&format!("{}/config/config.toml", &tmp_home))
                .map_err(|e| eg!(e))
        })
        .and_then(|cfg| cfg.genesis_file.to_str().map(|f| f.to_owned()).c(d!()))
        .and_then(gen)
        .and_then(|_| fs::remove_dir_all(tmp_home).c(d!()))
    }

    fn apply_genesis(&self, n: Option<NodeId>) -> Result<()> {
        let nodes = n.map(|id| vec![id]).unwrap_or_else(|| {
            self.meta
                .bootstraps
                .keys()
                .chain(self.meta.nodes.keys())
                .copied()
                .collect()
        });

        let errlist = thread::scope(|s| {
            let mut hdrs = vec![];
            for n in nodes.iter() {
                let hdr = s.spawn(|| {
                    let n = self
                        .meta
                        .nodes
                        .get(n)
                        .or_else(|| self.meta.bootstraps.get(n))
                        .c(d!())?;
                    let remote = Remote::from(&n.host);
                    let cfgfile = format!("{}/config/config.toml", &n.home);
                    remote
                        .read_file(cfgfile)
                        .c(d!())
                        .and_then(|c| TmConfig::parse_toml(c).map_err(|e| eg!(e)))
                        .map(|cfg| PathBuf::from(&n.home).join(cfg.genesis_file))
                        .and_then(|genesis_path| {
                            self.meta
                                .genesis
                                .as_ref()
                                .c(d!("BUG"))
                                .and_then(|g| serde_json::to_vec_pretty(g).c(d!()))
                                .and_then(|g| {
                                    remote.write_file(&genesis_path, &g).c(d!())
                                })
                        })
                });
                hdrs.push(hdr);
            }
            hdrs.into_iter()
                .flat_map(|h| h.join())
                .filter(|t| t.is_err())
                .collect::<Vec<_>>()
        });

        check_errlist!(errlist)
    }

    #[inline(always)]
    pub fn get_env_list() -> Result<Vec<EnvName>> {
        EnvMeta::<C, Node<P>>::get_env_list().c(d!())
    }

    fn load_env_by_cfg<A, U>(cfg: &EnvCfg<A, C, P, U>) -> Result<Env<C, P, S>>
    where
        A: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
        U: CustomOps,
    {
        Self::load_env_by_name(&cfg.name)
            .c(d!())
            .and_then(|env| match env {
                Some(env) => Ok(env),
                None => {
                    eprintln!();
                    eprintln!("********************");
                    eprintln!(
                        "\x1b[01mHINTS: \x1b[33;01mENV({}) NOT FOUND\x1b[00m",
                        &cfg.name
                    );
                    eprintln!("********************");
                    Err(eg!("ENV({}) NOT FOUND", &cfg.name))
                }
            })
    }

    #[inline(always)]
    pub fn load_env_by_name(cfg_name: &EnvName) -> Result<Option<Env<C, P, S>>> {
        EnvMeta::<C, Node<P>>::load_env_by_name(cfg_name).c(d!())
    }

    #[inline(always)]
    pub fn write_cfg(&self) -> Result<()> {
        serde_json::to_vec_pretty(self).c(d!()).and_then(|d| {
            fs::write(format!("{}/config.json", &self.meta.home), d).c(d!())
        })
    }

    // alloc <host,ports> for a new node
    fn alloc_hosts_ports(&mut self, node_kind: &Kind) -> Result<(HostMeta, P)> {
        let host = self.alloc_host(node_kind).c(d!())?;
        let ports = self.alloc_ports(node_kind, &host).c(d!())?;
        Ok((host, ports))
    }

    fn alloc_host(&mut self, node_kind: &Kind) -> Result<HostMeta> {
        let (max_host, max_weight) = self
            .meta
            .hosts
            .as_ref()
            .values()
            .map(|h| (h.meta.clone(), h.weight))
            .max_by(|a, b| a.1.cmp(&b.1))
            .c(d!("BUG"))?;

        let h = if matches!(node_kind, Kind::Bootstrap) {
            max_host
        } else {
            let mut seq = self
                .meta
                .hosts
                .as_ref()
                .values()
                .map(|h| (h.meta.clone(), (h.node_cnt * max_weight) / h.weight))
                .collect::<Vec<_>>();
            seq.sort_unstable_by(|a, b| a.1.cmp(&b.1));
            seq.into_iter().next().c(d!()).map(|h| h.0)?
        };

        self.meta.hosts.as_mut().get_mut(&h.addr).unwrap().node_cnt += 1;

        Ok(h)
    }

    fn alloc_ports(&self, node_kind: &Kind, host: &HostMeta) -> Result<P> {
        let reserved_ports = P::reserved();
        let reserved = reserved_ports
            .iter()
            .map(|p| format!("{},{}", &host.addr, p))
            .collect::<Vec<_>>();
        let remote = Remote::from(host);

        let occupied = remote.get_occupied_ports().c(d!())?;
        let port_is_free = |p: &u16| !occupied.contains(p);

        let mut res = vec![];
        if matches!(node_kind, Kind::Bootstrap)
            && ENV_NAME_DEFAULT == self.meta.name.as_ref()
            && reserved.iter().all(|hp| !PC.contains(hp))
            && reserved_ports.iter().all(|p| port_is_free(p))
        {
            res = reserved_ports;
        } else {
            let mut cnter = 10000;
            while reserved.len() > res.len() {
                let p = 20000 + random::<u16>() % (65535 - 20000);
                let hp = format!("{},{}", &host.addr, p);
                if !reserved.contains(&hp) && !PC.contains(&hp) && port_is_free(&p) {
                    res.push(p);
                }
                cnter -= 1;
                alt!(0 == cnter, return Err(eg!("ports can not be allocated")))
            }
        }

        PC.set(
            &res.iter()
                .map(|p| format!("{},{}", &host.addr, p))
                .collect::<Vec<_>>(),
        );

        P::try_create(&res).c(d!())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct Node<P: NodePorts> {
    id: NodeId,
    #[serde(rename = "tendermint_node_id")]
    tm_id: String,
    #[serde(rename = "node_home_dir")]
    pub home: String,
    kind: Kind,
    pub host: HostMeta,
    pub ports: P,
}

impl<P: NodePorts> Node<P> {
    fn start<C, S>(&self, env: &Env<C, P, S>) -> Result<()>
    where
        C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
        S: NodeOptsGenerator<Node<P>, EnvMeta<C, Node<P>>>,
    {
        self.stop().c(d!())?;

        let (tmvars, tmopts) = env.node_opts_generator.tendermint_opts(self, &env.meta);
        let (appvars, appopts) = env.node_opts_generator.app_opts(self, &env.meta);
        let cmd = format!(
            "{tmvars} {tmbin} {tmopts} >>{home}/tendermint.log 2>&1 & \
             {appvars} {appbin} {appopts} >>{home}/app.log 2>&1 &",
            tmbin = env.meta.tendermint_bin,
            appbin = env.meta.app_bin,
            home = &self.home,
        );

        let outputs = Remote::from(&self.host).exec_cmd(&cmd).c(d!())?;
        let log = format!("{}\n{}", &cmd, outputs.as_str());
        self.write_dev_log(&log).c(d!())
    }

    fn stop(&self) -> Result<()> {
        let cmd = format!(
            "for i in \
                $(ps ax -o pid,args \
                    | grep '{}' \
                    | grep -v 'grep' \
                    | grep -Eo '^ *[0-9]+' \
                    | sed 's/ //g' \
                ); \
             do kill -9 $i; done",
            &self.home
        );
        let outputs = Remote::from(&self.host).exec_cmd(&cmd).c(d!())?;
        let log = format!("{}\n{}", &cmd, outputs.as_str());
        self.write_dev_log(&log).c(d!())
    }

    fn write_dev_log(&self, log: &str) -> Result<()> {
        let log = format!("\n\n[ {} ]\n{}: {}", datetime!(), &self.host.addr, log);
        let logfile = format!("{}/mgmt.log", &self.home);
        Remote::from(&self.host)
            .write_file(logfile, log.as_bytes())
            .c(d!())
    }

    // - release all occupied ports
    // - remove all files related to this node
    fn clean(&self) -> Result<()> {
        for port in self.ports.get_port_list().iter() {
            PC.remove(&format!("{},{}", &self.host.addr, port));
        }

        // remove all related files
        Remote::from(&self.host)
            .exec_cmd(&format!("rm -rf {}", &self.home))
            .c(d!())
            .map(|_| ())
    }
}

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
enum Kind {
    #[serde(rename = "ValidatorOrFull")]
    Node,
    Bootstrap,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub enum Op<A, C, P, U>
where
    A: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    P: NodePorts,
    U: CustomOps,
{
    Create(EnvOpts<A, C>),
    Destroy,
    DestroyAll,
    Start,
    StartAll,
    Stop,
    StopAll,
    PushNode,
    PopNode,
    Show,
    ShowAll,
    List,
    HostPutFile {
        local_path: String,
        remote_path: Option<String>,
        hosts: Option<Hosts>,
    },
    HostGetFile {
        remote_path: String,
        local_base_dir: Option<String>,
        hosts: Option<Hosts>,
    },
    HostExec {
        cmd: Option<String>,
        script_path: Option<String>,
        hosts: Option<Hosts>,
    },
    NodeCollectLogs {
        local_base_dir: Option<String>,
    },
    Custom(U),
    Nil(P),
}

/// Options specified with the create operation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct EnvOpts<A, C>
where
    A: fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
    C: Send + Sync + fmt::Debug + Clone + Serialize + for<'a> Deserialize<'a>,
{
    /// host list of the env
    pub hosts: Hosts,

    /// seconds between two blocks
    pub block_itv_secs: BlockItv,

    /// how many initial validators should be created,
    /// default to 4
    pub initial_validator_num: u8,

    pub app_bin_path: String,
    pub app_extra_opts: String,

    pub tendermint_bin_path: String,
    pub tendermint_extra_opts: String,

    pub force_create: bool,

    pub app_state: A,
    pub custom_data: C,
}

static PC: Lazy<PortsCache> = Lazy::new(PortsCache::new);

#[derive(Serialize, Deserialize)]
struct PortsCache {
    vsdb_base_dir: String,
    // [ <remote addr + remote port> ]
    port_set: MapxRaw,
}

impl PortsCache {
    fn new() -> Self {
        let vbd = format!("{}/ports_cache", &*GLOBAL_BASE_DIR);
        pnk!(vsdb::vsdb_set_base_dir(&vbd));
        Self {
            vsdb_base_dir: vbd,
            port_set: MapxRaw::new(),
        }
    }

    fn contains(&self, port: &str) -> bool {
        self.port_set.contains_key(port.as_bytes())
    }

    fn set(&self, ports: &[String]) {
        for p in ports {
            assert!(
                unsafe { self.port_set.shadow() }
                    .insert(p.as_bytes(), [1])
                    .is_none()
            );
        }
    }

    fn remove(&self, port: &str) {
        unsafe { self.port_set.shadow() }.remove(port.as_bytes());
    }
}
