use super::{
    host::{Host, HostAddr, HostMeta, HostOS},
    Env, Node, NodeOptsGenerator, NodePorts,
};
use crate::check_errlist;
use ruc::{ssh, *};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use std::{fs, sync::Mutex, thread};

pub(super) struct Remote<'a> {
    inner: ssh::RemoteHost<'a>,
}

impl<'a> From<&'a HostMeta> for Remote<'a> {
    fn from(h: &'a HostMeta) -> Self {
        Remote {
            inner: ssh::RemoteHost {
                addr: &h.addr,
                user: &h.ssh_user,
                port: h.ssh_port,
                local_privkey: h.ssh_local_privkey.as_path(),
            },
        }
    }
}

impl<'a> From<&'a Host> for Remote<'a> {
    fn from(h: &'a Host) -> Self {
        Self::from(&h.meta)
    }
}

impl<'a> Remote<'a> {
    // execute a cmd on a remote host and get its outputs
    pub(super) fn exec_cmd(&self, cmd: &str) -> Result<String> {
        let cmd = format!("ulimit -n 100000 >/dev/null 2>&1;{}", cmd);
        self.inner
            .exec_cmd(&cmd)
            .map_err(|e| eg!(e))
            .map(|c| String::from_utf8_lossy(&c).into_owned())
    }

    pub(super) fn read_file<P: AsRef<Path>>(&self, path: P) -> Result<String> {
        self.inner
            .read_file(path)
            .map_err(|e| eg!(e))
            .map(|c| String::from_utf8_lossy(&c).into_owned())
    }

    pub(super) fn get_file<LP: AsRef<Path>, RP: AsRef<Path>>(
        &self,
        remote_path: RP,
        local_path: LP,
    ) -> Result<()> {
        self.inner
            .get_file(remote_path, local_path)
            .map_err(|e| eg!(e))
    }

    pub(super) fn write_file<P: AsRef<Path>>(
        &self,
        remote_path: P,
        contents: &[u8],
    ) -> Result<()> {
        self.inner
            .write_file(remote_path, contents)
            .map_err(|e| eg!(e))
    }

    pub(super) fn put_file<LP: AsRef<Path>, RP: AsRef<Path>>(
        &self,
        local_path: LP,
        remote_path: RP,
    ) -> Result<()> {
        self.inner
            .put_file(local_path, remote_path)
            .map_err(|e| eg!(e))
    }

    // ssh fh@192.168.2.105 ''
    pub(super) fn get_occupied_ports(&self) -> Result<BTreeSet<u16>> {
        self.exec_cmd(
            r#"if [[ "Linux" = `uname -s` ]]; then ss -ntua | sed 's/ \+/ /g' | cut -d ' ' -f 5 | grep -o '[0-9]\+$'; elif [[ "Darwin" = `uname -s` ]]; then lsof -nP -i TCP | grep -o ':[0-9]\+[ -]'; else exit 1; fi"#,
        )
        .c(d!())?
        .lines()
            .map(|l| l.trim_matches(|c| c == ':' || c == '-' || c == ' '))
        .filter(|p| !p.is_empty())
        .map(|p| p.trim().parse::<u16>().c(d!()))
        .collect::<Result<BTreeSet<u16>>>()
    }

    pub(super) fn get_hosts_weight(&self) -> Result<u64> {
        let cpunum = self
            .exec_cmd(
            r#"if [[ "Linux" = `uname -s` ]]; then grep -c processor /proc/cpuinfo; elif [[ "Darwin" = `uname -s` ]]; then sysctl -a | grep 'machdep.cpu.core_count' | grep -o '[0-9]\+$'; else exit 1; fi"#,
                )
            .c(d!())?
            .trim()
            .parse::<u64>()
            .c(d!())?;
        let bogomips = self
            .exec_cmd(
            r#"if [[ "Linux" = `uname -s` ]]; then grep bogomips /proc/cpuinfo | head -1 | sed 's/ //g' | cut -d ':' -f 2; elif [[ "Darwin" = `uname -s` ]]; then echo 4000.0; else exit 1; fi"#)
            .c(d!())?
            .trim()
            .parse::<f32>()
            .c(d!())? as u64;
        Ok(cpunum.saturating_mul(bogomips))
    }

    pub(super) fn hosts_os(&self) -> Result<HostOS> {
        let os = self.exec_cmd("uname -s").c(d!())?;
        let os = match os.trim() {
            "Linux" => HostOS::Linux,
            "Darwin" => HostOS::MacOS,
            "FreeBSD" => HostOS::FreeBSD,
            _ => HostOS::Unknown(os),
        };
        Ok(os)
    }

    // fn get_local_privkey(&self) -> Result<String> {
    //     fs::read_to_string(self.ssh_local_privkey).c(d!())
    // }

    // fn port_is_free(&self, port: u16) -> bool {
    //     let occupied = pnk!(self.get_occupied_ports());
    //     !occupied.contains(&port)
    // }
}

// put a local file to some hosts
pub(super) fn put_file_to_hosts(
    hosts: &BTreeMap<HostAddr, Host>,
    local_path: &str,
    remote_path: Option<&str>,
) -> Result<()> {
    let remote_path = if let Some(rp) = remote_path {
        rp
    } else {
        local_path
    };

    let errlist = thread::scope(|s| {
        hosts
            .values()
            .map(|h| {
                s.spawn(move || {
                    let remote = Remote::from(h);
                    remote.put_file(local_path, remote_path).c(d!())
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

// get a remote file from some hosts
pub(super) fn get_file_from_hosts(
    hosts: &BTreeMap<HostAddr, Host>,
    remote_path: &str,
    local_base_dir: Option<&str>,
) -> Result<()> {
    let local_base_dir = if let Some(lbd) = local_base_dir {
        lbd
    } else {
        "/tmp"
    };
    let remote_path = PathBuf::try_from(remote_path).c(d!())?;
    let remote_file = remote_path.file_name().c(d!())?.to_str().c(d!())?;
    let remote_path = &remote_path;

    let errlist = thread::scope(|s| {
        hosts
            .values()
            .map(|h| {
                let local_path =
                    format!("{}/{}_{}", local_base_dir, &h.meta.addr, remote_file);
                s.spawn(move || {
                    let remote = Remote::from(h);
                    remote.get_file(remote_path, local_path).c(d!())
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

// execute some commands or a script on some hosts
pub(super) fn exec_cmds_on_hosts(
    hosts: &BTreeMap<HostAddr, Host>,
    cmd: Option<&str>,
    script_path: Option<&str>,
) -> Result<()> {
    static LK: Mutex<()> = Mutex::new(());

    if let Some(cmd) = cmd {
        let errlist = thread::scope(|s| {
            hosts
                .values()
                .map(|h| {
                    s.spawn(move || {
                        let remote = Remote::from(h);
                        info!(remote.exec_cmd(cmd), &h.meta.addr).map(|outputs| {
                            let lk = LK.lock();
                            println!("== HOST: {} ==\n{}", &h.meta.addr, outputs);
                            drop(lk);
                        })
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .flat_map(|h| h.join())
                .filter(|t| t.is_err())
                .collect::<Vec<_>>()
        });
        check_errlist!(errlist)
    } else if let Some(sp) = script_path {
        let tmp_script_path = format!("/tmp/._{}", rand::random::<u64>());
        let cmd = format!("bash {}", tmp_script_path);

        let script = fs::read_to_string(sp).c(d!())?;
        let script =
            format!("{} && rm -f {}", script.trim_end(), tmp_script_path).into_bytes();

        let errlist = thread::scope(|s| {
            hosts
                .values()
                .map(|h| {
                    let remote = Remote::from(h);
                    let cmd = &cmd;
                    let script = &script;
                    let tmp_script_path = &tmp_script_path;
                    s.spawn(move || {
                        remote.write_file(tmp_script_path, script).c(d!()).and_then(
                            |_| {
                                info!(remote.exec_cmd(cmd), &h.meta.addr).map(
                                    |outputs| {
                                        let lk = LK.lock();
                                        println!(
                                            "== HOST: {} ==\n{}",
                                            &h.meta.addr, outputs
                                        );
                                        drop(lk);
                                    },
                                )
                            },
                        )
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .flat_map(|h| h.join())
                .filter(|t| t.is_err())
                .collect::<Vec<_>>()
        });
        check_errlist!(errlist)
    } else {
        Err(eg!("neither `cmd` nor `script_path` has value!"))
    }
}

pub(super) fn collect_logs_from_nodes<P: NodePorts, S: NodeOptsGenerator<Node<P>>>(
    env: &Env<P, S>,
    local_base_dir: Option<&str>,
) -> Result<()> {
    let local_base_dir = if let Some(lbd) = local_base_dir {
        lbd
    } else {
        "/tmp"
    };

    let errlist = thread::scope(|s| {
        env.nodes
            .values()
            .chain(env.seeds.values())
            .flat_map(|n| {
                ["app.log", "tendermint.log", "mgmt.log"].iter().map(|log| {
                    (
                        n.host.clone(),
                        format!("{}/{}", &n.home, log),
                        format!("N{}_{}", n.id, log),
                    )
                })
            })
            .map(|(host, remote_path, remote_file)| {
                s.spawn(move || {
                    let remote = Remote::from(&host);
                    let local_path =
                        format!("{}/{}_{}", local_base_dir, &host.addr, remote_file);
                    remote.get_file(remote_path, local_path).c(d!())
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
