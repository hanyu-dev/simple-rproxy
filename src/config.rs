use std::{
    env::var,
    fs,
    net::SocketAddr,
    path::Path,
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, Result};
use arc_swap::ArcSwapOption;
use clap::Parser;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::utils::{Upstream, UpstreamArg, VERSION};

/// type alia: upstream map
type UpstreamMap = DashMap<Arc<str>, Arc<Upstream>, foldhash::fast::RandomState>;

// Global config

/// Global proxy protocol flag, optimized for performance.
pub(crate) static HTTPS_ONLY: AtomicBool = AtomicBool::new(false);

/// Global default upstream
pub(crate) static DEFAULT_UPSTREAM: ArcSwapOption<Upstream> = ArcSwapOption::const_empty();

/// Global target upstreams map
pub(crate) static TARGET_UPSTREAMS: LazyLock<UpstreamMap> = LazyLock::new(UpstreamMap::default);

/// Set if enable zero-copy, default enable
pub(crate) static ADV_ENABLE_ZERO_COPY: LazyLock<bool> = LazyLock::new(|| {
    var("RPROXY_ENABLE_ZERO_COPY")
        .map(|env_str| {
            let env_str = env_str.trim();

            #[allow(clippy::manual_unwrap_or, reason = "may add new branch")]
            if let Ok(enable) = env_str.parse::<i32>() {
                enable == 1
            } else if let Ok(enable) = env_str.parse::<bool>() {
                enable
            } else {
                true
            }
        })
        .unwrap_or(true)
});

/// Set IP TOS.
pub(crate) static ADV_IP_TOS: LazyLock<Option<u32>> = LazyLock::new(|| {
    let env_str = var("RPROXY_IP_TOS").ok()?;
    let env_str = env_str.trim();

    if let ip_tos @ Some(_) = env_str.parse::<u32>().ok() {
        ip_tos
    } else {
        Some(match env_str {
            "LOWDELAY" => 0x10,
            "THROUGHPUT" => 0x08,
            "RELIABILITY" => 0x04,
            "MINCOST" => 0x02,
            _ => return None,
        })
    }
});

/// Global config, which is less frequently used.
pub(crate) static CONFIG: ArcSwapOption<Config> = ArcSwapOption::const_empty();

#[cfg(unix)]
pub(crate) static PID_FILE: ArcSwapOption<crate::utils::PidFile> = ArcSwapOption::const_empty();

/// Config version
const CONFIG_VERSION: u8 = 5;

#[cfg(unix)]
/// Defalt PID file name
const DEFAULT_PID_FILE: &str = concat!("/dev/shm/", env!("CARGO_PKG_NAME"), "/current.pid");

#[cfg(unix)]
fn default_pid_file() -> Arc<str> {
    DEFAULT_PID_FILE.into()
}

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub(crate) struct Config {
    /// Version of config file.
    pub version: u8,

    #[cfg(unix)]
    #[serde(default)]
    /// PID file, default to be /run/simple-rproxy.pid
    pub pid_file: Option<Arc<str>>,

    /// Local socket addr to bind to, default to be 0.0.0.0:443
    pub listen: SocketAddr,

    /// Default upstream to connect to.
    pub default_upstream: Arc<Upstream>,

    /// Upstreams to connect to.
    pub upstream: UpstreamMap,

    /// If set, only accept HTTPS connections.
    pub https_only: bool,
}

impl Config {
    /// Apply global config, return old config.
    fn apply_global_config(self, _is_reload: bool) -> Option<Arc<Self>> {
        #[cfg(unix)]
        if !_is_reload {
            use crate::utils::PidFile;

            if let Some(pid_file) =
                PidFile::new(self.pid_file.clone().expect("must have pid file set"))
                    .expect("Create PID file error")
            {
                PID_FILE.swap(Some(Arc::new(pid_file)));
            } else {
                // no op
            };
        }

        HTTPS_ONLY.store(self.https_only, Ordering::Relaxed);

        DEFAULT_UPSTREAM.store(Some(Arc::clone(&self.default_upstream)));

        TARGET_UPSTREAMS.clear();
        self.upstream.iter().for_each(|kv| {
            TARGET_UPSTREAMS.insert(Arc::clone(kv.key()), Arc::clone(kv.value()));
        });

        CONFIG.swap(Some(self.into()))
    }
}

#[derive(Debug, clap::Parser)]
#[command(version, about, long_about = None)]
pub(crate) struct Cli {
    #[arg(short, long)]
    /// Local socket addr to bind to, default to be 0.0.0.0:443
    pub listen: Option<SocketAddr>,

    #[arg(short, long, value_parser = Upstream::parse)]
    /// Default upstream to connect to.
    ///
    /// If no default upstream specified in `--upstream`, you must specify one
    /// here.
    pub default_upstream: Option<Arc<Upstream>>,

    #[arg(short, long)]
    /// Upstreams to connect to.
    ///
    /// The format should be `{TARGET_SNI}:{UPSTREAM}`.
    ///
    /// # Examples
    ///
    /// - `default:127.0.0.1:443` // default upstream
    /// - `example.com:127.0.0.1:8443` // {SNI}:{UPSTREAM}
    /// - `PROXY_PROTOCOL_V2@example.com:127.0.0.1:443` // The upstream accepts
    ///   proxy protocol v2.
    ///
    ///   Notes: V1 version is not supported.
    ///
    /// # Notice
    ///
    /// If no default upstream specified, the first one will be used as default
    /// upstream.
    pub upstream: Vec<UpstreamArg>,

    #[arg(long, default_value_t = true)]
    /// If set, only accept HTTPS connections.
    pub https_only: bool,

    #[cfg(unix)]
    #[arg(long)]
    /// PID file name
    ///
    ///
    /// # Notice
    ///
    /// Will override the config file's setting.
    pub pid_file: Option<Arc<str>>,

    #[clap(subcommand)]
    /// Subcommand
    subcommand: Option<SubCommand>,
}

#[derive(Debug, Clone, Copy)]
#[derive(clap::Subcommand)]
enum SubCommand {
    /// Generate exxample config file.
    GenerateConfig,

    /// Print version and exit.
    Version,

    #[cfg(unix)]
    /// Reload
    Reload {
        #[arg(short, long)]
        /// PID to reload, or get from PID file
        pid: Option<u32>,
    },
}

impl Cli {
    /// Try init config from Cli / Config file, or exit early.
    ///
    /// Return true if can start or restart the server.
    pub(crate) fn try_init() -> Result<bool> {
        let mut args = Self::parse();

        // * Handle sub command
        if let Some(cmd) = args.subcommand.take() {
            match cmd {
                SubCommand::GenerateConfig => {
                    tracing::info!("Generating example config file...");

                    Self::gen_example_config_file()?;

                    return Ok(false);
                }
                SubCommand::Version => {
                    tracing::info!("Server version: {}", VERSION);

                    return Ok(false);
                }
                #[cfg(unix)]
                SubCommand::Reload { pid } => {
                    use std::process;

                    tracing::info!("Try reload server...");

                    let pid = pid
                        .or_else(|| {
                            let file = args
                                .pid_file
                                .as_ref()
                                .map(AsRef::as_ref)
                                .unwrap_or(DEFAULT_PID_FILE);
                            fs::read_to_string(file)
                                .inspect_err(|e| {
                                    tracing::error!(file, "Read PID file error: {e:?}");
                                })
                                .ok()?
                                .parse()
                                .inspect_err(|e| {
                                    tracing::error!(file, "Parse PID file error: {e:?}");
                                })
                                .ok()
                        })
                        .context("No PID")?;

                    let status = process::Command::new("/bin/kill")
                        .arg("-HUP")
                        .arg(pid.to_string())
                        .stdin(process::Stdio::null())
                        .stdout(process::Stdio::piped())
                        .status()?;

                    tracing::info!(pid, "Reload finished, result: {status:?}");

                    return Ok(false);
                }
            }
        }

        match Self::load_config_file()? {
            #[cfg_attr(not(unix), allow(unused_mut, reason = "cfg"))]
            Some(mut config) => {
                tracing::info!("Config loaded from file: {config:#?}");

                #[cfg(unix)]
                {
                    config.pid_file = Some(
                        args.pid_file
                            .or(config.pid_file)
                            .unwrap_or_else(default_pid_file),
                    );
                }

                config.apply_global_config(false);
            }
            _ => {
                tracing::info!("No config file found, use CLI args to init config.");

                let Cli {
                    listen,
                    default_upstream,
                    upstream,
                    https_only,
                    #[cfg(unix)]
                    pid_file,
                    subcommand: _,
                } = args;

                let listen = listen.unwrap_or_else(|| {
                    tracing::warn!("No listen addr specified, use default: 0.0.0.0:443");
                    SocketAddr::from(([0, 0, 0, 0], 443))
                });

                let upstream: DashMap<_, _, _> = upstream
                    .into_iter()
                    .map(|UpstreamArg { sni, upstream }| (sni, upstream))
                    .collect();

                let default_upstream = upstream
                    .remove("default")
                    .map(|(_, value)| value)
                    .or(default_upstream)
                    .context("No default upstream set, see `--help` for more details")?;

                let config = Config {
                    version: CONFIG_VERSION,
                    #[cfg(unix)]
                    pid_file: Some(pid_file.unwrap_or_else(default_pid_file)),
                    listen,
                    default_upstream,
                    upstream,
                    https_only,
                };

                tracing::info!("Config loaded from CLI args: {config:#?}");
                config.apply_global_config(false);
            }
        }

        Ok(true)
    }

    /// Reload config from file.
    ///
    /// If listen addr is changed, return true.
    pub(crate) fn reload_config() -> Result<bool> {
        let config = Self::load_config_file()?.context("Cannot reload without config file")?;

        tracing::info!("New config to be loaded: {config:#?}");

        let new_listen = config.listen;
        let old_config = config.apply_global_config(true);

        #[allow(unsafe_code, reason = "Have checked old_config is not None")]
        Ok(unsafe { old_config.unwrap_unchecked().listen != new_listen })
    }

    fn gen_example_config_file() -> Result<()> {
        let config_file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open("./config.example.json")
            .context("Open ./config.example.json error")?;

        let upstream = [
            (
                "example.com".into(),
                Upstream::parse("127.0.0.1:8443").unwrap().into(),
            ),
            (
                "example-proxy-protocol-v2.com".into(),
                Upstream::parse("127.0.0.1:8443")
                    .unwrap()
                    .set_proxy_protocol(true)
                    .into(),
            ),
            #[cfg(unix)]
            (
                "unix-path.example.com".into(),
                Upstream::parse("unix:/run/nginx/example.sock")
                    .unwrap()
                    .into(),
            ),
            #[cfg(unix)]
            (
                "unix-path.example-proxy-protocol-v2.com".into(),
                Upstream::parse("unix:/run/nginx/example.sock")
                    .unwrap()
                    .set_proxy_protocol(true)
                    .into(),
            ),
        ]
        .into_iter()
        .collect();

        let config = Config {
            version: CONFIG_VERSION,
            #[cfg(unix)]
            pid_file: Some(default_pid_file()),
            listen: SocketAddr::from(([0, 0, 0, 0], 443)),
            default_upstream: Upstream::parse("127.0.0.1:8443").unwrap().into(),
            upstream,
            https_only: true,
        };

        serde_json::to_writer_pretty(config_file, &config)
            .context("Write config.example.json error")?;

        tracing::info!("Config file generated, please edit, rename to `config.json` and restart.");

        Ok(())
    }

    fn load_config_file() -> Result<Option<Config>> {
        let file_path = Path::new("./config.json");

        if !file_path.exists() {
            tracing::info!("No config file found");
            return Ok(None);
        }

        let file = fs::OpenOptions::new()
            .read(true)
            .open(file_path)
            .context("Open config file error")?;

        serde_json::from_reader(file)
            .map(Some)
            .context("Parse config file error")
    }
}
