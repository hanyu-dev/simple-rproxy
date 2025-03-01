use std::{
    env::var,
    fs,
    net::SocketAddr,
    path::Path,
    sync::{Arc, LazyLock},
};

use anyhow::{Context, Result, anyhow, bail};
use arc_swap::ArcSwapOption;
use clap::Parser;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use crate::utils::{Upstream, UpstreamArg, VERSION};

/// type alia: upstream map
type UpstreamMap = DashMap<Arc<str>, Arc<Upstream>, foldhash::fast::RandomState>;

// Global config

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

fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 443))
}

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
/// Server config
pub(crate) struct Config {
    /// Version of config file.
    pub version: u8,

    #[cfg(unix)]
    #[serde(default = "default_pid_file")]
    /// PID file, default to be `/dev/shm/simple-rproxy/current.pid`.
    pub pid_file: Arc<str>,

    #[serde(default = "default_listen")]
    /// Local socket addr to bind to, default to be `0.0.0.0:443`.
    pub listen: SocketAddr,

    #[serde(default)]
    /// Default upstream to connect to.
    ///
    /// If not set, will send TLS alert to HTTPS stream and drop the
    /// connection immediately when there's no matched upstream.
    pub default_upstream: Option<Arc<Upstream>>,

    #[serde(default, alias = "upstream")]
    /// Upstreams to connect to.
    pub upstreams: UpstreamMap,

    #[serde(skip)]
    config_file: Arc<str>,
}

impl Config {
    /// Try init config from config file or CLI args.
    ///
    /// Return `true` if can start or restart the server.
    pub(crate) fn try_init() -> Result<bool> {
        let mut args = Cli::parse();

        // * Handle sub command
        if let Some(cmd) = args.subcommand.take() {
            match cmd {
                SubCommand::GenerateConfig => {
                    tracing::info!("Generating example config file...");

                    Self::generate_example_config_file()?;
                }
                SubCommand::Version => {
                    tracing::info!("Server version: {}", VERSION);
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
                                    tracing::error!(file, "Read PID file error: {e:?}.");
                                })
                                .ok()?
                                .parse()
                                .inspect_err(|e| {
                                    tracing::error!(file, "Parse PID file error: {e:?}.");
                                })
                                .ok()
                        })
                        .context("No PID provided.")?;

                    let status = process::Command::new("/bin/kill")
                        .arg("-HUP")
                        .arg(pid.to_string())
                        .stdin(process::Stdio::null())
                        .stdout(process::Stdio::piped())
                        .status()?;

                    tracing::info!(pid, "Reload finished, result: {status:?}.");
                }
            }

            return Ok(false);
        }

        Self::load_config_file(Some(args.config_file.clone()))?
            .inspect(|config| {
                tracing::info!("Config loaded from file: {config:#?}");
            })
            .unwrap_or_else(|| {
                tracing::info!("No config file found, use command line args to init config.");

                let Cli {
                    listen,
                    default_upstream,
                    upstream,
                    pid_file,
                    config_file,
                    ..
                } = args;

                let upstreams = upstream
                    .into_iter()
                    .map(|UpstreamArg { sni, upstream }| (sni, upstream))
                    .collect();

                let config = Config {
                    version: CONFIG_VERSION,
                    pid_file: pid_file.unwrap_or_else(default_pid_file),
                    listen: listen.unwrap_or_else(default_listen),
                    default_upstream,
                    upstreams,
                    config_file,
                };

                tracing::info!("Config loaded from CLI args: {config:#?}");
                config
            })
            .apply_global_config::<false>()?;

        Ok(true)
    }

    /// Apply global config, return old config.
    fn apply_global_config<const IS_RELOAD: bool>(mut self) -> Result<Option<Arc<Self>>> {
        #[cfg(unix)]
        // `reload` should never affect PID file!
        if IS_RELOAD {
            self.pid_file = CONFIG
                .load()
                .as_ref()
                .expect("can reload only after the server has been started")
                .pid_file
                .clone();
        } else {
            use crate::utils::PidFile;

            if let pid_file @ Some(_) =
                PidFile::new(self.pid_file.clone()).context("Create PID file error")?
            {
                PID_FILE.store(pid_file);
            } else {
                // no op
            };
        }

        DEFAULT_UPSTREAM.store(self.default_upstream.clone());

        TARGET_UPSTREAMS.retain(|key, _v| self.upstreams.contains_key(key));
        self.upstreams.iter().for_each(|kv| {
            TARGET_UPSTREAMS.insert(Arc::clone(kv.key()), Arc::clone(kv.value()));
        });

        Ok(CONFIG.swap(Some(self.into())))
    }

    /// Load config file from given path, or from path that the command line arg
    /// set.
    ///
    /// # Errors
    ///
    /// - Config version mismatched.
    /// - IO error.
    fn load_config_file(path: Option<Arc<str>>) -> Result<Option<Config>> {
        let config = CONFIG.load();
        let config_path_str = config
            .as_ref()
            .map(|c| c.config_file.clone())
            .or(path)
            .expect("No config path given?");
        let config_path = Path::new(&*config_path_str);

        tracing::trace!(config_path = &*config_path_str, "Loading config file.");

        if !config_path.exists() {
            return Ok(None);
        }

        let mut config: Result<Config, serde_json::Error> = serde_json::from_reader(
            fs::OpenOptions::new()
                .read(true)
                .open(config_path)
                .context("Open config file error")?,
        );

        if let Ok(config) = config.as_mut() {
            if config.version != CONFIG_VERSION {
                bail!(
                    "Invalid config, version mismatched, expect {CONFIG_VERSION} but {}",
                    config.version
                )
            }

            config.config_file = config_path_str;
        }

        config.map(Some).context("Parse config file error")
    }

    /// Generate example config file in current dir.
    fn generate_example_config_file() -> Result<()> {
        let config_file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open("./config.example.json")
            .context("Open ./config.example.json error")?;

        let upstreams = [
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
            pid_file: default_pid_file(),
            listen: default_listen(),
            default_upstream: None,
            upstreams,
            config_file: "./config.json".into(), // actually no need?
        };

        serde_json::to_writer_pretty(config_file, &config)
            .context("Write config.example.json error")?;

        tracing::info!("Config file generated, please edit, rename to `config.json` and restart.");

        Ok(())
    }

    /// Reload config from file.
    ///
    /// If listen addr is changed, return true.
    pub(crate) fn reload() -> Result<bool> {
        let config = Self::load_config_file(None)?.ok_or_else(|| {
            let config = CONFIG.load();
            let config_file = &*config
                .as_ref()
                .expect("will reload only after the server has been started")
                .config_file;
            anyhow!("Non existing config file when reloading: `{config_file}`")
        })?;

        tracing::info!("New config loaded from file: {config:#?}");

        let new_listen = config.listen;
        let old_config = config
            .apply_global_config::<true>()
            .expect("may fail only when the first time running server");

        #[allow(unsafe_code, reason = "Have checked old_config is not None")]
        Ok(unsafe { old_config.unwrap_unchecked().listen != new_listen })
    }
}

#[derive(Debug, clap::Parser)]
#[command(version, about, long_about = None)]
pub(crate) struct Cli {
    #[arg(short, long, default_value = "./config.json")]
    /// Config file.
    ///
    /// # Notice
    ///
    /// If the config file exists, we will load from it and **IGNORE** all
    /// command line args.
    pub config_file: Arc<str>,

    #[arg(short, long)]
    /// Local socket addr to bind to, default to be `0.0.0.0:443`.
    pub listen: Option<SocketAddr>,

    #[arg(short, long, value_parser = Upstream::parse)]
    /// Default upstream to connect to.
    ///
    /// If no default upstream specified, the server will send TLS alert (for
    /// HTTPS connection), then the connection will be dropped immediately.
    pub default_upstream: Option<Arc<Upstream>>,

    #[arg(short, long)]
    /// Upstreams to connect to.
    ///
    /// The format should be `{TARGET_SNI}:{UPSTREAM}`.
    ///
    /// # Examples
    ///
    /// - `example.com:127.0.0.1:8443` // {SNI}:{UPSTREAM}
    /// - `PROXY_PROTOCOL_V2@example.com:127.0.0.1:443` // The upstream accepts
    ///   proxy protocol v2 (v1 version is not supported).
    pub upstream: Vec<UpstreamArg>,

    #[cfg(unix)]
    #[arg(long)]
    /// PID file.
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
