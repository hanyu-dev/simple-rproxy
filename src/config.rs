use std::{
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

/// Global config, which is less frequently used.
pub(crate) static CONFIG: ArcSwapOption<Config> = ArcSwapOption::const_empty();

/// Config version
const CONFIG_VERSION: u8 = 1;

#[derive(Debug)]
#[derive(Serialize, Deserialize)]
pub(crate) struct Config {
    /// Version of config file.
    pub version: u8,

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
    fn apply_global_config(self) -> Option<Arc<Self>> {
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
            }
        }

        match Self::load_config_file()? {
            Some(config) => {
                tracing::info!("Config loaded from file: {config:#?}");

                config.apply_global_config();
            }
            _ => {
                tracing::info!("No config file found, use CLI args to init config.");

                let Cli {
                    listen,
                    default_upstream,
                    upstream,
                    https_only,
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
                    listen,
                    default_upstream,
                    upstream,
                    https_only,
                };

                tracing::info!("Config loaded from CLI args: {config:#?}");
                config.apply_global_config();
            }
        }

        Ok(true)
    }

    /// Reload config from file.
    ///
    /// If listen addr is changed, return true.
    pub(crate) fn reload_config() -> Result<bool> {
        let new_listen = {
            CONFIG
                .load()
                .as_ref()
                .expect("Cannot reload config before init")
                .listen
        };

        let config = Self::load_config_file()?.context("Cannot reload without config file")?;

        let old_config = CONFIG.swap(Some(config.into()));

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
