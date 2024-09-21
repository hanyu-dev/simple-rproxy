use std::{
    collections::HashSet,
    fs, io,
    net::SocketAddr,
    process::exit,
    sync::{Arc, OnceLock},
};

use anyhow::{anyhow, bail, Result};
use arc_swap::ArcSwap;
use clap::Parser;
use once_cell::unsync::OnceCell;
use serde::{Deserialize, Serialize};

use crate::error::Error;

/// Global config
pub static ARGS: OnceLock<ArcSwap<Args>> = OnceLock::new();
/// Global target hosts set
pub static TARGET_HOSTS: OnceLock<ArcSwap<HashSet<String, ahash::RandomState>>> = OnceLock::new();

#[macro_export]
/// Get the global [Args] instance and get $name.
macro_rules! get_args {
    () => {
        $crate::config::ARGS
            .get()
            .expect("ARGS must be initialized")
            .load()
    };
}

#[derive(Debug, clap::Parser, Serialize, Deserialize)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[arg(short, long)]
    /// Local socket addr to bind to, default to be 0.0.0.0:443
    pub listen: Option<SocketAddr>,

    #[arg(long, value_parser = Upstream::parse)]
    #[serde(
        serialize_with = "Upstream::as_str",
        deserialize_with = "Upstream::from_str"
    )]
    /// Default upstream like `nginx` to connect to.
    ///
    /// Notice: Unix socket path is only available on Unix platforms and must be prefixed with `unix:`.
    ///
    /// Example: `--default-upstream unix:/path/to/unix.sock` or `--upstream 0.0.0.0:443"
    pub default_upstream: Option<Upstream>,

    #[arg(long, value_delimiter = ',')]
    /// If any of `target_host`s is detected in incoming TLS stream SNI, the underlying
    /// connection will be forwarded to the corresponding `target_upstream`.
    target_host: Vec<String>,

    #[arg(long, value_parser = Upstream::parse)]
    #[serde(
        serialize_with = "Upstream::as_str",
        deserialize_with = "Upstream::from_str"
    )]
    /// Target upstream to connect to when incoming TLS stream's SNI matches any of `target_host`s.
    pub target_upstream: Option<Upstream>,

    #[arg(long)]
    /// If set, only accept HTTPS connections.
    pub https_only: bool,
}

impl Args {
    pub fn try_init() -> Result<()> {
        let mut args = Self::parse();

        let config_file = OnceCell::new();

        if args.listen.is_none() {
            if let Ok(Some(listen)) = config_file
                .get_or_try_init(Self::from_file)
                .map(|f| f.listen)
            {
                args.listen = Some(listen);
            } else {
                args.listen = Some(SocketAddr::from(([0, 0, 0, 0], 443)));
            }
        }

        if args.default_upstream.is_none() {
            if let Some(default_iupstream) = config_file
                .get_or_try_init(Self::from_file)?
                .default_upstream
                .clone()
            {
                args.default_upstream = Some(default_iupstream);
            } else {
                bail!("missing default upstream in both cmdline args and config file");
            }
        }

        if args.target_host.is_empty() {
            let target_host = &config_file.get_or_try_init(Self::from_file)?.target_host;
            if !target_host.is_empty() {
                args.target_host = target_host.clone();
            } else {
                bail!("missing target host in both cmdline args and config file");
            }
        }

        if args.target_upstream.is_none() {
            if let Some(target_upstream) = config_file
                .get_or_try_init(Self::from_file)?
                .target_upstream
                .clone()
            {
                args.target_upstream = Some(target_upstream);
            } else {
                bail!("missing target upstream in both cmdline args and config file");
            }
        }

        if !args.https_only {
            args.https_only = config_file.get_or_try_init(Self::from_file)?.https_only;
        }

        args.set_global();

        Ok(())
    }

    #[allow(unused)]
    /// Reload config from file.
    ///
    /// If listen addr is changed, return true.
    pub fn reload_config() -> Result<bool> {
        let listen = get_args!().listen;

        Self::from_file()?.set_global();

        Ok(get_args!().listen == listen)
    }

    fn set_global(self) {
        tracing::debug!("Setting global config: \n###\n{:#?}\n###", &self);

        if let Err(target_host) = TARGET_HOSTS.set(ArcSwap::from(Arc::new(HashSet::from_iter(
            self.target_host.clone(),
        )))) {
            TARGET_HOSTS.get().unwrap().store(target_host.into_inner());
        }

        if let Err(args) = ARGS.set(ArcSwap::from(Arc::new(self))) {
            ARGS.get().unwrap().store(args.into_inner());
        }
    }

    fn from_file() -> Result<Self> {
        match fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("./config.json")
        {
            Ok(config_file) => serde_json::from_reader(config_file).map_err(Into::into),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                tracing::info!("Config file not found, generate example config and exit. DO RENAME to `config.json` after editted.");

                if let Ok(f) = fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open("./config.example.json")
                {
                    let _ = serde_json::to_writer_pretty(
                        f,
                        &Args {
                            listen: Some(SocketAddr::from(([0, 0, 0, 0], 443))),
                            default_upstream: Some(Upstream::SocketAddr(SocketAddr::from((
                                [127, 0, 0, 1],
                                443,
                            )))),
                            target_host: vec!["example.com".to_string()],
                            target_upstream: Some(Upstream::SocketAddr(SocketAddr::from((
                                [127, 0, 0, 1],
                                443,
                            )))),
                            https_only: false,
                        },
                    );
                }

                exit(0)
            }
            Err(e) => Err(anyhow!(Error::Config("IO")).context(e)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Upstream to connect to.
pub enum Upstream {
    /// Upstream addr to connect to.
    SocketAddr(SocketAddr),

    #[cfg(unix)]
    /// Unix socket path to connect to.
    Unix(String),
}

impl Upstream {
    /// Parse string to [Upstream], for [clap].
    fn parse(s: &str) -> Result<Self> {
        #[allow(unused_variables)]
        if let Some(unix_path) = s.strip_prefix("unix:") {
            #[cfg(unix)]
            return Ok(Upstream::Unix(unix_path.to_string()));
            #[cfg(not(unix))]
            bail!("Unix socket path is not supported on this platform");
        } else {
            match s.parse() {
                Ok(addr) => Ok(Upstream::SocketAddr(addr)),
                Err(_) => bail!("Invalid upstream. See help for more details"),
            }
        }
    }

    fn from_str<'de, D>(deserializer: D) -> Result<Option<Self>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let string = Option::<String>::deserialize(deserializer)?;

        if string.is_none() {
            return Ok(None);
        }

        let string = string.unwrap();

        #[allow(unused_variables)]
        if let Some(unix_path) = string.strip_prefix("unix:") {
            #[cfg(unix)]
            return Ok(Some(Upstream::Unix(unix_path.to_string())));
            #[cfg(not(unix))]
            return Err(D::Error::custom(
                "Unix socket path is not supported on this platform",
            ));
        } else {
            match string.parse() {
                Ok(addr) => Ok(Some(Upstream::SocketAddr(addr))),
                Err(_) => Err(D::Error::custom(format!(
                    "Invalid upstream `{string}`. See help for more details"
                ))),
            }
        }
    }

    fn as_str<S>(v: &Option<Self>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match v {
            Some(Upstream::SocketAddr(addr)) => addr.to_string().serialize(serializer),
            #[cfg(unix)]
            Some(Upstream::Unix(path)) => format!("unix:{}", path).serialize(serializer),
            None => "".serialize(serializer),
        }
    }
}
