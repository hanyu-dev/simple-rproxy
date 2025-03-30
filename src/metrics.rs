//! Traffic metrics

use std::{
    env, fmt, io,
    net::IpAddr,
    sync::{LazyLock, OnceLock},
};

use anyhow::Result;
use dashmap::DashMap;
use macro_toolset::wrapper;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::{
    config,
    utils::{ArchivedTraffic, AtomicTraffic, Traffic},
};

static TRAFFICS: LazyLock<DashMap<IpAddr, AtomicTraffic>> = LazyLock::new(DashMap::new);

pub(crate) static TRAFFICS_TX: OnceLock<tokio::sync::mpsc::Sender<(IpAddr, Traffic)>> =
    OnceLock::new();

#[macro_export]
/// send metric
macro_rules! send_metric {
    ($ip:expr, $traffic:expr) => {{
        #[allow(unsafe_code, reason = "must have initialized TRAFFICS_TX")]
        unsafe { $crate::metrics::TRAFFICS_TX.get().unwrap_unchecked() }
            .send(($ip, $traffic))
            .await
            .expect("Channel will be closed only when exit");
    }};
}

/// init metrics related stuff
pub(crate) async fn init_metrics() {
    let (channel_tx, mut channel_rx) = tokio::sync::mpsc::channel(8192);

    TRAFFICS_TX
        .set(channel_tx)
        .expect("should init metrics once");

    tokio::spawn(async move {
        while let Some((ip, traffic)) = channel_rx.recv().await {
            match TRAFFICS.entry(ip) {
                dashmap::Entry::Occupied(occupied_entry) => {
                    occupied_entry.get().fetch_add(traffic);
                }
                dashmap::Entry::Vacant(vacant_entry) => {
                    vacant_entry.insert(AtomicTraffic::new(traffic));
                }
            };
        }

        tracing::info!("Metrics channel closed.");
    });

    let metrics_listen = config::CONFIG
        .load()
        .as_ref()
        .expect("must have config initialized")
        .metrics_listen;

    let metrics_listener = TcpListener::bind(metrics_listen).await.unwrap();

    tokio::spawn(async move {
        loop {
            let (mut incoming, _remote_addr) = match metrics_listener.accept().await {
                Ok(accepted) => accepted,
                Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                    tracing::debug!("Connection aborted.");
                    continue;
                }
                Err(e) => {
                    tracing::error!("Failed to accept: {:#?}", e);
                    break;
                }
            };

            tokio::spawn(async move {
                let mut metrics_req = [0u8; 1];
                incoming.read_exact(&mut metrics_req).await?;

                let metrics_reply =
                    match rkyv::access::<ArchivedMetricsReq, rkyv::rancor::Error>(&metrics_req)? {
                        ArchivedMetricsReq::Traffics => {
                            let mut traffics = TRAFFICS
                                .iter()
                                .map(|v| TrafficData {
                                    ip: *v.key(),
                                    traffic: Traffic::from_atomic(v.value()),
                                })
                                .collect::<Vec<_>>();

                            traffics
                                .sort_unstable_by(|p, l| l.traffic.total().cmp(&p.traffic.total()));

                            rkyv::to_bytes::<rkyv::rancor::Error>(&TrafficDatas::new(traffics))
                        }
                    }?;

                incoming.write_all(&metrics_reply).await?;
                incoming.write_u8(b'\n').await?;

                Ok::<_, anyhow::Error>(())
            });
        }
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)]
#[rkyv(
    // This will generate a PartialEq impl between our unarchived
    // and archived types
    compare(PartialEq),
    // Derives can be passed through to the generated type:
    derive(Debug),
)]
#[repr(u8)]
#[non_exhaustive]
/// Metrics req type
pub(crate) enum MetricsReq {
    /// Traffics
    Traffics = 0x01,
}

impl MetricsReq {
    /// Write request to TCP stream.
    pub(crate) async fn write_data(self, w: &mut TcpStream) -> Result<()> {
        w.write_all(&rkyv::to_bytes::<rkyv::rancor::Error>(&self)?)
            .await
            .map_err(Into::into)
    }
}

// #[test]
// fn t() {
//     let mut traffics = vec![
//         ("127.0.0.1".parse::<IpAddr>().unwrap(), 0u64, 0u64, 0u64),
//         (
//             "2408:8206:5431:bc9f:51da:d1ac:9363:4be7".parse().unwrap(),
//             48834234234092u64,
//             1565475688420013u64,
//             48834234234092u64 + 1565475688420013u64,
//         ),
//     ];

//     traffics.sort_unstable_by(|l, r| r.3.cmp(&l.3));

//     println!(
//         "|{: ^4}|{: ^39}|{: ^11}|{: ^11}|{: ^11}|",
//         "No", "IP Address", "TX", "RX", "TOTAL"
//     );
//     println!(
//         "|{: >4}|{: >39}|{: >11}|{: >11}|{: >11}|",
//         44, "", "1024.0 PiB", "1024.0 PiB", "1024.0 PiB"
//     );
//     println!(
//         "|{: >4}|{: >39}|{: >11}|{: >11}|{: >11}|",
//         444, "", "1024.0 PiB", "1024.0 PiB", "1024.0 PiB"
//     );
//     traffics
//         .into_iter()
//         .enumerate()
//         .take(9999)
//         .for_each(|(idx, (ip, tx, rx, total))| {
//             println!(
//                 "|{: >4}|{: >39}|{: >11}|{: >11}|{: >11}|",
//                 idx,
//                 ip,
//                 human_format_next::Formatter::BINARY
//                     .with_custom_unit("B")
//                     .format(tx)
//                     .to_string(),
//                 human_format_next::Formatter::BINARY
//                     .with_custom_unit("B")
//                     .format(rx)
//                     .to_string(),
//                 human_format_next::Formatter::BINARY
//                     .with_custom_unit("B")
//                     .format(total)
//                     .to_string()
//             );
//         });
// }

#[derive(Debug, Clone, Copy)]
#[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)]
pub(crate) struct TrafficData {
    ip: IpAddr,
    traffic: Traffic,
}

wrapper! {
    #[derive(Debug, Clone)]
    #[derive(rkyv::Serialize, rkyv::Deserialize, rkyv::Archive)]
    pub(crate) TrafficDatas(Vec<TrafficData>)
}

impl fmt::Display for ArchivedTrafficDatas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let to_show = env::var("SHOW_TRAFFICS")
            .ok()
            .and_then(|r| r.parse::<usize>().ok())
            .unwrap_or(50);

        writeln!(
            f,
            "┌{:─^4}┬{:─^39}┬{:─^11}┬{:─^11}┬{:─^11}┐",
            "", "", "", "", ""
        )?;
        writeln!(
            f,
            "│{: ^4}│{: ^39}│{: ^11}│{: ^11}│{: ^11}│",
            "No", "IP Address", "TX", "RX", "TOTAL"
        )?;

        for (
            idx,
            &ArchivedTrafficData {
                ip,
                traffic: ArchivedTraffic { tx, rx },
            },
        ) in self.inner.iter().enumerate().take(to_show)
        {
            let tx = tx.to_native();
            let rx = rx.to_native();
            let ip = match ip.as_ipaddr() {
                ip @ IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                    Some(v4) => IpAddr::V4(v4),
                    None => ip,
                },
                ip => ip,
            };

            writeln!(
                f,
                "├{:─^4}┼{:─^39}┼{:─^11}┼{:─^11}┼{:─^11}┤",
                "", "", "", "", ""
            )?;
            writeln!(
                f,
                "│{: >4}│{: >39}│{: >11}│{: >11}│{: >11}│",
                idx,
                ip,
                human_format_next::Formatter::BINARY
                    .with_custom_unit("B")
                    .format(tx)
                    .to_string(),
                human_format_next::Formatter::BINARY
                    .with_custom_unit("B")
                    .format(rx)
                    .to_string(),
                human_format_next::Formatter::BINARY
                    .with_custom_unit("B")
                    .format(tx + rx)
                    .to_string()
            )?;
        }

        if let Some(leftover) = self.inner.len().checked_sub(to_show).take_if(|l| *l > 0) {
            if leftover > 1 {
                writeln!(
                    f,
                    "├{:─^4}┼{:─^39}┼{:─^11}┼{:─^11}┼{:─^11}┤",
                    "", "", "", "", ""
                )?;
                writeln!(
                    f,
                    "│{: >4}│{: >39}│{: >11}│{: >11}│{: >11}│",
                    "...", "...", "...", "...", "..."
                )?;
            }

            writeln!(
                f,
                "├{:─^4}┼{:─^39}┼{:─^11}┼{:─^11}┼{:─^11}┤",
                "", "", "", "", ""
            )?;
            writeln!(
                f,
                "│{: >4}│{: >39}│{: >11}│{: >11}│{: >11}│",
                self.inner.len(),
                "...",
                "...",
                "...",
                "..."
            )?;
        }

        writeln!(
            f,
            "└{:─^4}┴{:─^39}┴{:─^11}┴{:─^11}┴{:─^11}┘",
            "", "", "", "", ""
        )?;

        Ok(())
    }
}

impl TrafficDatas {
    pub(crate) fn access(raw: &[u8]) -> Result<&ArchivedTrafficDatas, rkyv::rancor::Error> {
        rkyv::access(raw)
    }
}
