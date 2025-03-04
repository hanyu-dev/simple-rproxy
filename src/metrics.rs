//! Traffic metrics

use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{LazyLock, OnceLock},
};

use capnp::{capability::Promise, message::ReaderOptions};
use capnp_rpc::{RpcSystem, rpc_twoparty_capnp, twoparty};
use dashmap::DashMap;
use futures_util::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::{
    config::CONFIG,
    proto,
    utils::{AtomicTraffic, Traffic},
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

/// Init metrics collector and exporter
pub(crate) async fn init_metrics_channel() {
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
}

/// Init metrics server
pub(crate) fn init_metrics_server() {
    std::thread::Builder::new()
        .name("metrics".into())
        .spawn(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Build metrics thread tokio runtime error");

            let local_set = tokio::task::LocalSet::new();

            local_set.spawn_local(async move {
                let metrics_client: proto::metrics::Client = capnp_rpc::new_client(MetricsImpl);

                let metrics_listener = {
                    let metrics_listen = CONFIG
                        .load()
                        .as_ref()
                        .expect("must have config initialized")
                        .metrics_listen;

                    TcpListener::bind(metrics_listen)
                        .await
                        .inspect_err(|e| {
                            tracing::error!("Bind to {metrics_listen} error: {e:?}");
                        })
                        .unwrap()
                };

                loop {
                    let (incoming, remote_addr) = match metrics_listener.accept().await {
                        Ok(accepted) => accepted,
                        Err(e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                            continue;
                        }
                        Err(e) => {
                            tracing::error!("Failed to accept: {:#?}", e);
                            break;
                        }
                    };

                    let _ = incoming
                        .set_nodelay(true)
                        .inspect_err(|e| tracing::error!(remote_addr = ?remote_addr, "Set no delay error: {e:?}"));

                    let (reader, writer) = incoming.compat().split();

                    let network = twoparty::VatNetwork::new(
                        futures_util::io::BufReader::new(reader),
                        futures_util::io::BufWriter::new(writer),
                        rpc_twoparty_capnp::Side::Server,
                        ReaderOptions::default()
                    );

                    let rpc_system =
                        RpcSystem::new(Box::new(network), Some(metrics_client.clone().client));

                    tokio::task::spawn_local(rpc_system);
                }
            });

            rt.block_on(local_set);
        })
        .expect("create metrics thread error");
}

pub(crate) fn print_traffics(metrics_listen: SocketAddr, to_show: usize) {
    // F**k capnproto-rust, why not tokio???
    use capnp_rpc::{RpcSystem, rpc_twoparty_capnp, twoparty};
    use futures_util::AsyncReadExt;
    use tokio::{net::TcpStream, task::LocalSet};
    use tokio_util::compat::TokioAsyncReadCompatExt;

    let local_set = LocalSet::new();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    local_set.block_on(&rt, async move {
        let stream = TcpStream::connect(&metrics_listen)
            .await
            .expect("connect to metrics error");

        let _ = stream.set_nodelay(true).inspect_err(|e| {
            tracing::error!(metrics_listen = ?metrics_listen, "Set no delay error: {e:?}");
        });

        let (reader, writer) = stream.compat().split();

        let network = twoparty::VatNetwork::new(
            futures_util::io::BufReader::new(reader),
            futures_util::io::BufWriter::new(writer),
            rpc_twoparty_capnp::Side::Client,
            ReaderOptions::default(),
        );

        let mut rpc_system = RpcSystem::new(Box::new(network), None);
        let metrics_client: proto::metrics::Client =
            rpc_system.bootstrap(rpc_twoparty_capnp::Side::Server);

        tokio::task::spawn_local(rpc_system);

        let traffics = metrics_client
            .get_traffic_infos_request()
            .send()
            .promise
            .await
            .unwrap();

        let mut traffics = traffics
            .get()
            .unwrap()
            .get_reply()
            .unwrap()
            .get_inner()
            .unwrap()
            .iter()
            .map(|t| {
                let tx = t.get_tx();
                let rx = t.get_rx();
                (t.get_ip().unwrap(), tx, rx, tx + rx)
            })
            .collect::<Vec<_>>();

        let traffics_len = traffics.len();
        tracing::info!("Found {traffics_len} traffics records, {to_show} to show.");

        traffics.sort_unstable_by(|l, r| r.3.cmp(&l.3));

        println!(
            "┌{:─^4}┬{:─^39}┬{:─^11}┬{:─^11}┬{:─^11}┐",
            "", "", "", "", ""
        );
        println!(
            "│{: ^4}│{: ^39}│{: ^11}│{: ^11}│{: ^11}│",
            "No", "IP Address", "TX", "RX", "TOTAL"
        );
        traffics
            .into_iter()
            .enumerate()
            .take(to_show)
            .for_each(|(idx, (ip, tx, rx, total))| {
                let ip = ip.as_slice().unwrap();

                #[allow(clippy::unreachable, reason = "should not have invalid ip")]
                let ip = ip
                    .as_array::<4>()
                    .map(|&ip| IpAddr::from(ip))
                    .or_else(|| ip.as_array::<16>().map(|&ip| IpAddr::from(ip)))
                    .unwrap_or_else(|| unreachable!("found invalid ip: {:?}", ip));

                println!(
                    "├{:─^4}┼{:─^39}┼{:─^11}┼{:─^11}┼{:─^11}┤",
                    "", "", "", "", ""
                );
                println!(
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
                        .format(total)
                        .to_string()
                );
            });

        if let Some(leftover) = traffics_len.checked_sub(to_show).take_if(|l| *l > 0) {
            if leftover > 1 {
                println!(
                    "├{:─^4}┼{:─^39}┼{:─^11}┼{:─^11}┼{:─^11}┤",
                    "", "", "", "", ""
                );
                println!(
                    "│{: >4}│{: >39}│{: >11}│{: >11}│{: >11}│",
                    "...", "...", "...", "...", "..."
                );
            }

            println!(
                "├{:─^4}┼{:─^39}┼{:─^11}┼{:─^11}┼{:─^11}┤",
                "", "", "", "", ""
            );
            println!(
                "│{: >4}│{: >39}│{: >11}│{: >11}│{: >11}│",
                1.min(leftover), "...", "...", "...", "..."
            )
        }

        println!(
            "└{:─^4}┴{:─^39}┴{:─^11}┴{:─^11}┴{:─^11}┘",
            "", "", "", "", ""
        );
    });
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

struct MetricsImpl;

impl proto::metrics::Server for MetricsImpl {
    fn get_traffic_infos(
        &mut self,
        _: proto::metrics::GetTrafficInfosParams,
        mut results: proto::metrics::GetTrafficInfosResults,
    ) -> Promise<(), capnp::Error> {
        Promise::from_future(async move {
            let traffics: Vec<(IpAddr, Traffic)> = TRAFFICS
                .iter()
                .map(|r| (*r.key(), Traffic::from_atomic(r.value())))
                .collect();

            let mut traffics_reply_builder =
                results.get().init_reply().init_inner(traffics.len() as u32);

            traffics
                .into_iter()
                .enumerate()
                .for_each(|(idx, (ip, Traffic { tx, rx }))| {
                    let mut current = traffics_reply_builder.reborrow().get(idx as u32);

                    let ip = ip.as_octets();
                    current
                        .reborrow()
                        .init_ip(ip.len() as u32)
                        .as_slice()
                        .expect("init")
                        .clone_from_slice(ip);

                    current.set_tx(tx);
                    current.set_rx(rx);
                });

            Ok(())
        })
    }
}
