//! Traffic metrics

use std::{
    net::IpAddr,
    sync::{LazyLock, OnceLock},
};

use dashmap::DashMap;

use crate::utils::{AtomicTraffic, Traffic};

static METRICS: LazyLock<DashMap<IpAddr, AtomicTraffic>> = LazyLock::new(DashMap::new);

pub(crate) static METRIC_TX: OnceLock<tokio::sync::mpsc::Sender<(IpAddr, Traffic)>> =
    OnceLock::new();

#[macro_export]
/// send metric
macro_rules! send_metric {
    ($ip:expr, $traffic:expr) => {{
        #[allow(unsafe_code, reason = "must have initialized METRIC_TX")]
        unsafe { $crate::metrics::METRIC_TX.get().unwrap_unchecked() }
            .send(($ip, $traffic))
            .await
            .expect("Channel will be closed only when exit");
    }};
}

/// Init metrics collector and exporter
pub(crate) async fn init_metrics() {
    // Channel
    {
        let (channel_tx, mut channel_rx) = tokio::sync::mpsc::channel(8192);

        METRIC_TX.set(channel_tx).expect("should init metrics once");

        tokio::spawn(async move {
            while let Some((ip, traffic)) = channel_rx.recv().await {
                match METRICS.entry(ip) {
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

    // Simple server
}
