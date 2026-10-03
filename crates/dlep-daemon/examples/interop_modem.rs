//! Controlled modem fixture for .github/scripts/interop-dlepard.py.
//! Commands use stdin; lifecycle acknowledgements use stdout. No wire encoding
//! is implemented here: all traffic goes through the public daemon API.
use dlep_core::{MacAddress, StatusCode};
use dlep_daemon::{DaemonEvent, DestinationId, LinkMetrics, ModemConfig, ModemDaemon};
use std::io::{BufRead, Write};
use std::time::Duration;

fn report(line: &str) {
    println!("{line}");
    std::io::stdout().flush().unwrap();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = ModemConfig::default();
    config.shared.network.bind_addr = "127.0.0.1".parse()?;
    config.shared.network.tcp_port = 0;
    config.shared.network.discovery_port = 0;
    config.shared.network.use_tls = false;
    // Strict GTSM remains enabled, including the privileged packet monitor.
    config.shared.timers.heartbeat_interval_ms = 1_000;
    config.shared.timers.termination_timeout_ms = Some(2_000);
    config.metrics.max_data_rate_rx_bps = 10_000_000;
    config.metrics.max_data_rate_tx_bps = 20_000_000;
    config.metrics.current_data_rate_rx_bps = 5_000_000;
    config.metrics.current_data_rate_tx_bps = 7_000_000;
    config.metrics.latency_us = 2_500;
    let modem = ModemDaemon::builder().config(config).spawn().await?;
    let mut events = modem.subscribe();
    let event_task = tokio::spawn(async move {
        while let Ok(event) = events.recv().await {
            match event {
                DaemonEvent::SessionUp { .. } => report("UP"),
                DaemonEvent::SessionDown { reason, .. } => report(&format!("DOWN {}", reason.0)),
                DaemonEvent::CommandRejected { rejection, .. } => panic!("{rejection:?}"),
                _ => {}
            }
        }
    });
    report(&format!("READY {}", modem.local_addr()));
    let (tx, mut commands) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            if tx.send(line.expect("stdin command")).is_err() {
                break;
            }
        }
    });
    let destination = DestinationId(MacAddress::new_eui48([2, 0, 0, 0, 0, 1]));
    let mut metrics = LinkMetrics {
        max_data_rate_rx_bps: 10_000_000,
        max_data_rate_tx_bps: 20_000_000,
        current_data_rate_rx_bps: 4_000_000,
        current_data_rate_tx_bps: 6_000_000,
        latency: Duration::from_micros(3_500),
        ..Default::default()
    };
    while let Some(command) = commands.recv().await {
        match command.as_str() {
            "add" => modem.add_destination(destination, metrics).await?,
            "update" => {
                metrics.current_data_rate_rx_bps = 2_000_000;
                metrics.current_data_rate_tx_bps = 3_000_000;
                metrics.latency = Duration::from_micros(4_500);
                modem.update_destination(destination, metrics).await?;
            }
            "drop" => {
                modem
                    .drop_destination(destination, StatusCode::SUCCESS)
                    .await?
            }
            "shutdown" => break,
            _ => return Err(format!("unknown fixture command: {command}").into()),
        }
        report(&format!("OK {command}"));
    }
    modem.shutdown().await?;
    event_task.await?;
    report("STOPPED");
    Ok(())
}
