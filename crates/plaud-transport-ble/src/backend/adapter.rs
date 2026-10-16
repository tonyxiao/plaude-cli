//! btleplug-backed BLE adapter: scan, connect, CCCD, channel bridge,
//! and battery reader.
//!
//! All btleplug types are confined to this module. The rest of the
//! crate sees only [`BleChannel`], [`BatteryReader`], and
//! [`ScanProvider`].

use std::time::Duration;

use async_trait::async_trait;
use btleplug::{
    api::{Central, Characteristic, Manager as _, Peripheral as _, PeripheralProperties, ScanFilter, WriteType},
    platform::{Adapter, Manager, Peripheral},
};
use bytes::Bytes;
use futures::stream::StreamExt;
use plaud_domain::{BatteryLevel, DeviceCandidate, TransportHint};
use plaud_transport::{Error, Result};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::{battery::BatteryReader, channel::BleChannel, constants::DEFAULT_CHANNEL_CAPACITY, discovery::ScanProvider};

// ---------------------------------------------------------------------------
// GATT UUIDs from docs/protocol/ble-gatt.md
// ---------------------------------------------------------------------------

/// Control-in characteristic (phone → device), UUID `0x2BB1`.
const CONTROL_IN_UUID: Uuid = Uuid::from_u128(0x00002bb1_0000_1000_8000_00805f9b34fb);

/// Control+bulk-out characteristic (device → phone, notify), UUID `0x2BB0`.
const NOTIFY_OUT_UUID: Uuid = Uuid::from_u128(0x00002bb0_0000_1000_8000_00805f9b34fb);

/// Note Pro discovery service observed in advertising data.
const NOTE_PRO_DISCOVERY_UUID: Uuid = Uuid::from_u128(0x0000504c_0000_1000_8000_00805f9b34fb);

/// Note Pro manufacturer identifier observed in advertising data.
const NOTE_PRO_MANUFACTURER_ID: u16 = 0x005d;

/// Standard SIG Battery Level characteristic, UUID `0x2A19`.
const BATTERY_LEVEL_UUID: Uuid = Uuid::from_u128(0x00002a19_0000_1000_8000_00805f9b34fb);

// ---------------------------------------------------------------------------
// ScanProvider
// ---------------------------------------------------------------------------

/// Discovers Plaud devices via btleplug BLE scanning.
pub struct BtleplugScanProvider;

#[async_trait]
impl ScanProvider for BtleplugScanProvider {
    async fn scan(&self, timeout: Duration) -> Result<Vec<DeviceCandidate>> {
        let adapter = default_adapter().await?;

        adapter
            .start_scan(ScanFilter::default())
            .await
            .map_err(|e| Error::Transport(format!("scan start failed: {e}")))?;

        tokio::time::sleep(timeout).await;

        let _ = adapter.stop_scan().await;

        let peripherals = adapter
            .peripherals()
            .await
            .map_err(|e| Error::Transport(format!("enumerate peripherals: {e}")))?;

        let mut candidates = Vec::new();
        tracing::debug!(count = peripherals.len(), "BLE scan completed");
        for p in peripherals {
            if let Some(candidate) = peripheral_to_candidate(&p).await {
                candidates.push(candidate);
            }
        }
        Ok(candidates)
    }
}

/// Check if a discovered peripheral matches the Plaud advertising
/// profile and convert it to a `DeviceCandidate`.
async fn peripheral_to_candidate(p: &Peripheral) -> Option<DeviceCandidate> {
    let props = p.properties().await.ok()??;
    candidate_from_properties(&props)
}

fn candidate_from_properties(props: &PeripheralProperties) -> Option<DeviceCandidate> {
    if props.manufacturer_data.contains_key(&NOTE_PRO_MANUFACTURER_ID) {
        tracing::debug!(name = ?props.local_name, advertisement_name = ?props.advertisement_name, services = ?props.services, "Pro discovery metadata");
    }
    // CoreBluetooth can omit the name on subsequent discoveries. Require
    // both identifiers before supplying the observed Pro name.
    let name = props.local_name.as_deref().or_else(|| {
        (props.manufacturer_data.contains_key(&NOTE_PRO_MANUFACTURER_ID) && props.services.contains(&NOTE_PRO_DISCOVERY_UUID))
            .then_some("Plaud Note Pro")
    })?;
    let manufacturer_id = props
        .manufacturer_data
        .keys()
        .copied()
        .find(|id| crate::discovery::matches_advertisement(name, *id))?;
    let rssi = props.rssi;
    Some(DeviceCandidate::new(name.to_owned(), manufacturer_id, rssi, TransportHint::Ble))
}

// ---------------------------------------------------------------------------
// connect_peripheral — the bridge from btleplug → BleChannel
// ---------------------------------------------------------------------------

/// Scan for a Plaud device, connect, enable CCCD on the vendor notify
/// characteristic, and return a [`BleChannel`] + [`BtleplugBatteryReader`]
/// ready for use by [`crate::session::BleSession`].
///
/// The returned channel bridges btleplug notifications into the
/// `BleChannel::rx` sender and `BleChannel::tx` receiver into btleplug
/// GATT writes, so the session layer is completely unaware of btleplug.
pub async fn connect_peripheral(scan_timeout: Duration) -> Result<(BleChannel, BtleplugBatteryReader)> {
    connect(scan_timeout, false).await
}

/// Connect using the advertised Note Pro discovery service. Paired credentials
/// independently authenticate the selected device before vendor commands run.
///
/// # Errors
/// Returns a transport error if no advertising Pro can be connected.
pub async fn connect_pro_peripheral(scan_timeout: Duration) -> Result<(BleChannel, BtleplugBatteryReader)> {
    connect(scan_timeout, true).await
}

async fn connect(scan_timeout: Duration, pro_only: bool) -> Result<(BleChannel, BtleplugBatteryReader)> {
    let adapter = default_adapter().await?;
    let peripheral = scan_and_find(&adapter, scan_timeout, pro_only).await?;
    let note_pro = pro_only
        || peripheral
            .properties()
            .await
            .ok()
            .flatten()
            .is_some_and(|properties| properties.manufacturer_data.contains_key(&NOTE_PRO_MANUFACTURER_ID));

    peripheral
        .connect()
        .await
        .map_err(|e| Error::Transport(format!("connect failed: {e}")))?;

    peripheral
        .discover_services()
        .await
        .map_err(|e| Error::Transport(format!("service discovery failed: {e}")))?;

    let chars = peripheral.characteristics();

    let control_in = find_characteristic(&chars, CONTROL_IN_UUID)?;
    let notify_out = find_characteristic(&chars, NOTIFY_OUT_UUID)?;
    let battery_char = find_characteristic(&chars, BATTERY_LEVEL_UUID)?;

    // Enable notifications on the vendor notify characteristic (CCCD)
    peripheral
        .subscribe(&notify_out)
        .await
        .map_err(|e| Error::Transport(format!("CCCD subscribe failed: {e}")))?;

    // Brief settle time for BlueZ to flush any stale notifications
    // from a previous connection.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Build the BleChannel by bridging btleplug ↔ mpsc
    let (session_tx, peer_rx) = mpsc::channel::<Bytes>(DEFAULT_CHANNEL_CAPACITY);
    let (peer_tx, session_rx) = mpsc::channel::<Bytes>(DEFAULT_CHANNEL_CAPACITY);

    let channel = BleChannel {
        tx: session_tx,
        rx: session_rx,
    };

    // Spawn notification handler: btleplug notifications → peer_tx → session rx
    let p_notify = peripheral.clone();
    tokio::spawn(async move {
        let Ok(mut stream) = p_notify.notifications().await else {
            return;
        };
        while let Some(data) = stream.next().await {
            let val = &data.value;
            if val.len() >= 2 {
                tracing::trace!(
                    len = val.len(),
                    first_bytes = %val.iter().take(12.min(val.len())).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" "),
                    "ble notification"
                );
            }
            if peer_tx.send(Bytes::from(data.value)).await.is_err() {
                break;
            }
        }
    });

    // Spawn write handler: session tx → peer_rx → btleplug writes
    let p_write = peripheral.clone();
    let control_in_write = control_in.clone();
    tokio::spawn(async move {
        let mut rx = peer_rx;
        while let Some(frame) = rx.recv().await {
            if p_write.write(&control_in_write, &frame, WriteType::WithoutResponse).await.is_err() {
                break;
            }
        }
    });

    let battery_reader = BtleplugBatteryReader {
        peripheral,
        battery_char,
        note_pro,
    };

    Ok((channel, battery_reader))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Get the first available BLE adapter.
async fn default_adapter() -> Result<Adapter> {
    let manager = Manager::new()
        .await
        .map_err(|e| Error::Transport(format!("btleplug manager: {e}")))?;
    let adapters = manager
        .adapters()
        .await
        .map_err(|e| Error::Transport(format!("no BLE adapters: {e}")))?;
    adapters
        .into_iter()
        .next()
        .ok_or_else(|| Error::Transport("no BLE adapter found".to_owned()))
}

/// Scan for a Plaud device and return the first matching peripheral.
async fn scan_and_find(adapter: &Adapter, timeout: Duration, pro_only: bool) -> Result<Peripheral> {
    adapter
        .start_scan(ScanFilter::default())
        .await
        .map_err(|e| Error::Transport(format!("scan failed: {e}")))?;
    // CoreBluetooth supplies name, service, and manufacturer data in separate
    // updates. Inspect throughout the window instead of taking one final snapshot.
    let found = tokio::time::timeout(timeout, async {
        loop {
            let peripherals = adapter
                .peripherals()
                .await
                .map_err(|e| Error::Transport(format!("enumerate: {e}")))?;
            for peripheral in peripherals {
                if let Some(candidate) = peripheral_to_candidate(&peripheral).await {
                    if !pro_only || candidate.manufacturer_id == NOTE_PRO_MANUFACTURER_ID {
                        return Ok(peripheral);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    let _ = adapter.stop_scan().await;
    match found {
        Ok(result) => result,
        Err(_) => Err(Error::Transport(
            "no Plaud Note or Note Pro device found — is it turned on and nearby?".to_owned(),
        )),
    }
}

/// Find a characteristic by UUID in the discovered set.
fn find_characteristic(chars: &std::collections::BTreeSet<Characteristic>, uuid: Uuid) -> Result<Characteristic> {
    chars
        .iter()
        .find(|c| c.uuid == uuid)
        .cloned()
        .ok_or_else(|| Error::Transport(format!("characteristic {uuid} not found after service discovery")))
}

// ---------------------------------------------------------------------------
// BatteryReader
// ---------------------------------------------------------------------------

/// Reads the standard SIG Battery Level from a connected peripheral.
pub struct BtleplugBatteryReader {
    peripheral: Peripheral,
    battery_char: Characteristic,
    note_pro: bool,
}

impl BtleplugBatteryReader {
    /// Whether this connection matched the observed Note Pro advertising profile.
    #[must_use]
    pub const fn is_note_pro(&self) -> bool {
        self.note_pro
    }
}

#[async_trait]
impl BatteryReader for BtleplugBatteryReader {
    async fn read_battery(&self) -> Result<BatteryLevel> {
        let data = self
            .peripheral
            .read(&self.battery_char)
            .await
            .map_err(|e| Error::Transport(format!("battery read failed: {e}")))?;
        let percent = data.first().copied().unwrap_or(0);
        BatteryLevel::new(percent).map_err(|e| Error::Protocol(format!("invalid battery level: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_nameless_manufacturer_without_pro_service() {
        let mut props = PeripheralProperties::default();
        props.manufacturer_data.insert(0x005d, vec![]);
        assert!(candidate_from_properties(&props).is_none());
    }

    #[test]
    fn rejects_nameless_pro_service_without_manufacturer() {
        let mut props = PeripheralProperties::default();
        props.services.push(Uuid::from_u128(0x0000504c_0000_1000_8000_00805f9b34fb));
        assert!(candidate_from_properties(&props).is_none());
    }

    #[test]
    fn recognizes_pro_without_corebluetooth_local_name() {
        let mut props = PeripheralProperties::default();
        props.manufacturer_data.insert(0x005d, vec![]);
        props.services.push(Uuid::from_u128(0x0000504c_0000_1000_8000_00805f9b34fb));
        let candidate = candidate_from_properties(&props).expect("observed Pro profile");
        assert_eq!(candidate.local_name, "Plaud Note Pro");
        assert_eq!(candidate.manufacturer_id, 0x005d);
    }
}
