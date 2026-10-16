//! Download-only Wi-Fi adapter reusing BLE for identity and battery queries.
use crate::{protocol::WifiFile, session::WifiSession};
use async_trait::async_trait;
use plaud_domain::{BatteryLevel, CommonSettingKey, DeviceInfo, Recording, RecordingId, SettingValue, StorageStats};
use plaud_transport::{Error, Result, Transport};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Authenticated Wi-Fi file transport; mutations are deliberately unsupported.
pub struct WifiTransport {
    session: Arc<Mutex<WifiSession>>,
    ble: Arc<dyn Transport>,
    listing: Mutex<Option<Vec<WifiFile>>>,
}
impl WifiTransport {
    /// Build from a connected session and the retained BLE control transport.
    pub fn new(session: Arc<Mutex<WifiSession>>, ble: Arc<dyn Transport>) -> Self {
        Self {
            session,
            ble,
            listing: Mutex::new(None),
        }
    }
}
fn read_only<T>() -> Result<T> {
    Err(Error::Unsupported {
        capability: "Wi-Fi backend supports recording downloads only",
    })
}
#[async_trait]
impl Transport for WifiTransport {
    async fn device_info(&self) -> Result<DeviceInfo> {
        self.ble.device_info().await
    }
    async fn battery(&self) -> Result<BatteryLevel> {
        self.ble.battery().await
    }
    async fn storage(&self) -> Result<StorageStats> {
        self.ble.storage().await
    }
    async fn list_recordings(&self) -> Result<Vec<Recording>> {
        let mut cache = self.listing.lock().await;
        if let Some(list) = cache.as_ref() {
            return Ok(list.iter().map(|file| file.recording.clone()).collect());
        }
        let list = self.session.lock().await.list_files().await?;
        *cache = Some(list.clone());
        Ok(list.into_iter().map(|file| file.recording).collect())
    }
    async fn read_recording(&self, id: &RecordingId) -> Result<Vec<u8>> {
        self.read_recording_asr(id).await
    }
    async fn read_recording_asr(&self, id: &RecordingId) -> Result<Vec<u8>> {
        self.list_recordings().await?;
        let cached = {
            let cache = self.listing.lock().await;
            let mut matches = cache.as_ref().into_iter().flatten().filter(|file| file.recording.id() == id);
            let first = matches.next().cloned();
            if matches.next().is_some() {
                return Err(Error::Protocol(
                    "recording id occurs in multiple Wi-Fi file types; download is ambiguous".into(),
                ));
            }
            first
        };
        let file = if let Some(file) = cached {
            file
        } else {
            let file = self
                .session
                .lock()
                .await
                .find_file(id.as_unix_seconds() as u64)
                .await?
                .ok_or_else(|| Error::NotFound(format!("recording {id} is not available from the device")))?;
            if let Some(cache) = self.listing.lock().await.as_mut() {
                if !cache
                    .iter()
                    .any(|existing| existing.recording.id() == file.recording.id() && existing.file_type == file.file_type)
                {
                    cache.push(file.clone());
                }
            }
            file
        };
        let size = usize::try_from(file.recording.asr_size()).map_err(|_| Error::Protocol("recording too large".into()))?;
        self.session
            .lock()
            .await
            .read(
                id.as_unix_seconds() as u64,
                crate::protocol::NORMAL_AUDIO_SCENE,
                Some(size).filter(|n| *n > 0),
            )
            .await
    }
    async fn delete_recording(&self, _id: &RecordingId) -> Result<()> {
        read_only()
    }
    async fn read_setting(&self, key: CommonSettingKey) -> Result<SettingValue> {
        self.ble.read_setting(key).await
    }
    async fn write_setting(&self, _key: CommonSettingKey, _value: SettingValue) -> Result<()> {
        read_only()
    }
    async fn start_recording(&self) -> Result<()> {
        read_only()
    }
    async fn stop_recording(&self) -> Result<()> {
        read_only()
    }
    async fn pause_recording(&self) -> Result<()> {
        read_only()
    }
    async fn resume_recording(&self) -> Result<()> {
        read_only()
    }
    async fn set_privacy(&self, _on: bool) -> Result<()> {
        read_only()
    }
}
