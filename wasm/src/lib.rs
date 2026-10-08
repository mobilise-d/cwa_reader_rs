use cwa_reader_rs::header::{format_raw_time, read_cwa_header_bytes, CwaHeader};
use serde::Serialize;
use wasm_bindgen::prelude::*;

// The browser bridge formats clock values exactly like the Python bridge. The
// core represents them with Utc for arithmetic, without establishing a timezone.
#[derive(Serialize)]
struct HeaderMetadata {
    packet_header: String,
    packet_length: u16,
    hardware_type: String,
    device_id: u32,
    session_id: u32,
    upper_device_id: u16,
    logging_start_time_raw: Option<String>,
    logging_end_time_raw: Option<String>,
    last_change_time_raw: Option<String>,
    flash_led: u8,
    sensor_config: u8,
    sample_rate_hz: f64,
    accel_range: u8,
    firmware_revision: u8,
    annotation: String,
    gyro_range: Option<u16>,
    magnetometer_enabled: bool,
}

impl From<CwaHeader> for HeaderMetadata {
    fn from(header: CwaHeader) -> Self {
        Self {
            packet_header: header.packet_header,
            packet_length: header.packet_length,
            hardware_type: header.hardware_type,
            device_id: header.device_id,
            session_id: header.session_id,
            upper_device_id: header.upper_device_id,
            logging_start_time_raw: header.logging_start_time.map(format_raw_time),
            logging_end_time_raw: header.logging_end_time.map(format_raw_time),
            last_change_time_raw: header.last_change_time.map(format_raw_time),
            flash_led: header.flash_led,
            sensor_config: header.sensor_config,
            sample_rate_hz: header.sample_rate_hz,
            accel_range: header.accel_range,
            firmware_revision: header.firmware_revision,
            annotation: header.annotation,
            gyro_range: header.gyro_range,
            magnetometer_enabled: header.magnetometer_enabled,
        }
    }
}

/// Parse the first 1,024 bytes of a CWA file. Additional bytes are ignored.
/// Returns header configuration only; actual sample timing needs data packets.
#[wasm_bindgen(js_name = readHeader)]
pub fn read_header(bytes: &[u8]) -> Result<JsValue, JsError> {
    let metadata = HeaderMetadata::from(
        read_cwa_header_bytes(bytes).map_err(|error| JsError::new(&error.to_string()))?,
    );
    metadata
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| JsError::new(&error.to_string()))
}
