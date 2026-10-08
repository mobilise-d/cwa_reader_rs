use crate::errors;
use crate::packet::{cwa_timestamp, packet_meta, read_sector};
use chrono::{DateTime, TimeZone, Utc};
use serde::Serialize;
use std::fs::File;
use std::io::{Cursor, Read};

#[derive(Debug, Serialize, Clone)]
pub struct CwaHeader {
    // Header identification
    pub packet_header: String,
    pub packet_length: u16,
    pub hardware_type: String,
    pub device_id: u32,
    pub session_id: u32,
    pub upper_device_id: u16,

    // Timing configuration
    pub logging_start_time: Option<DateTime<Utc>>,
    pub logging_end_time: Option<DateTime<Utc>>,
    // Deprecated
    // pub logging_capacity: u32,
    pub last_change_time: Option<DateTime<Utc>>,

    // Device configuration
    pub flash_led: u8,
    pub sensor_config: u8,
    pub sample_rate_hz: f64,
    pub accel_range: u8,
    pub firmware_revision: u8,
    // We are not parsing the time zone field, as it is unused
    // pub time_zone: i16,

    // Metadata
    pub annotation: String,

    // Parsed sensor configuration (for AX6)
    pub gyro_range: Option<u16>,
    pub magnetometer_enabled: bool,
}

fn parse_annotation(buffer: &[u8]) -> String {
    // Annotation starts at offset 64 and is 448 bytes long
    let annotation_bytes = &buffer[64..512];

    // Find the end of meaningful data (ignore trailing 0x20, 0x00, 0xFF bytes)
    let mut end = annotation_bytes.len();
    for i in (0..annotation_bytes.len()).rev() {
        if annotation_bytes[i] != 0x20 && annotation_bytes[i] != 0x00 && annotation_bytes[i] != 0xFF
        {
            end = i + 1;
            break;
        }
    }

    // Convert to string, handling invalid UTF-8 gracefully
    String::from_utf8_lossy(&annotation_bytes[..end]).to_string()
}

pub fn read_cwa_header(file_path: &str) -> Result<CwaHeader, errors::CwaError> {
    read_cwa_header_from_reader(&mut File::open(file_path)?)
}

/// Parse the first 1,024 bytes of a browser file without inspecting data packets.
/// Device clock values are represented with `Utc` for arithmetic; they do not
/// establish the recording's actual timezone.
pub fn read_cwa_header_bytes(bytes: &[u8]) -> Result<CwaHeader, errors::CwaError> {
    read_cwa_header_from_reader(&mut Cursor::new(bytes))
}

/// Read a complete metadata block at the reader's current position.
pub fn read_cwa_header_from_reader<R: Read>(reader: &mut R) -> Result<CwaHeader, errors::CwaError> {
    let mut buffer = vec![0u8; 1024]; // CWA header is always 1024 bytes

    // Read the complete header block
    reader.read_exact(&mut buffer)?;

    // Parse packet header (offset 0-1): ASCII "MD", little-endian (0x444D)
    let packet_header =
        std::str::from_utf8(&buffer[0..2]).map_err(|_| "Invalid packet header format")?;

    if packet_header != "MD" {
        return Err("First block is not a metadata block".into());
    }

    // Parse packet length (offset 2-3): Should be 1020 bytes
    let packet_length = u16::from_le_bytes([buffer[2], buffer[3]]);

    // Hardware type (offset 4): 0x00/0xff/0x17 = AX3, 0x64 = AX6
    let hardware_type_byte = buffer[4];
    let hardware_type = if hardware_type_byte == 0x64 {
        "AX6".to_string()
    } else {
        "AX3".to_string()
    };

    // Device ID (offset 5-6): Lower 16 bits
    let lower_device_id = u16::from_le_bytes([buffer[5], buffer[6]]) as u32;

    // Session ID (offset 7-10): 4 bytes, little-endian
    let session_id = u32::from_le_bytes([buffer[7], buffer[8], buffer[9], buffer[10]]);

    // Upper device ID (offset 11-12): Upper 16 bits, treat 0xFFFF as 0x0000
    let upper_device_id = u16::from_le_bytes([buffer[11], buffer[12]]);
    let upper_device_id_corrected = if upper_device_id == 0xFFFF {
        0
    } else {
        upper_device_id
    };

    // Combine device ID
    let device_id = ((upper_device_id_corrected as u32) << 16) | lower_device_id;

    // Logging start time (offset 13-16): CWA timestamp
    let logging_start_time_raw =
        u32::from_le_bytes([buffer[13], buffer[14], buffer[15], buffer[16]]);
    let logging_start_time = cwa_timestamp(logging_start_time_raw);

    // Logging end time (offset 17-20): CWA timestamp
    let logging_end_time_raw = u32::from_le_bytes([buffer[17], buffer[18], buffer[19], buffer[20]]);
    let logging_end_time = cwa_timestamp(logging_end_time_raw);

    // Logging capacity (offset 21-24): Deprecated, should be 0
    // let logging_capacity = u32::from_le_bytes([buffer[21], buffer[22], buffer[23], buffer[24]]);

    // Flash LED (offset 26): Flash LED during recording
    let flash_led = buffer[26];

    // Sensor config (offset 35): AX6 sensor configuration
    let sensor_config = buffer[35];

    // Parse sensor configuration for AX6
    let (gyro_range, magnetometer_enabled) =
        if hardware_type == "AX6" && sensor_config != 0x00 && sensor_config != 0xFF {
            let gyro_range_code = sensor_config & 0x0F; // Bottom nibble
            let magnetometer_flag = (sensor_config & 0xF0) != 0; // Top nibble non-zero

            // Gyro range: 8000/2^n dps, where n is the code
            let gyro_range = match gyro_range_code {
                2 => Some(2000),
                3 => Some(1000),
                4 => Some(500),
                5 => Some(250),
                6 => Some(125),
                _ => None,
            };

            (gyro_range, magnetometer_flag)
        } else {
            (None, false)
        };

    // Sampling rate (offset 36): Rate code
    let sampling_rate = buffer[36];

    // Calculate actual sample rate: frequency (3200/(1<<(15-(rate & 0x0f)))) Hz
    let sample_rate_hz = 3200.0 / ((1 << (15 - (sampling_rate & 0x0F))) as f64);

    // Calculate accelerometer range: (+/-g) (16 >> (rate >> 6))
    let accel_range = 16 >> (sampling_rate >> 6);

    // Last change time (offset 37-40): CWA timestamp
    let last_change_time_raw = u32::from_le_bytes([buffer[37], buffer[38], buffer[39], buffer[40]]);
    let last_change_time = cwa_timestamp(last_change_time_raw);

    // Firmware revision (offset 41)
    let firmware_revision = buffer[41];

    // Time zone (offset 42-43): Signed 16-bit, unused (0xFFFF = -1 = unknown)
    // let time_zone = i16::from_le_bytes([buffer[42], buffer[43]]);

    // Parse annotation (offset 64-511): Metadata
    let annotation = parse_annotation(&buffer);

    Ok(CwaHeader {
        packet_header: packet_header.to_string(),
        packet_length,
        hardware_type,
        device_id,
        session_id,
        upper_device_id,
        logging_start_time,
        logging_end_time,
        last_change_time,
        flash_led,
        sensor_config,
        sample_rate_hz,
        accel_range,
        firmware_revision,
        annotation,
        gyro_range,
        magnetometer_enabled,
    })
}

#[derive(Debug, Clone, Copy)]
pub struct DataTimingSummary {
    pub first_sample_us: Option<i64>,
    pub last_sample_us: Option<i64>,
    pub sample_count: u64,
}

pub fn format_raw_time(time: DateTime<Utc>) -> String {
    time.naive_utc().format("%Y-%m-%dT%H:%M:%S%.f").to_string()
}

pub fn timestamp_us_to_raw_string(timestamp_us: i64) -> Option<String> {
    let secs = timestamp_us.div_euclid(1_000_000);
    let micros = timestamp_us.rem_euclid(1_000_000) as u32;
    Utc.timestamp_opt(secs, micros * 1_000)
        .single()
        .map(format_raw_time)
}

pub fn scan_data_timing(file_path: &str) -> Result<DataTimingSummary, errors::CwaError> {
    scan_data_timing_from_reader(&mut File::open(file_path)?)
}

/// Scan metadata and packet timing from the reader's current position without
/// decoding sensor measurements.
pub fn scan_data_timing_from_reader<R: Read>(
    mut file: &mut R,
) -> Result<DataTimingSummary, errors::CwaError> {
    let mut metadata = [0u8; 1024];
    file.read_exact(&mut metadata)?;
    if &metadata[0..2] != b"MD" {
        return Err("First block is not a metadata block".into());
    }

    let mut previous_packet_end = None;
    let mut first_sample_us = None;
    let mut last_sample_us = None;
    let mut sample_count_total = 0_u64;

    while let Some(buffer) = read_sector(&mut file)? {
        let Some(meta) = packet_meta(&buffer)? else {
            continue;
        };
        let (natural_t0, natural_t1) = meta.natural_bounds();
        let sample_count = meta.sample_count;

        let mut t0 = natural_t0;
        if let Some(last_end) = previous_packet_end {
            if t0 - last_end < 1.0 {
                t0 = last_end;
            }
        }

        let step = (natural_t1 - t0) / sample_count as f64;
        let packet_first_us = (t0 * 1_000_000.0) as i64;
        let packet_last_us = ((t0 + (sample_count - 1) as f64 * step) * 1_000_000.0) as i64;

        first_sample_us.get_or_insert(packet_first_us);
        last_sample_us = Some(packet_last_us);
        sample_count_total += sample_count as u64;
        previous_packet_end = Some(natural_t1);
    }

    Ok(DataTimingSummary {
        first_sample_us,
        last_sample_us,
        sample_count: sample_count_total,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_bytes_read_device_configuration_without_data_packets() {
        let mut bytes = [0u8; 1024];
        bytes[..2].copy_from_slice(b"MD");
        bytes[2..4].copy_from_slice(&1020u16.to_le_bytes());
        bytes[4] = 0x64;
        bytes[5..7].copy_from_slice(&42u16.to_le_bytes());
        bytes[7..11].copy_from_slice(&17u32.to_le_bytes());
        bytes[11..13].copy_from_slice(&2u16.to_le_bytes());
        bytes[35] = 0x14;
        bytes[36] = 0x4a;
        bytes[64..69].copy_from_slice(b"hello");
        let header = read_cwa_header_bytes(&bytes).expect("complete header");
        assert_eq!(header.device_id, 131114);
        assert_eq!(header.session_id, 17);
        assert_eq!(header.hardware_type, "AX6");
        assert_eq!(header.sample_rate_hz, 100.0);
        assert_eq!(header.accel_range, 8);
        assert_eq!(header.gyro_range, Some(500));
        assert!(header.magnetometer_enabled);
        assert_eq!(header.annotation, "hello");
        assert!(header.logging_start_time.is_none());
        assert!(read_cwa_header_bytes(&bytes[..1023]).is_err());
    }
}
