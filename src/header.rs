use pyo3::prelude::*;
use serde::Serialize;
use std::fs::File;
use std::io::Read;
use chrono::{DateTime, Utc, TimeZone};
use crate::errors;



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


fn get_cwa_timestamp(cwa_time_info: u32) -> Option<DateTime<Utc>> {
    // Special values: 0 = always started/stopped, -1 (0xFFFFFFFF) = never started/stopped
    if cwa_time_info == 0 || cwa_time_info == 0xFFFFFFFF {
        return None;
    }
    
    // Timestamps are packed: (MSB) YYYYYYMM MMDDDDDh hhhhmmmm mmssssss (LSB)
    let year = ((cwa_time_info >> 26) & 0x3f) as i32 + 2000;
    let month = ((cwa_time_info >> 22) & 0x0f) as u32;
    let day = ((cwa_time_info >> 17) & 0x1f) as u32;
    let hours = ((cwa_time_info >> 12) & 0x1f) as u32;
    let mins = ((cwa_time_info >> 6) & 0x3f) as u32;
    let secs = (cwa_time_info & 0x3f) as u32;

    match Utc.with_ymd_and_hms(year, month, day, hours, mins, secs) {
        chrono::LocalResult::Single(dt) => Some(dt),
        _ => None,
    }
}

fn parse_annotation(buffer: &[u8]) -> String {
    // Annotation starts at offset 64 and is 448 bytes long
    let annotation_bytes = &buffer[64..512];
    
    // Find the end of meaningful data (ignore trailing 0x20, 0x00, 0xFF bytes)
    let mut end = annotation_bytes.len();
    for i in (0..annotation_bytes.len()).rev() {
        if annotation_bytes[i] != 0x20 && annotation_bytes[i] != 0x00 && annotation_bytes[i] != 0xFF {
            end = i + 1;
            break;
        }
    }
    
    // Convert to string, handling invalid UTF-8 gracefully
    String::from_utf8_lossy(&annotation_bytes[..end]).to_string()
}

fn read_cwa_header(file_path: &str) -> Result<CwaHeader, errors::CwaError> {
    let mut file = File::open(file_path)?;
    let mut buffer = vec![0u8; 1024]; // CWA header is always 1024 bytes
    
    // Read the complete header block
    file.read_exact(&mut buffer)?;
    
    // Parse packet header (offset 0-1): ASCII "MD", little-endian (0x444D)
    let packet_header = std::str::from_utf8(&buffer[0..2])
        .map_err(|_| "Invalid packet header format")?;
    
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
    let upper_device_id_corrected = if upper_device_id == 0xFFFF { 0 } else { upper_device_id };
    
    // Combine device ID
    let device_id = ((upper_device_id_corrected as u32) << 16) | lower_device_id;
    
    // Logging start time (offset 13-16): CWA timestamp
    let logging_start_time_raw = u32::from_le_bytes([buffer[13], buffer[14], buffer[15], buffer[16]]);
    let logging_start_time = get_cwa_timestamp(logging_start_time_raw);
    
    // Logging end time (offset 17-20): CWA timestamp
    let logging_end_time_raw = u32::from_le_bytes([buffer[17], buffer[18], buffer[19], buffer[20]]);
    let logging_end_time = get_cwa_timestamp(logging_end_time_raw);
    
    // Logging capacity (offset 21-24): Deprecated, should be 0
    // let logging_capacity = u32::from_le_bytes([buffer[21], buffer[22], buffer[23], buffer[24]]);
    
    // Flash LED (offset 26): Flash LED during recording
    let flash_led = buffer[26];
    
    // Sensor config (offset 35): AX6 sensor configuration
    let sensor_config = buffer[35];
    
    // Parse sensor configuration for AX6
    let (gyro_range, magnetometer_enabled) = if hardware_type == "AX6" && sensor_config != 0x00 && sensor_config != 0xFF {
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
    let last_change_time = get_cwa_timestamp(last_change_time_raw);
    
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

#[pyfunction]
pub fn read_header(py: Python, file_path: &str) -> PyResult<Py<PyAny>> {
    match read_cwa_header(file_path) {
        Ok(header) => {
            let header_dict = pyo3::types::PyDict::new(py);
            
            // Header identification
            header_dict.set_item("packet_header", header.packet_header)?;
            header_dict.set_item("packet_length", header.packet_length)?;
            header_dict.set_item("hardware_type", header.hardware_type)?;
            header_dict.set_item("device_id", header.device_id)?;
            header_dict.set_item("session_id", header.session_id)?;
            header_dict.set_item("upper_device_id", header.upper_device_id)?;
            
            // Timing configuration
            header_dict.set_item("logging_start_time", 
                header.logging_start_time.map(|t| t.to_rfc3339()).unwrap_or_else(|| "None".to_string()))?;
            header_dict.set_item("logging_end_time", 
                header.logging_end_time.map(|t| t.to_rfc3339()).unwrap_or_else(|| "None".to_string()))?;
            header_dict.set_item("last_change_time", 
                header.last_change_time.map(|t| t.to_rfc3339()).unwrap_or_else(|| "None".to_string()))?;
            
            // Device configuration
            header_dict.set_item("flash_led", header.flash_led)?;
            header_dict.set_item("sensor_config", header.sensor_config)?;
            header_dict.set_item("sample_rate_hz", header.sample_rate_hz)?;
            header_dict.set_item("accel_range", header.accel_range)?;
            header_dict.set_item("firmware_revision", header.firmware_revision)?;
            
            // Metadata
            header_dict.set_item("annotation", header.annotation)?;
            
            // Parsed sensor configuration (for AX6)
            header_dict.set_item("gyro_range", header.gyro_range)?;
            header_dict.set_item("magnetometer_enabled", header.magnetometer_enabled)?;
            
            Ok(header_dict.into())
        }
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }
}