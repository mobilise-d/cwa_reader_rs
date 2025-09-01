
use pyo3::prelude::*;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use chrono::{DateTime, Utc, TimeZone};
use crate::errors::CwaError;

use pyo3::types::PyDict;


/// CWA Data Block structure (512 bytes)
#[derive(Debug)]
struct CwaDataBlock {
    packet_header: String,           // @ 0  +2   ASCII "AX", little-endian (0x5841)
    packet_length: u16,              // @ 2  +2   Packet length (508 bytes)
    device_fractional: u16,          // @ 4  +2   Device ID or fractional timestamp
    session_id: u32,                 // @ 6  +4   Session identifier
    sequence_id: u32,                // @10  +4   Sequence counter
    timestamp: u32,                  // @14  +4   RTC timestamp
    light_scale: u16,                // @18  +2   Light sensor + accel/gyro scale info
    temperature: u16,                // @20  +2   Temperature sensor value
    events: u8,                      // @22  +1   Event flags
    battery: u8,                     // @23  +1   Battery level
    sample_rate: u8,                 // @24  +1   Sample rate code
    num_axes_bps: u8,                // @25  +1   Number of axes and packing format
    timestamp_offset: i16,           // @26  +2   Timestamp offset
    sample_count: u16,               // @28  +2   Number of samples
    raw_sample_data: Vec<u8>,        // @30  +480 Raw sample data
    checksum: u16,                   // @510 +2   Checksum
}

impl CwaDataBlock {
    fn from_buffer(buffer: &[u8]) -> Result<Self, CwaError> {
        if buffer.len() != 512 {
            return Err("Data block must be exactly 512 bytes".into());
        }
        
        // Parse packet header
        let packet_header = std::str::from_utf8(&buffer[0..2])
            .map_err(|_| "Invalid packet header format")?;
        
        if packet_header != "AX" {
            return Err("Invalid data block header".into());
        }
        
        Ok(CwaDataBlock {
            packet_header: packet_header.to_string(),
            packet_length: u16::from_le_bytes([buffer[2], buffer[3]]),
            device_fractional: u16::from_le_bytes([buffer[4], buffer[5]]),
            session_id: u32::from_le_bytes([buffer[6], buffer[7], buffer[8], buffer[9]]),
            sequence_id: u32::from_le_bytes([buffer[10], buffer[11], buffer[12], buffer[13]]),
            timestamp: u32::from_le_bytes([buffer[14], buffer[15], buffer[16], buffer[17]]),
            light_scale: u16::from_le_bytes([buffer[18], buffer[19]]),
            temperature: u16::from_le_bytes([buffer[20], buffer[21]]),
            events: buffer[22],
            battery: buffer[23],
            sample_rate: buffer[24],
            num_axes_bps: buffer[25],
            timestamp_offset: i16::from_le_bytes([buffer[26], buffer[27]]),
            sample_count: u16::from_le_bytes([buffer[28], buffer[29]]),
            raw_sample_data: buffer[30..510].to_vec(),
            checksum: u16::from_le_bytes([buffer[510], buffer[511]]),
        })
    }
    
    /// Get the timestamp for this block
    fn get_block_timestamp(&self) -> Option<DateTime<Utc>> {
        if self.timestamp == 0 {
            return None;
        }
        
        // Parse CWA timestamp format: (MSB) YYYYYYMM MMDDDDDh hhhhmmmm mmssssss (LSB)
        let year = ((self.timestamp >> 26) & 0x3f) as i32 + 2000;
        let month = ((self.timestamp >> 22) & 0x0f) as u32;
        let day = ((self.timestamp >> 17) & 0x1f) as u32;
        let hours = ((self.timestamp >> 12) & 0x1f) as u32;
        let mins = ((self.timestamp >> 6) & 0x3f) as u32;
        let secs = (self.timestamp & 0x3f) as u32;
        
        match Utc.with_ymd_and_hms(year, month, day, hours, mins, secs) {
            chrono::LocalResult::Single(dt) => Some(dt),
            _ => None,
        }
    }
    
    /// Get the actual sample rate in Hz
    fn get_sample_rate_hz(&self) -> f64 {
        3200.0 / ((1 << (15 - (self.sample_rate & 0x0F))) as f64)
    }
    
    /// Get the accelerometer range in g
    fn get_accel_range(&self) -> u8 {
        16 >> (self.sample_rate >> 6)
    }
    
    /// Get the number of axes (3=Axyz, 6=Gxyz/Axyz, 9=Gxyz/Axyz/Mxyz)
    fn get_num_axes(&self) -> u8 {
        (self.num_axes_bps >> 4) & 0x0F
    }
    
    /// Get the packing format (2 = 3x 16-bit signed, 0 = 3x 10-bit signed + 2-bit exponent)
    fn get_packing_format(&self) -> u8 {
        self.num_axes_bps & 0x0F
    }
    
    /// Check if high-precision fractional timestamp is available
    fn has_fractional_timestamp(&self) -> bool {
        (self.device_fractional & 0x8000) != 0
    }
    
    /// Get fractional timestamp (if available)
    fn get_fractional_timestamp(&self) -> Option<f64> {
        if self.has_fractional_timestamp() {
            Some((self.device_fractional & 0x7FFF) as f64 / 32768.0)
        } else {
            None
        }
    }
    
    /// Extract light sensor value
    fn get_light_value(&self) -> u16 {
        self.light_scale & 0x03FF // Bottom 10 bits
    }
    
    /// Extract temperature value (bottom 10 bits)
    fn get_temperature_value(&self) -> u16 {
        self.temperature & 0x03FF
    }
    
    /// Get accelerometer scale factor from light_scale field
    fn get_accel_scale(&self) -> f64 {
        let scale_bits = (self.light_scale >> 13) & 0x07; // Top 3 bits
        1.0 / (256.0 * (1 << scale_bits) as f64) // 1/2^(8+n) g
    }
    
    /// Get gyroscope scale factor from light_scale field (for AX6)
    fn get_gyro_scale(&self) -> Option<f64> {
        let gyro_bits = (self.light_scale >> 10) & 0x07; // Bits 10-12
        if gyro_bits > 0 {
            Some(8000.0 / (1 << gyro_bits) as f64) // 8000/2^n dps
        } else {
            None
        }
    }
    
    /// Parse samples from the data block
    fn parse_samples(&self) -> Result<Vec<SampleData>, CwaError> {
        let num_axes = self.get_num_axes();
        let packing_format = self.get_packing_format();
        
        match (num_axes, packing_format) {
            // 3-axis accelerometer, unpacked mode (3x 16-bit signed)
            (3, 2) => self.parse_3axis_unpacked(),
            // 3-axis accelerometer, packed mode (3x 10-bit + 2-bit exponent)
            (3, 0) => self.parse_3axis_packed(),
            // 6-axis IMU (gyro + accel), unpacked mode
            (6, 2) => self.parse_6axis_unpacked(),
            // 9-axis IMU (gyro + accel + mag), unpacked mode
            (9, 2) => self.parse_9axis_unpacked(),
            _ => Err(format!("Unsupported sample format: {} axes, packing {}", num_axes, packing_format).into()),
        }
    }
    
    /// Parse 3-axis accelerometer data in unpacked mode
    fn parse_3axis_unpacked(&self) -> Result<Vec<SampleData>, CwaError> {
        let sample_count = self.sample_count as usize;
        let bytes_per_sample = 6; // 3 axes * 2 bytes each
        let accel_scale = self.get_accel_scale() as f32;
        
        if self.raw_sample_data.len() < sample_count * bytes_per_sample {
            return Err("Insufficient data for unpacked 3-axis samples".into());
        }
        
        let mut samples = Vec::with_capacity(sample_count);
        
        for i in 0..sample_count {
            let offset = i * bytes_per_sample;
            let x = i16::from_le_bytes([self.raw_sample_data[offset], self.raw_sample_data[offset + 1]]) as f32 * accel_scale;
            let y = i16::from_le_bytes([self.raw_sample_data[offset + 2], self.raw_sample_data[offset + 3]]) as f32 * accel_scale;
            let z = i16::from_le_bytes([self.raw_sample_data[offset + 4], self.raw_sample_data[offset + 5]]) as f32 * accel_scale;
            
            samples.push(SampleData {
                acc_x: x,
                acc_y: y,
                acc_z: z,
                gyro_x: 0.0,
                gyro_y: 0.0,
                gyro_z: 0.0,
                mag_x: 0.0,
                mag_y: 0.0,
                mag_z: 0.0,
            });
        }
        
        Ok(samples)
    }
    
    /// Parse 3-axis accelerometer data in packed mode
    fn parse_3axis_packed(&self) -> Result<Vec<SampleData>, CwaError> {
        let sample_count = self.sample_count as usize;
        let bytes_per_sample = 4; // 1 packed 32-bit value per sample
        
        if self.raw_sample_data.len() < sample_count * bytes_per_sample {
            return Err("Insufficient data for packed 3-axis samples".into());
        }
        
        let mut samples = Vec::with_capacity(sample_count);
        
        for i in 0..sample_count {
            let offset = i * bytes_per_sample;
            let packed = u32::from_le_bytes([
                self.raw_sample_data[offset],
                self.raw_sample_data[offset + 1],
                self.raw_sample_data[offset + 2],
                self.raw_sample_data[offset + 3],
            ]);
            
            // Unpack the 32-bit value: eezzzzzz zzzzyyyy yyyyyyxx xxxxxxxx
            let exponent = (packed >> 30) & 0x03;
            let x = ((packed & 0x3FF) as i16) << 6 >> 6; // Sign extend 10-bit to 16-bit
            let y = (((packed >> 10) & 0x3FF) as i16) << 6 >> 6;
            let z = (((packed >> 20) & 0x3FF) as i16) << 6 >> 6;
            
            // Apply exponent and scale to g units (always 1/256 g for AX3)
            let scale = (1 << exponent) as f32 / 256.0;
            
            samples.push(SampleData {
                acc_x: x as f32 * scale,
                acc_y: y as f32 * scale,
                acc_z: z as f32 * scale,
                gyro_x: 0.0,
                gyro_y: 0.0,
                gyro_z: 0.0,
                mag_x: 0.0,
                mag_y: 0.0,
                mag_z: 0.0,
            });
        }
        
        Ok(samples)
    }
    
    /// Parse 6-axis IMU data (gyro + accel) in unpacked mode
    fn parse_6axis_unpacked(&self) -> Result<Vec<SampleData>, CwaError> {
        let sample_count = self.sample_count as usize;
        let bytes_per_sample = 12; // 6 axes * 2 bytes each
        let accel_scale = self.get_accel_scale() as f32;
        let gyro_scale = self.get_gyro_scale().unwrap_or(2000.0) as f32 / 32768.0; // Default to 2000 dps range
        
        if self.raw_sample_data.len() < sample_count * bytes_per_sample {
            return Err("Insufficient data for unpacked 6-axis samples".into());
        }
        
        let mut samples = Vec::with_capacity(sample_count);
        
        for i in 0..sample_count {
            let offset = i * bytes_per_sample;
            // Order: gx, gy, gz, ax, ay, az
            let gx = i16::from_le_bytes([self.raw_sample_data[offset], self.raw_sample_data[offset + 1]]) as f32 * gyro_scale;
            let gy = i16::from_le_bytes([self.raw_sample_data[offset + 2], self.raw_sample_data[offset + 3]]) as f32 * gyro_scale;
            let gz = i16::from_le_bytes([self.raw_sample_data[offset + 4], self.raw_sample_data[offset + 5]]) as f32 * gyro_scale;
            let ax = i16::from_le_bytes([self.raw_sample_data[offset + 6], self.raw_sample_data[offset + 7]]) as f32 * accel_scale;
            let ay = i16::from_le_bytes([self.raw_sample_data[offset + 8], self.raw_sample_data[offset + 9]]) as f32 * accel_scale;
            let az = i16::from_le_bytes([self.raw_sample_data[offset + 10], self.raw_sample_data[offset + 11]]) as f32 * accel_scale;
            
            samples.push(SampleData {
                acc_x: ax,
                acc_y: ay,
                acc_z: az,
                gyro_x: gx,
                gyro_y: gy,
                gyro_z: gz,
                mag_x: 0.0,
                mag_y: 0.0,
                mag_z: 0.0,
            });
        }
        
        Ok(samples)
    }
    
    /// Parse 9-axis IMU data (gyro + accel + mag) in unpacked mode
    fn parse_9axis_unpacked(&self) -> Result<Vec<SampleData>, CwaError> {
        let sample_count = self.sample_count as usize;
        let bytes_per_sample = 18; // 9 axes * 2 bytes each
        let accel_scale = self.get_accel_scale() as f32;
        let gyro_scale = self.get_gyro_scale().unwrap_or(2000.0) as f32 / 32768.0;
        let mag_scale = 1.0 / 32768.0; // Magnetometer scale (placeholder)
        
        if self.raw_sample_data.len() < sample_count * bytes_per_sample {
            return Err("Insufficient data for unpacked 9-axis samples".into());
        }
        
        let mut samples = Vec::with_capacity(sample_count);
        
        for i in 0..sample_count {
            let offset = i * bytes_per_sample;
            // Order: gx, gy, gz, ax, ay, az, mx, my, mz
            let gx = i16::from_le_bytes([self.raw_sample_data[offset], self.raw_sample_data[offset + 1]]) as f32 * gyro_scale;
            let gy = i16::from_le_bytes([self.raw_sample_data[offset + 2], self.raw_sample_data[offset + 3]]) as f32 * gyro_scale;
            let gz = i16::from_le_bytes([self.raw_sample_data[offset + 4], self.raw_sample_data[offset + 5]]) as f32 * gyro_scale;
            let ax = i16::from_le_bytes([self.raw_sample_data[offset + 6], self.raw_sample_data[offset + 7]]) as f32 * accel_scale;
            let ay = i16::from_le_bytes([self.raw_sample_data[offset + 8], self.raw_sample_data[offset + 9]]) as f32 * accel_scale;
            let az = i16::from_le_bytes([self.raw_sample_data[offset + 10], self.raw_sample_data[offset + 11]]) as f32 * accel_scale;
            let mx = i16::from_le_bytes([self.raw_sample_data[offset + 12], self.raw_sample_data[offset + 13]]) as f32 * mag_scale;
            let my = i16::from_le_bytes([self.raw_sample_data[offset + 14], self.raw_sample_data[offset + 15]]) as f32 * mag_scale;
            let mz = i16::from_le_bytes([self.raw_sample_data[offset + 16], self.raw_sample_data[offset + 17]]) as f32 * mag_scale;
            
            samples.push(SampleData {
                acc_x: ax,
                acc_y: ay,
                acc_z: az,
                gyro_x: gx,
                gyro_y: gy,
                gyro_z: gz,
                mag_x: mx,
                mag_y: my,
                mag_z: mz,
            });
        }
        
        Ok(samples)
    }
}

#[derive(Debug, Clone)]
struct SampleData {
    acc_x: f32,
    acc_y: f32,
    acc_z: f32,
    gyro_x: f32,
    gyro_y: f32,
    gyro_z: f32,
    mag_x: f32,
    mag_y: f32,
    mag_z: f32,
}

#[derive(Debug)]
pub struct CwaDataResult {
    pub timestamps: Vec<i64>,
    pub samples: Vec<SampleData>,
    pub temperatures: Vec<f32>,
    pub light_values: Vec<f32>,
    pub battery_levels: Vec<f32>,
}

/// Main function to read CWA data and return structured data
pub fn read_cwa_data(file_path: &str, start_block: Option<usize>, num_blocks: Option<usize>) -> Result<CwaDataResult, CwaError> {
    let mut file = File::open(file_path)?;
    
    // We don't need the header for data reading, just validate file format
    let mut header_buffer = vec![0u8; 2];
    file.read_exact(&mut header_buffer)?;
    if std::str::from_utf8(&header_buffer).map_err(|_| "Invalid header")? != "MD" {
        return Err("Not a valid CWA file".into());
    }
    
    // Skip header (1024 bytes) and seek to first data block
    file.seek(SeekFrom::Start(1024))?;
    
    // Determine how many blocks to read
    let file_size = file.metadata()?.len();
    let data_size = file_size - 1024; // Subtract header size
    let total_blocks = (data_size / 512) as usize; // Each data block is 512 bytes
    
    let start_block = start_block.unwrap_or(0);
    let num_blocks = num_blocks.unwrap_or(total_blocks - start_block);
    let end_block = std::cmp::min(start_block + num_blocks, total_blocks);
    
    if start_block >= total_blocks {
        return Err("Start block is beyond file size".into());
    }
    
    // Seek to start block
    file.seek(SeekFrom::Start(1024 + (start_block * 512) as u64))?;
    
    // Collect all samples and timestamps
    let mut all_timestamps = Vec::new();
    let mut all_samples = Vec::new();
    let mut all_temperatures = Vec::new();
    let mut all_light_values = Vec::new();
    let mut all_battery_levels = Vec::new();
    
    for _block_idx in start_block..end_block {
        let mut buffer = vec![0u8; 512];
        match file.read_exact(&mut buffer) {
            Ok(_) => {},
            Err(_) => break, // End of file
        }
        
        let data_block = CwaDataBlock::from_buffer(&buffer)?;
        
        // Skip non-data blocks or blocks with no samples
        if data_block.sample_count == 0 {
            continue;
        }
        
        // Parse samples from this block
        let samples = data_block.parse_samples()?;
        let sample_count = samples.len();
        
        // Calculate timestamps for each sample
        let timestamps = calculate_sample_timestamps(&data_block, sample_count)?;
        
        // Extract auxiliary data
        let temp_value = data_block.get_temperature_value() as f32;
        let light_value = data_block.get_light_value() as f32;
        let battery_value = data_block.battery as f32;
        
        // Add to collections
        all_timestamps.extend(timestamps);
        all_samples.extend(samples);
        all_temperatures.extend(vec![temp_value; sample_count]);
        all_light_values.extend(vec![light_value; sample_count]);
        all_battery_levels.extend(vec![battery_value; sample_count]);
    }
    
    if all_samples.is_empty() {
        return Err("No valid sample data found in the specified range".into());
    }
    
    // Return structured data
    Ok(CwaDataResult {
        timestamps: all_timestamps,
        samples: all_samples,
        temperatures: all_temperatures,
        light_values: all_light_values,
        battery_levels: all_battery_levels,
    })
}

/// Calculate timestamps for each sample in a data block
fn calculate_sample_timestamps(data_block: &CwaDataBlock, sample_count: usize) -> Result<Vec<i64>, CwaError> {
    let block_timestamp = data_block.get_block_timestamp()
        .ok_or("Invalid block timestamp")?;
    
    let sample_rate_hz = data_block.get_sample_rate_hz();
    let sample_interval_microseconds = (1_000_000.0 / sample_rate_hz) as i64;
    
    // Handle fractional timestamp if available
    let base_timestamp = if data_block.has_fractional_timestamp() {
        let fractional_seconds = data_block.get_fractional_timestamp().unwrap_or(0.0);
        let fractional_microseconds = (fractional_seconds * 1_000_000.0) as i64;
        block_timestamp.timestamp_micros() + fractional_microseconds
    } else {
        // Use timestamp offset for legacy compatibility
        let offset_samples = data_block.timestamp_offset as i64;
        let offset_microseconds = offset_samples * sample_interval_microseconds;
        block_timestamp.timestamp_micros() - offset_microseconds
    };
    
    // Generate timestamps for each sample
    let mut timestamps = Vec::with_capacity(sample_count);
    for i in 0..sample_count {
        let sample_timestamp = base_timestamp + (i as i64 * sample_interval_microseconds);
        timestamps.push(sample_timestamp);
    }
    
    Ok(timestamps)
}

/// Convert CwaDataResult to Python dictionary for pandas compatibility
fn create_python_dict(py: Python, data: CwaDataResult) -> PyResult<PyObject> {
    let dict = PyDict::new(py);
    
    // Convert timestamps to Python list (microseconds since epoch)
    let timestamps: Vec<i64> = data.timestamps;
    dict.set_item("timestamp", timestamps.into_pyobject(py)?)?;
    
    // Extract individual arrays from samples
    let sample_count = data.samples.len();
    let mut acc_x = Vec::with_capacity(sample_count);
    let mut acc_y = Vec::with_capacity(sample_count);
    let mut acc_z = Vec::with_capacity(sample_count);
    let mut gyro_x = Vec::with_capacity(sample_count);
    let mut gyro_y = Vec::with_capacity(sample_count);
    let mut gyro_z = Vec::with_capacity(sample_count);
    let mut mag_x = Vec::with_capacity(sample_count);
    let mut mag_y = Vec::with_capacity(sample_count);
    let mut mag_z = Vec::with_capacity(sample_count);
    
    for sample in data.samples {
        acc_x.push(sample.acc_x);
        acc_y.push(sample.acc_y);
        acc_z.push(sample.acc_z);
        gyro_x.push(sample.gyro_x);
        gyro_y.push(sample.gyro_y);
        gyro_z.push(sample.gyro_z);
        mag_x.push(sample.mag_x);
        mag_y.push(sample.mag_y);
        mag_z.push(sample.mag_z);
    }
    
    // Add all arrays to the dictionary
    dict.set_item("acc_x", acc_x.into_pyobject(py)?)?;
    dict.set_item("acc_y", acc_y.into_pyobject(py)?)?;
    dict.set_item("acc_z", acc_z.into_pyobject(py)?)?;
    dict.set_item("gyro_x", gyro_x.into_pyobject(py)?)?;
    dict.set_item("gyro_y", gyro_y.into_pyobject(py)?)?;
    dict.set_item("gyro_z", gyro_z.into_pyobject(py)?)?;
    dict.set_item("mag_x", mag_x.into_pyobject(py)?)?;
    dict.set_item("mag_y", mag_y.into_pyobject(py)?)?;
    dict.set_item("mag_z", mag_z.into_pyobject(py)?)?;
    dict.set_item("temperature", data.temperatures.into_pyobject(py)?)?;
    dict.set_item("light", data.light_values.into_pyobject(py)?)?;
    dict.set_item("battery", data.battery_levels.into_pyobject(py)?)?;
    
    Ok(dict.into())
}

/// Python interface for reading CWA data
#[pyfunction]
pub fn read_cwa_file(
    py: Python,
    file_path: &str,
    start_block: Option<usize>,
    num_blocks: Option<usize>,
) -> PyResult<PyObject> {
    match read_cwa_data(file_path, start_block, num_blocks) {
        Ok(data) => create_python_dict(py, data),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())),
    }
}