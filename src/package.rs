
use pyo3::prelude::*;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use chrono::{DateTime, Utc, TimeZone};
use crate::errors::CwaError;

use pyo3::types::PyDict;
use numpy::IntoPyArray;

/// Configuration options for CWA data parsing
#[derive(Debug, Clone)]
pub struct CwaParsingOptions {
    pub include_magnetometer: bool,
    pub include_temperature: bool,
    pub include_light: bool,
    pub include_battery: bool,
}

impl Default for CwaParsingOptions {
    fn default() -> Self {
        Self {
            include_magnetometer: true,
            include_temperature: true,
            include_light: true,
            include_battery: true,
        }
    }
}

/// CWA Data Block structure (512 bytes)
#[derive(Debug)]
#[allow(dead_code)] // Some fields may be used for future functionality
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
    
    /// Get the number of axes (3=Axyz, 6=Gxyz/Axyz, 9=Gxyz/Axyz/Mxyz)
    fn get_num_axes(&self) -> u8 {
        (self.num_axes_bps >> 4) & 0x0F
    }
    
    /// Get the packing format (2 = 3x 16-bit signed, 0 = 3x 10-bit signed + 2-bit exponent)
    fn get_packing_format(&self) -> u8 {
        self.num_axes_bps & 0x0F
    }
    
    /// Extract light sensor value
    fn get_light_value(&self) -> u16 {
        self.light_scale & 0x03FF // Bottom 10 bits
    }
    
    /// Extract temperature value (bottom 10 bits)
    fn get_temperature_value(&self) -> u16 {
        self.temperature & 0x03FF
    }
    
    /// Get calibrated temperature in Celsius (Java: temperature = (float) (((getUnsignedShort(block, 20) & 0x3ff) * 150.0 - 20500) / 1000))
    fn get_temperature_celsius(&self) -> f32 {
        let raw_temp = self.get_temperature_value() as f32;
        (raw_temp * 150.0 - 20500.0) / 1000.0
    }
    
    /// Get calibrated light value (Java: light = (float) Math.pow(10, (getUnsignedShort(block, 18) & 0x3ff) / 341.0))
    fn get_light_calibrated(&self) -> f32 {
        let raw_light = self.get_light_value() as f32;
        10.0_f32.powf(raw_light / 341.0)
    }
    
    /// Get accelerometer scale factor from light_scale field (Java: accelUnit = 1 << (8 + ((rawLight >>> 13) & 0x07)))
    fn get_accel_unit(&self) -> i32 {
        let scale_bits = (self.light_scale >> 13) & 0x07; // Top 3 bits
        1 << (8 + scale_bits) // Java: accelUnit = 1 << (8 + ((rawLight >>> 13) & 0x07))
    }
    
    /// Get gyroscope range and unit from light_scale field (for AX6)
    fn get_gyro_range_and_unit(&self) -> (i32, f32) {
        let gyro_bits = (self.light_scale >> 10) & 0x07; // Bits 10-12
        if gyro_bits != 0 {
            let gyro_range = 8000 / (1 << gyro_bits); // Java: gyroRange = 8000 / (1 << ((rawLight >>> 10) & 0x07))
            let gyro_unit = 32768.0 / gyro_range as f32; // Java: gyroUnit = 32768.0f / gyroRange
            (gyro_range, gyro_unit)
        } else {
            (2000, 32768.0 / 2000.0) // Default values
        }
    }
    
    /// Get accelerometer scale factor (legacy method for compatibility)
    fn get_accel_scale(&self) -> f64 {
        1.0 / self.get_accel_unit() as f64
    }
    
    /// Get gyroscope scale factor (legacy method for compatibility)
    fn get_gyro_scale(&self) -> Option<f64> {
        let (range, _) = self.get_gyro_range_and_unit();
        if range > 0 {
            Some(range as f64)
        } else {
            None
        }
    }
    
    /// Parse samples from the data block
    fn parse_samples(&self, options: &CwaParsingOptions) -> Result<Vec<SampleData>, CwaError> {
        let num_axes = self.get_num_axes();
        let packing_format = self.get_packing_format();
        
        match (num_axes, packing_format) {
            // 3-axis accelerometer, unpacked mode (3x 16-bit signed)
            (3, 2) => self.parse_3axis_unpacked(options),
            // 3-axis accelerometer, packed mode (3x 10-bit + 2-bit exponent)
            (3, 0) => self.parse_3axis_packed(options),
            // 6-axis IMU (gyro + accel), unpacked mode
            (6, 2) => self.parse_6axis_unpacked(options),
            // 9-axis IMU (gyro + accel + mag), unpacked mode
            (9, 2) => self.parse_9axis_unpacked(options),
            _ => Err(format!("Unsupported sample format: {} axes, packing {}", num_axes, packing_format).into()),
        }
    }
    
    /// Parse 3-axis accelerometer data in unpacked mode
    fn parse_3axis_unpacked(&self, _options: &CwaParsingOptions) -> Result<Vec<SampleData>, CwaError> {
        let sample_count = self.sample_count as usize;
        let bytes_per_sample = 6; // 3 axes * 2 bytes each
        let accel_unit = self.get_accel_unit() as f32; // Java: accelUnit
        
        if self.raw_sample_data.len() < sample_count * bytes_per_sample {
            return Err("Insufficient data for unpacked 3-axis samples".into());
        }
        
        let mut samples = Vec::with_capacity(sample_count);
        
        for i in 0..sample_count {
            let offset = i * bytes_per_sample;
            let x_raw = i16::from_le_bytes([self.raw_sample_data[offset], self.raw_sample_data[offset + 1]]);
            let y_raw = i16::from_le_bytes([self.raw_sample_data[offset + 2], self.raw_sample_data[offset + 3]]);
            let z_raw = i16::from_le_bytes([self.raw_sample_data[offset + 4], self.raw_sample_data[offset + 5]]);
            
            // Java: ax = (float)sampleValues[numAxes * i + accelAxis + 0] / accelUnit;
            let x = x_raw as f32 / accel_unit;
            let y = y_raw as f32 / accel_unit;
            let z = z_raw as f32 / accel_unit;
            
            samples.push(SampleData {
                acc_x: x,
                acc_y: y,
                acc_z: z,
                gyro_x: 0.0,
                gyro_y: 0.0,
                gyro_z: 0.0,
                mag_x: None,
                mag_y: None,
                mag_z: None,
            });
        }
        
        Ok(samples)
    }
    
    /// Parse 3-axis accelerometer data in packed mode
    fn parse_3axis_packed(&self, _options: &CwaParsingOptions) -> Result<Vec<SampleData>, CwaError> {
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
            
            // Java implementation: Sign-extend 10-bit value, adjust for exponent
            // sampleValues[i * numAxes + 0] = (short)((short)(0xffffffc0 & (value <<  6)) >> (6 - ((value >> 30) & 0x03)));
            // sampleValues[i * numAxes + 1] = (short)((short)(0xffffffc0 & (value >>  4)) >> (6 - ((value >> 30) & 0x03)));
            // sampleValues[i * numAxes + 2] = (short)((short)(0xffffffc0 & (value >> 14)) >> (6 - ((value >> 30) & 0x03)));
            
            let exponent = (packed >> 30) & 0x03;
            let shift_amount = 6 - exponent;
            
            // Extract and sign-extend 10-bit values, then apply exponent shift
            let x_raw = (packed & 0x3FF) as i16;
            let y_raw = ((packed >> 10) & 0x3FF) as i16;
            let z_raw = ((packed >> 20) & 0x3FF) as i16;
            
            // Sign extend 10-bit to 16-bit by shifting left 6, then right 6
            let x_signed = (x_raw << 6) >> 6;
            let y_signed = (y_raw << 6) >> 6;
            let z_signed = (z_raw << 6) >> 6;
            
            // Apply exponent shift (equivalent to Java's >> (6 - exponent))
            let x = x_signed >> shift_amount;
            let y = y_signed >> shift_amount;
            let z = z_signed >> shift_amount;
            
            // Convert to g units (1/256 g per unit)
            let scale = 1.0 / 256.0;
            
            samples.push(SampleData {
                acc_x: x as f32 * scale,
                acc_y: y as f32 * scale,
                acc_z: z as f32 * scale,
                gyro_x: 0.0,
                gyro_y: 0.0,
                gyro_z: 0.0,
                mag_x: None,
                mag_y: None,
                mag_z: None,
            });
        }
        
        Ok(samples)
    }
    
    /// Parse 6-axis IMU data (gyro + accel) in unpacked mode
    fn parse_6axis_unpacked(&self, _options: &CwaParsingOptions) -> Result<Vec<SampleData>, CwaError> {
        let sample_count = self.sample_count as usize;
        let bytes_per_sample = 12; // 6 axes * 2 bytes each
        let accel_unit = self.get_accel_unit() as f32; // Java: accelUnit
        let (_, gyro_unit) = self.get_gyro_range_and_unit(); // Java: gyroUnit
        
        if self.raw_sample_data.len() < sample_count * bytes_per_sample {
            return Err("Insufficient data for unpacked 6-axis samples".into());
        }
        
        let mut samples = Vec::with_capacity(sample_count);
        
        for i in 0..sample_count {
            let offset = i * bytes_per_sample;
            // Order: gx, gy, gz, ax, ay, az (Java: gyroAxis = 0, accelAxis = 3)
            let gx_raw = i16::from_le_bytes([self.raw_sample_data[offset], self.raw_sample_data[offset + 1]]);
            let gy_raw = i16::from_le_bytes([self.raw_sample_data[offset + 2], self.raw_sample_data[offset + 3]]);
            let gz_raw = i16::from_le_bytes([self.raw_sample_data[offset + 4], self.raw_sample_data[offset + 5]]);
            let ax_raw = i16::from_le_bytes([self.raw_sample_data[offset + 6], self.raw_sample_data[offset + 7]]);
            let ay_raw = i16::from_le_bytes([self.raw_sample_data[offset + 8], self.raw_sample_data[offset + 9]]);
            let az_raw = i16::from_le_bytes([self.raw_sample_data[offset + 10], self.raw_sample_data[offset + 11]]);
            
            // Java: gx = (float)sampleValues[numAxes * i + gyroAxis + 0] / gyroUnit;
            // Java: ax = (float)sampleValues[numAxes * i + accelAxis + 0] / accelUnit;
            let gx = gx_raw as f32 / gyro_unit;
            let gy = gy_raw as f32 / gyro_unit;
            let gz = gz_raw as f32 / gyro_unit;
            let ax = ax_raw as f32 / accel_unit;
            let ay = ay_raw as f32 / accel_unit;
            let az = az_raw as f32 / accel_unit;
            
            samples.push(SampleData {
                acc_x: ax,
                acc_y: ay,
                acc_z: az,
                gyro_x: gx,
                gyro_y: gy,
                gyro_z: gz,
                mag_x: None,
                mag_y: None,
                mag_z: None,
            });
        }
        
        Ok(samples)
    }
    
    /// Parse 9-axis IMU data (gyro + accel + mag) in unpacked mode
    fn parse_9axis_unpacked(&self, options: &CwaParsingOptions) -> Result<Vec<SampleData>, CwaError> {
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
                mag_x: if options.include_magnetometer { Some(mx) } else { None },
                mag_y: if options.include_magnetometer { Some(my) } else { None },
                mag_z: if options.include_magnetometer { Some(mz) } else { None },
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
    mag_x: Option<f32>,
    mag_y: Option<f32>,
    mag_z: Option<f32>,
}

#[derive(Debug)]
pub struct CwaDataResult {
    pub timestamps: Vec<i64>,
    // Store data in columnar format to eliminate first copy
    pub acc_x: Vec<f32>,
    pub acc_y: Vec<f32>,
    pub acc_z: Vec<f32>,
    pub gyro_x: Vec<f32>,
    pub gyro_y: Vec<f32>,
    pub gyro_z: Vec<f32>,
    pub mag_x: Option<Vec<f32>>,
    pub mag_y: Option<Vec<f32>>,
    pub mag_z: Option<Vec<f32>>,
    pub temperatures: Option<Vec<f32>>,
    pub light_values: Option<Vec<f32>>,
    pub battery_levels: Option<Vec<f32>>,
}

/// Main function to read CWA data and return structured data
pub fn read_cwa_data(
    file_path: &str, 
    start_block: Option<usize>, 
    num_blocks: Option<usize>,
    options: Option<CwaParsingOptions>
) -> Result<CwaDataResult, CwaError> {
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
    
    let options = options.unwrap_or_default();
    
    // Pre-allocate columnar vectors for better performance
    let mut all_timestamps = Vec::new();
    let mut acc_x = Vec::new();
    let mut acc_y = Vec::new();
    let mut acc_z = Vec::new();
    let mut gyro_x = Vec::new();
    let mut gyro_y = Vec::new();
    let mut gyro_z = Vec::new();
    let mut mag_x = if options.include_magnetometer { Some(Vec::new()) } else { None };
    let mut mag_y = if options.include_magnetometer { Some(Vec::new()) } else { None };
    let mut mag_z = if options.include_magnetometer { Some(Vec::new()) } else { None };
    let mut all_temperatures = if options.include_temperature { Some(Vec::new()) } else { None };
    let mut all_light_values = if options.include_light { Some(Vec::new()) } else { None };
    let mut all_battery_levels = if options.include_battery { Some(Vec::new()) } else { None };
    
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
        let samples = data_block.parse_samples(&options)?;
        let sample_count = samples.len();
        
        // Calculate timestamps for each sample
        let timestamps = calculate_sample_timestamps(&data_block, sample_count)?;
        
        // Extract auxiliary data (calibrated values to match Java implementation)
        let temp_value = data_block.get_temperature_celsius();
        let light_value = data_block.get_light_calibrated();
        let battery_value = data_block.battery as f32;
        
        // Add timestamps
        all_timestamps.extend(timestamps);
        
        // Directly populate columnar vectors (eliminates first copy)
        for sample in samples {
            acc_x.push(sample.acc_x);
            acc_y.push(sample.acc_y);
            acc_z.push(sample.acc_z);
            gyro_x.push(sample.gyro_x);
            gyro_y.push(sample.gyro_y);
            gyro_z.push(sample.gyro_z);
            
            // Handle magnetometer data if requested
            if let Some(ref mut mag_x_vec) = mag_x {
                mag_x_vec.push(sample.mag_x.unwrap_or(0.0));
            }
            if let Some(ref mut mag_y_vec) = mag_y {
                mag_y_vec.push(sample.mag_y.unwrap_or(0.0));
            }
            if let Some(ref mut mag_z_vec) = mag_z {
                mag_z_vec.push(sample.mag_z.unwrap_or(0.0));
            }
        }
        
        // Only collect auxiliary data if requested
        if let Some(ref mut temps) = all_temperatures {
            temps.extend(vec![temp_value; sample_count]);
        }
        if let Some(ref mut lights) = all_light_values {
            lights.extend(vec![light_value; sample_count]);
        }
        if let Some(ref mut batteries) = all_battery_levels {
            batteries.extend(vec![battery_value; sample_count]);
        }
    }
    
    if acc_x.is_empty() {
        return Err("No valid sample data found in the specified range".into());
    }
    
    // Return structured data in columnar format
    Ok(CwaDataResult {
        timestamps: all_timestamps,
        acc_x,
        acc_y,
        acc_z,
        gyro_x,
        gyro_y,
        gyro_z,
        mag_x,
        mag_y,
        mag_z,
        temperatures: all_temperatures,
        light_values: all_light_values,
        battery_levels: all_battery_levels,
    })
}

/// Calculate timestamps for each sample in a data block (following Java implementation)
fn calculate_sample_timestamps(data_block: &CwaDataBlock, sample_count: usize) -> Result<Vec<i64>, CwaError> {
    let block_timestamp = data_block.get_block_timestamp()
        .ok_or("Invalid block timestamp")?;
    
    let freq = data_block.get_sample_rate_hz();
    let timestamp_offset = data_block.timestamp_offset;
    
    // Java implementation:
    // https://github.com/OxWearables/actipy/blob/master/src/actipy/AxivityReader.java
    // offsetStart = (float) -timestampOffset / freq;
    // blockTime += (long) Math.floor(offsetStart);
    // offsetStart -= (float) Math.floor(offsetStart);
    // blockStartTime = (double) blockTime + offsetStart;
    // blockEndTime = blockStartTime + (float) sampleCount / freq;
    
    let offset_start = -(timestamp_offset as f64) / freq;
    let block_time_seconds = block_timestamp.timestamp() as f64;
    
    // Fix so blockTime takes negative offset into account (for < :00 s boundaries)
    let adjusted_block_time = block_time_seconds + offset_start.floor();
    let adjusted_offset_start = offset_start - offset_start.floor();
    
    // Start and end of block
    let block_start_time = adjusted_block_time + adjusted_offset_start;
    let block_end_time = block_start_time + (sample_count as f64) / freq;
    
    // Generate timestamps for each sample (Java: t = blockStartTime + (double)i * (blockEndTime - blockStartTime) / sampleCount)
    let mut timestamps = Vec::with_capacity(sample_count);
    for i in 0..sample_count {
        let t = block_start_time + (i as f64) * (block_end_time - block_start_time) / (sample_count as f64);
        let t_millis = t * 1000.0; // Convert to milliseconds
        let t_micros = (t_millis * 1000.0) as i64; // Convert to microseconds for consistency
        timestamps.push(t_micros);
    }
    
    Ok(timestamps)
}

/// Convert CwaDataResult to Python dictionary with NumPy arrays (zero-copy)
fn create_python_dict_numpy(py: Python, data: CwaDataResult) -> PyResult<Py<PyAny>> {
    let dict = PyDict::new(py);
    
    // Convert timestamps to NumPy array (zero-copy transfer)
    dict.set_item("timestamp", data.timestamps.into_pyarray(py))?;
    
    // Convert sensor data to NumPy arrays (zero-copy transfer)
    dict.set_item("acc_x", data.acc_x.into_pyarray(py))?;
    dict.set_item("acc_y", data.acc_y.into_pyarray(py))?;
    dict.set_item("acc_z", data.acc_z.into_pyarray(py))?;
    dict.set_item("gyro_x", data.gyro_x.into_pyarray(py))?;
    dict.set_item("gyro_y", data.gyro_y.into_pyarray(py))?;
    dict.set_item("gyro_z", data.gyro_z.into_pyarray(py))?;
    
    // Only include magnetometer data if requested
    if let Some(mag_x_data) = data.mag_x {
        dict.set_item("mag_x", mag_x_data.into_pyarray(py))?;
    }
    if let Some(mag_y_data) = data.mag_y {
        dict.set_item("mag_y", mag_y_data.into_pyarray(py))?;
    }
    if let Some(mag_z_data) = data.mag_z {
        dict.set_item("mag_z", mag_z_data.into_pyarray(py))?;
    }
    
    // Only include auxiliary data if requested
    if let Some(temperatures) = data.temperatures {
        dict.set_item("temperature", temperatures.into_pyarray(py))?;
    }
    if let Some(light_values) = data.light_values {
        dict.set_item("light", light_values.into_pyarray(py))?;
    }
    if let Some(battery_levels) = data.battery_levels {
        dict.set_item("battery", battery_levels.into_pyarray(py))?;
    }
    
    Ok(dict.into())
}

/// Python interface for reading CWA data
#[pyfunction]
#[pyo3(signature = (file_path, start_block=None, num_blocks=None, include_magnetometer=true, include_temperature=true, include_light=true, include_battery=true))]
pub fn read_cwa_file(
    py: Python,
    file_path: &str,
    start_block: Option<usize>,
    num_blocks: Option<usize>,
    include_magnetometer: bool,
    include_temperature: bool,
    include_light: bool,
    include_battery: bool,
) -> PyResult<Py<PyAny>> {
    let options = CwaParsingOptions {
        include_magnetometer,
        include_temperature,
        include_light,
        include_battery,
    };
    
    match read_cwa_data(file_path, start_block, num_blocks, Some(options)) {
        Ok(data) => create_python_dict_numpy(py, data),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string())),
    }
}