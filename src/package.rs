use crate::errors::CwaError;
use chrono::{DateTime, TimeZone, Utc};
use pyo3::prelude::*;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

use numpy::IntoPyArray;
use pyo3::types::PyDict;

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
    packet_header: String,    // @ 0  +2   ASCII "AX", little-endian (0x5841)
    packet_length: u16,       // @ 2  +2   Packet length (508 bytes)
    device_fractional: u16,   // @ 4  +2   Device ID or fractional timestamp
    session_id: u32,          // @ 6  +4   Session identifier
    sequence_id: u32,         // @10  +4   Sequence counter
    timestamp: u32,           // @14  +4   RTC timestamp
    light_scale: u16,         // @18  +2   Light sensor + accel/gyro scale info
    temperature: u16,         // @20  +2   Temperature sensor value
    events: u8,               // @22  +1   Event flags
    battery: u8,              // @23  +1   Battery level
    sample_rate: u8,          // @24  +1   Sample rate code
    num_axes_bps: u8,         // @25  +1   Number of axes and packing format
    timestamp_offset: i16,    // @26  +2   Timestamp offset
    sample_count: u16,        // @28  +2   Number of samples
    raw_sample_data: Vec<u8>, // @30  +480 Raw sample data
    checksum: u16,            // @510 +2   Checksum
}

impl CwaDataBlock {
    fn from_buffer(buffer: &[u8]) -> Result<Self, CwaError> {
        if buffer.len() != 512 {
            return Err("Data block must be exactly 512 bytes".into());
        }

        // Parse packet header
        let packet_header =
            std::str::from_utf8(&buffer[0..2]).map_err(|_| "Invalid packet header format")?;

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
            _ => Err(format!(
                "Unsupported sample format: {} axes, packing {}",
                num_axes, packing_format
            )
            .into()),
        }
    }

    /// Parse 3-axis accelerometer data in unpacked mode
    fn parse_3axis_unpacked(
        &self,
        _options: &CwaParsingOptions,
    ) -> Result<Vec<SampleData>, CwaError> {
        let sample_count = self.sample_count as usize;
        let bytes_per_sample = 6; // 3 axes * 2 bytes each
        let accel_unit = self.get_accel_unit() as f32; // Java: accelUnit

        if self.raw_sample_data.len() < sample_count * bytes_per_sample {
            return Err("Insufficient data for unpacked 3-axis samples".into());
        }

        let mut samples = Vec::with_capacity(sample_count);

        for i in 0..sample_count {
            let offset = i * bytes_per_sample;
            let x_raw = i16::from_le_bytes([
                self.raw_sample_data[offset],
                self.raw_sample_data[offset + 1],
            ]);
            let y_raw = i16::from_le_bytes([
                self.raw_sample_data[offset + 2],
                self.raw_sample_data[offset + 3],
            ]);
            let z_raw = i16::from_le_bytes([
                self.raw_sample_data[offset + 4],
                self.raw_sample_data[offset + 5],
            ]);

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
    fn parse_3axis_packed(
        &self,
        _options: &CwaParsingOptions,
    ) -> Result<Vec<SampleData>, CwaError> {
        let sample_count = self.sample_count as usize;
        let bytes_per_sample = 4; // 1 packed 32-bit value per sample
        let accel_unit = self.get_accel_unit() as f32;

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

            let exponent = (packed >> 30) & 0x03;
            let shift_amount = 6 - exponent;

            let x = ((((packed << 6) as u16) & 0xffc0) as i16) >> shift_amount;
            let y = ((((packed >> 4) as u16) & 0xffc0) as i16) >> shift_amount;
            let z = ((((packed >> 14) as u16) & 0xffc0) as i16) >> shift_amount;

            samples.push(SampleData {
                acc_x: x as f32 / accel_unit,
                acc_y: y as f32 / accel_unit,
                acc_z: z as f32 / accel_unit,
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
    fn parse_6axis_unpacked(
        &self,
        _options: &CwaParsingOptions,
    ) -> Result<Vec<SampleData>, CwaError> {
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
            let gx_raw = i16::from_le_bytes([
                self.raw_sample_data[offset],
                self.raw_sample_data[offset + 1],
            ]);
            let gy_raw = i16::from_le_bytes([
                self.raw_sample_data[offset + 2],
                self.raw_sample_data[offset + 3],
            ]);
            let gz_raw = i16::from_le_bytes([
                self.raw_sample_data[offset + 4],
                self.raw_sample_data[offset + 5],
            ]);
            let ax_raw = i16::from_le_bytes([
                self.raw_sample_data[offset + 6],
                self.raw_sample_data[offset + 7],
            ]);
            let ay_raw = i16::from_le_bytes([
                self.raw_sample_data[offset + 8],
                self.raw_sample_data[offset + 9],
            ]);
            let az_raw = i16::from_le_bytes([
                self.raw_sample_data[offset + 10],
                self.raw_sample_data[offset + 11],
            ]);

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
    fn parse_9axis_unpacked(
        &self,
        options: &CwaParsingOptions,
    ) -> Result<Vec<SampleData>, CwaError> {
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
            let gx = i16::from_le_bytes([
                self.raw_sample_data[offset],
                self.raw_sample_data[offset + 1],
            ]) as f32
                * gyro_scale;
            let gy = i16::from_le_bytes([
                self.raw_sample_data[offset + 2],
                self.raw_sample_data[offset + 3],
            ]) as f32
                * gyro_scale;
            let gz = i16::from_le_bytes([
                self.raw_sample_data[offset + 4],
                self.raw_sample_data[offset + 5],
            ]) as f32
                * gyro_scale;
            let ax = i16::from_le_bytes([
                self.raw_sample_data[offset + 6],
                self.raw_sample_data[offset + 7],
            ]) as f32
                * accel_scale;
            let ay = i16::from_le_bytes([
                self.raw_sample_data[offset + 8],
                self.raw_sample_data[offset + 9],
            ]) as f32
                * accel_scale;
            let az = i16::from_le_bytes([
                self.raw_sample_data[offset + 10],
                self.raw_sample_data[offset + 11],
            ]) as f32
                * accel_scale;
            let mx = i16::from_le_bytes([
                self.raw_sample_data[offset + 12],
                self.raw_sample_data[offset + 13],
            ]) as f32
                * mag_scale;
            let my = i16::from_le_bytes([
                self.raw_sample_data[offset + 14],
                self.raw_sample_data[offset + 15],
            ]) as f32
                * mag_scale;
            let mz = i16::from_le_bytes([
                self.raw_sample_data[offset + 16],
                self.raw_sample_data[offset + 17],
            ]) as f32
                * mag_scale;

            samples.push(SampleData {
                acc_x: ax,
                acc_y: ay,
                acc_z: az,
                gyro_x: gx,
                gyro_y: gy,
                gyro_z: gz,
                mag_x: if options.include_magnetometer {
                    Some(mx)
                } else {
                    None
                },
                mag_y: if options.include_magnetometer {
                    Some(my)
                } else {
                    None
                },
                mag_z: if options.include_magnetometer {
                    Some(mz)
                } else {
                    None
                },
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
    options: Option<CwaParsingOptions>,
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

    let initial_previous_packet_end = find_previous_packet_end(&mut file, start_block)?;

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
    let mut mag_x = if options.include_magnetometer {
        Some(Vec::new())
    } else {
        None
    };
    let mut mag_y = if options.include_magnetometer {
        Some(Vec::new())
    } else {
        None
    };
    let mut mag_z = if options.include_magnetometer {
        Some(Vec::new())
    } else {
        None
    };
    let mut all_temperatures = if options.include_temperature {
        Some(Vec::new())
    } else {
        None
    };
    let mut all_light_values = if options.include_light {
        Some(Vec::new())
    } else {
        None
    };
    let mut all_battery_levels = if options.include_battery {
        Some(Vec::new())
    } else {
        None
    };

    let mut previous_packet_end: Option<f64> = initial_previous_packet_end;

    for _block_idx in start_block..end_block {
        let mut buffer = vec![0u8; 512];
        match file.read_exact(&mut buffer) {
            Ok(_) => {}
            Err(_) => break, // End of file
        }

        let data_block = CwaDataBlock::from_buffer(&buffer)?;

        if data_block.sample_rate == 0 {
            return Err("Old CWA format packets are not supported".into());
        }

        // Skip non-data blocks or blocks with no samples
        if data_block.sample_count == 0 {
            continue;
        }

        // Parse samples from this block
        let samples = data_block.parse_samples(&options)?;
        let sample_count = samples.len();

        // Calculate timestamps for each sample
        let (timestamps, packet_end) = calculate_sample_timestamps_with_prev_end(
            &data_block,
            sample_count,
            previous_packet_end,
        )?;
        previous_packet_end = Some(packet_end);

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

/// Calculate timestamps for each sample in a data block
fn calculate_sample_timestamps(
    data_block: &CwaDataBlock,
    sample_count: usize,
) -> Result<Vec<i64>, CwaError> {
    let (timestamps, _) =
        calculate_sample_timestamps_with_prev_end(data_block, sample_count, None)?;
    Ok(timestamps)
}

fn calculate_sample_timestamps_with_prev_end(
    data_block: &CwaDataBlock,
    sample_count: usize,
    previous_packet_end: Option<f64>,
) -> Result<(Vec<i64>, f64), CwaError> {
    if sample_count == 0 {
        return Ok((Vec::new(), previous_packet_end.unwrap_or(0.0)));
    }

    let (natural_t0, natural_t1) = natural_packet_bounds(data_block, sample_count)?;
    let mut t0 = natural_t0;
    let t1 = natural_t1;

    if let Some(last_end) = previous_packet_end {
        if t0 - last_end < 1.0 {
            t0 = last_end;
        }
    }

    // Generate timestamps for each sample
    let mut timestamps = Vec::with_capacity(sample_count);
    for i in 0..sample_count {
        let t = t0 + (i as f64 * (t1 - t0) / sample_count as f64);
        let t_micros = (t * 1_000_000.0) as i64; // Convert to microseconds
        timestamps.push(t_micros);
    }

    Ok((timestamps, t1))
}

fn natural_packet_bounds(
    data_block: &CwaDataBlock,
    sample_count: usize,
) -> Result<(f64, f64), CwaError> {
    let block_timestamp = data_block
        .get_block_timestamp()
        .ok_or("Invalid block timestamp")?;

    let freq = data_block.get_sample_rate_hz() as f32;
    let mut offset_start = -(data_block.timestamp_offset as f32) / freq;
    let offset_floor = offset_start.floor();
    let time0 = block_timestamp.timestamp() as f64 + offset_floor as f64;
    offset_start -= offset_floor;

    let t0 = time0 + offset_start as f64;
    let t1 = t0 + (sample_count as f32 / freq) as f64;
    Ok((t0, t1))
}

fn find_previous_packet_end(file: &mut File, start_block: usize) -> Result<Option<f64>, CwaError> {
    if start_block == 0 {
        return Ok(None);
    }

    let mut idx = start_block;
    while idx > 0 {
        idx -= 1;
        let pos = 1024 + (idx as u64) * 512;
        file.seek(SeekFrom::Start(pos))?;

        let mut buffer = vec![0u8; 512];
        if file.read_exact(&mut buffer).is_err() {
            continue;
        }

        let Ok(block) = CwaDataBlock::from_buffer(&buffer) else {
            continue;
        };

        if block.sample_rate == 0 || block.sample_count == 0 {
            continue;
        }

        if block.get_block_timestamp().is_none() {
            continue;
        }

        let (_, t1) = natural_packet_bounds(&block, block.sample_count as usize)?;
        return Ok(Some(t1));
    }

    Ok(None)
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
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            e.to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_cwa_timestamp(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
    ) -> u32 {
        (((year as u32 - 2000) & 0x3f) << 26)
            | ((month & 0x0f) << 22)
            | ((day & 0x1f) << 17)
            | ((hour & 0x1f) << 12)
            | ((minute & 0x3f) << 6)
            | (second & 0x3f)
    }

    fn c_decode_packed_axes(value: u32) -> (i16, i16, i16) {
        let exp = (value >> 30) & 0x03;
        let x = ((((value << 6) as u16) & 0xffc0) as i16) >> (6 - exp);
        let y = ((((value >> 4) as u16) & 0xffc0) as i16) >> (6 - exp);
        let z = ((((value >> 14) as u16) & 0xffc0) as i16) >> (6 - exp);
        (x, y, z)
    }

    fn c_style_timestamps(
        year: i32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
        sample_rate: u8,
        timestamp_offset: i16,
        sample_count: usize,
    ) -> Vec<i64> {
        let base = Utc
            .with_ymd_and_hms(year, month, day, hour, minute, second)
            .single()
            .expect("valid datetime")
            .timestamp() as f64;
        let freq = (3200.0f32 / ((1 << (15 - (sample_rate & 0x0f))) as f32)) as f64;
        let mut offset_start = (-(timestamp_offset as f32) / (freq as f32)) as f64;
        let offset_floor = offset_start.floor();
        let time0 = base + offset_floor;
        offset_start -= offset_floor;
        let t0 = time0 + offset_start;
        let t1 = t0 + ((sample_count as f32) / (freq as f32)) as f64;
        let mut out = Vec::with_capacity(sample_count);
        for i in 0..sample_count {
            let t = t0 + (i as f64 * (t1 - t0) / sample_count as f64);
            out.push((t * 1_000_000.0) as i64);
        }
        out
    }

    #[test]
    fn timestamps_use_timestamp_offset_like_c_exporter() {
        let block = CwaDataBlock {
            packet_header: "AX".to_string(),
            packet_length: 508,
            device_fractional: 0,
            session_id: 1,
            sequence_id: 1,
            timestamp: encode_cwa_timestamp(2012, 3, 27, 11, 14, 58),
            light_scale: 0,
            temperature: 0,
            events: 0,
            battery: 0,
            sample_rate: 0x4a,
            num_axes_bps: 0x32,
            timestamp_offset: 50,
            sample_count: 120,
            raw_sample_data: vec![0; 480],
            checksum: 0,
        };

        let timestamps = calculate_sample_timestamps(&block, 12).expect("timestamps");
        let expected = c_style_timestamps(2012, 3, 27, 11, 14, 58, 0x4a, 50, 12);

        assert_eq!(timestamps, expected);
    }

    #[test]
    fn packed_3axis_decode_matches_c_bit_packing_and_scale() {
        let packed = 0x9234_5678_u32;
        let (x, y, z) = c_decode_packed_axes(packed);

        let block = CwaDataBlock {
            packet_header: "AX".to_string(),
            packet_length: 508,
            device_fractional: 0,
            session_id: 1,
            sequence_id: 1,
            timestamp: encode_cwa_timestamp(2012, 3, 27, 11, 14, 58),
            light_scale: 2 << 13,
            temperature: 0,
            events: 0,
            battery: 0,
            sample_rate: 0x4a,
            num_axes_bps: 0x30,
            timestamp_offset: 0,
            sample_count: 1,
            raw_sample_data: {
                let mut v = vec![0; 480];
                v[0..4].copy_from_slice(&packed.to_le_bytes());
                v
            },
            checksum: 0,
        };

        let samples = block
            .parse_samples(&CwaParsingOptions::default())
            .expect("samples");

        let expected_scale = 1.0f32 / 1024.0f32;
        let expected_x = x as f32 * expected_scale;
        let expected_y = y as f32 * expected_scale;
        let expected_z = z as f32 * expected_scale;

        assert!((samples[0].acc_x - expected_x).abs() < 1e-7);
        assert!((samples[0].acc_y - expected_y).abs() < 1e-7);
        assert!((samples[0].acc_z - expected_z).abs() < 1e-7);
    }

    #[test]
    fn stream_timestamps_do_not_jump_backwards_between_adjacent_blocks() {
        let block1 = CwaDataBlock {
            packet_header: "AX".to_string(),
            packet_length: 508,
            device_fractional: 0,
            session_id: 1,
            sequence_id: 1,
            timestamp: encode_cwa_timestamp(2012, 1, 1, 0, 0, 1),
            light_scale: 0,
            temperature: 0,
            events: 0,
            battery: 0,
            sample_rate: 0x4a,
            num_axes_bps: 0x32,
            timestamp_offset: 0,
            sample_count: 100,
            raw_sample_data: vec![0; 480],
            checksum: 0,
        };

        let block2 = CwaDataBlock {
            packet_header: "AX".to_string(),
            packet_length: 508,
            device_fractional: 0,
            session_id: 1,
            sequence_id: 2,
            timestamp: encode_cwa_timestamp(2012, 1, 1, 0, 0, 3),
            light_scale: 0,
            temperature: 0,
            events: 0,
            battery: 0,
            sample_rate: 0x4a,
            num_axes_bps: 0x32,
            timestamp_offset: 150,
            sample_count: 100,
            raw_sample_data: vec![0; 480],
            checksum: 0,
        };

        let (ts1, end1) =
            calculate_sample_timestamps_with_prev_end(&block1, 100, None).expect("block1");
        let (ts2, _) =
            calculate_sample_timestamps_with_prev_end(&block2, 100, Some(end1)).expect("block2");

        assert!(ts2[0] >= ts1[99]);
    }

    #[test]
    fn seeding_with_previous_natural_end_matches_full_sequence_next_block() {
        let block1 = CwaDataBlock {
            packet_header: "AX".to_string(),
            packet_length: 508,
            device_fractional: 0,
            session_id: 1,
            sequence_id: 1,
            timestamp: encode_cwa_timestamp(2012, 1, 1, 0, 0, 1),
            light_scale: 0,
            temperature: 0,
            events: 0,
            battery: 0,
            sample_rate: 0x4a,
            num_axes_bps: 0x32,
            timestamp_offset: 0,
            sample_count: 120,
            raw_sample_data: vec![0; 480],
            checksum: 0,
        };

        let block2 = CwaDataBlock {
            packet_header: "AX".to_string(),
            packet_length: 508,
            device_fractional: 0,
            session_id: 1,
            sequence_id: 2,
            timestamp: encode_cwa_timestamp(2012, 1, 1, 0, 0, 3),
            light_scale: 0,
            temperature: 0,
            events: 0,
            battery: 0,
            sample_rate: 0x4a,
            num_axes_bps: 0x32,
            timestamp_offset: 150,
            sample_count: 120,
            raw_sample_data: vec![0; 480],
            checksum: 0,
        };

        let (_, full_end_1) =
            calculate_sample_timestamps_with_prev_end(&block1, 120, None).expect("full block1");
        let (full_ts_2, _) =
            calculate_sample_timestamps_with_prev_end(&block2, 120, Some(full_end_1))
                .expect("full block2");

        let (_, natural_end_1) = natural_packet_bounds(&block1, 120).expect("natural bounds");
        let (seeded_ts_2, _) =
            calculate_sample_timestamps_with_prev_end(&block2, 120, Some(natural_end_1))
                .expect("seeded block2");

        assert_eq!(full_ts_2, seeded_ts_2);
    }
}
