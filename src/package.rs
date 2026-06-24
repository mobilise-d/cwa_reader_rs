use crate::errors::CwaError;
use chrono::{DateTime, TimeZone, Utc};
use csv::WriterBuilder;
use pyo3::prelude::*;
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom};

use numpy::IntoPyArray;
use pyo3::types::PyDict;

const MAX_RESAMPLE_HZ: f64 = 10_000.0;

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

#[derive(Debug, Clone, Copy)]
struct TimeRangeOptions {
    start_time_seconds: Option<f64>,
    end_time_seconds: Option<f64>,
}

impl TimeRangeOptions {
    fn has_bounds(&self) -> bool {
        self.start_time_seconds.is_some() || self.end_time_seconds.is_some()
    }

    fn validate(&self) -> Result<(), CwaError> {
        for value in [self.start_time_seconds, self.end_time_seconds]
            .into_iter()
            .flatten()
        {
            if !value.is_finite() {
                return Err("time range values must be finite".into());
            }
        }

        if let (Some(start), Some(end)) = (self.start_time_seconds, self.end_time_seconds) {
            if end <= start {
                return Err("range_end_time must be greater than range_start_time".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct ResampleOptions {
    target_hz: f64,
}

impl ResampleOptions {
    fn parse(target_hz: f64, method: &str) -> Result<Self, CwaError> {
        if !target_hz.is_finite() || target_hz <= 0.0 {
            return Err("resample_hz must be a finite value > 0".into());
        }
        if target_hz > MAX_RESAMPLE_HZ {
            return Err(format!("resample_hz must be <= {MAX_RESAMPLE_HZ}").into());
        }

        match method {
            "cubic" => Ok(Self { target_hz }),
            _ => Err(format!("Unsupported resample_method '{method}'. Supported: cubic").into()),
        }
    }
}

fn resolve_block_range(
    file_size: u64,
    start_block: Option<usize>,
    num_blocks: Option<usize>,
) -> Result<(usize, usize), CwaError> {
    if file_size < 1024 {
        return Err("File too small to be a valid CWA file".into());
    }

    let data_size = file_size - 1024;
    let total_blocks = (data_size / 512) as usize;
    let start_block = start_block.unwrap_or(0);
    if start_block >= total_blocks {
        return Err("Start block is beyond file size".into());
    }

    let num_blocks = num_blocks.unwrap_or(total_blocks - start_block);
    let end_block = std::cmp::min(start_block.saturating_add(num_blocks), total_blocks);
    Ok((start_block, end_block))
}

fn open_cwa_data_blocks(
    file_path: &str,
    start_block: Option<usize>,
    num_blocks: Option<usize>,
) -> Result<(File, usize, usize, Option<f64>), CwaError> {
    let mut file = File::open(file_path)?;

    let mut header = [0u8; 2];
    file.read_exact(&mut header)?;
    if header != *b"MD" {
        return Err("Not a valid CWA file".into());
    }

    let file_size = file.metadata()?.len();
    let (start_block, end_block) = resolve_block_range(file_size, start_block, num_blocks)?;
    let previous_packet_end = find_previous_packet_end(&mut file, start_block)?;
    file.seek(SeekFrom::Start(1024 + (start_block * 512) as u64))?;

    Ok((file, start_block, end_block, previous_packet_end))
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
        let month = (self.timestamp >> 22) & 0x0f;
        let day = (self.timestamp >> 17) & 0x1f;
        let hours = (self.timestamp >> 12) & 0x1f;
        let mins = (self.timestamp >> 6) & 0x3f;
        let secs = self.timestamp & 0x3f;

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
        (raw_temp * 75.0 / 256.0) - 50.0
    }

    /// Get battery in volts (matches cwa-convert -battv)
    fn get_battery_voltage(&self) -> f32 {
        6.0 * (512.0 + self.battery as f32) / 1024.0
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

#[derive(Clone, Copy)]
struct CsvRowValues {
    timestamp: i64,
    acc_x: f32,
    acc_y: f32,
    acc_z: f32,
    gyro_x: f32,
    gyro_y: f32,
    gyro_z: f32,
    mag_x: Option<f32>,
    mag_y: Option<f32>,
    mag_z: Option<f32>,
    temperature: Option<f32>,
    light: Option<f32>,
    battery: Option<f32>,
}

#[derive(Clone)]
struct TimedSample {
    time_seconds: f64,
    sample: SampleData,
    temperature: f32,
    light: f32,
    battery: f32,
}

struct StreamingResampler {
    options: ResampleOptions,
    range: TimeRangeOptions,
    samples: VecDeque<TimedSample>,
    acc_left: usize,
    target_start_ms: Option<f64>,
    next_target_index: u64,
    done: bool,
    result: CwaDataResult,
}

impl StreamingResampler {
    fn new(
        parse_options: &CwaParsingOptions,
        options: ResampleOptions,
        range: TimeRangeOptions,
    ) -> Result<Self, CwaError> {
        range.validate()?;

        Ok(Self {
            options,
            range,
            samples: VecDeque::new(),
            acc_left: 0,
            target_start_ms: None,
            next_target_index: 0,
            done: false,
            result: CwaDataResult {
                timestamps: Vec::new(),
                acc_x: Vec::new(),
                acc_y: Vec::new(),
                acc_z: Vec::new(),
                gyro_x: Vec::new(),
                gyro_y: Vec::new(),
                gyro_z: Vec::new(),
                mag_x: if parse_options.include_magnetometer {
                    Some(Vec::new())
                } else {
                    None
                },
                mag_y: if parse_options.include_magnetometer {
                    Some(Vec::new())
                } else {
                    None
                },
                mag_z: if parse_options.include_magnetometer {
                    Some(Vec::new())
                } else {
                    None
                },
                temperatures: if parse_options.include_temperature {
                    Some(Vec::new())
                } else {
                    None
                },
                light_values: if parse_options.include_light {
                    Some(Vec::new())
                } else {
                    None
                },
                battery_levels: if parse_options.include_battery {
                    Some(Vec::new())
                } else {
                    None
                },
            },
        })
    }

    fn is_done(&self) -> bool {
        self.done
    }

    fn into_result(mut self) -> Result<CwaDataResult, CwaError> {
        self.emit_ready(true);
        if self.result.timestamps.is_empty() {
            return Err("No samples remain after applying time range/resampling".into());
        }
        Ok(self.result)
    }

    fn push_sample(
        &mut self,
        time_seconds: f64,
        sample: &SampleData,
        temperature: f32,
        light: f32,
        battery: f32,
    ) {
        if self.done {
            return;
        }

        self.samples.push_back(TimedSample {
            time_seconds,
            sample: sample.clone(),
            temperature,
            light,
            battery,
        });

        if self.target_start_ms.is_none() {
            let mut start = time_seconds;
            if let Some(range_start) = self.range.start_time_seconds {
                if range_start > start {
                    start = range_start;
                }
            }
            self.target_start_ms = Some(start * 1000.0);
            self.next_target_index = 0;
        }

        self.emit_ready(false);
    }

    fn emit_ready(&mut self, final_flush: bool) {
        let Some(target_start_ms) = self.target_start_ms else {
            return;
        };
        let step_ms = 1000.0 / self.options.target_hz;

        loop {
            let target_time = (target_start_ms + self.next_target_index as f64 * step_ms) / 1000.0;
            if self
                .range
                .end_time_seconds
                .is_some_and(|end| target_time >= end)
            {
                self.done = true;
                break;
            }

            self.acc_left = self.advance_left(self.acc_left, target_time);
            if !self.has_bracket(self.acc_left, target_time) {
                self.prune();
                break;
            }
            if !self.has_cubic_lookahead(self.acc_left, final_flush) {
                self.prune();
                break;
            }

            self.emit_one(target_time);
            self.next_target_index += 1;
            self.prune();
        }
    }

    fn sample_time(&self, idx: usize) -> f64 {
        self.samples[idx].time_seconds
    }

    fn advance_left(&self, mut left: usize, target_time: f64) -> usize {
        while left + 1 < self.samples.len() && self.sample_time(left + 1) < target_time {
            left += 1;
        }
        left
    }

    fn has_bracket(&self, left: usize, target_time: f64) -> bool {
        if self.samples.len() < 2 || left + 1 >= self.samples.len() {
            return false;
        }
        let x_left = self.sample_time(left);
        let x_right = self.sample_time(left + 1);
        target_time >= x_left && target_time <= x_right
    }

    fn has_cubic_lookahead(&self, left: usize, final_flush: bool) -> bool {
        left == 0 || left + 2 < self.samples.len() || final_flush
    }

    fn interpolate_value<F>(&self, left: usize, target_time: f64, value_fn: F) -> f32
    where
        F: Fn(&TimedSample) -> f32,
    {
        let right = left + 1;

        if left > 0 && right + 1 < self.samples.len() {
            let x0 = self.sample_time(left - 1);
            let x1 = self.sample_time(left);
            let x2 = self.sample_time(right);
            let x3 = self.sample_time(right + 1);
            let y0 = value_fn(&self.samples[left - 1]) as f64;
            let y1 = value_fn(&self.samples[left]) as f64;
            let y2 = value_fn(&self.samples[right]) as f64;
            let y3 = value_fn(&self.samples[right + 1]) as f64;

            if let Some(v) = cubic_lagrange_4pt(target_time, [x0, x1, x2, x3], [y0, y1, y2, y3]) {
                return v as f32;
            }
        }

        let x_left = self.sample_time(left);
        let x_right = self.sample_time(right);
        let y_left = value_fn(&self.samples[left]) as f64;
        let y_right = value_fn(&self.samples[right]) as f64;
        if (x_right - x_left).abs() < 1e-12 {
            y_left as f32
        } else {
            (y_left + (y_right - y_left) * ((target_time - x_left) / (x_right - x_left))) as f32
        }
    }

    fn emit_one(&mut self, target_time: f64) {
        let acc_left = self.acc_left;
        let gyro_left = acc_left;

        let out_acc_x = self.interpolate_value(acc_left, target_time, |s| s.sample.acc_x);
        let out_acc_y = self.interpolate_value(acc_left, target_time, |s| s.sample.acc_y);
        let out_acc_z = self.interpolate_value(acc_left, target_time, |s| s.sample.acc_z);
        let out_gyro_x = self.interpolate_value(gyro_left, target_time, |s| s.sample.gyro_x);
        let out_gyro_y = self.interpolate_value(gyro_left, target_time, |s| s.sample.gyro_y);
        let out_gyro_z = self.interpolate_value(gyro_left, target_time, |s| s.sample.gyro_z);
        let out_mag_x = if self.result.mag_x.is_some() {
            Some(self.interpolate_value(acc_left, target_time, |s| s.sample.mag_x.unwrap_or(0.0)))
        } else {
            None
        };
        let out_mag_y = if self.result.mag_y.is_some() {
            Some(self.interpolate_value(acc_left, target_time, |s| s.sample.mag_y.unwrap_or(0.0)))
        } else {
            None
        };
        let out_mag_z = if self.result.mag_z.is_some() {
            Some(self.interpolate_value(acc_left, target_time, |s| s.sample.mag_z.unwrap_or(0.0)))
        } else {
            None
        };
        let out_temperature = if self.result.temperatures.is_some() {
            Some(self.interpolate_value(acc_left, target_time, |s| s.temperature))
        } else {
            None
        };
        let out_light = if self.result.light_values.is_some() {
            Some(self.interpolate_value(acc_left, target_time, |s| s.light))
        } else {
            None
        };
        let out_battery = if self.result.battery_levels.is_some() {
            Some(self.interpolate_value(acc_left, target_time, |s| s.battery))
        } else {
            None
        };

        self.result
            .timestamps
            .push((target_time * 1_000_000.0) as i64);
        self.result.acc_x.push(out_acc_x);
        self.result.acc_y.push(out_acc_y);
        self.result.acc_z.push(out_acc_z);
        self.result.gyro_x.push(out_gyro_x);
        self.result.gyro_y.push(out_gyro_y);
        self.result.gyro_z.push(out_gyro_z);

        if let Some(ref mut mag_x) = self.result.mag_x {
            mag_x.push(out_mag_x.expect("mag_x computed"));
        }
        if let Some(ref mut mag_y) = self.result.mag_y {
            mag_y.push(out_mag_y.expect("mag_y computed"));
        }
        if let Some(ref mut mag_z) = self.result.mag_z {
            mag_z.push(out_mag_z.expect("mag_z computed"));
        }

        if let Some(ref mut temperatures) = self.result.temperatures {
            temperatures.push(out_temperature.expect("temperature computed"));
        }
        if let Some(ref mut lights) = self.result.light_values {
            lights.push(out_light.expect("light computed"));
        }
        if let Some(ref mut batteries) = self.result.battery_levels {
            batteries.push(out_battery.expect("battery computed"));
        }
    }

    fn prune(&mut self) {
        let remove = self.acc_left.saturating_sub(1);
        if remove == 0 {
            return;
        }
        for _ in 0..remove {
            let _ = self.samples.pop_front();
        }
        self.acc_left = self.acc_left.saturating_sub(remove);
    }
}

/// Main function to read CWA data and return structured data
pub fn read_cwa_data(
    file_path: &str,
    start_block: Option<usize>,
    num_blocks: Option<usize>,
    options: Option<CwaParsingOptions>,
) -> Result<CwaDataResult, CwaError> {
    let (mut file, start_block, end_block, initial_previous_packet_end) =
        open_cwa_data_blocks(file_path, start_block, num_blocks)?;

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
    let mut buffer = [0u8; 512];

    for _block_idx in start_block..end_block {
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
        let battery_value = data_block.get_battery_voltage();

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
            temps.resize(temps.len() + sample_count, temp_value);
        }
        if let Some(ref mut lights) = all_light_values {
            lights.resize(lights.len() + sample_count, light_value);
        }
        if let Some(ref mut batteries) = all_battery_levels {
            batteries.resize(batteries.len() + sample_count, battery_value);
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

fn read_cwa_data_resampled_streaming(
    file_path: &str,
    start_block: Option<usize>,
    num_blocks: Option<usize>,
    parse_options: CwaParsingOptions,
    resample_options: ResampleOptions,
    time_range: TimeRangeOptions,
) -> Result<CwaDataResult, CwaError> {
    let (mut file, start_block, end_block, initial_previous_packet_end) =
        open_cwa_data_blocks(file_path, start_block, num_blocks)?;

    let mut previous_packet_end: Option<f64> = initial_previous_packet_end;
    let mut buffer = [0u8; 512];
    let mut resampler: Option<StreamingResampler> = None;

    'block_loop: for _block_idx in start_block..end_block {
        match file.read_exact(&mut buffer) {
            Ok(_) => {}
            Err(_) => break,
        }

        let data_block = CwaDataBlock::from_buffer(&buffer)?;
        if data_block.sample_rate == 0 {
            return Err("Old CWA format packets are not supported".into());
        }
        if data_block.sample_count == 0 {
            continue;
        }

        let samples = data_block.parse_samples(&parse_options)?;
        let sample_count = samples.len();
        let (timestamps, packet_end) = calculate_sample_timestamps_with_prev_end(
            &data_block,
            sample_count,
            previous_packet_end,
        )?;
        previous_packet_end = Some(packet_end);

        let temp_value = data_block.get_temperature_celsius();
        let light_value = data_block.get_light_calibrated();
        let battery_value = data_block.get_battery_voltage();

        if resampler.is_none() {
            resampler = Some(StreamingResampler::new(
                &parse_options,
                resample_options,
                time_range,
            )?);
        }
        let state = resampler.as_mut().expect("resampler initialized");

        for i in 0..sample_count {
            let ts_seconds = timestamps[i] as f64 / 1_000_000.0;
            state.push_sample(
                ts_seconds,
                &samples[i],
                temp_value,
                light_value,
                battery_value,
            );
            if state.is_done() {
                break 'block_loop;
            }
        }
    }

    let state = resampler.ok_or("No valid sample data found in the specified range")?;
    state.into_result()
}

fn filter_data_by_time_range(
    data: CwaDataResult,
    range: TimeRangeOptions,
) -> Result<CwaDataResult, CwaError> {
    if !range.has_bounds() {
        return Ok(data);
    }
    range.validate()?;

    let start = range.start_time_seconds;
    let end = range.end_time_seconds;

    let mut keep_indices = Vec::with_capacity(data.timestamps.len());
    for (idx, ts) in data.timestamps.iter().enumerate() {
        let ts_seconds = *ts as f64 / 1_000_000.0;
        if start.is_some_and(|s| ts_seconds < s) {
            continue;
        }
        if end.is_some_and(|e| ts_seconds >= e) {
            continue;
        }
        keep_indices.push(idx);
    }

    if keep_indices.is_empty() {
        return Err("No samples remain after applying time range".into());
    }

    let filter_f32 = |src: Vec<f32>| -> Vec<f32> { keep_indices.iter().map(|&i| src[i]).collect() };

    let timestamps = keep_indices.iter().map(|&i| data.timestamps[i]).collect();
    let acc_x = filter_f32(data.acc_x);
    let acc_y = filter_f32(data.acc_y);
    let acc_z = filter_f32(data.acc_z);
    let gyro_x = filter_f32(data.gyro_x);
    let gyro_y = filter_f32(data.gyro_y);
    let gyro_z = filter_f32(data.gyro_z);

    let mag_x = data
        .mag_x
        .map(|src| keep_indices.iter().map(|&i| src[i]).collect());
    let mag_y = data
        .mag_y
        .map(|src| keep_indices.iter().map(|&i| src[i]).collect());
    let mag_z = data
        .mag_z
        .map(|src| keep_indices.iter().map(|&i| src[i]).collect());
    let temperatures = data
        .temperatures
        .map(|src| keep_indices.iter().map(|&i| src[i]).collect());
    let light_values = data
        .light_values
        .map(|src| keep_indices.iter().map(|&i| src[i]).collect());
    let battery_levels = data
        .battery_levels
        .map(|src| keep_indices.iter().map(|&i| src[i]).collect());

    Ok(CwaDataResult {
        timestamps,
        acc_x,
        acc_y,
        acc_z,
        gyro_x,
        gyro_y,
        gyro_z,
        mag_x,
        mag_y,
        mag_z,
        temperatures,
        light_values,
        battery_levels,
    })
}

fn cubic_lagrange_4pt(t: f64, x: [f64; 4], y: [f64; 4]) -> Option<f64> {
    let d0 = (x[0] - x[1]) * (x[0] - x[2]) * (x[0] - x[3]);
    let d1 = (x[1] - x[0]) * (x[1] - x[2]) * (x[1] - x[3]);
    let d2 = (x[2] - x[0]) * (x[2] - x[1]) * (x[2] - x[3]);
    let d3 = (x[3] - x[0]) * (x[3] - x[1]) * (x[3] - x[2]);

    if d0.abs() < 1e-12 || d1.abs() < 1e-12 || d2.abs() < 1e-12 || d3.abs() < 1e-12 {
        return None;
    }

    let l0 = ((t - x[1]) * (t - x[2]) * (t - x[3])) / d0;
    let l1 = ((t - x[0]) * (t - x[2]) * (t - x[3])) / d1;
    let l2 = ((t - x[0]) * (t - x[1]) * (t - x[3])) / d2;
    let l3 = ((t - x[0]) * (t - x[1]) * (t - x[2])) / d3;

    Some(y[0] * l0 + y[1] * l1 + y[2] * l2 + y[3] * l3)
}

/// Calculate timestamps for each sample in a data block
#[allow(dead_code)]
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

fn csv_header(options: &CwaParsingOptions) -> Vec<&'static str> {
    let mut header = vec![
        "time", "acc_x", "acc_y", "acc_z", "gyro_x", "gyro_y", "gyro_z",
    ];
    if options.include_magnetometer {
        header.push("mag_x");
        header.push("mag_y");
        header.push("mag_z");
    }
    if options.include_temperature {
        header.push("temperature");
    }
    if options.include_light {
        header.push("light");
    }
    if options.include_battery {
        header.push("battery");
    }
    header
}

fn write_csv_row<W: std::io::Write>(
    writer: &mut csv::Writer<W>,
    row_fields: &mut [String],
    options: &CwaParsingOptions,
    row: CsvRowValues,
) -> Result<(), CwaError> {
    for field in row_fields.iter_mut() {
        field.clear();
    }

    let mut col = 0usize;
    write!(
        &mut row_fields[col],
        "{:.4}",
        row.timestamp as f64 / 1_000_000.0
    )
    .unwrap();
    col += 1;
    write!(&mut row_fields[col], "{:.6}", row.acc_x).unwrap();
    col += 1;
    write!(&mut row_fields[col], "{:.6}", row.acc_y).unwrap();
    col += 1;
    write!(&mut row_fields[col], "{:.6}", row.acc_z).unwrap();
    col += 1;
    write!(&mut row_fields[col], "{:.6}", row.gyro_x).unwrap();
    col += 1;
    write!(&mut row_fields[col], "{:.6}", row.gyro_y).unwrap();
    col += 1;
    write!(&mut row_fields[col], "{:.6}", row.gyro_z).unwrap();
    col += 1;

    if options.include_magnetometer {
        write!(&mut row_fields[col], "{:.6}", row.mag_x.unwrap_or(0.0)).unwrap();
        col += 1;
        write!(&mut row_fields[col], "{:.6}", row.mag_y.unwrap_or(0.0)).unwrap();
        col += 1;
        write!(&mut row_fields[col], "{:.6}", row.mag_z.unwrap_or(0.0)).unwrap();
        col += 1;
    }
    if options.include_temperature {
        write!(
            &mut row_fields[col],
            "{:.6}",
            row.temperature
                .ok_or("Temperature requested but unavailable")?
        )
        .unwrap();
        col += 1;
    }
    if options.include_light {
        write!(
            &mut row_fields[col],
            "{:.6}",
            row.light.ok_or("Light requested but unavailable")?
        )
        .unwrap();
        col += 1;
    }
    if options.include_battery {
        write!(
            &mut row_fields[col],
            "{:.6}",
            row.battery.ok_or("Battery requested but unavailable")?
        )
        .unwrap();
    }

    writer.write_record(row_fields.iter().map(String::as_str))?;
    Ok(())
}

fn write_data_result_csv(
    output_path: &str,
    data: &CwaDataResult,
    options: &CwaParsingOptions,
) -> Result<(), CwaError> {
    let output_file = File::create(output_path)?;
    let output_buffer = BufWriter::with_capacity(16 * 1024 * 1024, output_file);
    let mut writer = WriterBuilder::new()
        .has_headers(false)
        .quote_style(csv::QuoteStyle::Never)
        .from_writer(output_buffer);

    let header = csv_header(options);
    writer.write_record(&header)?;

    let field_count = header.len();
    let mut row_fields: Vec<String> = (0..field_count)
        .map(|_| String::with_capacity(32))
        .collect();

    let row_count = data.timestamps.len();
    for i in 0..row_count {
        write_csv_row(
            &mut writer,
            &mut row_fields,
            options,
            CsvRowValues {
                timestamp: data.timestamps[i],
                acc_x: data.acc_x[i],
                acc_y: data.acc_y[i],
                acc_z: data.acc_z[i],
                gyro_x: data.gyro_x[i],
                gyro_y: data.gyro_y[i],
                gyro_z: data.gyro_z[i],
                mag_x: data.mag_x.as_ref().map(|values| values[i]),
                mag_y: data.mag_y.as_ref().map(|values| values[i]),
                mag_z: data.mag_z.as_ref().map(|values| values[i]),
                temperature: data.temperatures.as_ref().map(|values| values[i]),
                light: data.light_values.as_ref().map(|values| values[i]),
                battery: data.battery_levels.as_ref().map(|values| values[i]),
            },
        )?;
    }

    writer.flush()?;
    Ok(())
}

fn parse_time_range_options(
    range_start_time: Option<f64>,
    range_end_time: Option<f64>,
) -> PyResult<TimeRangeOptions> {
    let range = TimeRangeOptions {
        start_time_seconds: range_start_time,
        end_time_seconds: range_end_time,
    };
    range
        .validate()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    Ok(range)
}

fn parse_resample_options(
    resample_hz: Option<f64>,
    resample_method: &str,
) -> PyResult<Option<ResampleOptions>> {
    match resample_hz {
        Some(target_hz) => Ok(Some(
            ResampleOptions::parse(target_hz, resample_method)
                .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?,
        )),
        None => Ok(None),
    }
}

/// Python interface for reading CWA data.
///
/// Optional resampling parameters:
/// - `resample_hz`: when set, data is resampled onto a regular grid.
/// - `resample_method`: currently supports `"cubic"`.
/// - `range_start_time` / `range_end_time`: optional epoch-second window filter.
#[pyfunction]
#[pyo3(signature = (
    file_path,
    start_block=None,
    num_blocks=None,
    include_magnetometer=true,
    include_temperature=true,
    include_light=true,
    include_battery=true,
    resample_hz=None,
    resample_method="cubic",
    range_start_time=None,
    range_end_time=None
))]
#[allow(clippy::too_many_arguments)]
pub fn read_cwa_file(
    py: Python,
    file_path: &str,
    start_block: Option<usize>,
    num_blocks: Option<usize>,
    include_magnetometer: bool,
    include_temperature: bool,
    include_light: bool,
    include_battery: bool,
    resample_hz: Option<f64>,
    resample_method: &str,
    range_start_time: Option<f64>,
    range_end_time: Option<f64>,
) -> PyResult<Py<PyAny>> {
    let options = CwaParsingOptions {
        include_magnetometer,
        include_temperature,
        include_light,
        include_battery,
    };

    let time_range = parse_time_range_options(range_start_time, range_end_time)?;
    let resample_options = parse_resample_options(resample_hz, resample_method)?;

    match if let Some(resample) = resample_options {
        read_cwa_data_resampled_streaming(
            file_path,
            start_block,
            num_blocks,
            options,
            resample,
            time_range,
        )
    } else {
        read_cwa_data(file_path, start_block, num_blocks, Some(options))
            .and_then(|data| filter_data_by_time_range(data, time_range))
    } {
        Ok(data) => create_python_dict_numpy(py, data),
        Err(e) => Err(PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(
            e.to_string(),
        )),
    }
}

#[pyfunction]
/// Write CWA samples directly to CSV.
///
/// Supports the same optional resampling and time-range controls as `read_cwa_file`.
#[pyo3(signature = (
    file_path,
    output_path,
    start_block=None,
    num_blocks=None,
    include_magnetometer=true,
    include_temperature=false,
    include_light=false,
    include_battery=false,
    resample_hz=None,
    resample_method="cubic",
    range_start_time=None,
    range_end_time=None
))]
#[allow(clippy::too_many_arguments)]
pub fn write_cwa_csv(
    file_path: &str,
    output_path: &str,
    start_block: Option<usize>,
    num_blocks: Option<usize>,
    include_magnetometer: bool,
    include_temperature: bool,
    include_light: bool,
    include_battery: bool,
    resample_hz: Option<f64>,
    resample_method: &str,
    range_start_time: Option<f64>,
    range_end_time: Option<f64>,
) -> PyResult<()> {
    let options = CwaParsingOptions {
        include_magnetometer,
        include_temperature,
        include_light,
        include_battery,
    };

    let time_range = parse_time_range_options(range_start_time, range_end_time)?;
    let resample_options = parse_resample_options(resample_hz, resample_method)?;

    write_cwa_csv_data(
        file_path,
        output_path,
        start_block,
        num_blocks,
        options,
        resample_options,
        time_range,
    )
    .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

fn write_cwa_csv_data(
    file_path: &str,
    output_path: &str,
    start_block: Option<usize>,
    num_blocks: Option<usize>,
    options: CwaParsingOptions,
    resample_options: Option<ResampleOptions>,
    time_range: TimeRangeOptions,
) -> Result<(), CwaError> {
    time_range.validate()?;

    if let Some(resample) = resample_options {
        let data = read_cwa_data_resampled_streaming(
            file_path,
            start_block,
            num_blocks,
            options.clone(),
            resample,
            time_range,
        )?;
        return write_data_result_csv(output_path, &data, &options);
    }

    if time_range.has_bounds() {
        let data = read_cwa_data(file_path, start_block, num_blocks, Some(options.clone()))?;
        let data = filter_data_by_time_range(data, time_range)?;
        return write_data_result_csv(output_path, &data, &options);
    }

    let (mut file, start_block, end_block, initial_previous_packet_end) =
        open_cwa_data_blocks(file_path, start_block, num_blocks)?;

    let output_file = File::create(output_path)?;
    let output_buffer = BufWriter::with_capacity(16 * 1024 * 1024, output_file);
    let mut writer = WriterBuilder::new()
        .has_headers(false)
        .quote_style(csv::QuoteStyle::Never)
        .from_writer(output_buffer);

    let header = csv_header(&options);
    writer.write_record(&header)?;

    let field_count = header.len();
    let mut row_fields: Vec<String> = (0..field_count)
        .map(|_| String::with_capacity(32))
        .collect();

    let mut previous_packet_end: Option<f64> = initial_previous_packet_end;
    let mut buffer = [0u8; 512];
    for _block_idx in start_block..end_block {
        match file.read_exact(&mut buffer) {
            Ok(_) => {}
            Err(_) => break,
        }

        let data_block = CwaDataBlock::from_buffer(&buffer)?;
        if data_block.sample_rate == 0 {
            return Err("Old CWA format packets are not supported".into());
        }
        if data_block.sample_count == 0 {
            continue;
        }

        let samples = data_block.parse_samples(&options)?;
        let sample_count = samples.len();
        let (timestamps, packet_end) = calculate_sample_timestamps_with_prev_end(
            &data_block,
            sample_count,
            previous_packet_end,
        )?;
        previous_packet_end = Some(packet_end);

        let temp_value = data_block.get_temperature_celsius();
        let light_value = data_block.get_light_calibrated();
        let battery_value = data_block.get_battery_voltage();

        for i in 0..sample_count {
            let sample = &samples[i];
            write_csv_row(
                &mut writer,
                &mut row_fields,
                &options,
                CsvRowValues {
                    timestamp: timestamps[i],
                    acc_x: sample.acc_x,
                    acc_y: sample.acc_y,
                    acc_z: sample.acc_z,
                    gyro_x: sample.gyro_x,
                    gyro_y: sample.gyro_y,
                    gyro_z: sample.gyro_z,
                    mag_x: sample.mag_x,
                    mag_y: sample.mag_y,
                    mag_z: sample.mag_z,
                    temperature: Some(temp_value),
                    light: Some(light_value),
                    battery: Some(battery_value),
                },
            )?;
        }
    }

    writer.flush()?;
    Ok(())
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

    fn sample_with_acc_x(acc_x: f32) -> SampleData {
        SampleData {
            acc_x,
            acc_y: 0.0,
            acc_z: 0.0,
            gyro_x: 0.0,
            gyro_y: 0.0,
            gyro_z: 0.0,
            mag_x: None,
            mag_y: None,
            mag_z: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
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

    #[test]
    fn streaming_resampler_waits_for_cubic_lookahead() {
        let parse_options = CwaParsingOptions {
            include_magnetometer: false,
            include_temperature: false,
            include_light: false,
            include_battery: false,
        };
        let mut resampler = StreamingResampler::new(
            &parse_options,
            ResampleOptions { target_hz: 2.0 },
            TimeRangeOptions {
                start_time_seconds: Some(1.5),
                end_time_seconds: Some(2.0),
            },
        )
        .expect("resampler");

        for t in [0.0_f64, 1.0, 2.0] {
            resampler.push_sample(t, &sample_with_acc_x((t * t * t) as f32), 0.0, 0.0, 0.0);
        }
        assert!(resampler.result.timestamps.is_empty());

        resampler.push_sample(3.0, &sample_with_acc_x(27.0), 0.0, 0.0, 0.0);
        let result = resampler.into_result().expect("result");

        assert_eq!(result.timestamps, vec![1_500_000]);
        assert!((result.acc_x[0] - 3.375).abs() < 1e-6);
    }
}
