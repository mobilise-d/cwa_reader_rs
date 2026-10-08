use crate::errors::CwaError;
use crate::packet::{cwa_timestamp, packet_meta, PacketMeta};
use chrono::{DateTime, Utc};
use csv::WriterBuilder;
use std::collections::VecDeque;
use std::fmt::Write as _;

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
pub enum CutConfig {
    Full,
    Blocks {
        start: Option<usize>,
        end: Option<usize>,
    },
    Seconds {
        start: Option<f64>,
        end: Option<f64>,
    },
}

impl CutConfig {
    pub fn validate(&self) -> Result<(), CwaError> {
        match self {
            CutConfig::Full => Ok(()),
            CutConfig::Blocks { start, end } => {
                if let (Some(start), Some(end)) = (start, end) {
                    if end <= start {
                        return Err("blocks end must be greater than start".into());
                    }
                }
                Ok(())
            }
            CutConfig::Seconds { start, end } => {
                for value in [*start, *end].into_iter().flatten() {
                    if !value.is_finite() {
                        return Err("seconds cut values must be finite".into());
                    }
                    if value < 0.0 {
                        return Err("seconds cut values must be >= 0".into());
                    }
                }

                if let (Some(start), Some(end)) = (start, end) {
                    if end <= start {
                        return Err("seconds end must be greater than start".into());
                    }
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ResampleOptions {
    target_hz: f64,
}

impl ResampleOptions {
    pub fn parse(target_hz: f64, method: &str) -> Result<Self, CwaError> {
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

// File offsets remain 64-bit even when the target's pointers are 32-bit.
pub(crate) fn data_block_offset(block_index: u64) -> Result<u64, CwaError> {
    block_index
        .checked_mul(512)
        .and_then(|offset| offset.checked_add(1024))
        .ok_or_else(|| "CWA data block byte offset overflow".into())
}

fn checked_sample_count(current: usize, additional: usize) -> Result<usize, CwaError> {
    let count = current
        .checked_add(additional)
        .ok_or("CWA sample count overflow")?;
    // Timestamps are the largest per-sample element (i64); Rust allocations
    // cannot exceed isize::MAX bytes even when usize can represent the count.
    if count > (isize::MAX as usize) / std::mem::size_of::<i64>() {
        return Err("CWA sample arrays exceed this target's addressable size".into());
    }
    Ok(count)
}

fn reserve_column<T>(column: &mut Vec<T>, additional: usize) -> Result<(), CwaError> {
    let max_elements = (isize::MAX as usize) / std::mem::size_of::<T>();
    let required = column
        .len()
        .checked_add(additional)
        .ok_or("CWA column capacity overflow")?;
    if required > max_elements {
        return Err("CWA sample arrays exceed this target's addressable size".into());
    }
    // Avoid amortized doubling past the address limit while retaining ordinary
    // geometric growth for recordings that fit comfortably in memory.
    let reservation = if column.capacity() > max_elements / 2 {
        column.try_reserve_exact(additional)
    } else {
        column.try_reserve(additional)
    };
    reservation.map_err(|e| format!("Cannot allocate CWA sample column: {e}").into())
}

pub(crate) fn resolve_block_range(
    file_size: u64,
    start_block: Option<usize>,
    num_blocks: Option<usize>,
) -> Result<(usize, usize), CwaError> {
    if file_size < 1024 {
        return Err("File too small to be a valid CWA file".into());
    }

    let data_size = file_size - 1024;
    if !data_size.is_multiple_of(512) {
        return Err("Incomplete CWA data block".into());
    }
    let total_blocks = usize::try_from(data_size / 512)
        .map_err(|_| "CWA block count exceeds this target's addressable size")?;
    let start_block = start_block.unwrap_or(0);
    if start_block >= total_blocks {
        return Err("Start block is beyond file size".into());
    }

    let num_blocks = num_blocks.unwrap_or(total_blocks - start_block);
    let end_block = std::cmp::min(start_block.saturating_add(num_blocks), total_blocks);
    Ok((start_block, end_block))
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
        cwa_timestamp(self.timestamp)
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
                gyro_x: None,
                gyro_y: None,
                gyro_z: None,
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
                gyro_x: None,
                gyro_y: None,
                gyro_z: None,
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
                gyro_x: Some(gx),
                gyro_y: Some(gy),
                gyro_z: Some(gz),
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
                gyro_x: Some(gx),
                gyro_y: Some(gy),
                gyro_z: Some(gz),
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
    gyro_x: Option<f32>,
    gyro_y: Option<f32>,
    gyro_z: Option<f32>,
    mag_x: Option<f32>,
    mag_y: Option<f32>,
    mag_z: Option<f32>,
}

#[derive(Debug, PartialEq)]
pub struct CwaDataResult {
    /// Integer microseconds in the device clock, or UTC after an explicit fixed offset.
    pub timestamps: Vec<i64>,
    // Store data in columnar format to eliminate first copy
    pub acc_x: Vec<f32>,
    pub acc_y: Vec<f32>,
    pub acc_z: Vec<f32>,
    pub gyro_x: Option<Vec<f32>>,
    pub gyro_y: Option<Vec<f32>>,
    pub gyro_z: Option<Vec<f32>>,
    pub mag_x: Option<Vec<f32>>,
    pub mag_y: Option<Vec<f32>>,
    pub mag_z: Option<Vec<f32>>,
    pub temperatures: Option<Vec<f32>>,
    pub light_values: Option<Vec<f32>>,
    pub battery_levels: Option<Vec<f32>>,
}

pub(crate) fn empty_result(options: &CwaParsingOptions) -> CwaDataResult {
    CwaDataResult {
        timestamps: Vec::new(),
        acc_x: Vec::new(),
        acc_y: Vec::new(),
        acc_z: Vec::new(),
        gyro_x: None,
        gyro_y: None,
        gyro_z: None,
        mag_x: None,
        mag_y: None,
        mag_z: None,
        temperatures: options.include_temperature.then(Vec::new),
        light_values: options.include_light.then(Vec::new),
        battery_levels: options.include_battery.then(Vec::new),
    }
}

pub(crate) fn decode_loaded_batch(
    plan: &crate::batch::BatchDescriptor,
    bytes: &[u8],
) -> Result<crate::batch::BatchResult, CwaError> {
    if bytes.len()
        != plan
            .loaded_packets
            .len()
            .checked_mul(512)
            .ok_or("CWA batch byte count overflow")?
    {
        return Err("Incomplete preloaded CWA batch".into());
    }
    let options = &plan.options.channels;
    let mut source = Vec::new();
    let mut previous_end = plan.previous_packet_end;
    let mut origin = plan.recording_origin_seconds;
    let mut first_domain = plan.first_domain_sample_us;
    let mut owned_first = None;
    let mut owned_end = None;
    let mut observed = SensorChannels::default();
    for (index, packet) in bytes.chunks_exact(512).enumerate() {
        let index = plan.loaded_packets.start + index;
        if index >= plan.selected_packets.end {
            break;
        }
        let buffer: &[u8; 512] = packet.try_into().expect("complete packet");
        let Some(meta) = packet_meta(buffer)? else {
            continue;
        };
        if index < plan.selected_packets.start {
            previous_end = Some(meta.natural_bounds().1);
            continue;
        }
        let block = CwaDataBlock::from_buffer(buffer)?;
        let samples = block.parse_samples(options)?;
        let (timestamps, end) =
            calculate_sample_timestamps_with_prev_end(&block, samples.len(), previous_end)?;
        previous_end = Some(end);
        if index < plan.selected_packets.start {
            continue;
        }
        origin.get_or_insert(timestamps[0] as f64 / 1_000_000.0);
        first_domain.get_or_insert(timestamps[0]);
        if plan.owned_packets.contains(&index) {
            owned_first.get_or_insert(timestamps[0] as f64 / 1_000_000.0);
        }
        if index >= plan.owned_packets.end {
            owned_end.get_or_insert(timestamps[0] as f64 / 1_000_000.0);
        }
        for (timestamp, sample) in timestamps.into_iter().zip(samples) {
            let time_seconds = timestamp as f64 / 1_000_000.0;
            if plan.owned_packets.contains(&index)
                && in_batch_time_range(plan, origin, time_seconds)
            {
                observed.gyro |= sample.gyro_x.is_some();
                observed.magnetometer |= sample.mag_x.is_some();
            }
            reserve_column(&mut source, 1)?;
            source.push((
                index,
                timestamp,
                TimedSample {
                    time_seconds,
                    sample,
                    temperature: block.get_temperature_celsius(),
                    light: block.get_light_calibrated(),
                    battery: block.get_battery_voltage(),
                },
            ));
        }
    }
    let mut grid_origin = plan.grid_origin_seconds;
    let mut result = empty_result(options);
    if let Some(resample) = plan.options.resample {
        if let Some((_, _, first)) = source.first() {
            let start = match plan.options.cut {
                CutConfig::Seconds {
                    start: Some(start), ..
                } => first
                    .time_seconds
                    .max(origin.expect("source origin") + start),
                _ => first.time_seconds,
            };
            let anchor = *grid_origin.get_or_insert(start);
            if let Some(lower) = owned_first {
                let step_ms = 1000.0 / resample.target_hz;
                let target_start_ms = anchor * 1000.0;
                let lower = match plan.options.cut {
                    CutConfig::Seconds {
                        start: Some(start), ..
                    } => lower.max(origin.expect("source origin") + start),
                    _ => lower,
                };
                let mut target_index = (((lower * 1000.0 - target_start_ms) / step_ms)
                    .floor()
                    .max(0.0)) as u64;
                let target_time = |index: u64| (target_start_ms + index as f64 * step_ms) / 1000.0;
                while target_time(target_index) < lower {
                    target_index = target_index
                        .checked_add(1)
                        .ok_or("CWA resampling target counter overflow")?;
                }
                let last_time = source.last().expect("source present").2.time_seconds;
                let domain_end = plan.loaded_packets.end >= plan.selected_packets.end;
                if owned_end.is_none()
                    && !domain_end
                    && in_batch_time_range(plan, origin, target_time(target_index))
                {
                    return Err(plan.insufficient(
                        crate::errors::ContextSide::Right,
                        "next ownership boundary is outside the loaded packets",
                    ));
                }
                let mut interpolator = LoadedInterpolator {
                    samples: source.iter().map(|(_, _, sample)| sample.clone()).collect(),
                    acc_left: 0,
                    result: empty_result(options),
                };
                loop {
                    let target = target_time(target_index);
                    if owned_end.is_some_and(|end| target >= end)
                        || !in_batch_time_range(plan, origin, target)
                    {
                        break;
                    }
                    if target > last_time {
                        if domain_end {
                            break;
                        }
                        return Err(plan.insufficient(
                            crate::errors::ContextSide::Right,
                            "target bracket is outside the loaded packets",
                        ));
                    }
                    interpolator.acc_left =
                        interpolator.advance_left(interpolator.acc_left, target);
                    let left = interpolator.acc_left;
                    if !interpolator.has_bracket(left, target) {
                        break;
                    }
                    if left == 0
                        && first_domain != source.first().map(|(_, timestamp, _)| *timestamp)
                    {
                        return Err(plan.insufficient(
                            crate::errors::ContextSide::Left,
                            "four original samples require more left context",
                        ));
                    }
                    if left > 0 && left + 2 >= interpolator.samples.len() && !domain_end {
                        return Err(plan.insufficient(
                            crate::errors::ContextSide::Right,
                            "four original samples require more right context",
                        ));
                    }
                    interpolator.emit_one(target)?;
                    target_index = target_index
                        .checked_add(1)
                        .ok_or("CWA resampling target counter overflow")?;
                }
                result = interpolator.result;
                for (column, present) in [
                    (&mut result.gyro_x, observed.gyro),
                    (&mut result.gyro_y, observed.gyro),
                    (&mut result.gyro_z, observed.gyro),
                    (&mut result.mag_x, observed.magnetometer),
                    (&mut result.mag_y, observed.magnetometer),
                    (&mut result.mag_z, observed.magnetometer),
                ] {
                    if present {
                        ensure_sensor_column(column, result.timestamps.len())?;
                    }
                }
            }
        }
    } else {
        for (index, timestamp, sample) in source {
            if plan.owned_packets.contains(&index)
                && in_batch_time_range(plan, origin, sample.time_seconds)
            {
                append_original_sample(&mut result, timestamp, &sample)?;
            }
        }
    }
    if let Some(offset) = plan.options.fixed_utc_offset_us {
        for timestamp in &mut result.timestamps {
            *timestamp = timestamp
                .checked_sub(offset)
                .ok_or("Timestamp overflow after fixed UTC offset")?;
        }
    }
    Ok(crate::batch::BatchResult {
        data: result,
        recording_origin_seconds: origin,
        grid_origin_seconds: grid_origin,
        first_domain_sample_us: first_domain,
    })
}

fn in_batch_time_range(
    plan: &crate::batch::BatchDescriptor,
    origin: Option<f64>,
    time: f64,
) -> bool {
    match plan.options.cut {
        CutConfig::Seconds { start, end } => {
            let origin = origin.expect("source origin");
            !start.is_some_and(|s| time < origin + s) && !end.is_some_and(|e| time >= origin + e)
        }
        _ => true,
    }
}

fn append_original_sample(
    result: &mut CwaDataResult,
    timestamp: i64,
    sample: &TimedSample,
) -> Result<(), CwaError> {
    checked_sample_count(result.timestamps.len(), 1)?;
    reserve_column(&mut result.timestamps, 1)?;
    for column in [&mut result.acc_x, &mut result.acc_y, &mut result.acc_z] {
        reserve_column(column, 1)?;
    }
    result.timestamps.push(timestamp);
    result.acc_x.push(sample.sample.acc_x);
    result.acc_y.push(sample.sample.acc_y);
    result.acc_z.push(sample.sample.acc_z);
    let previous_len = result.timestamps.len() - 1;
    for (column, value) in [
        (&mut result.gyro_x, sample.sample.gyro_x),
        (&mut result.gyro_y, sample.sample.gyro_y),
        (&mut result.gyro_z, sample.sample.gyro_z),
        (&mut result.mag_x, sample.sample.mag_x),
        (&mut result.mag_y, sample.sample.mag_y),
        (&mut result.mag_z, sample.sample.mag_z),
    ] {
        append_sensor_value(column, value, previous_len)?;
    }
    for (column, value) in [
        (&mut result.temperatures, sample.temperature),
        (&mut result.light_values, sample.light),
        (&mut result.battery_levels, sample.battery),
    ] {
        if let Some(values) = column {
            reserve_column(values, 1)?;
            values.push(value);
        }
    }
    Ok(())
}

/// Allocate a sensor column only once the sensor occurs in a sample.
/// Missing samples in a present channel are NaN, never fabricated zeroes.
fn ensure_sensor_column(
    column: &mut Option<Vec<f32>>,
    previous_len: usize,
) -> Result<(), CwaError> {
    if column.is_none() {
        let mut values = Vec::new();
        reserve_column(&mut values, previous_len)?;
        values.resize(previous_len, f32::NAN);
        *column = Some(values);
    }
    Ok(())
}

fn append_sensor_value(
    column: &mut Option<Vec<f32>>,
    value: Option<f32>,
    previous_len: usize,
) -> Result<(), CwaError> {
    if value.is_some() {
        ensure_sensor_column(column, previous_len)?;
    }
    if let Some(values) = column {
        reserve_column(values, 1)?;
        values.push(value.unwrap_or(f32::NAN));
    }
    Ok(())
}

#[derive(Clone, Copy, Default)]
pub(crate) struct SensorChannels {
    pub(crate) gyro: bool,
    pub(crate) magnetometer: bool,
}

impl CwaDataResult {
    pub(crate) fn sensor_channels(&self) -> SensorChannels {
        SensorChannels {
            gyro: self.gyro_x.is_some(),
            magnetometer: self.mag_x.is_some(),
        }
    }
}

#[derive(Clone, Copy)]
struct CsvRowValues {
    timestamp: i64,
    acc_x: f32,
    acc_y: f32,
    acc_z: f32,
    gyro_x: Option<f32>,
    gyro_y: Option<f32>,
    gyro_z: Option<f32>,
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

struct LoadedInterpolator {
    samples: VecDeque<TimedSample>,
    acc_left: usize,
    result: CwaDataResult,
}
impl LoadedInterpolator {
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

            if [y0, y1, y2, y3].iter().all(|value| !value.is_nan()) {
                if let Some(v) = cubic_lagrange_4pt(target_time, [x0, x1, x2, x3], [y0, y1, y2, y3])
                {
                    return v as f32;
                }
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

    fn interpolate_sensor<F>(&self, left: usize, target_time: f64, value_fn: F) -> Option<f32>
    where
        F: Fn(&TimedSample) -> Option<f32>,
    {
        for index in [left, left + 1] {
            if target_time == self.sample_time(index) {
                return value_fn(&self.samples[index]);
            }
        }
        let value = self.interpolate_value(left, target_time, |sample| {
            value_fn(sample).unwrap_or(f32::NAN)
        });
        (!value.is_nan()).then_some(value)
    }

    fn emit_one(&mut self, target_time: f64) -> Result<(), CwaError> {
        checked_sample_count(self.result.timestamps.len(), 1)?;
        reserve_column(&mut self.result.timestamps, 1)?;
        for column in [
            &mut self.result.acc_x,
            &mut self.result.acc_y,
            &mut self.result.acc_z,
        ] {
            reserve_column(column, 1)?;
        }
        for column in [
            &mut self.result.temperatures,
            &mut self.result.light_values,
            &mut self.result.battery_levels,
        ]
        .into_iter()
        .flatten()
        {
            reserve_column(column, 1)?;
        }
        let acc_left = self.acc_left;
        let gyro_left = acc_left;

        let out_acc_x = self.interpolate_value(acc_left, target_time, |s| s.sample.acc_x);
        let out_acc_y = self.interpolate_value(acc_left, target_time, |s| s.sample.acc_y);
        let out_acc_z = self.interpolate_value(acc_left, target_time, |s| s.sample.acc_z);
        let out_gyro_x = self.interpolate_sensor(gyro_left, target_time, |s| s.sample.gyro_x);
        let out_gyro_y = self.interpolate_sensor(gyro_left, target_time, |s| s.sample.gyro_y);
        let out_gyro_z = self.interpolate_sensor(gyro_left, target_time, |s| s.sample.gyro_z);
        let out_mag_x = self.interpolate_sensor(acc_left, target_time, |s| s.sample.mag_x);
        let out_mag_y = self.interpolate_sensor(acc_left, target_time, |s| s.sample.mag_y);
        let out_mag_z = self.interpolate_sensor(acc_left, target_time, |s| s.sample.mag_z);
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
        let previous_len = self.result.timestamps.len() - 1;
        append_sensor_value(&mut self.result.gyro_x, out_gyro_x, previous_len)?;
        append_sensor_value(&mut self.result.gyro_y, out_gyro_y, previous_len)?;
        append_sensor_value(&mut self.result.gyro_z, out_gyro_z, previous_len)?;
        append_sensor_value(&mut self.result.mag_x, out_mag_x, previous_len)?;
        append_sensor_value(&mut self.result.mag_y, out_mag_y, previous_len)?;
        append_sensor_value(&mut self.result.mag_z, out_mag_z, previous_len)?;

        if let Some(ref mut temperatures) = self.result.temperatures {
            temperatures.push(out_temperature.expect("temperature computed"));
        }
        if let Some(ref mut lights) = self.result.light_values {
            lights.push(out_light.expect("light computed"));
        }
        if let Some(ref mut batteries) = self.result.battery_levels {
            batteries.push(out_battery.expect("battery computed"));
        }
        Ok(())
    }
}

pub(crate) fn append_batch(
    output: &mut CwaDataResult,
    mut batch: CwaDataResult,
) -> Result<(), CwaError> {
    let previous_len = output.timestamps.len();
    let added = batch.timestamps.len();
    checked_sample_count(previous_len, added)?;
    reserve_column(&mut output.timestamps, added)?;
    output.timestamps.append(&mut batch.timestamps);
    for (out, values) in [
        (&mut output.acc_x, &mut batch.acc_x),
        (&mut output.acc_y, &mut batch.acc_y),
        (&mut output.acc_z, &mut batch.acc_z),
    ] {
        reserve_column(out, added)?;
        out.append(values);
    }
    for (out, values) in [
        (&mut output.gyro_x, batch.gyro_x),
        (&mut output.gyro_y, batch.gyro_y),
        (&mut output.gyro_z, batch.gyro_z),
        (&mut output.mag_x, batch.mag_x),
        (&mut output.mag_y, batch.mag_y),
        (&mut output.mag_z, batch.mag_z),
        (&mut output.temperatures, batch.temperatures),
        (&mut output.light_values, batch.light_values),
        (&mut output.battery_levels, batch.battery_levels),
    ] {
        if values.is_some() {
            ensure_sensor_column(out, previous_len)?;
        }
        if let Some(out) = out {
            reserve_column(out, added)?;
            match values {
                Some(values) => out.extend(values),
                None => out.resize(previous_len + added, f32::NAN),
            }
        }
    }
    Ok(())
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
    if data_block.get_block_timestamp().is_none() {
        return Err("Invalid block timestamp".into());
    }
    Ok(PacketMeta {
        sample_count,
        sample_rate: data_block.sample_rate,
        timestamp: data_block.timestamp,
        timestamp_offset: data_block.timestamp_offset,
    }
    .natural_bounds())
}

fn csv_header(options: &CwaParsingOptions, channels: SensorChannels) -> Vec<&'static str> {
    let mut header = vec!["time", "acc_x", "acc_y", "acc_z"];
    if channels.gyro {
        header.extend(["gyro_x", "gyro_y", "gyro_z"]);
    }
    if channels.magnetometer {
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
    channels: SensorChannels,
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
    if channels.gyro {
        write!(
            &mut row_fields[col],
            "{:.6}",
            row.gyro_x.unwrap_or(f32::NAN)
        )
        .unwrap();
        col += 1;
        write!(
            &mut row_fields[col],
            "{:.6}",
            row.gyro_y.unwrap_or(f32::NAN)
        )
        .unwrap();
        col += 1;
        write!(
            &mut row_fields[col],
            "{:.6}",
            row.gyro_z.unwrap_or(f32::NAN)
        )
        .unwrap();
        col += 1;
    }
    if channels.magnetometer {
        write!(&mut row_fields[col], "{:.6}", row.mag_x.unwrap_or(f32::NAN)).unwrap();
        col += 1;
        write!(&mut row_fields[col], "{:.6}", row.mag_y.unwrap_or(f32::NAN)).unwrap();
        col += 1;
        write!(&mut row_fields[col], "{:.6}", row.mag_z.unwrap_or(f32::NAN)).unwrap();
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

pub(crate) fn format_csv_batch(
    output: Vec<u8>,
    data: &CwaDataResult,
    options: &CwaParsingOptions,
    channels: SensorChannels,
    write_header: bool,
) -> Result<Vec<u8>, CwaError> {
    let mut writer = WriterBuilder::new()
        .has_headers(false)
        .quote_style(csv::QuoteStyle::Never)
        .from_writer(output);

    let header = csv_header(options, channels);
    if write_header {
        writer.write_record(&header)?;
    }

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
            channels,
            CsvRowValues {
                timestamp: data.timestamps[i],
                acc_x: data.acc_x[i],
                acc_y: data.acc_y[i],
                acc_z: data.acc_z[i],
                gyro_x: data.gyro_x.as_ref().map(|values| values[i]),
                gyro_y: data.gyro_y.as_ref().map(|values| values[i]),
                gyro_z: data.gyro_z.as_ref().map(|values| values[i]),
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
    writer
        .into_inner()
        .map_err(|error| CwaError::from(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn uploaded_bytes_decode_and_block_cuts_keep_full_read_timestamps() {
        let mut bytes = vec![0u8; 2048];
        bytes[..2].copy_from_slice(b"MD");
        for block in 0..2 {
            let start = 1024 + block * 512;
            let packet = &mut bytes[start..start + 512];
            packet[..2].copy_from_slice(b"AX");
            packet[2..4].copy_from_slice(&508u16.to_le_bytes());
            packet[14..18].copy_from_slice(
                &encode_cwa_timestamp(2012, 1, 1, 0, 0, block as u32 + 1).to_le_bytes(),
            );
            packet[24] = 0x4a;
            packet[25] = 0x32;
            packet[28..30].copy_from_slice(&2u16.to_le_bytes());
            packet[30..32].copy_from_slice(&256i16.to_le_bytes());
        }
        let full = crate::reader::CwaReader::new(std::io::Cursor::new(&bytes))
            .read_data(&crate::reader::CwaReadOptions::default())
            .expect("uploaded recording");
        let cut = crate::reader::CwaReader::new(std::io::Cursor::new(&bytes))
            .read_data(&crate::reader::CwaReadOptions {
                cut: CutConfig::Blocks {
                    start: Some(1),
                    end: Some(2),
                },
                ..Default::default()
            })
            .expect("block cut");
        assert_eq!(full.acc_x, vec![1.0, 0.0, 1.0, 0.0]);
        assert!(full.gyro_x.is_none());
        assert_eq!(cut.timestamps, full.timestamps[2..]);
        assert_eq!(full.timestamps[0], 1_325_376_001_000_000);
        let timing = crate::header::scan_data_timing_from_reader(&mut std::io::Cursor::new(&bytes))
            .expect("timing metadata");
        assert_eq!(timing.sample_count, 4);
        assert_eq!(timing.first_sample_us, Some(full.timestamps[0]));
        assert_eq!(timing.last_sample_us, full.timestamps.last().copied());
    }

    #[test]
    fn block_offsets_and_sample_counts_reject_overflow_without_allocating() {
        assert_eq!(
            data_block_offset(8_388_608).expect("4 GiB offset"),
            4_294_968_320
        );
        assert!(data_block_offset(u64::MAX).is_err());
        assert_eq!(checked_sample_count(7, 2).expect("small recording"), 9);
        assert!(checked_sample_count(usize::MAX, 1).is_err());
        let mut timestamps: Vec<i64> = Vec::new();
        assert!(reserve_column(&mut timestamps, usize::MAX).is_err());
        assert!(timestamps.is_empty());
        assert!(checked_sample_count((isize::MAX as usize) / 8, 1).is_err());
        #[cfg(target_pointer_width = "32")]
        assert!(resolve_block_range(2_199_023_256_576, None, None).is_err());
    }

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
}
