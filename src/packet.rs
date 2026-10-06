use crate::errors::CwaError;
use chrono::{DateTime, LocalResult, TimeZone, Utc};
use std::io::Read;

pub(crate) struct PacketMeta {
    pub sample_count: usize,
    pub sample_rate: u8,
    pub timestamp: u32,
    pub timestamp_offset: i16,
}

pub(crate) fn cwa_timestamp(value: u32) -> Option<DateTime<Utc>> {
    // CWA stores a device clock without a timezone. UTC is only the arithmetic
    // basis here; public outputs interpret it using utc_offset.
    if value == 0 || value == u32::MAX {
        return None;
    }
    let year = ((value >> 26) & 0x3f) as i32 + 2000;
    let month = (value >> 22) & 0x0f;
    let day = (value >> 17) & 0x1f;
    let hours = (value >> 12) & 0x1f;
    let mins = (value >> 6) & 0x3f;
    let secs = value & 0x3f;
    match Utc.with_ymd_and_hms(year, month, day, hours, mins, secs) {
        LocalResult::Single(time) => Some(time),
        _ => None,
    }
}

pub(crate) fn read_sector<R: Read>(reader: &mut R) -> Result<Option<[u8; 512]>, CwaError> {
    let mut buffer = [0u8; 512];
    if reader.read(&mut buffer[..1])? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut buffer[1..])?;
    Ok(Some(buffer))
}

pub(crate) fn packet_meta(buffer: &[u8; 512]) -> Result<Option<PacketMeta>, CwaError> {
    if &buffer[..2] != b"AX" {
        return Ok(None);
    }
    let sample_count = u16::from_le_bytes([buffer[28], buffer[29]]) as usize;
    if sample_count == 0 {
        return Ok(None);
    }
    let sample_rate = buffer[24];
    if sample_rate == 0 {
        return Err("Old CWA format packets are not supported".into());
    }
    let axes = buffer[25] >> 4;
    let packing = buffer[25] & 0x0f;
    let bytes_per_sample = match (axes, packing) {
        (3, 0) => 4,
        (3, 2) => 6,
        (6, 2) => 12,
        (9, 2) => 18,
        _ => {
            return Err(format!("Unsupported sample format: {axes} axes, packing {packing}").into())
        }
    };
    if sample_count * bytes_per_sample > 480 {
        return Err("Sample count exceeds packet capacity".into());
    }
    let timestamp = u32::from_le_bytes([buffer[14], buffer[15], buffer[16], buffer[17]]);
    if cwa_timestamp(timestamp).is_none() {
        return Err("Invalid block timestamp".into());
    }
    Ok(Some(PacketMeta {
        sample_count,
        sample_rate,
        timestamp,
        timestamp_offset: i16::from_le_bytes([buffer[26], buffer[27]]),
    }))
}

impl PacketMeta {
    pub fn natural_bounds(&self) -> (f64, f64) {
        let timestamp = cwa_timestamp(self.timestamp).expect("validated packet timestamp");
        let freq = (3200.0 / ((1 << (15 - (self.sample_rate & 0x0f))) as f64)) as f32;
        let mut offset_start = -(self.timestamp_offset as f32) / freq;
        let offset_floor = offset_start.floor();
        let time0 = timestamp.timestamp() as f64 + offset_floor as f64;
        offset_start -= offset_floor;
        let t0 = time0 + offset_start as f64;
        let t1 = t0 + (self.sample_count as f32 / freq) as f64;
        (t0, t1)
    }
}
