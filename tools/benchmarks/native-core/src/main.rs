//! Discard decoded batches immediately; no DataFrame or CSV formatting cost.
use cwa_core::batch::{BatchConfig, CwaBatchSession};
use cwa_core::data::{CutConfig, ResampleOptions};
use cwa_core::reader::{CwaReadOptions, CwaReader};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() < 4 {
        return Err(
            "usage: cwa-native-benchmark FILE PACKETS full|early|middle|late [RESAMPLE_HZ]".into(),
        );
    }
    let mut file = File::open(&args[1])?;
    let input_bytes = file.metadata()?.len();
    let packets = args[2].parse()?;
    let mut options = CwaReadOptions {
        batch: BatchConfig {
            packet_count: packets,
            overlap_packets: 1,
        },
        ..Default::default()
    };
    if args[3] != "full" {
        let metadata = CwaReader::new(file.try_clone()?).read_metadata()?;
        let first = metadata
            .data_bounds
            .first_sample_us
            .ok_or("Missing first sample")?;
        let last = metadata
            .data_bounds
            .last_sample_us
            .ok_or("Missing last sample")?;
        let duration = (last - first) as f64 / 1e6;
        let start = match args[3].as_str() {
            "early" => 0.0,
            "middle" => duration / 2.0,
            "late" => (duration - 61.0).max(0.0),
            _ => return Err("Unknown selection".into()),
        };
        options.cut = CutConfig::Seconds {
            start: Some(start),
            end: Some(start + 60.0),
        };
    }
    let resample_hz = args.get(4).map(|hz| hz.parse::<f64>()).transpose()?;
    if let Some(hz) = resample_hz {
        options.resample = Some(ResampleOptions::parse(hz, "cubic")?);
    }
    let resample_json = resample_hz
        .map(|hz| hz.to_string())
        .unwrap_or_else(|| "null".into());
    let started = Instant::now();
    let mut session = CwaBatchSession::new(input_bytes, options)?;
    let mut buffer = Vec::new();
    let (mut requests, mut reads, mut read_bytes, mut max_read_bytes) = (0u64, 0u64, 0u64, 0usize);
    let (mut batches, mut rows, mut output_bytes, mut max_output_bytes) =
        (0u64, 0u64, 0u64, 0usize);
    while let Some(request) = session.request() {
        requests += 1;
        file.seek(SeekFrom::Start(request.offset))?;
        buffer.resize(request.length, 0);
        let mut filled = 0;
        while filled < buffer.len() {
            reads += 1;
            let count = file.read(&mut buffer[filled..])?;
            if count == 0 {
                return Err("Unexpected EOF".into());
            }
            read_bytes += count as u64;
            max_read_bytes = max_read_bytes.max(count);
            filled += count;
        }
        if let Some(batch) = session.provide(&buffer)? {
            batches += 1;
            rows += batch.timestamps.len() as u64;
            let mut bytes = batch.timestamps.len() * 8;
            for column in [&batch.acc_x, &batch.acc_y, &batch.acc_z] {
                bytes += column.len() * 4;
            }
            for column in [
                &batch.gyro_x,
                &batch.gyro_y,
                &batch.gyro_z,
                &batch.mag_x,
                &batch.mag_y,
                &batch.mag_z,
                &batch.temperatures,
                &batch.light_values,
                &batch.battery_levels,
            ]
            .into_iter()
            .flatten()
            {
                bytes += column.len() * 4;
            }
            output_bytes += bytes as u64;
            max_output_bytes = max_output_bytes.max(bytes);
        }
    }
    let seconds = started.elapsed().as_secs_f64();
    // Linux's memory-map peak excludes inherited peaks from a replaced executable.
    let status = std::fs::read_to_string("/proc/self/status")?;
    let rss_kib: u64 = status
        .lines()
        .find(|line| line.starts_with("VmHWM:"))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()?;
    println!("{{\"input_bytes\":{input_bytes},\"batch_packets\":{packets},\"selection\":\"{}\",\"resample_hz\":{resample_json},\"reader_seconds\":{seconds},\"requests\":{requests},\"read_calls\":{reads},\"read_bytes\":{read_bytes},\"max_read_bytes\":{max_read_bytes},\"batches\":{batches},\"rows\":{rows},\"output_bytes\":{output_bytes},\"max_output_batch_bytes\":{max_output_bytes},\"input_buffer_capacity_bytes\":{},\"process_peak_rss_bytes\":{}}}", args[3], buffer.capacity(), rss_kib * 1024);
    Ok(())
}
