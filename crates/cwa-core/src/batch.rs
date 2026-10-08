//! Sequential requests for independently decoded, preloaded packet windows.
use crate::data::{self, CutConfig, CwaDataResult};
use crate::errors::CwaError;
use crate::packet::packet_meta;
use crate::reader::CwaReadOptions;
use std::collections::VecDeque;
use std::ops::Range;

#[derive(Debug, Clone, Copy)]
pub struct BatchConfig {
    pub packet_count: usize,
    pub overlap_packets: usize,
}
impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            packet_count: 256,
            overlap_packets: 1,
        }
    }
}
impl BatchConfig {
    pub fn validate(self) -> Result<(), CwaError> {
        if self.packet_count == 0 {
            return Err("batch_packets must be > 0".into());
        }
        let loaded_packets = self
            .overlap_packets
            .checked_mul(2)
            .and_then(|overlap| overlap.checked_add(self.packet_count))
            .ok_or("CWA packet batch count overflow")?;
        if loaded_packets > (isize::MAX as usize) / 512 {
            return Err("CWA packet batch exceeds this target's addressable size".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ReadRequest {
    pub offset: u64,
    pub length: usize,
}

/// A complete decoding description; no state from another decoder is required.
#[derive(Debug, Clone)]
pub struct BatchDescriptor {
    pub loaded_packets: Range<usize>,
    pub owned_packets: Range<usize>,
    pub selected_packets: Range<usize>,
    pub previous_packet_end: Option<f64>,
    pub recording_origin_seconds: Option<f64>,
    pub grid_origin_seconds: Option<f64>,
    pub first_domain_sample_us: Option<i64>,
    pub options: CwaReadOptions,
}
#[derive(Debug)]
pub struct BatchResult {
    pub data: CwaDataResult,
    pub recording_origin_seconds: Option<f64>,
    pub grid_origin_seconds: Option<f64>,
    pub first_domain_sample_us: Option<i64>,
}
impl BatchDescriptor {
    pub(crate) fn insufficient(
        &self,
        side: crate::errors::ContextSide,
        reason: &'static str,
    ) -> CwaError {
        CwaError::InsufficientContext {
            side,
            reason,
            owned_packets: self.owned_packets.clone(),
            loaded_packets: self.loaded_packets.clone(),
        }
    }
    pub fn decode(&self, bytes: &[u8]) -> Result<BatchResult, CwaError> {
        data::decode_loaded_batch(self, bytes)
    }
}

enum Phase {
    Header,
    Seed(usize),
    Locate,
    Payload,
    Finished,
}

struct CsvState {
    schema_pass: bool,
    channels: data::SensorChannels,
    header_written: bool,
    saw_output: bool,
}

pub struct CwaBatchSession {
    total_packets: usize,
    first_valid_packet: Option<usize>,
    descriptor: BatchDescriptor,
    phase: Phase,
    history: VecDeque<(usize, f64)>,
    seconds: Option<crate::locate::SecondsLocator>,
    csv: Option<CsvState>,
}
impl CwaBatchSession {
    pub fn new(file_size: u64, options: CwaReadOptions) -> Result<Self, CwaError> {
        options.cut.validate()?;
        options.batch.validate()?;
        let (first, total_packets) = data::resolve_block_range(file_size, None, None)?;
        debug_assert_eq!(first, 0);
        let selected_packets = match options.cut {
            CutConfig::Blocks { start, end } => {
                start.unwrap_or(0)..end.unwrap_or(total_packets).min(total_packets)
            }
            _ => 0..total_packets,
        };
        if selected_packets.start >= total_packets {
            return Err("Start block is beyond file size".into());
        }
        let owned_packets = selected_packets.start
            ..selected_packets
                .start
                .saturating_add(options.batch.packet_count)
                .min(selected_packets.end);
        let loaded_packets = owned_packets
            .start
            .saturating_sub(options.batch.overlap_packets)
            ..owned_packets
                .end
                .saturating_add(options.batch.overlap_packets)
                .min(total_packets);
        let seconds = match options.cut {
            CutConfig::Seconds { start, end } => Some(crate::locate::SecondsLocator::new(
                total_packets,
                start,
                end,
            )),
            _ => None,
        };
        Ok(Self {
            total_packets,
            first_valid_packet: None,
            descriptor: BatchDescriptor {
                loaded_packets,
                owned_packets,
                selected_packets,
                previous_packet_end: None,
                recording_origin_seconds: None,
                grid_origin_seconds: None,
                first_domain_sample_us: None,
                options,
            },
            phase: Phase::Header,
            history: VecDeque::new(),
            csv: None,
            seconds,
        })
    }
    /// CSV first determines the union of selected output channels using bounded
    /// batches, then formats the same batches with one consistent header.
    pub fn new_csv(file_size: u64, options: CwaReadOptions) -> Result<Self, CwaError> {
        let mut session = Self::new(file_size, options)?;
        session.csv = Some(CsvState {
            schema_pass: true,
            channels: Default::default(),
            header_written: false,
            saw_output: false,
        });
        Ok(session)
    }
    pub fn provide_csv(&mut self, bytes: &[u8]) -> Result<Option<Vec<u8>>, CwaError> {
        let Some(data) = self.provide(bytes)? else {
            return Ok(None);
        };
        let state = self.csv.as_mut().expect("CSV session");
        let output = data::format_csv_batch(
            Vec::new(),
            &data,
            &self.descriptor.options.channels,
            state.channels,
            !state.header_written,
        )?;
        state.header_written = true;
        Ok(Some(output))
    }
    fn restart_payload(&mut self) {
        let start = self.descriptor.selected_packets.start;
        let end = start
            .saturating_add(self.descriptor.options.batch.packet_count)
            .min(self.descriptor.selected_packets.end);
        self.descriptor.owned_packets = start..end;
        self.descriptor.loaded_packets = start
            .saturating_sub(self.descriptor.options.batch.overlap_packets)
            ..end
                .saturating_add(self.descriptor.options.batch.overlap_packets)
                .min(self.total_packets);
        self.descriptor.previous_packet_end = None;
        self.history.clear();
        self.phase = if self.descriptor.loaded_packets.start > self.first_valid_packet.unwrap_or(0)
        {
            Phase::Seed(self.descriptor.loaded_packets.start - 1)
        } else {
            Phase::Payload
        };
    }
    pub fn request(&self) -> Option<ReadRequest> {
        match self.phase {
            Phase::Header => Some(ReadRequest {
                offset: 0,
                length: 2,
            }),
            Phase::Seed(index) => Some(ReadRequest {
                offset: data::data_block_offset(index as u64).expect("validated packet offset"),
                length: 30,
            }),
            Phase::Locate => Some(ReadRequest {
                offset: data::data_block_offset(
                    self.seconds
                        .as_ref()
                        .expect("seconds locator")
                        .next_packet() as u64,
                )
                .expect("validated packet offset"),
                length: 30,
            }),
            Phase::Payload => Some(ReadRequest {
                offset: data::data_block_offset(self.descriptor.loaded_packets.start as u64)
                    .expect("validated packet offset"),
                length: self.descriptor.loaded_packets.len() * 512,
            }),
            Phase::Finished => None,
        }
    }
    pub fn descriptor(&self) -> Option<&BatchDescriptor> {
        matches!(self.phase, Phase::Payload).then_some(&self.descriptor)
    }
    pub(crate) fn no_output_error(&self) -> CwaError {
        if self.descriptor.first_domain_sample_us.is_none() {
            return "No valid sample data found in the specified range".into();
        }
        if self.descriptor.options.resample.is_some() {
            return "No samples remain after applying time range/resampling".into();
        }
        "No samples remain after applying time range".into()
    }
    pub fn finished(&self) -> bool {
        matches!(self.phase, Phase::Finished)
    }
    pub fn provide(&mut self, bytes: &[u8]) -> Result<Option<CwaDataResult>, CwaError> {
        let request = self.request().ok_or("Batch session is already finished")?;
        if bytes.len() != request.length {
            return Err("Incomplete preloaded CWA range".into());
        }
        match self.phase {
            Phase::Header => {
                if bytes != b"MD" {
                    return Err("Not a valid CWA file".into());
                }
                self.phase = if self.seconds.is_some() {
                    Phase::Locate
                } else if self.descriptor.loaded_packets.start > 0 {
                    Phase::Seed(self.descriptor.loaded_packets.start - 1)
                } else {
                    Phase::Payload
                };
                Ok(None)
            }
            Phase::Seed(index) => {
                let mut buffer = [0; 512];
                buffer[..30].copy_from_slice(bytes);
                if let Some(meta) = packet_meta(&buffer)? {
                    let end = meta.natural_bounds().1;
                    self.descriptor.previous_packet_end = Some(end);
                    self.history.push_back((index, end));
                    self.phase = Phase::Payload;
                } else {
                    self.phase = if index > 0 {
                        Phase::Seed(index - 1)
                    } else {
                        Phase::Payload
                    };
                }
                Ok(None)
            }
            Phase::Locate => {
                if let Some(located) = self
                    .seconds
                    .as_mut()
                    .expect("seconds locator")
                    .provide(bytes)?
                {
                    self.descriptor.selected_packets = located.packets;
                    self.descriptor.recording_origin_seconds = Some(located.origin);
                    self.first_valid_packet = Some(located.first_valid_packet);
                    self.seconds = None;
                    self.restart_payload();
                }
                Ok(None)
            }
            Phase::Payload => {
                let result = self.descriptor.decode(bytes)?;
                self.descriptor.recording_origin_seconds = result.recording_origin_seconds;
                self.descriptor.grid_origin_seconds = result.grid_origin_seconds;
                self.descriptor.first_domain_sample_us = result.first_domain_sample_us;
                for (index, packet) in bytes.chunks_exact(512).enumerate() {
                    let index = self.descriptor.loaded_packets.start + index;
                    if index >= self.descriptor.selected_packets.end {
                        break;
                    }
                    let buffer: &[u8; 512] = packet.try_into().expect("complete packet");
                    if let Some(meta) = packet_meta(buffer)? {
                        if self.history.back().is_none_or(|(last, _)| index > *last) {
                            self.history.push_back((index, meta.natural_bounds().1));
                        }
                    }
                }
                let start = self.descriptor.owned_packets.end;
                if start >= self.descriptor.selected_packets.end {
                    self.phase = Phase::Finished;
                } else {
                    let end = start
                        .saturating_add(self.descriptor.options.batch.packet_count)
                        .min(self.descriptor.selected_packets.end);
                    let loaded_start =
                        start.saturating_sub(self.descriptor.options.batch.overlap_packets);
                    self.descriptor.owned_packets = start..end;
                    self.descriptor.loaded_packets = loaded_start
                        ..end
                            .saturating_add(self.descriptor.options.batch.overlap_packets)
                            .min(self.total_packets);
                    self.descriptor.previous_packet_end = self
                        .history
                        .iter()
                        .rev()
                        .find(|(index, _)| *index < loaded_start)
                        .map(|(_, end)| *end);
                    while self.history.len() > 1
                        && self
                            .history
                            .get(1)
                            .is_some_and(|(index, _)| *index < loaded_start)
                    {
                        self.history.pop_front();
                    }
                    self.phase = Phase::Payload;
                }
                if let Some(csv) = self.csv.as_mut() {
                    if csv.schema_pass {
                        let channels = result.data.sensor_channels();
                        csv.channels.gyro |= channels.gyro;
                        csv.channels.magnetometer |= channels.magnetometer;
                        csv.saw_output |= !result.data.timestamps.is_empty();
                        if matches!(self.phase, Phase::Finished) {
                            let empty_error = !csv.saw_output
                                && (self.descriptor.options.resample.is_some()
                                    || matches!(
                                        self.descriptor.options.cut,
                                        CutConfig::Seconds { .. }
                                    ));
                            if empty_error {
                                return Err(self.no_output_error());
                            }
                            csv.schema_pass = false;
                            self.restart_payload();
                        }
                        return Ok(None);
                    }
                }
                Ok(Some(result.data))
            }
            Phase::Finished => unreachable!(),
        }
    }
}
