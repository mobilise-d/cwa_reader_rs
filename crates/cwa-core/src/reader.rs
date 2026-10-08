//! CWA operations over seekable input, including browser bytes in a `Cursor`.
use crate::data::{self, CutConfig, CwaDataResult, CwaParsingOptions, ResampleOptions};
use crate::errors::CwaError;
use crate::header::{
    self, format_raw_time, timestamp_us_to_raw_string, CwaHeader, DataBounds, DataTimingSummary,
};
use serde::Serialize;
use std::io::{Read, Seek, SeekFrom, Write};

/// Options shared by data decoding and CSV export. Timestamps use integer
/// microseconds; an optional fixed offset is subtracted from device-clock time.
#[derive(Debug, Clone)]
pub struct CwaReadOptions {
    pub cut: CutConfig,
    pub channels: CwaParsingOptions,
    pub resample: Option<ResampleOptions>,
    pub fixed_utc_offset_us: Option<i64>,
    pub batch: crate::batch::BatchConfig,
}

impl Default for CwaReadOptions {
    fn default() -> Self {
        Self {
            cut: CutConfig::Full,
            channels: CwaParsingOptions::default(),
            resample: None,
            fixed_utc_offset_us: None,
            batch: Default::default(),
        }
    }
}

/// Header configuration plus observed sample boundaries. Serialization uses the
/// same raw naive timestamp fields as the Python metadata dictionary.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct CwaMetadata {
    #[serde(flatten)]
    pub header: CwaHeader,
    #[serde(flatten)]
    pub data_bounds: DataBounds,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SamplingConsistencyReport {
    pub start_from_header_raw: Option<String>,
    pub end_from_header_raw: Option<String>,
    pub duration_s_from_header: Option<f64>,
    pub start_from_data_raw: Option<String>,
    pub end_from_data_raw: Option<String>,
    pub duration_s_from_data: Option<f64>,
    pub samplingrate_hz_from_header: f64,
    pub samplingrate_hz_from_data: Option<f64>,
}

impl SamplingConsistencyReport {
    fn from_timing(header: &CwaHeader, timing: &DataTimingSummary) -> Self {
        let duration_s_from_header = match (header.logging_start_time, header.logging_end_time) {
            (Some(start), Some(end)) => {
                Some((end.timestamp_micros() - start.timestamp_micros()) as f64 / 1_000_000.0)
            }
            _ => None,
        };
        let duration_s_from_data = match (timing.first_sample_us, timing.last_sample_us) {
            (Some(start), Some(end)) => Some((end - start) as f64 / 1_000_000.0),
            _ => None,
        };
        let samplingrate_hz_from_data = duration_s_from_data.and_then(|duration| {
            if timing.sample_count > 1 && duration > 0.0 {
                Some((timing.sample_count - 1) as f64 / duration)
            } else {
                None
            }
        });
        SamplingConsistencyReport {
            start_from_header_raw: header.logging_start_time.map(format_raw_time),
            end_from_header_raw: header.logging_end_time.map(format_raw_time),
            duration_s_from_header,
            start_from_data_raw: timing.first_sample_us.and_then(timestamp_us_to_raw_string),
            end_from_data_raw: timing.last_sample_us.and_then(timestamp_us_to_raw_string),
            duration_s_from_data,
            samplingrate_hz_from_header: header.sample_rate_hz,
            samplingrate_hz_from_data,
        }
    }
}

/// Reusable reader. Each operation starts at byte zero and leaves the input
/// available for subsequent operations. No path or filesystem is required.
pub struct CwaReader<R> {
    input: R,
}

impl CwaReader<std::fs::File> {
    /// Native path convenience; all parsing is shared with byte-backed readers.
    pub fn open(path: &str) -> Result<Self, CwaError> {
        Ok(Self::new(std::fs::File::open(path)?))
    }
}

impl<R: Read + Seek> CwaReader<R> {
    pub fn new(input: R) -> Self {
        Self { input }
    }

    /// Read only the first 1,024 bytes, without scanning sample packets.
    pub fn read_header(&mut self) -> Result<CwaHeader, CwaError> {
        self.input.seek(SeekFrom::Start(0))?;
        header::read_cwa_header_from_reader(&mut self.input)
    }

    /// Read header configuration and locate sample boundaries from both ends.
    /// Unvisited interior packets are not validated; the sampling report scans all packets.
    pub fn read_metadata(&mut self) -> Result<CwaMetadata, CwaError> {
        let header = self.read_header()?;
        let data_bounds = header::find_data_bounds_from_reader(&mut self.input)?;
        Ok(CwaMetadata {
            header,
            data_bounds,
        })
    }

    pub fn sampling_consistency_report(&mut self) -> Result<SamplingConsistencyReport, CwaError> {
        let header = self.read_header()?;
        self.input.seek(SeekFrom::Start(0))?;
        let timing = header::scan_data_timing_from_reader(&mut self.input)?;
        Ok(SamplingConsistencyReport::from_timing(&header, &timing))
    }

    /// Write CSV to an arbitrary sink using bounded packet batches. A bounded
    /// channel-union pass precedes output, which uses the same decoding engine.
    pub fn write_csv<W: Write>(
        &mut self,
        output: &mut W,
        options: &CwaReadOptions,
    ) -> Result<(), CwaError> {
        self.write_csv_with(|| Ok(output), options)
    }

    /// Defer opening an output sink until input selection and channel scans
    /// finish. Native path adapters use this to avoid truncating existing output
    /// when input validation fails. The factory is called at most once.
    pub fn write_csv_with<W: Write, F: FnOnce() -> Result<W, CwaError>>(
        &mut self,
        create_output: F,
        options: &CwaReadOptions,
    ) -> Result<(), CwaError> {
        let file_size = self.input.seek(SeekFrom::End(0))?;
        let mut session = crate::batch::CwaBatchSession::new_csv(file_size, options.clone())?;
        let mut buffer = Vec::new();
        let mut factory = Some(create_output);
        let mut output = None;
        while let Some(request) = session.request() {
            self.preload(request, &mut buffer)?;
            if let Some(chunk) = session.provide_csv(&buffer)? {
                if output.is_none() {
                    output = Some(factory.take().expect("output factory is called once")()?);
                }
                output
                    .as_mut()
                    .expect("output initialized")
                    .write_all(&chunk)?;
            }
        }
        if let Some(mut output) = output {
            output.flush()?;
        }
        Ok(())
    }

    fn preload(
        &mut self,
        request: crate::batch::ReadRequest,
        buffer: &mut Vec<u8>,
    ) -> Result<(), CwaError> {
        if request.length > buffer.len() {
            buffer
                .try_reserve_exact(request.length - buffer.len())
                .map_err(|e| format!("Cannot allocate CWA packet batch: {e}"))?;
        }
        buffer.resize(request.length, 0);
        self.input.seek(SeekFrom::Start(request.offset))?;
        self.input.read_exact(buffer)?;
        Ok(())
    }

    /// Decode selected samples into column arrays. The returned recording is
    /// allocated even when input decoding and resampling process packets incrementally.
    pub fn read_data(&mut self, options: &CwaReadOptions) -> Result<CwaDataResult, CwaError> {
        let file_size = self.input.seek(SeekFrom::End(0))?;
        let mut session = crate::batch::CwaBatchSession::new(file_size, options.clone())?;
        let mut result = data::empty_result(&options.channels);
        let mut buffer = Vec::new();
        while let Some(request) = session.request() {
            self.preload(request, &mut buffer)?;
            if let Some(batch) = session.provide(&buffer)? {
                data::append_batch(&mut result, batch)?;
            }
        }
        if result.timestamps.is_empty() {
            return Err(session.no_output_error());
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::CutConfig;
    use std::io::Cursor;

    fn timestamp(second: u32) -> u32 {
        (12 << 26) | (1 << 22) | (1 << 17) | second
    }

    fn recording() -> Vec<u8> {
        let mut bytes = vec![0u8; 1024 + 4 * 512];
        bytes[..2].copy_from_slice(b"MD");
        bytes[2..4].copy_from_slice(&1020u16.to_le_bytes());
        bytes[5..7].copy_from_slice(&42u16.to_le_bytes());
        bytes[13..17].copy_from_slice(&timestamp(0).to_le_bytes());
        bytes[17..21].copy_from_slice(&timestamp(4).to_le_bytes());
        bytes[36] = 0x49;
        for block in 0..4 {
            let offset = 1024 + block * 512;
            let packet = &mut bytes[offset..offset + 512];
            packet[..2].copy_from_slice(b"AX");
            packet[2..4].copy_from_slice(&508u16.to_le_bytes());
            packet[14..18].copy_from_slice(&timestamp(block as u32).to_le_bytes());
            packet[24] = 0x49;
            packet[25] = 0x32;
            packet[28..30].copy_from_slice(&50u16.to_le_bytes());
            for index in 0..50 {
                let value = ((block * 50 + index) * 128) as i16;
                packet[30 + index * 6..32 + index * 6].copy_from_slice(&value.to_le_bytes());
            }
        }
        bytes
    }

    #[test]
    fn bytes_and_native_paths_match_for_every_core_operation() {
        let bytes = recording();
        let path =
            std::env::temp_dir().join(format!("cwa-reader-byte-parity-{}.cwa", std::process::id()));
        let csv_path = path.with_extension("csv");
        struct Cleanup(std::path::PathBuf, std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
                let _ = std::fs::remove_file(&self.1);
            }
        }
        let _cleanup = Cleanup(path.clone(), csv_path.clone());
        std::fs::write(&path, &bytes).expect("native recording");
        let mut memory = CwaReader::new(Cursor::new(bytes.as_slice()));
        let mut native = CwaReader::open(&path.to_string_lossy()).expect("native reader");
        assert_eq!(memory.read_header().unwrap(), native.read_header().unwrap());
        assert_eq!(
            memory.read_metadata().unwrap(),
            native.read_metadata().unwrap()
        );
        assert_eq!(
            memory.sampling_consistency_report().unwrap(),
            native.sampling_consistency_report().unwrap()
        );
        for options in [
            CwaReadOptions::default(),
            CwaReadOptions {
                cut: CutConfig::Blocks {
                    start: Some(1),
                    end: Some(3),
                },
                ..CwaReadOptions::default()
            },
            CwaReadOptions {
                cut: CutConfig::Seconds {
                    start: Some(0.5),
                    end: Some(2.5),
                },
                ..CwaReadOptions::default()
            },
            CwaReadOptions {
                resample: Some(ResampleOptions::parse(80.0, "cubic").unwrap()),
                fixed_utc_offset_us: Some(-3_500_000),
                ..CwaReadOptions::default()
            },
            CwaReadOptions {
                cut: CutConfig::Seconds {
                    start: Some(0.5),
                    end: Some(2.5),
                },
                resample: Some(ResampleOptions::parse(25.0, "cubic").unwrap()),
                fixed_utc_offset_us: Some(1_250_000),
                batch: Default::default(),
                channels: CwaParsingOptions {
                    include_magnetometer: false,
                    include_temperature: false,
                    include_light: false,
                    include_battery: false,
                },
            },
        ] {
            assert_eq!(
                memory.read_data(&options).unwrap(),
                native.read_data(&options).unwrap()
            );
            let mut output = Vec::new();
            memory.write_csv(&mut output, &options).expect("memory CSV");
            native
                .write_csv(&mut std::fs::File::create(&csv_path).unwrap(), &options)
                .expect("native CSV");
            assert_eq!(output, std::fs::read(&csv_path).unwrap());
        }
    }

    #[test]
    fn malformed_byte_operations_return_errors_and_allow_header_preview() {
        let bytes = recording();
        let mut reader = CwaReader::new(Cursor::new(&bytes[..bytes.len() - 1]));
        assert!(reader.read_header().is_ok());
        assert!(reader.read_metadata().is_err());
        assert!(reader.sampling_consistency_report().is_err());
        assert!(reader.read_data(&CwaReadOptions::default()).is_err());
        let mut output = Vec::new();
        assert!(reader
            .write_csv(&mut output, &CwaReadOptions::default())
            .is_err());
        assert!(output.is_empty());
        let mut output_opened = false;
        assert!(reader
            .write_csv_with(
                || {
                    output_opened = true;
                    Ok(Vec::new())
                },
                &CwaReadOptions::default()
            )
            .is_err());
        assert!(
            !output_opened,
            "invalid input must not create or truncate output"
        );
        let mut reader = CwaReader::new(Cursor::new(bytes.as_slice()));
        let overflow = CwaReadOptions {
            fixed_utc_offset_us: Some(i64::MIN),
            ..CwaReadOptions::default()
        };
        assert!(reader.read_data(&overflow).is_err());
        assert!(reader.write_csv(&mut Vec::new(), &overflow).is_err());
    }

    #[test]
    fn metadata_and_sampling_report_match_uploaded_packet_timing() {
        let bytes = recording();
        let mut reader = CwaReader::new(Cursor::new(bytes.as_slice()));
        let metadata = reader.read_metadata().expect("metadata from bytes");
        assert_eq!(metadata.header.device_id, 42);
        assert_eq!(
            metadata.data_bounds.first_sample_us,
            Some(1_325_376_000_000_000)
        );
        assert_eq!(
            metadata.data_bounds.last_sample_us,
            Some(1_325_376_003_980_000)
        );
        let report = reader
            .sampling_consistency_report()
            .expect("sampling report from bytes");
        assert_eq!(
            report.start_from_header_raw.as_deref(),
            Some("2012-01-01T00:00:00")
        );
        assert_eq!(
            report.end_from_data_raw.as_deref(),
            Some("2012-01-01T00:00:03.980")
        );
        assert_eq!(report.duration_s_from_header, Some(4.0));
        assert_eq!(report.duration_s_from_data, Some(3.98));
        assert_eq!(report.samplingrate_hz_from_header, 50.0);
        assert_eq!(report.samplingrate_hz_from_data, Some(50.0));
        let mut header_only = CwaReader::new(Cursor::new(&bytes[..1024]));
        assert_eq!(
            header_only.read_header().expect("header preview").device_id,
            42
        );
        let report = header_only
            .sampling_consistency_report()
            .expect("header without samples");
        assert!(report.start_from_data_raw.is_none());
        assert!(report.samplingrate_hz_from_data.is_none());
    }

    #[test]
    fn resampling_and_csv_export_work_on_bytes_with_a_fractional_fixed_offset() {
        let bytes = recording();
        let mut reader = CwaReader::new(Cursor::new(bytes.as_slice()));
        let options = CwaReadOptions {
            cut: CutConfig::Seconds {
                start: Some(1.0),
                end: Some(2.0),
            },
            resample: Some(ResampleOptions::parse(25.0, "cubic").expect("supported rate")),
            fixed_utc_offset_us: Some(1_250_000),
            ..CwaReadOptions::default()
        };
        let data = reader
            .read_data(&options)
            .expect("resampling uploaded bytes");
        assert_eq!(data.timestamps.len(), 25);
        assert_eq!(data.timestamps[0], 1_325_375_999_750_000);
        for (index, value) in data.acc_x.iter().enumerate() {
            assert!((value - (25.0 + index as f32)).abs() < 1e-6);
        }
        let mut output = Vec::new();
        reader
            .write_csv(&mut output, &options)
            .expect("CSV in memory");
        let mut csv = csv::Reader::from_reader(output.as_slice());
        assert_eq!(
            csv.headers()
                .expect("CSV header")
                .iter()
                .collect::<Vec<_>>(),
            [
                "time",
                "acc_x",
                "acc_y",
                "acc_z",
                "temperature",
                "light",
                "battery"
            ]
        );
        let rows: Vec<_> = csv.records().collect::<Result<_, _>>().expect("CSV rows");
        assert_eq!(rows.len(), 25);
        assert_eq!(&rows[0][0], "1325375999.7500");
        assert_eq!(&rows[0][1], "25.000000");
    }

    #[test]
    fn seconds_cuts_on_uploaded_bytes_match_the_full_recording_slice() {
        let bytes = recording();
        let mut reader = CwaReader::new(Cursor::new(bytes.as_slice()));
        let full = reader
            .read_data(&CwaReadOptions::default())
            .expect("full recording");
        assert_eq!(full.timestamps.len(), 200);
        assert_eq!(full.timestamps[0], 1_325_376_000_000_000);
        let cut = reader
            .read_data(&CwaReadOptions {
                cut: CutConfig::Seconds {
                    start: Some(1.0),
                    end: Some(2.0),
                },
                ..CwaReadOptions::default()
            })
            .expect("seconds cut");
        assert_eq!(cut.timestamps, full.timestamps[50..100]);
        assert_eq!(cut.acc_x, full.acc_x[50..100]);
        assert!(cut.gyro_x.is_none());
        assert_eq!(cut.acc_x[0], 25.0);
        assert_eq!(cut.acc_x.last(), Some(&49.5));
    }
}
