use cwa_core::header::{format_raw_time, timestamp_us_to_raw_string};
use cwa_core::reader::CwaReader;
use pyo3::prelude::*;

/// Return a sampling consistency report for a CWA file.
///
/// The returned dictionary contains:
///
/// - `start_from_header_raw`: ISO 8601 timestamp from the metadata block `logging_start_time`
///   field, or `None` when the header uses an unset marker.
/// - `end_from_header_raw`: ISO 8601 timestamp from the metadata block `logging_end_time`
///   field, or `None` when the header uses an unset marker.
/// - `duration_s_from_header`: `end_from_header_raw - start_from_header_raw` in seconds, or
///   `None` when either header timestamp is unavailable.
/// - `start_from_data_raw`: ISO 8601 timestamp of the first sample produced by the data
///   packets, using the same packet timestamp, `timestampOffset`, and continuity
///   correction as `read_cwa_file`.
/// - `end_from_data_raw`: ISO 8601 timestamp of the last sample produced by the data
///   packets, using the same timestamp calculation as `read_cwa_file`.
/// - `duration_s_from_data`: `end_from_data_raw - start_from_data_raw` in seconds. This is
///   the inclusive first-sample-to-last-sample span, not the half-open packet end.
/// - `samplingrate_hz_from_header`: nominal sampling rate decoded from the metadata
///   block sampling-rate code as `3200 / (1 << (15 - (rate_code & 0x0f)))`.
/// - `samplingrate_hz_from_data`: effective sampling rate calculated as
///   `(sample_count - 1) / duration_s_from_data`, or `None` when fewer than two
///   samples or no positive data duration are available.
///
/// All timestamp strings preserve the raw device clock without a timezone.
/// Convert them to UTC or local time before analysis using the clock-sync offset.
/// This method accepts no UTC offset or timezone.
#[pyfunction]
pub fn sampling_consistency_report(py: Python, file_path: &str) -> PyResult<Py<PyAny>> {
    let data = CwaReader::open(file_path)
        .and_then(|mut reader| reader.sampling_consistency_report())
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;

    let report = pyo3::types::PyDict::new(py);
    report.set_item("start_from_header_raw", data.start_from_header_raw)?;
    report.set_item("end_from_header_raw", data.end_from_header_raw)?;
    report.set_item("duration_s_from_header", data.duration_s_from_header)?;
    report.set_item("start_from_data_raw", data.start_from_data_raw)?;
    report.set_item("end_from_data_raw", data.end_from_data_raw)?;
    report.set_item("duration_s_from_data", data.duration_s_from_data)?;
    report.set_item(
        "samplingrate_hz_from_header",
        data.samplingrate_hz_from_header,
    )?;
    report.set_item("samplingrate_hz_from_data", data.samplingrate_hz_from_data)?;

    Ok(report.into())
}

/// Read CWA header and sample timing metadata without timezone conversion.
/// Scans packet metadata without decoding sensor values.
/// `logging_start_time_raw`, `logging_end_time_raw`, and `last_change_time_raw`
/// are naive ISO 8601 strings preserving the unaltered sensor clock values,
/// or None when unset. Convert them to UTC or local time for most analysis.
/// `start_from_data_raw` and `end_from_data_raw` are the first and last actual
/// sample timestamps, including packet sample offsets and continuity correction,
/// or None when no valid samples exist. Seconds cuts start at `start_from_data_raw`.
/// `last_change_time_raw` records the last metadata write, which need not be
/// the last clock synchronization; check your configuration software.
#[pyfunction]
pub fn read_metadata(py: Python, file_path: &str) -> PyResult<Py<PyAny>> {
    let metadata = CwaReader::open(file_path)
        .and_then(|mut reader| reader.read_metadata())
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
    let header = metadata.header;
    let data = metadata.data_timing;
    let header_dict = pyo3::types::PyDict::new(py);

    // Header identification
    header_dict.set_item("packet_header", header.packet_header)?;
    header_dict.set_item("packet_length", header.packet_length)?;
    header_dict.set_item("hardware_type", header.hardware_type)?;
    header_dict.set_item("device_id", header.device_id)?;
    header_dict.set_item("session_id", header.session_id)?;
    header_dict.set_item("upper_device_id", header.upper_device_id)?;

    // Timing configuration
    header_dict.set_item(
        "logging_start_time_raw",
        header.logging_start_time.map(format_raw_time),
    )?;
    header_dict.set_item(
        "logging_end_time_raw",
        header.logging_end_time.map(format_raw_time),
    )?;
    header_dict.set_item(
        "last_change_time_raw",
        header.last_change_time.map(format_raw_time),
    )?;
    header_dict.set_item(
        "start_from_data_raw",
        data.first_sample_us.and_then(timestamp_us_to_raw_string),
    )?;
    header_dict.set_item(
        "end_from_data_raw",
        data.last_sample_us.and_then(timestamp_us_to_raw_string),
    )?;

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
