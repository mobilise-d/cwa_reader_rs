use crate::data::{CutConfig, CwaDataResult, CwaParsingOptions, ResampleOptions};
use crate::reader::{CwaReadOptions, CwaReader};
use numpy::IntoPyArray;
use pyo3::prelude::*;
use pyo3::types::{PyDelta, PyDeltaAccess, PyDict, PyTzInfo};
use std::fs::File;
use std::io::BufWriter;

fn get_optional_f64(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<f64>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(None);
    };
    if value.is_none() {
        Ok(None)
    } else {
        value.extract()
    }
}

fn get_optional_usize(dict: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<usize>> {
    let Some(value) = dict.get_item(key)? else {
        return Ok(None);
    };
    if value.is_none() {
        Ok(None)
    } else {
        value.extract()
    }
}

fn parse_cut_config(cut: Option<&Bound<'_, PyAny>>) -> PyResult<CutConfig> {
    let Some(cut) = cut else {
        return Ok(CutConfig::Full);
    };
    if cut.is_none() {
        return Ok(CutConfig::Full);
    }

    let dict = cut.downcast::<PyDict>().map_err(|_| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(
            "cut must be created by seconds() or blocks()",
        )
    })?;
    let kind = dict
        .get_item("type")?
        .ok_or_else(|| PyErr::new::<pyo3::exceptions::PyValueError, _>("cut is missing type"))?
        .extract::<String>()?;

    let cut = match kind.as_str() {
        "seconds" => CutConfig::Seconds {
            start: get_optional_f64(dict, "start")?,
            end: get_optional_f64(dict, "end")?,
        },
        "blocks" => CutConfig::Blocks {
            start: get_optional_usize(dict, "start")?,
            end: get_optional_usize(dict, "end")?,
        },
        _ => {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "cut type must be 'seconds' or 'blocks'",
            ))
        }
    };

    cut.validate()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;
    Ok(cut)
}

/// Transfer sample columns to pandas with the device clock as a datetime index.
fn create_python_dataframe(py: Python, data: CwaDataResult, utc: bool) -> PyResult<Py<PyAny>> {
    let dict = PyDict::new(py);

    // Convert sensor data to NumPy arrays (zero-copy transfer)
    dict.set_item("acc_x", data.acc_x.into_pyarray(py))?;
    dict.set_item("acc_y", data.acc_y.into_pyarray(py))?;
    dict.set_item("acc_z", data.acc_z.into_pyarray(py))?;
    if let Some(values) = data.gyro_x {
        dict.set_item("gyro_x", values.into_pyarray(py))?;
    }
    if let Some(values) = data.gyro_y {
        dict.set_item("gyro_y", values.into_pyarray(py))?;
    }
    if let Some(values) = data.gyro_z {
        dict.set_item("gyro_z", values.into_pyarray(py))?;
    }

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

    let pandas = py.import("pandas")?;
    let datetime_kwargs = PyDict::new(py);
    datetime_kwargs.set_item("name", "timestamp")?;
    datetime_kwargs.set_item("copy", false)?;
    datetime_kwargs.set_item(
        "dtype",
        if utc {
            "datetime64[us, UTC]"
        } else {
            "datetime64[us]"
        },
    )?;
    let timestamps = data.timestamps.into_pyarray(py);
    let index = pandas
        .getattr("DatetimeIndex")?
        .call((timestamps,), Some(&datetime_kwargs))?;
    let dataframe_kwargs = PyDict::new(py);
    dataframe_kwargs.set_item("index", index)?;
    dataframe_kwargs.set_item("copy", false)?;
    Ok(pandas
        .getattr("DataFrame")?
        .call((dict,), Some(&dataframe_kwargs))?
        .unbind())
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

#[pyfunction]
#[pyo3(signature = (start=None, end=None))]
pub fn seconds(py: Python, start: Option<f64>, end: Option<f64>) -> PyResult<Py<PyAny>> {
    let cut = CutConfig::Seconds { start, end };
    cut.validate()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let dict = PyDict::new(py);
    dict.set_item("type", "seconds")?;
    dict.set_item("start", start)?;
    dict.set_item("end", end)?;
    Ok(dict.into())
}

#[pyfunction]
#[pyo3(signature = (start=None, end=None))]
pub fn blocks(py: Python, start: Option<usize>, end: Option<usize>) -> PyResult<Py<PyAny>> {
    let cut = CutConfig::Blocks { start, end };
    cut.validate()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string()))?;

    let dict = PyDict::new(py);
    dict.set_item("type", "blocks")?;
    dict.set_item("start", start)?;
    dict.set_item("end", end)?;
    Ok(dict.into())
}

fn fixed_timezone_offset_us(timezone: Option<&Bound<'_, PyTzInfo>>) -> PyResult<Option<i64>> {
    let Some(timezone) = timezone else {
        return Ok(None);
    };
    let offset = timezone
        .call_method1("utcoffset", (timezone.py().None(),))?
        .cast_into::<PyDelta>()?;
    Ok(Some(
        (i64::from(offset.get_days()) * 86400 + i64::from(offset.get_seconds())) * 1_000_000
            + i64::from(offset.get_microseconds()),
    ))
}

/// Python interface for reading CWA data.
///
/// Returns a pandas DataFrame with a DatetimeIndex named `timestamp`.
/// `fixed_utc_offset_timezone` accepts a Python `datetime.timezone` object.
/// Its fixed offset is subtracted throughout and the index is UTC-aware.
/// Otherwise the index is naive. Determine any named timezone's offset in Python
/// at clock synchronization, rather than at recording start.
/// Numeric channel columns retain their float32 dtype.
///
/// Gyro and magnetometer columns are included only when present in the selected
/// samples. Recorded zero measurements remain present; missing samples in a
/// present channel are NaN.
///
/// Optional resampling parameters:
/// - `resample_hz`: when set, data is resampled onto a regular grid.
/// - `resample_method`: currently supports `"cubic"`.
#[pyfunction]
#[pyo3(signature = (
    file_path,
    cut=None,
    include_magnetometer=true,
    include_temperature=true,
    include_light=true,
    include_battery=true,
    resample_hz=None,
    resample_method="cubic",
    *,
    fixed_utc_offset_timezone=None
))]
#[allow(clippy::too_many_arguments)]
pub fn read_cwa_file(
    py: Python,
    file_path: &str,
    cut: Option<&Bound<'_, PyAny>>,
    include_magnetometer: bool,
    include_temperature: bool,
    include_light: bool,
    include_battery: bool,
    resample_hz: Option<f64>,
    resample_method: &str,
    fixed_utc_offset_timezone: Option<&Bound<'_, PyTzInfo>>,
) -> PyResult<Py<PyAny>> {
    let options = CwaParsingOptions {
        include_magnetometer,
        include_temperature,
        include_light,
        include_battery,
    };

    let cut = parse_cut_config(cut)?;
    let resample_options = parse_resample_options(resample_hz, resample_method)?;
    let offset_us = fixed_timezone_offset_us(fixed_utc_offset_timezone)?;
    let options = CwaReadOptions {
        cut,
        channels: options,
        resample: resample_options,
        fixed_utc_offset_us: offset_us,
    };
    let data = CwaReader::open(file_path)
        .and_then(|mut reader| reader.read_data(&options))
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))?;
    create_python_dataframe(py, data, offset_us.is_some())
}

#[pyfunction]
/// Write CWA samples directly to CSV.
///
/// Supports the same optional resampling and time-range controls as `read_cwa_file`.
/// `fixed_utc_offset_timezone` accepts a Python `datetime.timezone` object;
/// with it, numeric `time` values are UTC Unix seconds.
/// Otherwise they encode the device clock without assigning a timezone.
#[pyo3(signature = (
    file_path,
    output_path,
    cut=None,
    include_magnetometer=true,
    include_temperature=false,
    include_light=false,
    include_battery=false,
    resample_hz=None,
    resample_method="cubic",
    *,
    fixed_utc_offset_timezone=None
))]
#[allow(clippy::too_many_arguments)]
pub fn write_cwa_csv(
    file_path: &str,
    output_path: &str,
    cut: Option<&Bound<'_, PyAny>>,
    include_magnetometer: bool,
    include_temperature: bool,
    include_light: bool,
    include_battery: bool,
    resample_hz: Option<f64>,
    resample_method: &str,
    fixed_utc_offset_timezone: Option<&Bound<'_, PyTzInfo>>,
) -> PyResult<()> {
    let options = CwaParsingOptions {
        include_magnetometer,
        include_temperature,
        include_light,
        include_battery,
    };

    let cut = parse_cut_config(cut)?;
    let resample_options = parse_resample_options(resample_hz, resample_method)?;
    let options = CwaReadOptions {
        cut,
        channels: options,
        resample: resample_options,
        fixed_utc_offset_us: fixed_timezone_offset_us(fixed_utc_offset_timezone)?,
    };
    CwaReader::open(file_path)
        .and_then(|mut reader| {
            reader.write_csv_with(
                || {
                    Ok(BufWriter::with_capacity(
                        16 * 1024 * 1024,
                        File::create(output_path)?,
                    ))
                },
                &options,
            )
        })
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}
