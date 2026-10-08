use cwa_core::header::read_cwa_header_bytes;
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// Parse the first 1,024 bytes of a CWA file. Additional bytes are ignored.
/// Returns header configuration only; actual sample timing needs data packets.
#[wasm_bindgen(js_name = readHeader)]
pub fn read_header(bytes: &[u8]) -> Result<JsValue, JsError> {
    let header = read_cwa_header_bytes(bytes).map_err(|error| JsError::new(&error.to_string()))?;
    js_metadata(&header)
}

fn js_metadata(value: &impl Serialize) -> Result<JsValue, JsError> {
    value
        .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
        .map_err(|error| JsError::new(&error.to_string()))
}

/// Read header configuration and actual sample start/end timing from CWA bytes.
#[wasm_bindgen(js_name = readMetadata)]
pub fn read_metadata(bytes: &[u8]) -> Result<JsValue, JsError> {
    let metadata = cwa_core::reader::CwaReader::new(std::io::Cursor::new(bytes))
        .read_metadata()
        .map_err(|error| JsError::new(&error.to_string()))?;
    js_metadata(&metadata)
}

/// Compare configured timing and sampling rate with the data packets.
#[wasm_bindgen(js_name = samplingConsistencyReport)]
pub fn sampling_consistency_report(bytes: &[u8]) -> Result<JsValue, JsError> {
    let report = cwa_core::reader::CwaReader::new(std::io::Cursor::new(bytes))
        .sampling_consistency_report()
        .map_err(|error| JsError::new(&error.to_string()))?;
    js_metadata(&report)
}

#[derive(serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct BrowserOptions {
    cut: Option<BrowserCut>,
    include_magnetometer: Option<bool>,
    include_temperature: Option<bool>,
    include_light: Option<bool>,
    include_battery: Option<bool>,
    resample_hz: Option<f64>,
    resample_method: Option<String>,
    fixed_utc_offset_seconds: Option<f64>,
}

#[derive(serde::Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum BrowserCut {
    Blocks {
        start: Option<usize>,
        end: Option<usize>,
    },
    Seconds {
        start: Option<f64>,
        end: Option<f64>,
    },
}

impl BrowserCut {
    fn core(&self) -> cwa_core::data::CutConfig {
        match *self {
            Self::Blocks { start, end } => cwa_core::data::CutConfig::Blocks { start, end },
            Self::Seconds { start, end } => cwa_core::data::CutConfig::Seconds { start, end },
        }
    }
}

fn read_options(value: JsValue, csv: bool) -> Result<cwa_core::reader::CwaReadOptions, JsError> {
    let options = if value.is_undefined() || value.is_null() {
        BrowserOptions::default()
    } else {
        serde_wasm_bindgen::from_value(value).map_err(|error| JsError::new(&error.to_string()))?
    };
    let cut = options
        .cut
        .as_ref()
        .map(BrowserCut::core)
        .unwrap_or(cwa_core::data::CutConfig::Full);
    cut.validate()
        .map_err(|error| JsError::new(&error.to_string()))?;
    let resample = options
        .resample_hz
        .map(|hz| {
            cwa_core::data::ResampleOptions::parse(
                hz,
                options.resample_method.as_deref().unwrap_or("cubic"),
            )
        })
        .transpose()
        .map_err(|error| JsError::new(&error.to_string()))?;
    let fixed_utc_offset_us = options
        .fixed_utc_offset_seconds
        .map(|seconds| {
            if !seconds.is_finite() || seconds.abs() >= 86400.0 {
                return Err(JsError::new(
                    "fixed_utc_offset_seconds must be finite and strictly between -86400 and 86400",
                ));
            }
            // Match Python timedelta's microsecond precision and ties-to-even rule.
            let micros = (seconds * 1_000_000.0).round_ties_even() as i64;
            if micros.abs() >= 86_400_000_000 {
                return Err(JsError::new(
                    "fixed UTC offset must be strictly less than 24 hours",
                ));
            }
            Ok(micros)
        })
        .transpose()?;
    Ok(cwa_core::reader::CwaReadOptions {
        cut,
        channels: cwa_core::data::CwaParsingOptions {
            include_magnetometer: options.include_magnetometer.unwrap_or(true),
            include_temperature: options.include_temperature.unwrap_or(!csv),
            include_light: options.include_light.unwrap_or(!csv),
            include_battery: options.include_battery.unwrap_or(!csv),
        },
        resample,
        fixed_utc_offset_us,
    })
}

fn set(target: &JsValue, key: &str, value: &JsValue) -> Result<(), JsError> {
    js_sys::Reflect::set(target, &JsValue::from_str(key), value)
        .map(|_| ())
        .map_err(|error| JsError::new(&format!("{error:?}")))
}

fn sample_arrays(data: cwa_core::data::CwaDataResult, utc: bool) -> Result<JsValue, JsError> {
    let columns = js_sys::Object::new();
    for (name, values) in [
        ("acc_x", data.acc_x),
        ("acc_y", data.acc_y),
        ("acc_z", data.acc_z),
    ] {
        set(
            &columns,
            name,
            &js_sys::Float32Array::from(values.as_slice()),
        )?;
    }
    for (name, values) in [
        ("gyro_x", data.gyro_x),
        ("gyro_y", data.gyro_y),
        ("gyro_z", data.gyro_z),
        ("mag_x", data.mag_x),
        ("mag_y", data.mag_y),
        ("mag_z", data.mag_z),
        ("temperature", data.temperatures),
        ("light", data.light_values),
        ("battery", data.battery_levels),
    ] {
        if let Some(values) = values {
            set(
                &columns,
                name,
                &js_sys::Float32Array::from(values.as_slice()),
            )?;
        }
    }
    let result = js_sys::Object::new();
    set(
        &result,
        "timestamps_us",
        &js_sys::BigInt64Array::from(data.timestamps.as_slice()),
    )?;
    set(&result, "columns", &columns)?;
    set(
        &result,
        "timezone",
        &if utc {
            JsValue::from_str("UTC")
        } else {
            JsValue::NULL
        },
    )?;
    Ok(result.into())
}

/// Decode a complete CWA byte buffer into exact timestamps and float32 columns.
#[wasm_bindgen(js_name = readCwaFile, unchecked_return_type = "CwaSamples")]
pub fn read_cwa_file(
    bytes: &[u8],
    #[wasm_bindgen(unchecked_optional_param_type = "ReadOptions")] options: JsValue,
) -> Result<JsValue, JsError> {
    let options = read_options(options, false)?;
    let data = cwa_core::reader::CwaReader::new(std::io::Cursor::new(bytes))
        .read_data(&options)
        .map_err(|error| JsError::new(&error.to_string()))?;
    sample_arrays(data, options.fixed_utc_offset_us.is_some())
}

/// Return CSV bytes using the same cut, channel, resampling and offset options.
#[wasm_bindgen(js_name = writeCwaCsv)]
pub fn write_cwa_csv(
    bytes: &[u8],
    #[wasm_bindgen(unchecked_optional_param_type = "ReadOptions")] options: JsValue,
) -> Result<Vec<u8>, JsError> {
    let options = read_options(options, true)?;
    let mut output = Vec::new();
    cwa_core::reader::CwaReader::new(std::io::Cursor::new(bytes))
        .write_csv(&mut output, &options)
        .map_err(|error| JsError::new(&error.to_string()))?;
    Ok(output)
}

/// Construct a validated start-inclusive, end-exclusive seconds cut.
#[wasm_bindgen(unchecked_return_type = "CwaCut")]
pub fn seconds(start: Option<f64>, end: Option<f64>) -> Result<JsValue, JsError> {
    let cut = BrowserCut::Seconds { start, end };
    cut.core()
        .validate()
        .map_err(|error| JsError::new(&error.to_string()))?;
    js_metadata(&cut)
}

/// Construct a validated start-inclusive, end-exclusive data-block cut.
#[wasm_bindgen(unchecked_return_type = "CwaCut")]
pub fn blocks(start: Option<f64>, end: Option<f64>) -> Result<JsValue, JsError> {
    fn index(value: Option<f64>) -> Result<Option<usize>, JsError> {
        value
            .map(|value| {
                if !value.is_finite()
                    || value < 0.0
                    || value.fract() != 0.0
                    || value > u32::MAX as f64
                {
                    return Err(JsError::new(
                        "block indexes must be integers between 0 and 4294967295",
                    ));
                }
                Ok(value as usize)
            })
            .transpose()
    }
    let cut = BrowserCut::Blocks {
        start: index(start)?,
        end: index(end)?,
    };
    cut.core()
        .validate()
        .map_err(|error| JsError::new(&error.to_string()))?;
    js_metadata(&cut)
}

#[wasm_bindgen(typescript_custom_section)]
const TYPES: &'static str = r#"
export type CwaCut =
    | { type: 'blocks'; start?: number | null; end?: number | null }
    | { type: 'seconds'; start?: number | null; end?: number | null };
export interface ReadOptions {
    cut?: CwaCut | null;
    include_magnetometer?: boolean;
    include_temperature?: boolean;
    include_light?: boolean;
    include_battery?: boolean;
    resample_hz?: number | null;
    resample_method?: 'cubic';
    fixed_utc_offset_seconds?: number | null;
}
export interface CwaSamples {
    timestamps_us: BigInt64Array;
    columns: Record<string, Float32Array>;
    timezone: 'UTC' | null;
}
"#;
