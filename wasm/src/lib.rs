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

fn core_error(error: cwa_core::errors::CwaError) -> JsError {
    let output = JsError::new(&error.to_string());
    if let cwa_core::errors::CwaError::InsufficientContext {
        side,
        owned_packets,
        loaded_packets,
        reason,
    } = error
    {
        let object: JsValue = output.clone().into();
        for (name, value) in [
            ("code", JsValue::from_str("InsufficientContext")),
            (
                "side",
                JsValue::from_str(match side {
                    cwa_core::errors::ContextSide::Left => "left",
                    cwa_core::errors::ContextSide::Right => "right",
                }),
            ),
            (
                "ownedPackets",
                js_sys::Array::of2(
                    &JsValue::from_f64(owned_packets.start as f64),
                    &JsValue::from_f64(owned_packets.end as f64),
                )
                .into(),
            ),
            (
                "loadedPackets",
                js_sys::Array::of2(
                    &JsValue::from_f64(loaded_packets.start as f64),
                    &JsValue::from_f64(loaded_packets.end as f64),
                )
                .into(),
            ),
            ("reason", JsValue::from_str(reason)),
        ] {
            if let Err(error) = set(&object, name, &value) {
                return error;
            }
        }
    }
    output
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
    #[serde(rename = "batchPackets")]
    batch_packets: Option<usize>,
    #[serde(rename = "overlapPackets")]
    overlap_packets: Option<usize>,
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
    let batch_defaults = cwa_core::batch::BatchConfig::default();
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
        batch: cwa_core::batch::BatchConfig {
            packet_count: options.batch_packets.unwrap_or(batch_defaults.packet_count),
            overlap_packets: options
                .overlap_packets
                .unwrap_or(batch_defaults.overlap_packets),
        },
    })
}

/// Synchronous parser bridge. Browser source access lives in cwa_reader_file.js.
#[wasm_bindgen]
pub struct PacketBatchReader {
    session: cwa_core::batch::CwaBatchSession,
    utc: bool,
    csv: bool,
}

#[wasm_bindgen]
impl PacketBatchReader {
    #[wasm_bindgen(constructor)]
    pub fn new(
        file_size: f64,
        csv: bool,
        #[wasm_bindgen(unchecked_optional_param_type = "ReadOptions")] options: JsValue,
    ) -> Result<PacketBatchReader, JsError> {
        if !file_size.is_finite()
            || file_size < 0.0
            || file_size.fract() != 0.0
            || file_size > 9_007_199_254_740_991.0
        {
            return Err(JsError::new("file size must be a nonnegative safe integer"));
        }
        let options = read_options(options, csv)?;
        let utc = options.fixed_utc_offset_us.is_some();
        let session = if csv {
            cwa_core::batch::CwaBatchSession::new_csv(file_size as u64, options)
        } else {
            cwa_core::batch::CwaBatchSession::new(file_size as u64, options)
        }
        .map_err(core_error)?;
        Ok(Self { session, utc, csv })
    }

    #[wasm_bindgen(unchecked_return_type = "ReadRequest | null")]
    pub fn request(&self) -> Result<JsValue, JsError> {
        #[derive(Serialize)]
        struct Request {
            offset: f64,
            length: usize,
        }
        match self.session.request() {
            Some(request) => js_metadata(&Request {
                offset: request.offset as f64,
                length: request.length,
            }),
            None => Ok(JsValue::NULL),
        }
    }

    #[wasm_bindgen(unchecked_return_type = "CwaSamples | Uint8Array | null")]
    pub fn provide(&mut self, bytes: &[u8]) -> Result<JsValue, JsError> {
        if self.csv {
            return match self.session.provide_csv(bytes).map_err(core_error)? {
                Some(bytes) => Ok(js_sys::Uint8Array::from(bytes.as_slice()).into()),
                None => Ok(JsValue::NULL),
            };
        }
        match self.session.provide(bytes).map_err(core_error)? {
            Some(data) => sample_arrays(data, self.utc),
            None => Ok(JsValue::NULL),
        }
    }
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
        .map_err(core_error)?;
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
        .map_err(core_error)?;
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
    /** Number of owned 512-byte data packets per batch. Default 256. */
    batchPackets?: number;
    /** Physical packets loaded on each side, clipped at real file bounds. Default 1. */
    overlapPackets?: number;
}
export interface ReadRequest { offset: number; length: number; }
export interface InsufficientContextError extends Error {
    code: 'InsufficientContext';
    side: 'left' | 'right';
    ownedPackets: [number, number];
    loadedPackets: [number, number];
    reason: string;
}
export interface CwaSamples {
    timestamps_us: BigInt64Array;
    columns: Record<string, Float32Array>;
    timezone: 'UTC' | null;
}
"#;
