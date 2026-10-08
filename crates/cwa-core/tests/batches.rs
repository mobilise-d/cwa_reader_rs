use cwa_core::batch::{BatchConfig, CwaBatchSession};
use cwa_core::reader::CwaReadOptions;

fn recording(packets: usize, samples: u16) -> Vec<u8> {
    let mut bytes = vec![0; 1024 + packets * 512];
    bytes[..2].copy_from_slice(b"MD");
    for index in 0..packets {
        let p = &mut bytes[1024 + index * 512..1024 + (index + 1) * 512];
        p[..2].copy_from_slice(b"AX");
        p[2..4].copy_from_slice(&508u16.to_le_bytes());
        p[14..18]
            .copy_from_slice(&((12 << 26) | (1 << 22) | (1 << 17) | index as u32).to_le_bytes());
        p[24] = 0x49;
        p[25] = 0x32;
        p[28..30].copy_from_slice(&samples.to_le_bytes());
        for sample in 0..samples as usize {
            let value = ((index * samples as usize + sample) * 64) as i16;
            p[30 + sample * 6..32 + sample * 6].copy_from_slice(&value.to_le_bytes());
        }
    }
    bytes
}

#[test]
fn independent_preloaded_batches_own_each_original_sample_once() {
    let bytes = recording(6, 50);
    let options = CwaReadOptions {
        batch: BatchConfig {
            packet_count: 2,
            overlap_packets: 1,
        },
        ..Default::default()
    };
    let mut session = CwaBatchSession::new(bytes.len() as u64, options).unwrap();
    let mut timestamps = Vec::new();
    let mut values = Vec::new();
    while let Some(request) = session.request() {
        let window = &bytes[request.offset as usize..request.offset as usize + request.length];
        let independent = session
            .descriptor()
            .map(|plan| plan.decode(window).unwrap().data);
        if let Some(result) = session.provide(window).unwrap() {
            assert_eq!(independent.unwrap(), result);
            timestamps.extend(result.timestamps);
            values.extend(result.acc_x);
        }
    }
    assert!(session.finished());
    assert_eq!(timestamps.len(), 300);
    assert_eq!(
        timestamps,
        (0..300)
            .map(|i| 1_325_376_000_000_000 + i * 20_000)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        values,
        (0..300).map(|i| i as f32 * 0.25).collect::<Vec<_>>()
    );
}

#[test]
fn independent_resampled_batches_share_one_grid_and_never_duplicate_boundaries() {
    use cwa_core::data::ResampleOptions;
    let mut bytes = recording(4, 2);
    for packet in 0..4 {
        let start = 1024 + packet * 512;
        bytes[start + 14..start + 18]
            .copy_from_slice(&((12u32 << 26) | (1 << 22) | (1 << 17)).to_le_bytes());
        bytes[start + 26..start + 28].copy_from_slice(&(-(packet as i16) * 2).to_le_bytes());
        for sample in 0..2 {
            let index = packet * 2 + sample;
            bytes[start + 30 + sample * 6..start + 32 + sample * 6]
                .copy_from_slice(&((index * index * index * 64) as i16).to_le_bytes());
        }
    }
    let options = CwaReadOptions {
        resample: Some(ResampleOptions::parse(60.0, "cubic").unwrap()),
        batch: BatchConfig {
            packet_count: 2,
            overlap_packets: 1,
        },
        ..Default::default()
    };
    let mut session = CwaBatchSession::new(bytes.len() as u64, options).unwrap();
    let mut timestamps = Vec::new();
    let mut values = Vec::new();
    while let Some(request) = session.request() {
        let window = &bytes[request.offset as usize..request.offset as usize + request.length];
        let independent = session
            .descriptor()
            .map(|plan| plan.decode(window).unwrap().data);
        if let Some(result) = session.provide(window).unwrap() {
            assert_eq!(independent.unwrap(), result);
            timestamps.extend(result.timestamps);
            values.extend(result.acc_x);
        }
    }
    assert_eq!(
        timestamps,
        vec![
            1325376000000000,
            1325376000016666,
            1325376000033333,
            1325376000050000,
            1325376000066666,
            1325376000083333,
            1325376000100000,
            1325376000116666,
            1325376000133333
        ]
    );
    // Literal outputs from the preserved old engine. Target4 brackets samples3/4
    // across the owned batch join; linear fallback would produce a different value.
    let expected = [
        0.0,
        0.2083333283662796,
        1.1574074029922485,
        3.90625,
        9.259358406066895,
        18.084489822387695,
        31.25,
        49.62407302856445,
        75.16767883300781,
    ];
    assert_eq!(values.len(), expected.len());
    for (actual, expected) in values.iter().zip(expected) {
        assert!((actual - expected).abs() < 1e-6, "{actual} != {expected}");
    }
}

#[test]
fn missing_original_context_errors_while_true_recording_edges_allow_linear_interpolation() {
    use cwa_core::{
        data::ResampleOptions,
        errors::{ContextSide, CwaError},
    };
    let bytes = recording(6, 1);
    let options = CwaReadOptions {
        resample: Some(ResampleOptions::parse(25.0, "cubic").unwrap()),
        batch: BatchConfig {
            packet_count: 2,
            overlap_packets: 1,
        },
        ..Default::default()
    };
    let mut session = CwaBatchSession::new(bytes.len() as u64, options.clone()).unwrap();
    let mut insufficient = false;
    while let Some(request) = session.request() {
        let window = &bytes[request.offset as usize..request.offset as usize + request.length];
        match session.provide(window) {
            Err(CwaError::InsufficientContext {
                side: ContextSide::Right,
                owned_packets,
                loaded_packets,
                ..
            }) => {
                assert_eq!(owned_packets, 0..2);
                assert_eq!(loaded_packets, 0..3);
                insufficient = true;
                break;
            }
            other => {
                other.unwrap();
            }
        }
    }
    assert!(insufficient);
    let mut larger = CwaBatchSession::new(
        bytes.len() as u64,
        CwaReadOptions {
            batch: BatchConfig {
                overlap_packets: 2,
                ..options.batch
            },
            ..options.clone()
        },
    )
    .unwrap();
    while let Some(request) = larger.request() {
        larger
            .provide(&bytes[request.offset as usize..request.offset as usize + request.length])
            .unwrap();
    }
    let short = recording(2, 1);
    let mut at_eof = CwaBatchSession::new(short.len() as u64, options).unwrap();
    let mut count = 0;
    while let Some(request) = at_eof.request() {
        if let Some(data) = at_eof
            .provide(&short[request.offset as usize..request.offset as usize + request.length])
            .unwrap()
        {
            count += data.timestamps.len();
        }
    }
    assert_eq!(count, 1);
}

#[test]
fn cubic_uses_four_original_samples_and_linear_recording_edges() {
    use cwa_core::data::ResampleOptions;
    let mut bytes = recording(1, 4);
    for i in 0..4 {
        let offset = 1024 + 30 + i * 6;
        bytes[offset..offset + 2].copy_from_slice(&((i * i * i * 256) as i16).to_le_bytes());
    }
    let mut session = CwaBatchSession::new(
        bytes.len() as u64,
        CwaReadOptions {
            resample: Some(ResampleOptions::parse(100.0, "cubic").unwrap()),
            ..Default::default()
        },
    )
    .unwrap();
    let mut result = None;
    while let Some(request) = session.request() {
        if let Some(data) = session
            .provide(&bytes[request.offset as usize..request.offset as usize + request.length])
            .unwrap()
        {
            result = Some(data);
        }
    }
    let result = result.unwrap();
    // Preserved pre-refactor oracle: cubic at the interior, linear at both edges.
    assert_eq!(result.acc_x, vec![0.0, 0.5, 1.0, 3.375, 8.0, 17.5, 27.0]);
}

#[test]
fn csv_batches_write_one_header_and_the_same_owned_rows_as_the_native_writer() {
    use cwa_core::reader::CwaReader;
    use std::io::Cursor;
    let bytes = recording(6, 50);
    let options = CwaReadOptions {
        batch: BatchConfig {
            packet_count: 2,
            overlap_packets: 1,
        },
        ..Default::default()
    };
    let mut session = CwaBatchSession::new_csv(bytes.len() as u64, options.clone()).unwrap();
    let mut streamed = Vec::new();
    while let Some(request) = session.request() {
        if let Some(chunk) = session
            .provide_csv(&bytes[request.offset as usize..request.offset as usize + request.length])
            .unwrap()
        {
            streamed.extend(chunk);
        }
    }
    let mut native = Vec::new();
    CwaReader::new(Cursor::new(&bytes))
        .write_csv(&mut native, &options)
        .unwrap();
    assert_eq!(streamed, native);
    let text = String::from_utf8(streamed).unwrap();
    assert_eq!(text.lines().count(), 301);
    assert_eq!(
        text.lines()
            .filter(|line| line.starts_with("time,"))
            .count(),
        1
    );
    assert!(text
        .lines()
        .nth(1)
        .unwrap()
        .starts_with("1325376000.0000,0.000000,"));
}

#[test]
fn context_failure_discards_the_failed_batch_but_keeps_prior_owned_output() {
    use cwa_core::{data::ResampleOptions, errors::CwaError};
    let mut bytes = recording(6, 50);
    bytes[1024 + 4 * 512 + 28..1024 + 4 * 512 + 30].copy_from_slice(&1u16.to_le_bytes());
    let mut session = CwaBatchSession::new(
        bytes.len() as u64,
        CwaReadOptions {
            resample: Some(ResampleOptions::parse(60.0, "cubic").unwrap()),
            batch: BatchConfig {
                packet_count: 2,
                overlap_packets: 1,
            },
            ..Default::default()
        },
    )
    .unwrap();
    let mut accepted = Vec::new();
    let mut failed = false;
    while let Some(request) = session.request() {
        match session
            .provide(&bytes[request.offset as usize..request.offset as usize + request.length])
        {
            Ok(Some(result)) => accepted.extend(result.timestamps),
            Ok(None) => (),
            Err(CwaError::InsufficientContext {
                owned_packets,
                loaded_packets,
                ..
            }) => {
                assert_eq!(owned_packets, 2..4);
                assert_eq!(loaded_packets, 1..5);
                failed = true;
                break;
            }
            Err(error) => panic!("unexpected error {error}"),
        }
    }
    assert!(failed);
    assert_eq!(accepted.len(), 120);
    assert_eq!(accepted[0], 1_325_376_000_000_000);
    assert_eq!(accepted[119], 1_325_376_001_983_333);
}

#[test]
fn unsupported_batch_sizes_fail_without_allocating_large_payloads() {
    for batch in [
        BatchConfig {
            packet_count: 0,
            overlap_packets: 1,
        },
        BatchConfig {
            packet_count: usize::MAX,
            overlap_packets: 0,
        },
        BatchConfig {
            packet_count: 1,
            overlap_packets: usize::MAX,
        },
    ] {
        assert!(CwaBatchSession::new(
            1536,
            CwaReadOptions {
                batch,
                ..Default::default()
            }
        )
        .is_err());
    }
}

#[test]
fn seconds_cuts_seek_to_a_narrow_window_in_a_large_recording() {
    use cwa_core::data::CutConfig;
    // A source range budget makes an accidental full-file metadata scan fail
    // immediately, without allocating or reading a multi-gigabyte fixture.
    let packets = 8_500_000usize;
    let size = 1024 + packets as u64 * 512;
    let options = CwaReadOptions {
        cut: CutConfig::Seconds {
            start: Some(200_000.3),
            end: Some(200_060.3),
        },
        batch: BatchConfig {
            packet_count: 7,
            overlap_packets: 1,
        },
        ..Default::default()
    };
    let mut session = CwaBatchSession::new(size, options).unwrap();
    let mut read_bytes = 0;
    let mut read_calls = 0;
    let mut timestamps = Vec::new();
    while let Some(request) = session.request() {
        read_bytes += request.length;
        read_calls += 1;
        assert!(
            read_bytes < 100_000,
            "narrow cut exceeded range-read budget"
        );
        let mut bytes = vec![0u8; request.length];
        if request.offset == 0 {
            bytes[..2].copy_from_slice(b"MD");
        } else {
            let first = ((request.offset - 1024) / 512) as usize;
            for (offset, chunk) in bytes.chunks_mut(512).enumerate() {
                use chrono::{Datelike, Timelike};
                let time =
                    chrono::DateTime::from_timestamp(1_704_067_200 + (first + offset) as i64, 0)
                        .unwrap();
                let rtc = ((time.year() as u32 - 2000) << 26)
                    | (time.month() << 22)
                    | (time.day() << 17)
                    | (time.hour() << 12)
                    | (time.minute() << 6)
                    | time.second();
                let mut packet = [0u8; 512];
                let index = first + offset;
                // The first packet's short duration intentionally predicts a
                // position near1,000,000. Empty pages there require skipping and
                // a correction jump before reaching the dense selected window.
                if (999_990..1_000_010).contains(&index) {
                    chunk.fill(0);
                    continue;
                }
                packet[..2].copy_from_slice(b"AX");
                packet[14..18].copy_from_slice(&rtc.to_le_bytes());
                packet[24] = 0x49;
                packet[25] = 0x32;
                packet[28..30]
                    .copy_from_slice(&(if index == 0 { 10u16 } else { 50u16 }).to_le_bytes());
                chunk.copy_from_slice(&packet[..chunk.len()]);
            }
        }
        if let Some(batch) = session.provide(&bytes).unwrap() {
            timestamps.extend(batch.timestamps);
        }
    }
    assert!(read_calls < 100);
    assert_eq!(timestamps.len(), 3000);
    assert_eq!(timestamps.first(), Some(&1_704_267_200_300_000));
    assert_eq!(timestamps.last(), Some(&1_704_267_260_280_000));
}

#[test]
fn true_domain_start_needs_only_two_samples_for_its_linear_edge() {
    use cwa_core::data::ResampleOptions;
    let bytes = recording(6, 1);
    let mut session = CwaBatchSession::new(
        bytes.len() as u64,
        CwaReadOptions {
            resample: Some(ResampleOptions::parse(0.5, "cubic").unwrap()),
            batch: BatchConfig {
                packet_count: 1,
                overlap_packets: 1,
            },
            ..Default::default()
        },
    )
    .unwrap();
    while let Some(request) = session.request() {
        if let Some(batch) = session
            .provide(&bytes[request.offset as usize..request.offset as usize + request.length])
            .unwrap()
        {
            // The first owned packet contributes only the true first target;
            // interior cubic context in future batches is a separate requirement.
            assert_eq!(batch.timestamps, vec![1_325_376_000_000_000]);
            assert_eq!(batch.acc_x, vec![0.0]);
            return;
        }
    }
    panic!("first linear-edge target was not delivered");
}

#[test]
fn seconds_location_crosses_a_long_empty_prefix_without_rereading_it_for_context() {
    use cwa_core::data::CutConfig;
    let leading = 10_000;
    let valid = recording(4, 50);
    let mut bytes = vec![0u8; 1024 + (leading + 4) * 512];
    bytes[..2].copy_from_slice(b"MD");
    bytes[1024 + leading * 512..].copy_from_slice(&valid[1024..]);
    let mut session = CwaBatchSession::new(
        bytes.len() as u64,
        CwaReadOptions {
            cut: CutConfig::Seconds {
                start: Some(1.2),
                end: Some(1.8),
            },
            ..Default::default()
        },
    )
    .unwrap();
    let mut requests = 0;
    let mut timestamps = Vec::new();
    while let Some(request) = session.request() {
        requests += 1;
        assert!(
            requests < leading + 100,
            "known-empty prefix was read again for a nonexistent predecessor"
        );
        if let Some(batch) = session
            .provide(&bytes[request.offset as usize..request.offset as usize + request.length])
            .unwrap()
        {
            timestamps.extend(batch.timestamps);
        }
    }
    assert_eq!(timestamps.len(), 30);
    assert_eq!(timestamps.first(), Some(&1_325_376_001_200_000));
    assert_eq!(timestamps.last(), Some(&1_325_376_001_780_000));
}

#[test]
fn sample_sessions_reject_empty_recordings_and_selected_ranges_at_completion() {
    use cwa_core::data::CutConfig;
    for cut in [
        CutConfig::Full,
        CutConfig::Blocks {
            start: Some(1),
            end: Some(3),
        },
    ] {
        let mut bytes = recording(4, 50);
        match cut {
            CutConfig::Full => bytes[1024..].fill(0),
            _ => bytes[1024 + 512..1024 + 3 * 512].fill(0),
        }
        let mut session = CwaBatchSession::new(
            bytes.len() as u64,
            CwaReadOptions {
                cut,
                batch: BatchConfig {
                    packet_count: 1,
                    overlap_packets: 1,
                },
                ..Default::default()
            },
        )
        .unwrap();
        let mut failure = None;
        while let Some(request) = session.request() {
            match session
                .provide(&bytes[request.offset as usize..request.offset as usize + request.length])
            {
                Ok(Some(batch)) => assert!(batch.timestamps.is_empty()),
                Ok(None) => (),
                Err(error) => {
                    failure = Some(error.to_string());
                    break;
                }
            }
        }
        assert_eq!(
            failure.as_deref(),
            Some("No valid sample data found in the specified range")
        );
    }
}

#[test]
fn short_resampled_seconds_cut_needs_no_unused_next_ownership_boundary() {
    use cwa_core::data::{CutConfig, ResampleOptions};
    let mut bytes = recording(4, 50);
    // Nonlinear values ensure every interior target still uses original cubic
    // neighbors, including all context required by this short cut's final target.
    for sample in 3..13usize {
        let offset = 1024 + 30 + sample * 6;
        bytes[offset..offset + 2].copy_from_slice(&((sample.pow(3) * 8) as i16).to_le_bytes());
    }
    let options = CwaReadOptions {
        cut: CutConfig::Seconds {
            start: Some(0.1),
            end: Some(0.2),
        },
        resample: Some(ResampleOptions::parse(60.0, "cubic").unwrap()),
        batch: BatchConfig {
            packet_count: 1,
            overlap_packets: 0,
        },
        ..Default::default()
    };
    let mut session = CwaBatchSession::new(bytes.len() as u64, options).unwrap();
    let mut times = Vec::new();
    let mut x = Vec::new();
    while let Some(request) = session.request() {
        if let Some(batch) = session
            .provide(&bytes[request.offset as usize..request.offset as usize + request.length])
            .unwrap()
        {
            times.extend(batch.timestamps);
            x.extend(batch.acc_x);
        }
    }
    assert_eq!(
        times,
        vec![
            1325376000100000,
            1325376000116666,
            1325376000133333,
            1325376000150000,
            1325376000166666,
            1325376000183333
        ]
    );
    // Captured from the preserved pre-refactor Python wheel. These nonlinear
    // targets reject weakening the interior cubic checks to linear interpolation.
    assert_eq!(
        x,
        vec![
            3.90625,
            6.2030205726623535,
            9.259222984313965,
            13.18359088897705,
            18.084489822387695,
            24.070363998413086
        ]
    );
}

#[test]
fn one_sample_preload_reports_missing_right_bracket_before_emitting() {
    use cwa_core::{
        data::ResampleOptions,
        errors::{ContextSide, CwaError},
    };
    let bytes = recording(2, 1);
    let options = CwaReadOptions {
        resample: Some(ResampleOptions::parse(25.0, "cubic").unwrap()),
        batch: BatchConfig {
            packet_count: 1,
            overlap_packets: 0,
        },
        ..Default::default()
    };
    let mut session = CwaBatchSession::new(bytes.len() as u64, options.clone()).unwrap();
    let mut rejected = false;
    while let Some(request) = session.request() {
        match session
            .provide(&bytes[request.offset as usize..request.offset as usize + request.length])
        {
            Err(CwaError::InsufficientContext {
                side,
                owned_packets,
                loaded_packets,
                ..
            }) => {
                assert_eq!(side, ContextSide::Right);
                assert_eq!(owned_packets, 0..1);
                assert_eq!(loaded_packets, 0..1);
                rejected = true;
                break;
            }
            Err(error) => panic!("unexpected error: {error}"),
            Ok(None) => (),
            Ok(Some(_)) => panic!("one-sample window accepted without a right bracket"),
        }
    }
    assert!(rejected);
    let mut session = CwaBatchSession::new(
        bytes.len() as u64,
        CwaReadOptions {
            batch: BatchConfig {
                overlap_packets: 1,
                ..options.batch
            },
            ..options
        },
    )
    .unwrap();
    let mut timestamps = Vec::new();
    while let Some(request) = session.request() {
        if let Some(batch) = session
            .provide(&bytes[request.offset as usize..request.offset as usize + request.length])
            .unwrap()
        {
            timestamps.extend(batch.timestamps);
        }
    }
    // The second one-sample packet is continuity-adjusted to20ms, so only
    // the0ms target lies inside the true two-sample recording at25Hz.
    assert_eq!(timestamps, vec![1_325_376_000_000_000]);
}

#[test]
fn batch_timing_seed_survives_empty_runs_and_overlap_larger_than_ownership() {
    use cwa_core::{data::CutConfig, reader::CwaReader};
    let mut bytes = recording(30, 50);
    for packet in 0..30 {
        let start = 1024 + packet * 512;
        bytes[start + 26..start + 28].copy_from_slice(&((packet % 2 * 10) as i16).to_le_bytes());
        if (8..16).contains(&packet) {
            bytes[start..start + 2].copy_from_slice(b"ZZ");
        }
    }
    let options = CwaReadOptions {
        cut: CutConfig::Blocks {
            start: Some(5),
            end: Some(28),
        },
        batch: BatchConfig {
            packet_count: 64,
            overlap_packets: 0,
        },
        ..Default::default()
    };
    let expected = CwaReader::new(std::io::Cursor::new(&bytes))
        .read_data(&options)
        .unwrap();
    for overlap_packets in [0, 1, 5, 20] {
        let options = CwaReadOptions {
            batch: BatchConfig {
                packet_count: 2,
                overlap_packets,
            },
            ..options.clone()
        };
        let mut session = CwaBatchSession::new(bytes.len() as u64, options).unwrap();
        let mut timestamps = Vec::new();
        let mut values = Vec::new();
        while let Some(request) = session.request() {
            let window = &bytes[request.offset as usize..request.offset as usize + request.length];
            if let Some(output) = session.provide(window).unwrap() {
                timestamps.extend(output.timestamps);
                values.extend(output.acc_x);
            }
        }
        assert_eq!(timestamps, expected.timestamps);
        assert_eq!(values, expected.acc_x);
    }
}
