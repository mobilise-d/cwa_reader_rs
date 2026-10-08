//! Ordered packet timing search. This plans metadata requests only; it neither
//! decodes samples nor changes a batch's fixed interpolation overlap.
use crate::errors::CwaError;
use crate::packet::packet_meta;
use std::collections::BTreeMap;
use std::ops::Range;

#[derive(Clone, Copy)]
struct Timing {
    index: usize,
    start: f64,
    end: f64,
}
pub(crate) struct LocatedRange {
    pub packets: Range<usize>,
    pub origin: f64,
    pub first_valid_packet: usize,
}
enum Pending {
    Read(usize),
    Error(&'static str),
}

/// The cache contains only visited timing probes and compact empty intervals,
/// never a file-wide index. Known empty runs are crossed in one step.
/// Re-evaluating the small search after each response keeps asynchronous source
/// access outside the locator and avoids retaining a partially decoded packet.
pub(crate) struct SecondsLocator {
    total: usize,
    start: Option<f64>,
    end: Option<f64>,
    next: usize,
    probes: BTreeMap<usize, Timing>,
    empty_ranges: BTreeMap<usize, usize>,
}
impl SecondsLocator {
    pub fn new(total: usize, start: Option<f64>, end: Option<f64>) -> Self {
        Self {
            total,
            start,
            end,
            next: 0,
            probes: BTreeMap::new(),
            empty_ranges: BTreeMap::new(),
        }
    }
    pub fn next_packet(&self) -> usize {
        self.next
    }
    pub fn provide(&mut self, bytes: &[u8; 30]) -> Result<Option<LocatedRange>, CwaError> {
        let timing = packet_meta(bytes)?.map(|meta| {
            let (start, end) = meta.natural_bounds();
            Timing {
                index: self.next,
                start,
                end,
            }
        });
        if let Some(timing) = timing {
            self.probes.insert(self.next, timing);
        } else {
            self.remember_empty(self.next);
        }
        match self.locate() {
            Ok(range) => Ok(Some(range)),
            Err(Pending::Read(index)) => {
                self.next = index;
                Ok(None)
            }
            Err(Pending::Error(message)) => Err(message.into()),
        }
    }
    fn remember_empty(&mut self, index: usize) {
        let mut start = index;
        let mut end = index + 1;
        if let Some((&left, &right)) = self.empty_ranges.range(..=index).next_back() {
            if right >= index {
                start = left;
                end = end.max(right);
                self.empty_ranges.remove(&left);
            }
        }
        if let Some(&right) = self.empty_ranges.get(&end) {
            self.empty_ranges.remove(&end);
            end = right;
        }
        self.empty_ranges.insert(start, end);
    }
    fn empty_range(&self, index: usize) -> Option<Range<usize>> {
        self.empty_ranges
            .range(..=index)
            .next_back()
            .and_then(|(&start, &end)| (index < end).then_some(start..end))
    }
    fn next_valid(&self, mut index: usize, end: usize) -> Result<Option<Timing>, Pending> {
        while index < end {
            if let Some(timing) = self.probes.get(&index) {
                return Ok(Some(*timing));
            }
            if let Some(empty) = self.empty_range(index) {
                index = empty.end;
            } else {
                return Err(Pending::Read(index));
            }
        }
        Ok(None)
    }
    fn previous_valid(&self, mut end: usize) -> Result<Option<Timing>, Pending> {
        while end > 0 {
            let index = end - 1;
            if let Some(timing) = self.probes.get(&index) {
                return Ok(Some(*timing));
            }
            if let Some(empty) = self.empty_range(index) {
                end = empty.start;
            } else {
                return Err(Pending::Read(index));
            }
        }
        Ok(None)
    }
    fn adjusted_start(&self, timing: Timing) -> Result<f64, Pending> {
        let previous = self.previous_valid(timing.index)?;
        Ok(match previous {
            Some(previous) if timing.start - previous.end < 1.0 => previous.end,
            _ => timing.start,
        })
    }
    /// First packet whose natural end exceeds the start boundary, or whose
    /// continuity-adjusted start reaches the exclusive end boundary.
    fn boundary(
        &self,
        first: Timing,
        target: f64,
        end_boundary: bool,
    ) -> Result<Option<Timing>, Pending> {
        let mut lo = first.index;
        let mut hi = self.total;
        let duration = first.end - first.start;
        let mut probe = self.estimate(first.index, target - first.start, duration, lo, hi);
        let mut candidate = None;
        let mut slow_steps = 0;
        while lo < hi {
            let old_width = hi - lo;
            let Some(timing) = self.next_valid(probe, hi)? else {
                // Empty/non-data tail inside this bracket cannot contain a match.
                hi = probe;
                if lo < hi {
                    probe = lo + (hi - lo) / 2;
                }
                continue;
            };
            let time = if end_boundary {
                self.adjusted_start(timing)?
            } else {
                timing.end
            };
            let matches = if end_boundary {
                time >= target
            } else {
                time > target
            };
            if matches {
                candidate = Some(timing);
                hi = timing.index;
            } else {
                lo = timing.index + 1;
            }
            if lo < hi {
                // Correct the physical-page estimate by the observed time error.
                // A narrowing bracket and midpoint fallback guarantee progress
                // when packet density/rate differs from the initial estimate.
                slow_steps = if hi - lo > old_width / 2 {
                    slow_steps + 1
                } else {
                    0
                };
                probe = if slow_steps >= 2 {
                    slow_steps = 0;
                    lo + (hi - lo) / 2
                } else {
                    self.estimate(
                        timing.index,
                        target - time,
                        timing.end - timing.start,
                        lo,
                        hi,
                    )
                };
            }
        }
        Ok(candidate)
    }
    fn estimate(&self, index: usize, delta: f64, duration: f64, lo: usize, hi: usize) -> usize {
        let estimate = index as f64 + (delta / duration).floor();
        if estimate.is_finite() {
            (estimate.clamp(lo as f64, (hi - 1) as f64) as usize).clamp(lo, hi - 1)
        } else {
            lo + (hi - lo) / 2
        }
    }
    fn locate(&self) -> Result<LocatedRange, Pending> {
        let first = self
            .next_valid(0, self.total)?
            .ok_or(Pending::Error("No valid sample data found"))?;
        let matched = match self.start {
            Some(start) => self.boundary(first, first.start + start, false)?,
            None => Some(first),
        }
        .ok_or(Pending::Error(
            "No samples remain after applying seconds cut",
        ))?;
        let selected_start = self.previous_valid(matched.index)?.unwrap_or(matched).index;
        let selected_end = match self.end {
            Some(end) => match self.boundary(first, first.start + end, true)? {
                Some(excluded) if excluded.index <= matched.index => {
                    return Err(Pending::Error(
                        "No samples remain after applying seconds cut",
                    ))
                }
                Some(excluded) => excluded.index + 1,
                None => {
                    self.previous_valid(self.total)?
                        .expect("first valid packet exists")
                        .index
                        + 1
                }
            },
            None => {
                self.previous_valid(self.total)?
                    .expect("first valid packet exists")
                    .index
                    + 1
            }
        };
        Ok(LocatedRange {
            packets: selected_start..selected_end,
            origin: first.start,
            first_valid_packet: first.index,
        })
    }
}
