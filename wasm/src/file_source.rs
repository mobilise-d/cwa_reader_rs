//! A worker FileReaderSync adapts browser storage to the core's ordinary Read+Seek seam.
use std::io::{self, Read, Seek, SeekFrom};
use wasm_bindgen::{JsError, JsValue};
use web_sys::{Blob, FileReaderSync};

pub struct FileSource {
    file: Blob,
    reader: FileReaderSync,
    size: u64,
    position: u64,
}

pub fn reader(file: Blob) -> Result<cwa_core::reader::CwaReader<FileSource>, JsError> {
    let size = file.size();
    if size > 9_007_199_254_740_991.0 {
        return Err(JsError::new("file size must be a safe integer"));
    }
    let reader = FileReaderSync::new().map_err(|error| JsError::new(&format!("{error:?}")))?;
    Ok(cwa_core::reader::CwaReader::new(FileSource {
        file,
        reader,
        size: size as u64,
        position: 0,
    }))
}

fn browser_error(error: JsValue) -> io::Error {
    io::Error::other(format!("{error:?}"))
}

impl Read for FileSource {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let available = self.size.saturating_sub(self.position);
        let count = (output.len() as u64).min(available) as usize;
        if count == 0 {
            return Ok(0);
        }
        let end = self.position + count as u64;
        let slice = self
            .file
            .slice_with_f64_and_f64(self.position as f64, end as f64)
            .map_err(browser_error)?;
        let buffer = self
            .reader
            .read_as_array_buffer(&slice)
            .map_err(browser_error)?;
        let bytes = js_sys::Uint8Array::new(&buffer);
        if bytes.length() as usize != count {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Incomplete browser File range",
            ));
        }
        bytes.copy_to(&mut output[..count]);
        self.position = end;
        Ok(count)
    }
}

impl Seek for FileSource {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(position) => position as i128,
            SeekFrom::Current(offset) => self.position as i128 + offset as i128,
            SeekFrom::End(offset) => self.size as i128 + offset as i128,
        };
        self.position = u64::try_from(position).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "Invalid browser File seek")
        })?;
        Ok(self.position)
    }
}
