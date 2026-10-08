use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
mod data;
mod header;

/// A Python module implemented in Rust.
#[pymodule]
fn cwa_reader_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(header::read_metadata, m)?)?;
    m.add_function(wrap_pyfunction!(header::sampling_consistency_report, m)?)?;
    m.add_function(wrap_pyfunction!(data::seconds, m)?)?;
    m.add_function(wrap_pyfunction!(data::blocks, m)?)?;
    m.add_function(wrap_pyfunction!(data::read_cwa_file, m)?)?;
    m.add_function(wrap_pyfunction!(data::write_cwa_csv, m)?)?;
    Ok(())
}
