use pyo3::prelude::*;
use pyo3::wrap_pyfunction;
mod errors;
mod header;
mod package;


/// A Python module implemented in Rust.
#[pymodule]
fn cwa_reader_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(header::read_header, m)?)?;
    m.add_function(wrap_pyfunction!(package::read_cwa_file, m)?)?;
    Ok(())
}

