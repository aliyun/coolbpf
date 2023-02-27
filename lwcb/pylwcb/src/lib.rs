use lwcb::{LwCB, enable_python};
use pyo3::prelude::*;

#[pyclass(unsendable)]
struct Pylwcb {
    lwcb: LwCB,
    text: String,
}

#[pymethods]
impl Pylwcb {
    #[new]
    fn new(text: String) -> Self {
        enable_python();
        Pylwcb { lwcb: LwCB::new(), text }
    }

    fn attach(&mut self) {
        self.lwcb.compile(&self.text).unwrap();
        self.lwcb.generate_bytecode().unwrap();
        self.lwcb.attach().unwrap();
    }

    fn read_events(&mut self) -> PyResult<Vec<Vec<String>>>{
        Ok(self.lwcb.read_events())
    }
}

#[pyfunction]
fn say_hello() -> PyResult<String> {
    Ok("hello from pylwcb modules".to_string())
}

/// A Python module implemented in Rust. The name of this function must match
/// the `lib.name` setting in the `Cargo.toml`, else Python will not be able to
/// import the module.
#[pymodule]
fn pylwcb(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(say_hello, m)?)?;
    m.add_class::<Pylwcb>()?;
    Ok(())
}
