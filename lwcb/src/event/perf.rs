




pub struct Perf {
    printer: Option<Printer>,
    stringify: Option<Stringify>,
    typ: Type,
}


impl Perf {

    pub fn new(typ: Type) -> Self {
        Self {
            printer: None,
            stringify: None,
        }
    }

    pub fn printer(fmt: String, typ: Type) -> Self {
        Self {
            printer: Box::new(EventPrinter::new()),
            typ,
        }
    }

    pub fn stringify(typ: Type) -> Self {
        Self {
            typ,
        }
    }



}