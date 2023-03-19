use crate::types::Type;








pub trait EventHandle {

    fn handle(&mut self, typ: &Type, data: &[u8]);
}


pub struct EventPrinter {
}

impl EventPrinter {
    pub fn new() -> Self {
        EventPrinter {  }
    }
}

impl EventHandle for EventPrinter {

    fn handle(&mut self, typ: &Type, data: &[u8]) {
        match &typ.kind {

            _ => todo!()
        }
    }
}


pub struct EventStringify {



}


impl EventHandle for EventStringify {
    fn handle(&mut self, typ: &Type, data: &[u8]) {
        
    }
}


pub struct PerfEvent {
    handler: Box<dyn EventHandle>,
    typ: Type,
}


impl PerfEvent {


    pub fn printer(fmt: String, typ: Type) -> Self {
        Self {
            handler: Box::new(EventPrinter::new()),
            typ,
        }
    }

}