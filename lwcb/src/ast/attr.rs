#[derive(Debug, PartialEq, Clone)]
pub struct Attr<T> {
    node: T,
}

impl<T> Attr<T> {
    pub fn new(node: T) -> Self {
        Self { node }
    }
}
