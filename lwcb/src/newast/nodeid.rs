use std::sync::atomic::{AtomicU32, Ordering};

static GLOBAL_NODE_COUNTER: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Debug, Copy, PartialEq)]
pub struct NodeId(u32);

impl NodeId {
    pub fn get() -> Self {
        Self(GLOBAL_NODE_COUNTER.fetch_add(1, Ordering::SeqCst))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nodeid() {
        assert_eq!(NodeId::get(), NodeId(0));
        assert_eq!(NodeId::get(), NodeId(1));
    }
}
