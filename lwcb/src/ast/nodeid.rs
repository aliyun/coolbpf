use std::sync::atomic::{Ordering, AtomicUsize};

static GLOBAL_NODE_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Debug, Copy, PartialEq)]
pub struct NodeId(usize);

impl NodeId {
    pub fn get() -> Self {
        Self(GLOBAL_NODE_COUNTER.fetch_add(1, Ordering::SeqCst))
    }

    pub fn id(&self) -> usize {
        self.0
    }

    pub fn current() -> usize {
        GLOBAL_NODE_COUNTER.load(Ordering::Relaxed)
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
