use libbpf_rs::MapFlags;
use libbpf_rs::MapHandle;

use super::types::bpf;
use super::types::impl_default;

pub struct SystemAnalysis {
    raw: bpf::SystemAnalysis,
}

impl SystemAnalysis {}

impl_default!(SystemAnalysis);

pub struct SystemAnalysisMap {
    map: MapHandle,
}

impl SystemAnalysisMap {
    pub fn new(map: MapHandle) -> Self {
        SystemAnalysisMap { map }
    }

    pub fn key0_update(&self, sa: &SystemAnalysis) {
        let key: i32 = 0;
        self.map
            .update(&key.to_ne_bytes(), sa.slice(), MapFlags::ANY)
            .expect("failed to update system analysis map");
    }

    pub fn key0_lookup(&self) -> SystemAnalysis {
        let key: i32 = 0;
        let data = self
            .map
            .lookup(&key.to_ne_bytes(), MapFlags::ANY)
            .expect("failed to lookup system analysis map")
            .unwrap();

        let (head, body, _tail) = unsafe { data.align_to::<bpf::SystemAnalysis>() };
        debug_assert!(head.is_empty(), "Data was not aligned");
        let event = body[0];
        SystemAnalysis { raw: event }
    }
}
