use std::collections::HashMap;
use std::fs::read_to_string;

#[derive(Debug, Clone)]
pub struct TenSecHeatMap {
    pub pid: u32,
    pub comm: String,
    pub base: u64,
    pub values: [u16; 500],
}

impl TenSecHeatMap {
    pub fn new(pid: u32, comm: String) -> Self {
        TenSecHeatMap {
            pid,
            comm,
            base: 0,
            values: [0; 500],
        }
    }

    pub fn inc(&mut self, slot: usize) {
        self.values[slot] += 1;
    }
}

#[derive(Default)]
pub struct ProcessHeatMap {
    pub heat_maps: HashMap<u32, TenSecHeatMap>,
}

impl ProcessHeatMap {
    pub fn add_process(&mut self, pid: u32) {
        self.heat_maps.entry(pid).or_insert_with(|| {
            let comm = match read_to_string(format!("/proc/{pid}/comm")) {
                Ok(mut comm) => {
                    comm.pop();
                    comm
                }
                Err(_) => "Unknown".to_string(),
            };

            TenSecHeatMap::new(pid, comm)
        });
    }

    pub fn add(&mut self, pid: u32, ts: u64) -> Option<TenSecHeatMap> {
        let mut ret = None;
        match self.heat_maps.get_mut(&pid) {
            Some(heat) => {
                let ms = ts / 1000 / 1000;
                let ten_sec = ms % (1000 * 10);
                let base = ms / (1000 * 10);
                let slot = (ten_sec / 20) as usize;
                if heat.base != base {
                    if heat.base != 0 {
                        ret = Some(heat.clone());
                        heat.values.iter_mut().for_each(|x| *x = 0);
                    }
                    heat.base = base;
                }
                heat.inc(slot);
            }
            None => {}
        }
        ret
    }
}
