use super::info_vlen;
use crate::btf::BtfReader;

#[derive(Debug, Clone)]
pub struct DataSecInfo {
    pub type_id: u32,
    pub offset: u32,
    pub size: u32,
}

// https://docs.kernel.org/bpf/btf.html#btf-kind-datasec
#[derive(Debug, Clone)]
pub struct DataSec {
    pub name: String,
    pub size: u32,
    pub secs: Vec<DataSecInfo>,
}

impl DataSec {
    pub fn from_reader(reader: &mut BtfReader) -> Self {
        let name = reader.read_name();
        let info = reader.read_u32();
        let size = reader.read_u32();

        let vlen = info_vlen!(info);
        let mut secs = Vec::new();

        for _ in 0..vlen {
            secs.push(DataSecInfo {
                type_id: reader.read_u32(),
                offset: reader.read_u32(),
                size: reader.read_u32(),
            });
        }

        DataSec { name, size, secs }
    }
}
