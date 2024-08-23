use byteorder::NativeEndian;
use byteorder::ReadBytesExt as _;
use libbpf_rs::MapFlags;
use libbpf_rs::MapHandle;
use std::io::Cursor;

pub struct StackMap {
    map: MapHandle,
}

impl StackMap {
    pub fn new(map: MapHandle) -> Self {
        Self { map }
    }

    pub fn lookup(&self, id: i32) -> Vec<u64> {
        let mut ret = vec![];

        match self.map.lookup(&id.to_ne_bytes(), MapFlags::ANY) {
            Ok(x) => match x {
                Some(bytes) => {
                    let depth = bytes.len() / 8;
                    let mut rdr = Cursor::new(bytes);

                    for _ in 0..depth {
                        let addr = rdr.read_u64::<NativeEndian>().unwrap();
                        if addr == 0 {
                            break;
                        }
                        ret.push(addr);
                    }
                }
                None => {}
            },

            Err(e) => {
                log::debug!("failed to lookup stack map for id: {id}, err: {e}");
            }
        }

        ret
    }
}
