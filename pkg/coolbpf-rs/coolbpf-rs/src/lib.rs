mod coolbpf;
mod error;
pub mod logger;
pub use coolbpf::CoolBPF;

pub use libbpf_rs;
pub use metrics;

pub mod exporter;
pub mod helper;

/// Convert vec to struct
pub fn vec_to_anytype<'a, T>(data: &'a mut Vec<u8>) -> &'a T {
    let (head, body, _) = unsafe { data.align_to_mut::<T>() };
    assert!(head.is_empty(), "Data was not aligned");
    &body[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vec_to_anytype() {
        struct Event {
            cpu: u32,
        }

        let mut data: Vec<u8> = vec![1, 1, 1, 1];
        let event = vec_to_anytype::<Event>(&mut data);
        assert_eq!(event.cpu, 0x01010101);
    }
}
