use libbpf_rs::libbpf_sys::bpf_insn;
use object::write::Object;
use object::write::SectionId;
use object::write::Symbol;
use object::write::SymbolSection;
use object::SectionKind;
use object::SymbolFlags;
use object::SymbolKind;
use object::SymbolScope;

pub struct BPFObject {
    obj: Object<'static>,
}

impl BPFObject {
    pub fn new() -> Self {
        let mut obj = BPFObject {
            obj: Object::new(
                object::BinaryFormat::Elf,
                object::Architecture::Bpf,
                object::Endianness::Little,
            ),
        };
        obj.add_license();
        obj
    }

    fn add_license(&mut self) {
        let id = self
            .obj
            .add_section(vec![], "license".as_bytes().to_vec(), SectionKind::Text);
        self.obj
            .append_section_data(id, &"GPL".as_bytes().to_vec(), 1);
    }

    pub fn add_function(&mut self, sec_name: &str, name: &str, insts: &Vec<bpf_insn>) {
        let id = self
            .obj
            .add_section(vec![], sec_name.as_bytes().to_vec(), SectionKind::Text);
        let data: &[u8] =
            unsafe { std::slice::from_raw_parts(insts.as_ptr() as *const u8, insts.len() * 8) };
        self.add_symbol(name, id, (insts.len() * 8) as u64);
        self.obj.append_section_data(id, data, 8);
    }

    fn add_symbol(&mut self, name: &str, id: SectionId, sz: u64) {
        self.obj.add_symbol(Symbol {
            name: name.as_bytes().to_vec(),
            value: 0,
            size: sz,
            kind: SymbolKind::Text,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Section(id),
            flags: SymbolFlags::None,
        });
    }

    pub fn emit(self) -> Vec<u8> {
        self.obj.write().expect("failed to write BPF object")
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use libbpf_rs::libbpf_sys::BPF_ALU64;
    use libbpf_rs::libbpf_sys::BPF_EXIT;
    use libbpf_rs::libbpf_sys::BPF_JMP;
    use libbpf_rs::libbpf_sys::BPF_MOV;
    use libbpf_rs::ObjectBuilder;

    #[test]
    fn add_function() {
        let mut bpfobj = BPFObject::new();
        let mut insn2 = bpf_insn::default();
        let mut insn1 = bpf_insn::default();
        insn2.code = (BPF_JMP | BPF_EXIT) as u8;
        insn1.code = (BPF_ALU64 | BPF_MOV) as u8;
        insn1.set_dst_reg(0);
        bpfobj.add_function(
            "kprobe/tcp_sendmsg",
            "kprobe_tcp_sendmsg",
            &vec![insn1, insn2],
        );

        let mem_obj = bpfobj.emit();
        let mut builder = ObjectBuilder::default();
        let object = builder.open_memory("lwcb_test", &mem_obj).unwrap();
        let mut bpfskel = object.load().unwrap();
        bpfskel
            .prog_mut("kprobe_tcp_sendmsg")
            .unwrap()
            .attach()
            .unwrap();
    }
}
