use crate::interpreter::Interpreter;
use crate::pb::ustack;
use crate::pb::LivetraceCell;
use crate::pb::LivetraceList;
use crate::pb::Ustack;
use crate::probes::event::RawStack;
use crate::probes::event::RawUserStack;
use crate::probes::probes::Probes;
use crate::probes::types::bpf;
use crate::symbollizer::file_id::FileId64;
use crate::symbollizer::symbolizer::Symbol;
use crate::symbollizer::symbolizer::Symbolizer;
use anyhow::bail;
use anyhow::Result;
use protobuf::Message;
use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct KernelStack {
    syms: Vec<Symbol>,
}

impl KernelStack {
    pub fn new(symer: &Symbolizer, addrs: &Vec<u64>) -> Result<Self> {
        let frames = symer.kernel_symbolize(addrs);
        Ok(KernelStack { syms: frames })
    }
}

#[derive(Debug, Default)]
pub struct UserStack {
    syms: Vec<Symbol>,
}

impl UserStack {
    pub fn native(symer: &mut Symbolizer, probes: &mut Probes, pid: u32, id: i32) -> Result<Self> {
        let addrs = probes.stack_map.lookup(id);
        if addrs.is_empty() {
            bail!("miss kernel stack for id: {id}")
        }
        let frames = symer.proc_symbolize(pid, &addrs)?;
        Ok(UserStack { syms: frames })
    }

    pub fn new(symer: &mut Symbolizer, pid: u32, addrs: &Vec<u64>) -> Result<Self> {
        let frames = symer.proc_symbolize(pid, &addrs)?;
        Ok(UserStack { syms: frames })
    }
}

pub enum Frame {
    Addr(u64),
    Java(String),
}

#[derive(Debug, Default)]
pub struct Stack {
    count: u32,
    frames: Vec<Symbol>,
}

impl Stack {
    pub fn new(
        symer: &mut Symbolizer,
        raw: &RawStack,
        inters: &mut HashMap<u32, Interpreter>,
        cnt: u32,
    ) -> Result<Self> {
        let mut stack = Stack::default();
        let pid = raw.pid;
        if !raw.kernel.is_empty() {
            let kernel = KernelStack::new(symer, &raw.kernel)?;
            stack.frames.extend(kernel.syms);
        }

        match &raw.user {
            RawUserStack::Dynamic(frames) => {
                for i in frames {
                    let addr = i.addr_or_line;
                    let frame = i.kind as u32;
                    if frame == bpf::FRAME_MARKER_NATIVE {
                        let id = i.file_id;
                        let sym = symer.fileid_symbolize(&FileId64(id), addr);
                        stack.push(sym);
                    } else {
                        if let Some(inter) = inters.get_mut(&pid) {
                            let _ = inter.symbolize(&i, &mut stack);
                        }
                    }
                }
            }
            RawUserStack::Native(addrs) => {
                let user = UserStack::new(symer, pid, addrs)?;
                stack.frames.extend(user.syms);
            }
        }

        stack.count = cnt;
        Ok(stack)
    }

    pub fn push(&mut self, frame: Symbol) {
        self.frames.push(frame);
    }

    pub fn empty(&self) -> bool {
        self.frames.is_empty()
    }
}

impl ToString for Stack {
    fn to_string(&self) -> String {
        let s = self
            .frames
            .iter()
            .rev()
            .map(|x| x.name.clone())
            .collect::<Vec<String>>()
            .join(";");

        format!("{} {}", s, self.count)
    }
}

pub struct StackCounter {
    stacks: HashMap<RawStack, u32>,
    total: usize,
}

impl StackCounter {
    pub fn new() -> Self {
        StackCounter {
            stacks: HashMap::new(),
            total: 0,
        }
    }

    pub fn add(&mut self, raw: RawStack) {
        let count = self.stacks.entry(raw).or_insert(0);
        *count += 1;
        self.total += 1;
    }

    pub fn len(&self) -> usize {
        self.total
    }
}

#[derive(Default)]
pub struct StackAggregator {
    stacks: HashMap<u32, StackCounter>,
    pub total: usize,
}

impl StackAggregator {
    pub fn add(&mut self, raw: RawStack) {
        let sc = self.stacks.entry(raw.pid).or_insert(StackCounter::new());
        self.total += 1;
        sc.add(raw);
    }

    pub fn filter(&mut self, threshold: usize) {
        self.stacks.retain(|_, x| x.len() > threshold);
    }

    pub fn serialize(
        &mut self,
        symer: &mut Symbolizer,
        inters: &mut HashMap<u32, Interpreter>,
    ) -> Vec<u8> {
        let mut list = LivetraceList::new();
        for (pid, sc) in &self.stacks {
            for (raw, cnt) in &sc.stacks {
                let mut cell = LivetraceCell::new();
                cell.pid = *pid;
                cell.samples = *cnt;
                cell.kstack = raw.kernel.clone();
                cell.kstack.reverse();

                match &raw.user {
                    RawUserStack::Dynamic(frames) => {
                        for i in frames {
                            let addr = i.addr_or_line;
                            let frame = i.kind as u32;
                            if frame == bpf::FRAME_MARKER_NATIVE {
                                let id = i.file_id;
                                let mut ustack = Ustack::new();
                                let sym = symer.bias_by_fileid(&FileId64(id));
                                ustack.set_addr(*sym.unwrap() + addr);
                                cell.ustack.push(ustack);
                            } else {
                                // todo!("not support");
                                log::debug!("frame type: {}", frame);
                            }
                        }
                    }
                    RawUserStack::Native(addrs) => {
                        cell.ustack = addrs
                            .iter()
                            .map(|x| {
                                let mut ustack = Ustack::new();
                                ustack.set_addr(*x);
                                ustack
                            })
                            .collect();
                    }
                }
                cell.ustack.reverse();
                list.list.push(cell);
            }
        }

        list.write_to_bytes().unwrap()
    }

    pub fn symbolize(
        &mut self,
        symer: &mut Symbolizer,
        inters: &mut HashMap<u32, Interpreter>,
    ) -> Vec<SymbolizedStack> {
        let mut symbolized_stacks = vec![];
        for (pid, sc) in &self.stacks {
            let mut stacks = vec![];
            let mut count = 0;
            for (raw, &cnt) in &sc.stacks {
                match Stack::new(symer, raw, inters, cnt) {
                    Ok(stack) => {
                        stacks.push(stack);
                        count += cnt;
                    }
                    Err(e) => {
                        log::error!("{e}");
                        // the error indicates that the process may have already exited,
                        // and there is no need to symbolically resolve
                        break;
                    }
                }
            }

            if !stacks.is_empty() {
                symbolized_stacks.push(SymbolizedStack {
                    pid: *pid,
                    comm: match symer.proc_comm(*pid) {
                        Ok(comm) => comm.clone(),
                        Err(_) => String::new(),
                    },
                    stacks,
                    count,
                });
            }
        }
        symbolized_stacks
    }
}

pub struct SymbolizedStack {
    pub pid: u32,
    pub comm: String,
    pub count: u32,
    stacks: Vec<Stack>,
}

impl ToString for SymbolizedStack {
    fn to_string(&self) -> String {
        self.stacks
            .iter()
            .map(|x| format!("{}:{};{}", self.comm, self.pid, x.to_string()))
            .collect::<Vec<String>>()
            .join("\n")
    }
}
