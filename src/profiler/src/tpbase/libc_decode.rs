/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */
// Rewrite with gpt
use anyhow::bail;
use anyhow::Result;
use capstone::arch;
use capstone::arch::x86::X86InsnGroup;
use capstone::arch::x86::X86OpMem;
use capstone::arch::x86::X86Operand;
use capstone::arch::x86::X86OperandType;
use capstone::arch::x86::X86Reg;
use capstone::arch::ArchOperand;
use capstone::prelude::*;
use capstone::Capstone;
use capstone::InsnGroupType;
use std::cmp::max;

use crate::probes::types::bpf;

fn op_mem<'a>(op: &'a ArchOperand) -> Option<&'a X86OpMem> {
    if let ArchOperand::X86Operand(X86Operand {
        op_type: X86OperandType::Mem(op_mem),
        ..
    }) = op
    {
        return Some(op_mem);
    }
    None
}

fn op_reg(op: &ArchOperand) -> Option<RegId> {
    if let ArchOperand::X86Operand(X86Operand {
        op_type: X86OperandType::Reg(id),
        ..
    }) = op
    {
        return Some(*id);
    }
    None
}

fn op_imm(op: &ArchOperand) -> Option<i64> {
    if let ArchOperand::X86Operand(X86Operand {
        op_type: X86OperandType::Imm(id),
        ..
    }) = op
    {
        return Some(*id);
    }
    None
}

#[derive(Debug, Default, Copy, Clone)]
struct RegInfo {
    state: u8,
    multiplier: u8,
    indirect: u8,
    offset: i16,
}

const UNSPEC: u8 = 0;
const TSDBASE: u8 = 1;
const TSDELEMENTBASE: u8 = 2;
const TSDINDEX: u8 = 3;
const TSDVALUE: u8 = 4;

fn reg2ndx(reg: RegId) -> usize {
    let reg = X86Reg::Type::from(reg.0);
    match reg {
        X86Reg::X86_REG_RAX
        | X86Reg::X86_REG_EAX
        | X86Reg::X86_REG_AX
        | X86Reg::X86_REG_AL
        | X86Reg::X86_REG_AH => 1,
        X86Reg::X86_REG_RCX
        | X86Reg::X86_REG_ECX
        | X86Reg::X86_REG_CX
        | X86Reg::X86_REG_CL
        | X86Reg::X86_REG_CH => 2,
        X86Reg::X86_REG_RDX
        | X86Reg::X86_REG_EDX
        | X86Reg::X86_REG_DX
        | X86Reg::X86_REG_DL
        | X86Reg::X86_REG_DH => 3,
        X86Reg::X86_REG_RBX
        | X86Reg::X86_REG_EBX
        | X86Reg::X86_REG_BX
        | X86Reg::X86_REG_BL
        | X86Reg::X86_REG_BH => 4,
        X86Reg::X86_REG_RSP | X86Reg::X86_REG_ESP | X86Reg::X86_REG_SP | X86Reg::X86_REG_SPL => 5,
        X86Reg::X86_REG_RBP | X86Reg::X86_REG_EBP | X86Reg::X86_REG_BP | X86Reg::X86_REG_BPL => 6,
        X86Reg::X86_REG_RSI | X86Reg::X86_REG_ESI | X86Reg::X86_REG_SI | X86Reg::X86_REG_SIL => 7,
        X86Reg::X86_REG_RDI | X86Reg::X86_REG_EDI | X86Reg::X86_REG_DI | X86Reg::X86_REG_DIL => 8,
        X86Reg::X86_REG_R8 | X86Reg::X86_REG_R8D | X86Reg::X86_REG_R8W | X86Reg::X86_REG_R8B => 9,
        X86Reg::X86_REG_R9 | X86Reg::X86_REG_R9D | X86Reg::X86_REG_R9W | X86Reg::X86_REG_R9B => 10,
        X86Reg::X86_REG_R10
        | X86Reg::X86_REG_R10D
        | X86Reg::X86_REG_R10W
        | X86Reg::X86_REG_R10B => 11,
        X86Reg::X86_REG_R11
        | X86Reg::X86_REG_R11D
        | X86Reg::X86_REG_R11W
        | X86Reg::X86_REG_R11B => 12,
        X86Reg::X86_REG_R12
        | X86Reg::X86_REG_R12D
        | X86Reg::X86_REG_R12W
        | X86Reg::X86_REG_R12B => 13,
        X86Reg::X86_REG_R13
        | X86Reg::X86_REG_R13D
        | X86Reg::X86_REG_R13W
        | X86Reg::X86_REG_R13B => 14,
        X86Reg::X86_REG_R14
        | X86Reg::X86_REG_R14D
        | X86Reg::X86_REG_R14W
        | X86Reg::X86_REG_R14B => 15,
        X86Reg::X86_REG_R15
        | X86Reg::X86_REG_R15D
        | X86Reg::X86_REG_R15W
        | X86Reg::X86_REG_R15B => 16,
        _ => 0,
    }
}

fn has_fs_segment(ops: &Vec<ArchOperand>) -> bool {
    for op in ops {
        if let Some(mem) = op_mem(op) {
            if mem.segment() == X86Reg::X86_REG_FS.into() {
                return true;
            }
            
        }
    }
    false
}


pub fn decode_pthread_getspecific(code: &[u8]) -> u32 {
    let mut regs = [RegInfo::default(); 18];
    let mut dest_ndx = 0;
    let mut src_ndx = 0;
    let mut index_ndx = 0;

    // RDI = first argument = key index
    regs[reg2ndx(X86Reg::X86_REG_RDI.into())] = RegInfo {
        state: TSDINDEX,
        multiplier: 1,
        ..Default::default()
    };

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");

    let insns = cs.disasm_all(code, 0).expect("Failed to disassemble code");

    for insn in insns.iter() {
        let mnemonic = insn.mnemonic().unwrap();
        let detail: InsnDetail = cs.insn_detail(insn).expect("Failed to get insn detail");
        let arch_detail: ArchDetail = detail.arch_detail();
        let ops = arch_detail.operands();

        if ops.is_empty() {
            if mnemonic == "endbr64" {
                continue;
            }
        } else {
            dest_ndx = match op_reg(&ops[0]) {
                Some(reg) => reg2ndx(reg),
                None => {
                    continue;
                }
            };
        }

        match mnemonic {
            "shl" => {
                let value = op_imm(&ops[1]).unwrap() as i16;
                regs[dest_ndx].offset <<= value;
                regs[dest_ndx].multiplier <<= value;
            }
            "add" => {
                if has_fs_segment(&ops) && regs[dest_ndx].state == TSDINDEX{
                    regs[dest_ndx].state = TSDELEMENTBASE;
                    continue;
                }
                if let Some(reg) = op_reg(&ops[1]) {
                    src_ndx = reg2ndx(reg);
                    if (regs[dest_ndx].state == TSDBASE && regs[src_ndx].state == TSDINDEX)
                        || (regs[dest_ndx].state == TSDINDEX && regs[src_ndx].state == TSDBASE)
                    {
                        regs[dest_ndx].offset += regs[src_ndx].offset;
                        regs[dest_ndx].multiplier = max(
                            regs[dest_ndx].multiplier,
                            regs[src_ndx].multiplier,
                        );
                        regs[dest_ndx].state = TSDELEMENTBASE;
                        continue;
                    }
                } else if let Some(value) = op_imm(&ops[1]) {
                    regs[dest_ndx].offset += value as i16;
                }
            }
            "lea" => {
                let mem = op_mem(&ops[1]).unwrap();
                src_ndx = reg2ndx(mem.base());
                if regs[src_ndx].state == TSDINDEX {
                    if mem.index() == RegId::INVALID_REG {
                        regs[dest_ndx] = RegInfo {
                            state: TSDINDEX,
                            offset: regs[src_ndx].offset + mem.disp() as i16,
                            multiplier: regs[src_ndx].multiplier,
                            ..Default::default()
                        };
                    }
                } else if regs[src_ndx].state == TSDBASE {
                    index_ndx = reg2ndx(mem.index());
                    if regs[index_ndx].state == TSDINDEX {
                        regs[dest_ndx] = RegInfo {
                            state: TSDELEMENTBASE,
                            offset: regs[src_ndx].offset
                                + regs[index_ndx].offset
                                + mem.disp() as i16,
                            multiplier: regs[index_ndx].multiplier * (mem.scale() as u8),
                            ..Default::default()
                        };
                    }
                }
            }
            "mov" => {
                if has_fs_segment(&ops) {
                    regs[dest_ndx] = RegInfo {
                        state: TSDBASE,
                        ..Default::default()
                    };
                    continue;
                }
                if let Some(reg) = op_reg(&ops[1]) {
                    src_ndx = reg2ndx(reg);
                    regs[dest_ndx] = regs[src_ndx];
                    continue;
                }
                if let Some(mem) = op_mem(&ops[1]) {
                    src_ndx = reg2ndx(mem.base());
                    index_ndx = reg2ndx(mem.index());
                    if regs[src_ndx].state == TSDBASE {
                        if mem.index() == RegId::INVALID_REG {
                            regs[dest_ndx] = RegInfo {
                                state: TSDBASE,
                                offset: mem.disp() as i16,
                                indirect: 1,
                                ..Default::default()
                            };
                        } else if regs[index_ndx].state == TSDINDEX {
                            regs[dest_ndx] = RegInfo {
                                state: TSDVALUE,
                                offset: regs[src_ndx].offset,
                                indirect: regs[src_ndx].indirect,
                                multiplier: mem.scale() as u8,
                                ..Default::default()
                            };
                        }
                    } else if regs[src_ndx].state == TSDELEMENTBASE {
                        regs[dest_ndx] = RegInfo {
                            state: TSDVALUE,
                            offset: regs[src_ndx].offset + mem.disp() as i16,
                            indirect: regs[src_ndx].indirect,
                            multiplier: regs[src_ndx].multiplier * (mem.scale() as u8),
                            ..Default::default()
                        };
                    }
                }
            }
            "ret" => {
                src_ndx = reg2ndx(X86Reg::X86_REG_RAX.into()); // RAX
                if regs[src_ndx].state != TSDVALUE {
                    return 0;
                }
                return (regs[src_ndx].offset as u16 as u32)
                    | ((regs[src_ndx].multiplier as u32) << 16)
                    | ((regs[src_ndx].indirect as u32) << 24);
            }
            "cmp" | "test" => {
                // Opcodes without effect to dest_ndx.
            }
            _ => {
                // Unsupported opcode. Assume it modified the operand 0, and mark it unknown.
                regs[dest_ndx] = RegInfo {
                    state: UNSPEC,
                    ..Default::default()
                };
            }
        }
    }
    0
}

fn extract_tsd_info_x64_64(code: &[u8]) -> Result<bpf::TSDInfo> {
    let val = decode_pthread_getspecific(code);

    if val == 0 {
        bail!("unable to determine libc info");
    }

    Ok(bpf::TSDInfo {
        offset: (val & 0xffff) as i16,
        multiplier: (val >> 16) as u8,
        indirect: ((val >> 24) & 1) as u8,
    })
}

pub fn extract_tsd_info_native(code: &[u8]) -> Result<bpf::TSDInfo> {
    extract_tsd_info_x64_64(code)
}
