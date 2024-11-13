/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */
// Rewrite with gpt

use capstone::arch;
use capstone::arch::x86::X86OpMem;
use capstone::arch::x86::X86Operand;
use capstone::arch::x86::X86OperandType;
use capstone::arch::x86::X86Reg;
use capstone::arch::ArchOperand;
use capstone::prelude::*;
use capstone::Capstone;

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

pub fn decode_stub_argument_wrapper_x64(
    code: &[u8],
    arg_number: u8,
    symbol_value: u64,
    addr_base: u64,
) -> u64 {
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Att)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");

    let target_register64: RegId = match arg_number {
        0 => X86Reg::X86_REG_RDI.into(),
        1 => X86Reg::X86_REG_RSI.into(),
        2 => X86Reg::X86_REG_RDX.into(),
        _ => return 0,
    };

    let target_register32: RegId = match arg_number {
        0 => X86Reg::X86_REG_EDI.into(),
        1 => X86Reg::X86_REG_ESI.into(),
        2 => X86Reg::X86_REG_EDX.into(),
        _ => return 0,
    };

    let mut off = 0;

    for insn in cs
        .disasm_all(code, 0)
        .expect("Failed to disassemble code")
        .iter()
    {
        off += insn.len();
        let mnemonic = insn.mnemonic().unwrap();
        let detail: InsnDetail = cs.insn_detail(insn).expect("Failed to get insn detail");
        let arch_detail: ArchDetail = detail.arch_detail();
        let ops = arch_detail.operands();

        if mnemonic.starts_with("call") || mnemonic.starts_with("jmp") {
            // 调用/跳转指令表示结束
            return 0;
        }

        if mnemonic.starts_with("mov") || mnemonic.starts_with("lea") {
            if let Some(reg) = ops.get(1).and_then(|x| op_reg(x)) {
                if reg == target_register64 || reg == target_register32 {
                    if let Some(imm) = ops.get(0).and_then(|x| op_imm(x)) {
                        return imm as u64;
                    }

                    if let Some(mem) = ops.get(0).and_then(|x| op_mem(x)) {
                        if mem.base() == X86Reg::X86_REG_RIP.into() {
                            return symbol_value + off as u64 + mem.disp() as u64;
                        } else if addr_base != 0 {
                            return addr_base + mem.disp() as u64;
                        }
                    }
                }
            }
        }
    }

    0
}

pub fn decode_stub_argument_wrapper(
    code: &[u8],
    arg_number: u8,
    symbol_value: u64,
    addr_base: u64,
) -> u64 {
    decode_stub_argument_wrapper_x64(code, arg_number, symbol_value, addr_base)
}
