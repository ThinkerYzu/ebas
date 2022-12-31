const BPF_LD: u8 = 0x00;
const BPF_LDX: u8 = 0x01;
const BPF_ST: u8 = 0x02;
const BPF_STX: u8 = 0x03;
const BPF_ALU: u8 = 0x04;
const BPF_JMP: u8 = 0x05;
const BPF_JMP32: u8 = 0x06;
const BPF_ALU64: u8 = 0x07;

const BPF_ADD: u8 = 0x00;
const BPF_SUB: u8 = 0x10;
const BPF_MUL: u8 = 0x20;
const BPF_DIV: u8 = 0x30;
const BPF_OR: u8 = 0x40;
const BPF_AND: u8 = 0x50;
const BPF_LSH: u8 = 0x60;
const BPF_RSH: u8 = 0x70;
const BPF_NEG: u8 = 0x80;
const BPF_MOD: u8 = 0x90;
const BPF_XOR: u8 = 0xa0;
const BPF_MOV: u8 = 0xb0;
const BPF_ARSH: u8 = 0xc0;
const BPF_END: u8 = 0xd0;

const BPF_K: u8 = 0x00;
const BPF_X: u8 = 0x08;

const BPF_TO_LE: u8 = 0x00;
const BPF_TO_BE: u8 = 0x08;

const BPF_JA: u8 = 0x00;
const BPF_JEQ: u8 = 0x10;
const BPF_JGT: u8 = 0x20;
const BPF_JGE: u8 = 0x30;
const BPF_JSET: u8 = 0x40;
const BPF_JNE: u8 = 0x50;
const BPF_JSGT: u8 = 0x60;
const BPF_JSGE: u8 = 0x70;
const BPF_CALL: u8 = 0x80;
const BPF_EXIT: u8 = 0x90;
const BPF_JLT: u8 = 0xa0;
const BPF_JLE: u8 = 0xb0;
const BPF_JSLT: u8 = 0xc0;
const BPF_JSLE: u8 = 0xd0;

const BPF_IMM: u8 = 0x00;
#[allow(dead_code)]
const BPF_ABS: u8 = 0x20;
#[allow(dead_code)]
const BPF_IND: u8 = 0x40;
const BPF_MEM: u8 = 0x60;
#[allow(dead_code)]
const BPF_ATOMIC: u8 = 0xc0;

const BPF_W: u8 = 0x00;
const BPF_H: u8 = 0x08;
const BPF_B: u8 = 0x10;
const BPF_DW: u8 = 0x18;

const SH_DST: usize = 8;
const SH_SRC: usize = 12;
const SH_OFF: usize = 16;
pub const SH_IMM: usize = 32;

fn get_regno(reg: &str) -> Result<u8, ()> {
    if reg.len() >= 2 && &reg[0..1] == "r" {
        let no = reg[1..].parse().map_err(|_| ())?;
        if no <= 10 {
            return Ok(no);
        }
    }
    Err(())
}

fn parse_u64(v: &str) -> Result<u64, ()> {
    if v.len() > 2 && &v[..2] == "0x" {
        u64::from_str_radix(&v[2..], 16).map_err(|_| ())
    } else {
        v.parse().map_err(|_| ())
    }
}

fn gen_alu(cmd: u8, cmd_sp: &[&str], dst: &str, src: &str, buf: &mut Vec<u8>) -> Result<(), ()> {
    let alu = if cmd_sp.len() == 2 {
        if cmd_sp[1] == "64" {
            BPF_ALU64
        } else {
            return Err(());
        }
    } else if cmd_sp.len() == 1 {
        BPF_ALU
    } else {
        return Err(());
    };
    match parse_u64(src) {
        Ok(v) => {
            let code = cmd as u64
                | BPF_K as u64
                | alu as u64
                | ((get_regno(dst)? as u64) << SH_DST)
                | v << SH_IMM;
            buf.extend(code.to_ne_bytes());
        }
        _ => {
            let code = cmd as u64
                | BPF_X as u64
                | alu as u64
                | ((get_regno(dst)? as u64) << SH_DST)
                | ((get_regno(src)? as u64) << SH_SRC);
            buf.extend(code.to_ne_bytes());
        }
    }
    Ok(())
}

fn gen_jmp(
    cmd: u8,
    cmd_sp: &[&str],
    dst: &str,
    src: &str,
    off: isize,
    buf: &mut Vec<u8>,
) -> Result<(), ()> {
    let jtype = if cmd_sp.len() == 2 {
        if cmd_sp[1] == "32" {
            BPF_JMP32
        } else {
            return Err(());
        }
    } else {
        BPF_JMP
    };
    let code = cmd as u64
        | jtype as u64
        | (get_regno(dst)? as u64) << SH_DST
        | (get_regno(src)? as u64) << SH_SRC
        | ((off & 0xffff) as u64) << SH_OFF;
    buf.extend(code.to_ne_bytes());
    Ok(())
}

pub fn ebpf_code_gen(
    cmd: &str,
    dst: &str,
    dst_off: isize,
    src: &str,
    src_off: isize,
    buf: &mut Vec<u8>,
) -> Result<(), ()> {
    let cmd_sp: Vec<_> = cmd.split('.').collect();
    match cmd_sp[0] {
        "add" => {
            if src_off != 0 || dst_off != 0 {
                return Err(());
            }
            gen_alu(BPF_ADD, cmd_sp.as_slice(), dst, src, buf)?;
        }
        "sub" => {
            if src_off != 0 || dst_off != 0 {
                return Err(());
            }
            gen_alu(BPF_SUB, cmd_sp.as_slice(), dst, src, buf)?;
        }
        "mul" => {
            if src_off != 0 || dst_off != 0 {
                return Err(());
            }
            gen_alu(BPF_MUL, cmd_sp.as_slice(), dst, src, buf)?;
        }
        "div" => {
            if src_off != 0 || dst_off != 0 {
                return Err(());
            }
            gen_alu(BPF_DIV, cmd_sp.as_slice(), dst, src, buf)?;
        }
        "or" => {
            if src_off != 0 || dst_off != 0 {
                return Err(());
            }
            gen_alu(BPF_OR, cmd_sp.as_slice(), dst, src, buf)?;
        }
        "and" => {
            if src_off != 0 || dst_off != 0 {
                return Err(());
            }
            gen_alu(BPF_AND, cmd_sp.as_slice(), dst, src, buf)?;
        }
        "lsh" => {
            if src_off != 0 || dst_off != 0 {
                return Err(());
            }
            gen_alu(BPF_LSH, cmd_sp.as_slice(), dst, src, buf)?;
        }
        "rsh" => {
            if src_off != 0 || dst_off != 0 {
                return Err(());
            }
            gen_alu(BPF_RSH, cmd_sp.as_slice(), dst, src, buf)?;
        }
        "neg" => {
            if src_off != 0 || dst_off != 0 {
                return Err(());
            }
            gen_alu(BPF_NEG, cmd_sp.as_slice(), dst, src, buf)?;
        }
        "mod" => {
            if src_off != 0 || dst_off != 0 {
                return Err(());
            }
            gen_alu(BPF_MOD, cmd_sp.as_slice(), dst, src, buf)?;
        }
        "xor" => {
            if src_off != 0 || dst_off != 0 {
                return Err(());
            }
            gen_alu(BPF_XOR, cmd_sp.as_slice(), dst, src, buf)?;
        }
        "mov" => {
            if src_off != 0 || dst_off != 0 {
                return Err(());
            }
            gen_alu(BPF_MOV, cmd_sp.as_slice(), dst, src, buf)?;
        }
        "arsh" => {
            if src_off != 0 || dst_off != 0 {
                return Err(());
            }
            gen_alu(BPF_ARSH, cmd_sp.as_slice(), dst, src, buf)?;
        }
        "end" => {
            if src_off != 0 || dst_off != 0 {
                return Err(());
            }
            if cmd_sp.len() != 2 {
                return Err(());
            }
            let imm = match src {
                "16" => 16,
                "32" => 32,
                "64" => 64,
                _ => {
                    return Err(());
                }
            };
            match cmd_sp[1] {
                "le" => {
                    let code = BPF_END as u64
                        | BPF_TO_LE as u64
                        | BPF_ALU as u64
                        | (get_regno(dst)? as u64) << SH_DST
                        | (imm as u64) << SH_IMM;
                    buf.extend(code.to_ne_bytes());
                }
                "be" => {
                    let code = BPF_END as u64
                        | BPF_TO_BE as u64
                        | BPF_ALU as u64
                        | (get_regno(dst)? as u64) << SH_DST
                        | (imm as u64) << SH_IMM;
                    buf.extend(code.to_ne_bytes());
                }
                _ => {
                    return Err(());
                }
            }
        }
        "ja" => {
            gen_jmp(BPF_JA, cmd_sp.as_slice(), dst, src, src_off, buf)?;
        }
        "jeq" => {
            gen_jmp(BPF_JEQ, cmd_sp.as_slice(), dst, src, src_off, buf)?;
        }
        "jgt" => {
            gen_jmp(BPF_JGT, cmd_sp.as_slice(), dst, src, src_off, buf)?;
        }
        "jge" => {
            gen_jmp(BPF_JGE, cmd_sp.as_slice(), dst, src, src_off, buf)?;
        }
        "jset" => {
            gen_jmp(BPF_JSET, cmd_sp.as_slice(), dst, src, src_off, buf)?;
        }
        "jne" => {
            gen_jmp(BPF_JNE, cmd_sp.as_slice(), dst, src, src_off, buf)?;
        }
        "jsgt" => {
            gen_jmp(BPF_JSGT, cmd_sp.as_slice(), dst, src, src_off, buf)?;
        }
        "jsge" => {
            gen_jmp(BPF_JSGE, cmd_sp.as_slice(), dst, src, src_off, buf)?;
        }
        "call" => {
            if dst_off != 0 || !src.is_empty() || src_off != 0 {
                return Err(());
            }
            let code = if cmd_sp.len() == 2 {
                if cmd_sp[1] == "helper" {
                    BPF_JMP as u64 | BPF_CALL as u64 | parse_u64(dst)? << SH_IMM
                } else {
                    return Err(());
                }
            } else if cmd_sp.len() == 1 {
                BPF_JMP as u64 | BPF_CALL as u64 | 0x1000 | parse_u64(dst)? << SH_IMM
            } else {
                return Err(());
            };
            buf.extend(code.to_ne_bytes());
        }
        "exit" => {
            let code = BPF_JMP as u64 | BPF_EXIT as u64 | parse_u64(dst)? << SH_IMM;
            buf.extend(code.to_ne_bytes());
        }
        "jlt" => {
            gen_jmp(BPF_JLT, cmd_sp.as_slice(), dst, src, src_off, buf)?;
        }
        "jle" => {
            gen_jmp(BPF_JLE, cmd_sp.as_slice(), dst, src, src_off, buf)?;
        }
        "jslt" => {
            gen_jmp(BPF_JSLT, cmd_sp.as_slice(), dst, src, src_off, buf)?;
        }
        "jsle" => {
            gen_jmp(BPF_JSLE, cmd_sp.as_slice(), dst, src, src_off, buf)?;
        }
        "ld" => {
            if cmd_sp.len() != 2 {
                return Err(());
            }
            if dst_off != 0 {
                return Err(());
            }
            let sz = match cmd_sp[1] {
                "w" => BPF_W,
                "h" => BPF_H,
                "b" => BPF_B,
                "dw" => BPF_DW,
                _ => {
                    return Err(());
                }
            };
            if sz == BPF_DW {
                if let Ok(v) = parse_u64(src) {
                    let code = BPF_LD as u64
                        | BPF_DW as u64
                        | BPF_IMM as u64
                        | (get_regno(dst)? as u64) << SH_DST;
                    buf.extend(code.to_ne_bytes());
                    buf.extend(v.to_ne_bytes());
                    return Ok(());
                }
            }
            let code = BPF_LDX as u64
                | sz as u64
                | BPF_MEM as u64
                | (get_regno(dst)? as u64) << SH_DST
                | (get_regno(src)? as u64) << SH_SRC
                | ((src_off & 0xffff) as u64) << SH_OFF;
            buf.extend(code.to_ne_bytes());
        }
        "st" => {
            if cmd_sp.len() != 2 {
                return Err(());
            }
            if src_off != 0 {
                return Err(());
            }
            let sz = match cmd_sp[1] {
                "w" => BPF_W,
                "h" => BPF_H,
                "b" => BPF_B,
                "dw" => BPF_DW,
                _ => {
                    return Err(());
                }
            };
            let code = if let Ok(imm) = parse_u64(src) {
                BPF_ST as u64
                    | sz as u64
                    | BPF_MEM as u64
                    | (get_regno(dst)? as u64) << SH_DST
                    | ((dst_off & 0xffff) as u64) << SH_OFF
                    | imm << SH_IMM
            } else {
                BPF_STX as u64
                    | sz as u64
                    | BPF_MEM as u64
                    | (get_regno(dst)? as u64) << SH_DST
                    | (get_regno(src)? as u64) << SH_SRC
                    | ((dst_off & 0xffff) as u64) << SH_OFF
            };
            buf.extend(code.to_ne_bytes());
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_code_gen() {
        let mut buf = vec![];

        let r = ebpf_code_gen("add", "r1", 0, "r2", 0, &mut buf);
        assert_eq!(r, Ok(()));
        assert_eq!(buf, [BPF_ALU | BPF_ADD | BPF_X, 0x21, 0, 0, 0, 0, 0, 0]);

        buf.clear();
        let r = ebpf_code_gen("add", "r1", 0, "10", 0, &mut buf);
        assert_eq!(r, Ok(()));
        assert_eq!(buf, [BPF_ALU | BPF_ADD | BPF_K, 0x1, 0, 0, 0xa, 0, 0, 0]);

        buf.clear();
        let r = ebpf_code_gen("sub.64", "r1", 0, "10", 0, &mut buf);
        assert_eq!(r, Ok(()));
        assert_eq!(buf, [BPF_ALU64 | BPF_SUB | BPF_K, 0x1, 0, 0, 0xa, 0, 0, 0]);

        buf.clear();
        let r = ebpf_code_gen("mov.64", "r1", 0, "0x10", 0, &mut buf);
        assert_eq!(r, Ok(()));
        assert_eq!(buf, [BPF_ALU64 | BPF_MOV | BPF_K, 0x1, 0, 0, 0x10, 0, 0, 0]);

        buf.clear();
        let r = ebpf_code_gen("mov", "r1", 0, "10", 0, &mut buf);
        assert_eq!(r, Ok(()));
        assert_eq!(buf, [BPF_ALU | BPF_MOV | BPF_K, 0x1, 0, 0, 0xa, 0, 0, 0]);

        buf.clear();
        let r = ebpf_code_gen("mov", "r1", 0, "r3", 0, &mut buf);
        assert_eq!(r, Ok(()));
        assert_eq!(buf, [BPF_ALU | BPF_MOV | BPF_X, 0x31, 0, 0, 0, 0, 0, 0]);

        buf.clear();
        let r = ebpf_code_gen("st.dw", "r10", -8, "r1", 0, &mut buf);
        assert_eq!(r, Ok(()));
        assert_eq!(
            buf,
            [BPF_STX | BPF_DW | BPF_MEM, 0x1a, 0xf8, 0xff, 0, 0, 0, 0]
        );

        buf.clear();
        let r = ebpf_code_gen("st.dw", "r10", -8, "0x30", 0, &mut buf);
        assert_eq!(r, Ok(()));
        assert_eq!(
            buf,
            [BPF_ST | BPF_DW | BPF_MEM, 0x0a, 0xf8, 0xff, 0x30, 0, 0, 0]
        );

        buf.clear();
        let r = ebpf_code_gen("ld.dw", "r10", 0, "0x3033", 0, &mut buf);
        assert_eq!(r, Ok(()));
        assert_eq!(
            buf,
            [
                BPF_LD | BPF_DW | BPF_IMM,
                0x0a,
                0,
                0,
                0,
                0,
                0,
                0,
                0x33,
                0x30,
                0,
                0,
                0,
                0,
                0,
                0
            ]
        );

        buf.clear();
        let r = ebpf_code_gen("ld.w", "r10", 0, "0x3033", 0, &mut buf);
        assert_eq!(r, Err(()));

        buf.clear();
        let r = ebpf_code_gen("ld.dw", "r10", 0, "r5", 0x30, &mut buf);
        assert_eq!(r, Ok(()));
        assert_eq!(buf, [BPF_LDX | BPF_DW | BPF_MEM, 0x5a, 0x30, 0, 0, 0, 0, 0]);

        buf.clear();
        let r = ebpf_code_gen("jeq", "r1", 0, "r0", 28, &mut buf);
        assert_eq!(r, Ok(()));
        assert_eq!(buf, [BPF_JMP | BPF_JEQ, 0x1, 0x1c, 0, 0, 0, 0, 0]);

        buf.clear();
        let r = ebpf_code_gen("jsgt.32", "r1", 0, "r0", 24, &mut buf);
        assert_eq!(r, Ok(()));
        assert_eq!(buf, [BPF_JMP32 | BPF_JSGT, 0x1, 0x18, 0, 0, 0, 0, 0]);

        buf.clear();
        let r = ebpf_code_gen("call", "0x33", 0, "", 0, &mut buf);
        assert_eq!(r, Ok(()));
        assert_eq!(buf, [BPF_JMP | BPF_CALL, 0x10, 0, 0, 0x33, 0, 0, 0]);

        buf.clear();
        let r = ebpf_code_gen("call.helper", "0x33", 0, "", 0, &mut buf);
        assert_eq!(r, Ok(()));
        assert_eq!(buf, [BPF_JMP | BPF_CALL, 0x0, 0, 0, 0x33, 0, 0, 0]);
    }
}
