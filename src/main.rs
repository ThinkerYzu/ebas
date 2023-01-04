use std::ffi::{CStr, CString};
use std::mem;
use std::ptr;
use std::slice;

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::process;

mod btf;
mod codegen;
#[allow(dead_code, non_camel_case_types)]
mod elf;
mod parser;

use parser::{Insn, LabelType, ParseError};

#[allow(clippy::upper_case_acronyms)]
#[derive(PartialEq, Debug)]
enum ReloType {
    OFF,
    IMM,
    IMM64,
    DISP32,
}

#[allow(non_camel_case_types, dead_code)]
enum BPFRelo {
    R_BPF_64_64 = 1,
    R_BPF_64_ABS64 = 2,
    R_BPF_64_ABS32 = 3,
    R_BPF_64_32 = 10,
}

struct Relocation {
    name: String,
    off: usize,
    rtype: ReloType,
    sect: usize,
}

impl Relocation {
    fn gen_binary(&self, sym_ndx: usize) -> [u8; 16] {
        let rtype = match &self.rtype {
            ReloType::OFF => BPFRelo::R_BPF_64_32,
            ReloType::IMM => BPFRelo::R_BPF_64_32,
            ReloType::IMM64 => BPFRelo::R_BPF_64_64,
            ReloType::DISP32 => BPFRelo::R_BPF_64_32,
        };
        <[u8; 16]>::try_from(
            [
                (self.off as u64).to_le_bytes(),
                (((sym_ndx as u64) << 32) | (rtype as u64)).to_le_bytes(),
            ]
            .concat(),
        )
        .unwrap()
    }
}

#[derive(Debug, PartialEq)]
enum SymbolType {
    NoType,
    Func,
    Object,
    Section,
}

struct Symbol {
    stype: SymbolType,
    name: String,
    off: usize,
    sect: usize,
    size: usize,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, PartialEq)]
enum SectionType {
    NULL,
    STRTAB,
    SYMTAB,
    PROGBITS,
    NOBITS,
    REL,
}

struct Section {
    stype: SectionType,
    name: String,
    data: Vec<u8>,
    rels: Vec<Relocation>,
    data_off: usize,
    rels_off: usize,
    flags: u64,
}

pub struct Program {
    syms: Vec<Symbol>,
    sects: Vec<Section>,
    temp_rels: Vec<Relocation>,
    btf_builder: btf::BTFBuilder,
}

impl Program {
    fn find_section(&self, name: &str) -> Option<usize> {
        for (idx, sect) in self.sects.iter().enumerate() {
            if sect.name == name {
                return Some(idx);
            }
        }
        None
    }

    /// Commit relocations in the `temp_rels` to a separate section.
    fn commit_temp_rels(&mut self) -> Result<(), String> {
        if !self.sects.is_empty() && !self.temp_rels.is_empty() {
            if self.sects.last().unwrap().stype == SectionType::NOBITS {
                return Err(format!(
                    "A BSS section should not has any relocation: {:?}",
                    self.sects.last().unwrap().name
                ));
            }

            for ridx in (0..self.temp_rels.len()).rev() {
                if self.temp_rels[ridx].rtype == ReloType::OFF {
                    let rel = &self.temp_rels[ridx];
                    let sidx = rel.sect;
                    let ioff = rel.off;
                    let sym_idx = self
                        .find_symbol_idx(&rel.name)
                        .ok_or_else(|| format!("not found symbol: {:?}", rel.name))?;
                    let sym = &self.syms[sym_idx];
                    if sym.sect != sidx {
                        return Err("the offset is in different section".to_string());
                    }
                    let sym_off = sym.off;
                    let off = (sym_off - (ioff + 8)) >> 3;
                    codegen::fix_offset(&mut self.sects[sidx].data[ioff..(ioff + 8)], off);
                    self.temp_rels.remove(ridx);
                }
            }

            let mut rel_sect = Section {
                stype: SectionType::REL,
                name: format!(".rel{}", self.sects.last().unwrap().name),
                data: vec![],
                rels: vec![],
                data_off: 0,
                rels_off: 0,
                flags: elf::SHF_INFO_LINK,
            };
            rel_sect.rels.append(&mut self.temp_rels);
            assert!(self.temp_rels.is_empty());
            self.sects.push(rel_sect);
        }
        Ok(())
    }

    fn create_section(&mut self, name: &str, stype: SectionType) -> Result<usize, String> {
        if self.find_section(name).is_some() {
            return Err(format!("redefined a section: {:?}", name));
        }
        self.commit_temp_rels()?;
        self.sects.push(Section {
            stype,
            name: name.to_string(),
            data: vec![],
            rels: vec![],
            data_off: 0,
            rels_off: 0,
            flags: 0,
        });
        Ok(self.sects.len() - 1)
    }

    fn compute_strtab_len(&self) -> usize {
        self.syms.iter().map(|x| x.name.len() + 1).sum::<usize>()
            + self.sects.iter().map(|x| x.name.len() + 1).sum::<usize>()
            + 1
    }

    fn generate_strtab_content(&self) -> Vec<u8> {
        let mut strtab = vec![0x0];
        for sym in &self.syms {
            strtab.append(
                &mut CString::new(sym.name.as_str())
                    .unwrap()
                    .into_bytes_with_nul(),
            );
        }
        for sect in &self.sects {
            strtab.append(
                &mut CString::new(sect.name.as_str())
                    .unwrap()
                    .into_bytes_with_nul(),
            );
        }
        strtab
    }

    fn generate_symtab_content(&self) -> Vec<u8> {
        let mut symtab = vec![];
        for sym in self.syms.as_slice() {
            let st_info = match sym.stype {
                SymbolType::NoType => elf::STT_NOTYPE,
                SymbolType::Object => elf::STT_OBJECT | (elf::STB_GLOBAL << 4),
                SymbolType::Func => elf::STT_FUNC | (elf::STB_GLOBAL << 4),
                SymbolType::Section => elf::STT_SECTION,
            };
            let esym = elf::Elf64_Sym {
                st_name: self.find_strtab_off(&sym.name).unwrap() as elf::Elf64_Word,
                st_info,
                st_other: 0,
                st_shndx: sym.sect as elf::Elf64_Half,
                st_value: sym.off as elf::Elf64_Addr,
                st_size: sym.size as elf::Elf64_Xword,
            };
            symtab.extend_from_slice(unsafe {
                slice::from_raw_parts(
                    &esym as *const elf::Elf64_Sym as *const u8,
                    mem::size_of::<elf::Elf64_Sym>(),
                )
            });
        }
        symtab
    }

    fn fill_section_offs(&mut self) {
        if self.sects.len() == 2 {
            return;
        }
        // skip first two sections; "" & ".strtab".
        let sect = &mut self.sects[2];
        sect.data_off = mem::size_of::<elf::Elf64_Ehdr>();
        sect.rels_off = (sect.data_off + sect.data.len() + 7) & !0x7;
        for idx in 3..self.sects.len() {
            self.sects[idx].data_off =
                self.sects[idx - 1].rels_off + self.sects[idx - 1].rels.len() * 16;
            self.sects[idx].rels_off = if self.sects[idx].stype == SectionType::NOBITS {
                self.sects[idx].data_off
            } else {
                (self.sects[idx].data_off + self.sects[idx].data.len() + 7) & !0x7
            };
        }
    }

    fn generate_section_content(&self) -> Vec<u8> {
        let mut sects = vec![];
        for (ndx, sect) in self.sects.as_slice().iter().enumerate() {
            let sh_type = match sect.stype {
                SectionType::NULL => elf::SHT_NULL,
                SectionType::STRTAB => elf::SHT_STRTAB,
                SectionType::SYMTAB => elf::SHT_SYMTAB,
                SectionType::PROGBITS => elf::SHT_PROGBITS,
                SectionType::NOBITS => elf::SHT_NOBITS,
                SectionType::REL => elf::SHT_REL,
            };
            let sh_addralign = match sect.stype {
                SectionType::NULL => 0,
                SectionType::STRTAB => 1,
                SectionType::SYMTAB => 8,
                SectionType::PROGBITS => 8,
                SectionType::NOBITS => 8,
                SectionType::REL => 8,
            };
            let sh_entsize = match sect.stype {
                SectionType::NULL => 0,
                SectionType::STRTAB => 0,
                SectionType::SYMTAB => mem::size_of::<elf::Elf64_Sym>() as elf::Elf64_Xword,
                SectionType::PROGBITS => 0,
                SectionType::NOBITS => 0,
                SectionType::REL => 0x10,
            };
            let sh_link = match sect.stype {
                SectionType::NULL => 0,
                SectionType::STRTAB => 0,
                SectionType::SYMTAB => 1,
                SectionType::PROGBITS => 0,
                SectionType::NOBITS => 0,
                SectionType::REL => self.find_section(".symtab").unwrap() as elf::Elf64_Word,
            };
            let sh_info = match sect.stype {
                SectionType::NULL => 0,
                SectionType::STRTAB => 0,
                SectionType::SYMTAB => self.syms.len() as elf::Elf64_Word,
                SectionType::PROGBITS => 0,
                SectionType::NOBITS => 0,
                SectionType::REL => ndx as elf::Elf64_Word - 1,
            };

            let esect = elf::Elf64_Shdr {
                sh_name: self.find_strtab_off(&sect.name).unwrap() as elf::Elf64_Word,
                sh_type,
                sh_flags: sect.flags,
                sh_addr: 0,
                sh_offset: sect.data_off as elf::Elf64_Off,
                sh_size: (sect.data.len() + sect.rels.len() * 16) as elf::Elf64_Xword,
                sh_link,
                sh_info,
                sh_addralign,
                sh_entsize,
            };
            sects.extend_from_slice(unsafe {
                slice::from_raw_parts(
                    &esect as *const elf::Elf64_Shdr as *const u8,
                    mem::size_of::<elf::Elf64_Shdr>(),
                )
            });
        }
        sects
    }

    fn find_strtab_off(&self, s: &str) -> Option<usize> {
        let strtab = &self.sects[1].data;
        let mut off = 0;
        while strtab.len() > off {
            let v = unsafe { CStr::from_ptr(strtab[off..].as_ptr() as *const i8) };
            if v.to_str().unwrap() == s {
                return Some(off);
            }
            off += v.to_bytes().len() + 1;
        }
        None
    }

    fn find_symbol_idx(&self, name: &str) -> Option<usize> {
        for (i, sym) in self.syms.as_slice().iter().enumerate() {
            if sym.name == name {
                return Some(i);
            }
        }
        None
    }

    /// Fixes the relocations and symbol names in the program.
    ///
    /// This method iterates through each section in the `sects` field
    /// of the program and for each section, it iterates through each
    /// relocation in the `rels` field.  If the relocation has a type
    /// of `ReloType::DISP32`, the method updates the instruction in
    /// the section indicated by the `sect` field of the relocation
    /// with the correct offset by ORing the symbol offset with the
    /// relocation data and writing the result back to the `data`
    /// field of the relevant section. The method also updates the
    /// `name` field of the relocation with the section name of the
    /// symbol associated with the relocation based on the `name`
    /// field of the relocation.
    fn fix_relocations(&mut self) {
        for sidx in 0..self.sects.len() {
            for ridx in 0..self.sects[sidx].rels.len() {
                if self.sects[sidx].rels[ridx].rtype != ReloType::DISP32 {
                    continue;
                }

                let rel = &self.sects[sidx].rels[ridx];
                let rel_off = rel.off;
                let rel_sidx = rel.sect;
                let sym_idx = self.find_symbol_idx(&rel.name).unwrap();
                let sym = &self.syms[sym_idx];
                let sym_sidx = sym.sect;
                let sym_off = sym.off;
                assert_eq!(sym.stype, SymbolType::Func);

                let mut code = u64::from_le_bytes(
                    <[u8; 8]>::try_from(&self.sects[rel_sidx].data[rel_off..(rel_off + 8)])
                        .unwrap(),
                );
                code |= (sym_off as u64) << codegen::SH_IMM;
                self.sects[rel_sidx].data[rel_off..(rel_off + 8)]
                    .copy_from_slice(code.to_le_bytes().as_slice());

                let sect_sym_idx = self.find_symbol_idx(&self.sects[sym_sidx].name).unwrap();
                self.sects[sidx].rels[ridx].name = self.syms[sect_sym_idx].name.clone();
            }
        }
    }

    fn generate_strtab(&mut self) {
        self.sects[1].data = self.generate_strtab_content();
    }

    fn generate_elf(&mut self) -> Result<Vec<u8>, String> {
        let mut out = Vec::<u8>::new();
        let symtaboff = mem::size_of::<elf::Elf64_Ehdr>()
            + self
                .sects
                .iter()
                .map(|s| {
                    if s.stype == SectionType::NOBITS {
                        0
                    } else {
                        ((s.data.len() + 7) & !0x7) + s.rels.len() * 16
                    }
                })
                .sum::<usize>();
        let strtaboff = symtaboff + self.syms.len() * mem::size_of::<elf::Elf64_Sym>();
        let shoff = (strtaboff + self.compute_strtab_len() + 7) & !0x7;
        let ehdr = elf::Elf64_Ehdr {
            e_ident: [
                0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ],
            e_type: elf::ET_REL,
            e_machine: 0x00f7,
            e_version: 0x1,
            e_entry: 0x0,
            e_phoff: 0x0,
            e_shoff: shoff as elf::Elf64_Off,
            e_flags: 0x0,
            e_ehsize: mem::size_of::<elf::Elf64_Ehdr>() as elf::Elf64_Half,
            e_phentsize: 0x0,
            e_phnum: 0x0,
            e_shentsize: mem::size_of::<elf::Elf64_Shdr>() as elf::Elf64_Half,
            e_shnum: self.sects.len() as elf::Elf64_Half,
            e_shstrndx: 0x1,
        };
        let ehdr_ptr = &ehdr as *const elf::Elf64_Ehdr as *const u8;
        out.resize(mem::size_of::<elf::Elf64_Ehdr>(), 0);
        unsafe { ptr::copy(ehdr_ptr, out.as_mut_ptr(), out.len()) };

        self.fill_section_offs();
        self.sects[1].data_off = strtaboff;

        // This is required for find_strtab_off().
        self.generate_strtab();

        let symtab_idx = self
            .find_section(".symtab")
            .ok_or_else(|| ".symtab is not found".to_string())?;
        self.sects[symtab_idx].data = self.generate_symtab_content();
        assert_eq!(self.sects[symtab_idx].data_off, symtaboff);

        self.fix_relocations();

        for sect in self.sects[2..].iter() {
            if sect.stype != SectionType::NOBITS {
                out.extend_from_slice(&sect.data);
                out.resize((out.len() + 7) & !0x7, 0);
            }
            for rel in &sect.rels {
                let ndx = self
                    .find_symbol_idx(&rel.name)
                    .ok_or_else(|| format!("Unknown symbol: {}", rel.name))?;
                out.extend_from_slice(&rel.gen_binary(ndx));
            }
        }

        assert_eq!(out.len(), strtaboff);
        out.extend_from_slice(&self.sects[1].data);
        out.resize((out.len() + 7) & !0x7, 0);

        assert_eq!(out.len(), shoff);
        let shdrs = self.generate_section_content();
        out.extend_from_slice(&shdrs);

        Ok(out)
    }

    fn add_sym(&mut self, sym: Symbol) -> Result<(), String> {
        if self.find_symbol_idx(&sym.name).is_some() {
            return Err(format!("Redefine the symbol: {}", sym.name));
        }
        self.syms.push(sym);
        Ok(())
    }
}

struct AssemblySession {
    prog: Program,
    sect_idx: usize,
    sym_func_data_idx: Option<usize>,
}

impl AssemblySession {
    fn new() -> AssemblySession {
        AssemblySession {
            prog: Program {
                syms: vec![],
                sects: vec![],
                temp_rels: vec![],
                btf_builder: btf::BTFBuilder::new(),
            },
            sect_idx: 0,
            sym_func_data_idx: None,
        }
    }

    fn add_sym(
        &mut self,
        name: String,
        sym_type: SymbolType,
        line_no: usize,
        line: &str,
    ) -> Result<(), ParseError> {
        self.prog
            .add_sym(Symbol {
                stype: sym_type,
                name,
                off: self.prog.sects[self.sect_idx].data.len(),
                sect: self.sect_idx,
                size: 0,
            })
            .map_err(|e| ParseError::new_p(line_no, line, &e))?;
        Ok(())
    }

    fn start_sym_scope(
        &mut self,
        name: String,
        sym_type: SymbolType,
        line_no: usize,
        line: &str,
    ) -> Result<(), ParseError> {
        if let Some(sym_data_idx) = self.sym_func_data_idx {
            self.prog.syms[sym_data_idx].size =
                self.prog.sects[self.sect_idx].data.len() - self.prog.syms[sym_data_idx].off;
        }
        self.sym_func_data_idx = Some(self.prog.syms.len());
        self.prog
            .add_sym(Symbol {
                stype: sym_type,
                name,
                off: self.prog.sects[self.sect_idx].data.len(),
                sect: self.sect_idx,
                size: 0,
            })
            .map_err(|e| ParseError::new_p(line_no, line, &e))?;
        Ok(())
    }

    fn end_sym_scope(&mut self) {
        if let Some(sym_data_idx) = self.sym_func_data_idx {
            self.prog.syms[sym_data_idx].size =
                self.prog.sects[self.sect_idx].data.len() - self.prog.syms[sym_data_idx].off;
        }
        self.sym_func_data_idx = None;
    }

    fn cur_sect(&mut self) -> &mut Section {
        &mut self.prog.sects[self.sect_idx]
    }

    fn start_section(
        &mut self,
        name: String,
        sect_type: SectionType,
        line_no: usize,
        line: &str,
    ) -> Result<(), ParseError> {
        self.sect_idx = match self.prog.find_section(&name) {
            Some(idx) => idx,
            _ => {
                let idx = self
                    .prog
                    .create_section(&name, sect_type)
                    .map_err(|e| ParseError::new_p(0, line, &e))?;
                self.prog
                    .add_sym(Symbol {
                        stype: SymbolType::Section,
                        name,
                        off: 0,
                        sect: idx,
                        size: 0,
                    })
                    .map_err(|e| ParseError::new_p(line_no, line, &e))?;
                idx
            }
        };
        Ok(())
    }

    fn end_section(&mut self) {
        if let Some(sym_data_idx) = self.sym_func_data_idx {
            self.prog.syms[sym_data_idx].size =
                self.cur_sect().data.len() - self.prog.syms[sym_data_idx].off;
        }
        self.sym_func_data_idx = None;
    }
}

fn assembly(lines: Vec<String>) -> Result<Program, ParseError> {
    let mut s = AssemblySession::new();
    s.prog
        .create_section("", SectionType::NULL)
        .map_err(|e| ParseError::new_p(0, "", &e))?;
    s.prog
        .create_section(".strtab", SectionType::STRTAB)
        .map_err(|e| ParseError::new_p(0, "", &e))?;

    s.prog
        .add_sym(Symbol {
            stype: SymbolType::NoType,
            name: "".to_string(),
            off: 0,
            sect: 0,
            size: 0,
        })
        .map_err(|e| ParseError::new_p(0, "", &e))?;

    for (line_no, line) in lines.iter().enumerate() {
        let insn = parser::parse_line(line).map_err(|mut e| {
            e.line_no = line_no;
            e
        })?;

        match insn {
            Insn::Label(label, ltype) => match ltype {
                LabelType::Func => {
                    s.start_sym_scope(label, SymbolType::Func, line_no, line)?;
                }
                LabelType::Data => {
                    s.start_sym_scope(label, SymbolType::Object, line_no, line)?;
                }
                _ => {
                    s.add_sym(label, SymbolType::NoType, line_no, line)?;
                }
            },
            Insn::Insn(cmd, dst, dst_sign, dst_off, src, src_sign, src_off) => {
                if s.cur_sect().flags != 0
                    && s.cur_sect().flags != (elf::SHF_ALLOC | elf::SHF_EXECINSTR)
                {
                    return ParseError::new_prog(
                        line_no,
                        line,
                        "should not inter-mix data and instructions",
                    );
                }
                s.cur_sect().flags = elf::SHF_ALLOC | elf::SHF_EXECINSTR;

                if cmd == "exit" {
                    codegen::ebpf_code_gen(&cmd, "", 0, "", 0, &mut s.cur_sect().data)
                        .map_err(|_| ParseError::new_p(line_no, line, "fail to generate code"))?;
                    continue;
                }

                let saved_rels_len = s.prog.temp_rels.len();
                let dst = if &dst[0..1] == "@" {
                    let off = s.cur_sect().data.len();
                    s.prog.temp_rels.push(Relocation {
                        name: dst[1..].to_string(),
                        off,
                        rtype: if cmd == "call" {
                            ReloType::DISP32
                        } else {
                            ReloType::IMM
                        },
                        sect: s.sect_idx,
                    });
                    "0x0"
                } else {
                    &dst
                };
                let dst_off = if &dst_off[0..1] == "@" {
                    let off = s.cur_sect().data.len();
                    s.prog.temp_rels.push(Relocation {
                        name: dst_off[1..].to_string(),
                        off,
                        rtype: ReloType::OFF,
                        sect: s.sect_idx,
                    });
                    0x0
                } else {
                    let v: isize = dst_off
                        .parse()
                        .map_err(|_| ParseError::new_p(line_no, line, "invalid offset"))?;
                    v * dst_sign
                };
                let src = if !src.is_empty() && &src[0..1] == "@" {
                    let off = s.cur_sect().data.len();
                    s.prog.temp_rels.push(Relocation {
                        name: src[1..].to_string(),
                        off,
                        rtype: ReloType::IMM,
                        sect: s.sect_idx,
                    });
                    "0x0"
                } else {
                    &src
                };
                let src_off = if &src_off[0..1] == "@" {
                    let off = s.cur_sect().data.len();
                    s.prog.temp_rels.push(Relocation {
                        name: src_off[1..].to_string(),
                        off,
                        rtype: ReloType::OFF,
                        sect: s.sect_idx,
                    });
                    0x0
                } else {
                    let v: isize = src_off
                        .parse()
                        .map_err(|_| ParseError::new_p(line_no, line, "invalid source offset"))?;
                    v * src_sign
                };
                let rels_cnt = s.prog.temp_rels.len() - saved_rels_len;
                if rels_cnt > 2 {
                    eprintln!("Too many references to symbols. ({})", rels_cnt);
                    return ParseError::new_prog(line_no, line, "too many references to symbols");
                }

                let saved_sect_len = s.cur_sect().data.len();

                codegen::ebpf_code_gen(&cmd, dst, dst_off, src, src_off, &mut s.cur_sect().data)
                    .map_err(|_| ParseError::new_p(line_no, line, "fail to generate code"))?;

                let insn_len = s.cur_sect().data.len() - saved_sect_len;
                if insn_len == 16 {
                    for rel in &mut s.prog.temp_rels[saved_rels_len..] {
                        if rel.rtype == ReloType::IMM {
                            rel.rtype = ReloType::IMM64;
                        }
                    }
                }
            }
            Insn::Section(name) => {
                s.end_section();
                s.start_section(name, SectionType::PROGBITS, line_no, line)?;
            }
            Insn::Bss(name) => {
                s.end_section();
                s.start_section(name, SectionType::NOBITS, line_no, line)?;
                s.cur_sect().flags = elf::SHF_WRITE | elf::SHF_ALLOC;
            }
            Insn::Dbytes(mut v_u8v) => {
                if s.cur_sect().flags != 0
                    && s.cur_sect().flags != (elf::SHF_ALLOC | elf::SHF_WRITE)
                {
                    return ParseError::new_prog(
                        line_no,
                        line,
                        "should not inter-mix data and instructions",
                    );
                }
                s.cur_sect().flags = elf::SHF_ALLOC | elf::SHF_WRITE;
                s.cur_sect().data.append(&mut v_u8v);
            }
            Insn::Dwords(u32v) => {
                if s.cur_sect().flags != 0
                    && s.cur_sect().flags != (elf::SHF_ALLOC | elf::SHF_WRITE)
                {
                    return ParseError::new_prog(
                        line_no,
                        line,
                        "should not inter-mix data and instructions",
                    );
                }
                s.cur_sect().flags = elf::SHF_ALLOC | elf::SHF_WRITE;
                for v in u32v {
                    s.cur_sect().data.extend(v.to_ne_bytes());
                }
            }
            Insn::Ddwords(u64v) => {
                if s.cur_sect().flags != 0
                    && s.cur_sect().flags != (elf::SHF_ALLOC | elf::SHF_WRITE)
                {
                    return ParseError::new_prog(
                        line_no,
                        line,
                        "should not inter-mix data and instructions",
                    );
                }
                s.cur_sect().flags = elf::SHF_ALLOC | elf::SHF_WRITE;
                for v in u64v {
                    s.cur_sect().data.extend(v.to_ne_bytes());
                }
            }
            Insn::Map(name, typ, key_sz, val_sz, max_entries) => {
                s.end_sym_scope();
                let tid = s
                    .prog
                    .btf_builder
                    .add_map(name.clone(), typ, key_sz, val_sz, max_entries)
                    .map_err(|e| ParseError::new_p(line_no, "", &e))?;
                let tsize = s.prog.btf_builder.type_size(tid);
                s.start_sym_scope(name, SymbolType::Object, line_no, line)?;
                s.cur_sect().data.extend(vec![0; tsize]);
                s.end_sym_scope();
            }
            Insn::None => {}
        }
    }

    s.end_section();

    if s.prog.btf_builder.len() != 0 {
        let btf_bytes = s.prog.btf_builder.as_bytes();
        s.start_section(".BTF".to_string(), SectionType::PROGBITS, 0, "")?;
        s.cur_sect().data_off = btf_bytes.len();
        s.cur_sect().data = btf_bytes;
        s.end_section();
    }

    s.prog
        .create_section(".symtab", SectionType::SYMTAB)
        .map_err(|e| ParseError::new_p(0, "", &e))?;

    Ok(s.prog)
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <input-file> <output-file>", args[0]);
        process::exit(255);
    }
    let in_fn = &args[1];
    let out_fn = &args[2];

    let mut input = if let Ok(fo) = File::open(in_fn) {
        fo
    } else {
        eprintln!("Can not open {}", in_fn);
        process::exit(255);
    };
    let mut src_buf = String::new();

    if input.read_to_string(&mut src_buf).is_err() {
        eprintln!("Can not read {}", in_fn);
        process::exit(255);
    }
    let lines: Vec<_> = src_buf.split('\n').map(|x| x.to_string()).collect();
    let mut prog = match assembly(lines) {
        Ok(prog) => prog,
        Err(e) => {
            eprintln!("ERROR: line {}: {}", e.line_no, e.reason);
            eprintln!("{}", e.line);
            process::exit(255);
        }
    };
    let elf_content = match prog.generate_elf() {
        Ok(content) => content,
        Err(e) => {
            eprintln!("ERROR: {}", e);
            process::exit(255);
        }
    };

    let mut output = if let Ok(fo) = File::create(out_fn) {
        fo
    } else {
        eprintln!("Can not create {}", out_fn);
        process::exit(255);
    };

    if output.write_all(&elf_content).is_err() {
        eprintln!("Can not write {}", out_fn);
        process::exit(255);
    }
    println!("Write to {}", out_fn);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assembly() {
        let mut prog = assembly(vec![
            ".section \".data\"".to_string(),
            ".data DATA".to_string(),
            " db 0x33, 0x22".to_string(),
            ".data DATA1".to_string(),
            " db 0x33, 0x22".to_string(),
            ".section \".text\"".to_string(),
            ".function main".to_string(),
            "ld.dw r10, @DATA".to_string(),
            "mov r1, 10".to_string(),
            "mov r7, @DATA1".to_string(),
            ".section \"ttt/ff\"".to_string(),
            ".function test".to_string(),
            "mov r1, 10".to_string(),
            "call @test1".to_string(),
            ".function test1".to_string(),
            "mov r1, 10".to_string(),
            "call @main".to_string(),
        ])
        .unwrap();

        let sect_idx = prog.find_section(".data").unwrap();
        let data_sect = &prog.sects[sect_idx];
        assert_eq!(data_sect.data.len(), 4);
        assert_eq!(data_sect.data, [0x33, 0x22, 0x33, 0x22]);

        let sect_idx = prog.find_section(".text").unwrap();
        let text_sect = &prog.sects[sect_idx];
        assert_eq!(
            text_sect.data,
            [
                0x18, 0x0a, 0, 0, 0, 0, 0, 0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xb4, 0x1, 0,
                0, 0xa, 0, 0, 0, 0xb4, 0x7, 0, 0, 0x0, 0x0, 0x0, 0x0,
            ]
        );

        assert_eq!(prog.sects.len(), 8);
        assert_eq!(prog.sects[3].rels.len(), 0);
        assert_eq!(prog.sects[4].rels[0].rtype, ReloType::IMM64);
        assert_eq!(prog.sects[4].rels[0].off, 0);
        assert_eq!(prog.sects[4].rels[0].name, "DATA");
        assert_eq!(prog.sects[4].rels[1].rtype, ReloType::IMM);
        assert_eq!(prog.sects[4].rels[1].off, 24);
        assert_eq!(prog.sects[4].rels[1].name, "DATA1");
        assert_eq!(prog.sects[4].rels.len(), 2);

        assert_eq!(prog.syms.len(), 9);
        assert_eq!(prog.syms[1].name, ".data");
        assert_eq!(prog.syms[1].stype, SymbolType::Section);
        assert_eq!(prog.syms[2].name, "DATA");
        assert_eq!(prog.syms[2].stype, SymbolType::Object);
        assert_eq!(prog.syms[2].size, 2);
        assert_eq!(prog.syms[3].name, "DATA1");
        assert_eq!(prog.syms[3].off, 2);
        assert_eq!(prog.syms[3].size, 2);
        assert_eq!(prog.syms[4].name, ".text");
        assert_eq!(prog.syms[4].stype, SymbolType::Section);
        assert_eq!(prog.syms[5].name, "main");
        assert_eq!(prog.syms[5].off, 0);
        assert_eq!(prog.syms[5].size, 32);
        assert_eq!(prog.syms[5].stype, SymbolType::Func);

        assert_eq!(prog.sects[6].rels.len(), 2);
        assert_eq!(prog.sects[6].rels[0].name, "test1");
        assert_eq!(prog.sects[6].rels[1].name, "main");

        let _elf = prog.generate_elf().unwrap();

        assert_eq!(prog.sects[6].rels[0].name, "ttt/ff");
        assert_eq!(prog.sects[6].rels[1].name, ".text");
    }

    #[test]
    fn test_call() {
        let mut prog = assembly(vec![
            ".section \".text\"".to_string(),
            ".function foo".to_string(),
            "mov r1, 1".to_string(),
            ".function foo1".to_string(),
            "mov r1, 1".to_string(),
            ".section testsect".to_string(),
            ".function main".to_string(),
            "call @foo1".to_string(),
        ])
        .unwrap();

        assert_eq!(prog.sects.len(), 6);
        assert_eq!(prog.sects[2].name, ".text");
        assert_eq!(prog.sects[3].name, "testsect");
        assert_eq!(prog.syms.len(), 6);
        assert_eq!(prog.syms[2].name, "foo");
        assert_eq!(prog.sects[4].name, ".reltestsect");
        assert_eq!(prog.sects[4].rels.len(), 1);
        assert_eq!(prog.sects[4].rels[0].rtype, ReloType::DISP32);

        prog.generate_strtab();
        prog.fix_relocations();
        assert_eq!(prog.sects[4].rels[0].name, ".text");
        assert_eq!(prog.sects[4].rels[0].off, 0);
        assert_eq!(prog.sects[4].rels[0].sect, 3);
        assert_eq!(prog.sects[3].data, [0x85, 0x10, 0, 0, 0x8, 0, 0, 0]);
    }
}
