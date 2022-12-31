use std::ffi::{CStr, CString};
use std::mem;
use std::ptr;
use std::slice;

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::process;

#[allow(dead_code, non_camel_case_types)]
mod elf;

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
    REL,
}

struct Section {
    stype: SectionType,
    name: String,
    data: Vec<u8>,
    rels: Vec<Relocation>,
    data_off: usize,
    rels_off: usize,
}

struct Program {
    syms: Vec<Symbol>,
    sects: Vec<Section>,
    temp_rels: Vec<Relocation>,
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
    fn commit_temp_rels(&mut self) {
        if let Some(last) = self.sects.last_mut() {
            if !self.temp_rels.is_empty() {
                let mut rel_sect = Section {
                    stype: SectionType::REL,
                    name: format!(".rel{}", last.name),
                    data: vec![],
                    rels: vec![],
                    data_off: 0,
                    rels_off: 0,
                };
                rel_sect.rels.append(&mut self.temp_rels);
                assert!(self.temp_rels.is_empty());
                self.sects.push(rel_sect);
            }
        }
    }

    fn create_section(&mut self, name: &str, stype: SectionType) -> Result<usize, ()> {
        if self.find_section(name).is_some() {
            return Err(());
        }
        self.commit_temp_rels();
        self.sects.push(Section {
            stype,
            name: name.to_string(),
            data: vec![],
            rels: vec![],
            data_off: 0,
            rels_off: 0,
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
                SymbolType::Object => elf::STT_OBJECT,
                SymbolType::Func => elf::STT_FUNC,
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
            self.sects[idx].rels_off =
                (self.sects[idx].data_off + self.sects[idx].data.len() + 7) & !0x7;
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
                SectionType::REL => elf::SHT_REL,
            };
            let sh_addralign = match sect.stype {
                SectionType::NULL => 0,
                SectionType::STRTAB => 1,
                SectionType::SYMTAB => 8,
                SectionType::PROGBITS => 8,
                SectionType::REL => 8,
            };
            let sh_entsize = match sect.stype {
                SectionType::NULL => 0,
                SectionType::STRTAB => 0,
                SectionType::SYMTAB => mem::size_of::<elf::Elf64_Sym>() as elf::Elf64_Xword,
                SectionType::PROGBITS => 0,
                SectionType::REL => 0x10,
            };
            let sh_link = match sect.stype {
                SectionType::NULL => 0,
                SectionType::STRTAB => 0,
                SectionType::SYMTAB => 1,
                SectionType::PROGBITS => 0,
                SectionType::REL => self.find_section(".symtab").unwrap() as elf::Elf64_Word,
            };
            let sh_info = match sect.stype {
                SectionType::NULL => 0,
                SectionType::STRTAB => 0,
                SectionType::SYMTAB => self.syms.len() as elf::Elf64_Word,
                SectionType::PROGBITS => 0,
                SectionType::REL => ndx as elf::Elf64_Word - 1,
            };

            let esect = elf::Elf64_Shdr {
                sh_name: self.find_strtab_off(&sect.name).unwrap() as elf::Elf64_Word,
                sh_type,
                sh_flags: 0,
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
            let v = unsafe { CStr::from_ptr((&strtab[off..]).as_ptr() as *const i8) };
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
                code |= (sym_off as u64) << SH_IMM;
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
                .map(|s| ((s.data.len() + 7) & !0x7) + s.rels.len() * 16)
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
            out.extend_from_slice(&sect.data);
            out.resize((out.len() + 7) & !0x7, 0);
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
}

#[derive(Debug, PartialEq)]
enum LabelType {
    NoType,
    Func,
    Data,
}

#[derive(Debug, PartialEq)]
enum Insn {
    // label_name, is_function
    Label(String, LabelType),
    Insn(String, String, isize, String, String, isize, String),
    Section(String),
    Dbytes(Vec<u8>),
    Dwords(Vec<u32>),
    Ddwords(Vec<u64>),
    None,
}

const SH_DST: usize = 8;
const SH_SRC: usize = 12;
const SH_OFF: usize = 16;
const SH_IMM: usize = 32;

fn tokenize(line: &str) -> Result<Vec<&str>, ()> {
    let mut last_nows = 0;
    let mut tokens = vec![];
    let mut in_quote = false;

    for (off, c) in line.chars().enumerate() {
        if in_quote {
            if c == '"' {
                tokens.push(&line[last_nows..(off + 1)]);
                in_quote = false;
                last_nows = off + 1;
            }
            continue;
        }
        if c == '"' {
            if off != last_nows {
                tokens.push(&line[last_nows..off]);
            }
            last_nows = off;
            in_quote = true;
            continue;
        }
        if c.is_whitespace() {
            if off != last_nows {
                tokens.push(&line[last_nows..off]);
            }
            last_nows = off + 1;
            continue;
        }
        if c == '+' {
            if off != last_nows {
                tokens.push(&line[last_nows..off]);
            }

            tokens.push("+");
            last_nows = off + 1;
            continue;
        }
        if c == '-' {
            if off != last_nows {
                tokens.push(&line[last_nows..off]);
            }

            tokens.push("-");
            last_nows = off + 1;
            continue;
        }
        if c == '.' {
            if off != last_nows {
                tokens.push(&line[last_nows..off]);
            }

            tokens.push(".");
            last_nows = off + 1;
            continue;
        }
        if c == ':' {
            if off != last_nows {
                tokens.push(&line[last_nows..off]);
            }

            tokens.push(":");
            last_nows = off + 1;
            continue;
        }
        if c == ',' {
            if off != last_nows {
                tokens.push(&line[last_nows..off]);
            }

            tokens.push(",");
            last_nows = off + 1;
            continue;
        }
        if c == '[' {
            if off != last_nows {
                tokens.push(&line[last_nows..off]);
            }

            tokens.push("]");
            last_nows = off + 1;
            continue;
        }
        if c == ']' {
            if off != last_nows {
                tokens.push(&line[last_nows..off]);
            }

            tokens.push("]");
            last_nows = off + 1;
            continue;
        }
        if c == '/' {
            if off != last_nows {
                tokens.push(&line[last_nows..off]);
            }

            if off < line.len() - 1 && &line[off + 1..off + 2] == "/" {
                return Ok(tokens);
            }
            return Err(());
        }
        if !c.is_ascii_alphanumeric() && c != '_' && (off != last_nows || c != '@') {
            return Err(());
        }
    }
    if in_quote {
        return Err(());
    }
    if last_nows != line.len() {
        tokens.push(&line[last_nows..]);
    }

    Ok(tokens)
}

#[derive(PartialEq, Debug)]
struct ParseError {
    line: String,
    reason: String,
    line_no: usize,
}

impl ParseError {
    fn new(line: &str, reason: &str) -> Result<Insn, ParseError> {
        Err(ParseError {
            line: line.to_string(),
            reason: reason.to_string(),
            line_no: 0,
        })
    }

    fn new_prog(line_no: usize, line: &str, reason: &str) -> Result<Program, ParseError> {
        Err(ParseError {
            line: line.to_string(),
            reason: reason.to_string(),
            line_no,
        })
    }

    fn new_p(line_no: usize, line: &str, reason: &str) -> ParseError {
        ParseError {
            line: line.to_string(),
            reason: reason.to_string(),
            line_no,
        }
    }
}

fn parse_line(line: &str) -> Result<Insn, ParseError> {
    let mut tokens = tokenize(line).map_err(|_| ParseError::new_p(0, line, "tokenize error"))?;
    if tokens.is_empty() {
        return Ok(Insn::None);
    }

    if tokens[0] == "." {
        if tokens.len() < 2 {
            return ParseError::new(line, "invalid syntax");
        }
        match tokens[1] {
            "section" => {
                // section
                if tokens.len() != 3 {
                    ParseError::new(line, "need exact one section name")?;
                }
                let sect_name = if tokens[2].starts_with('\"') {
                    if !tokens[2].ends_with('\"') {
                        return ParseError::new(line, "missing quote (\")");
                    }
                    tokens[2]
                        .strip_prefix('\"')
                        .unwrap()
                        .strip_suffix('\"')
                        .unwrap()
                        .to_string()
                } else {
                    tokens[2].to_string()
                };
                Ok(Insn::Section(sect_name))
            }
            "function" => {
                if tokens.len() != 3 {
                    return ParseError::new(line, "need exact one function name");
                }
                let fname = tokens[2].to_string();
                Ok(Insn::Label(fname, LabelType::Func))
            }
            "data" => {
                if tokens.len() != 3 {
                    return ParseError::new(line, "need exact one data name");
                }
                let fname = tokens[2].to_string();
                Ok(Insn::Label(fname, LabelType::Data))
            }
            _ => ParseError::new(line, &format!("unknown keyword {}", tokens[1])),
        }
    } else if tokens.len() == 2 && tokens[1] == ":" {
        // label
        let label_name = tokens[0];
        Ok(Insn::Label(label_name.to_string(), LabelType::NoType))
    } else {
        match tokens[0] {
            "db" => {
                if tokens.len() % 2 != 0 {
                    return ParseError::new(
                        line,
                        "should be a list of numbers separated by commas (',')",
                    );
                }
                let mut values = vec![];
                for (i, tkn) in tokens[1..].iter().enumerate() {
                    if i % 2 == 0 {
                        if tkn.len() > 2 && &tkn[0..2] == "0x" {
                            values.push(
                                u8::from_str_radix(&tkn[2..], 16).map_err(|_| {
                                    ParseError::new_p(0, line, "invalid hex number")
                                })?,
                            );
                        } else {
                            values.push(
                                tkn.parse()
                                    .map_err(|_| ParseError::new_p(0, line, "invalid number"))?,
                            );
                        }
                    } else if *tkn != "," {
                        return ParseError::new(
                            line,
                            "should be a list of numbers separated by commas (',')",
                        );
                    }
                }
                Ok(Insn::Dbytes(values))
            }
            "dw" => {
                if tokens.len() % 2 != 0 {
                    return ParseError::new(
                        line,
                        "should be a list of numbers separated by commas (',')",
                    );
                }
                let mut values = vec![];
                for (i, tkn) in tokens[1..].iter().enumerate() {
                    if i % 2 == 0 {
                        if tkn.len() > 2 && &tkn[0..2] == "0x" {
                            values.push(
                                u32::from_str_radix(&tkn[2..], 16).map_err(|_| {
                                    ParseError::new_p(0, line, "invalid hex number")
                                })?,
                            );
                        } else {
                            values.push(
                                tkn.parse()
                                    .map_err(|_| ParseError::new_p(0, line, "invalid number"))?,
                            );
                        }
                    } else if *tkn != "," {
                        return ParseError::new(
                            line,
                            "should be a list of numbers separated by commas (',')",
                        );
                    }
                }
                Ok(Insn::Dwords(values))
            }
            "dd" => {
                if tokens.len() % 2 != 0 {
                    return ParseError::new(
                        line,
                        "should be a list of numbers separated by commas (',')",
                    );
                }
                let mut values = vec![];
                for (i, tkn) in tokens[1..].iter().enumerate() {
                    if i % 2 == 0 {
                        if tkn.len() > 2 && &tkn[0..2] == "0x" {
                            values.push(
                                u64::from_str_radix(&tkn[2..], 16).map_err(|_| {
                                    ParseError::new_p(0, line, "invalid hex number")
                                })?,
                            );
                        } else {
                            values.push(
                                tkn.parse().map_err(|_| {
                                    ParseError::new_p(0, line, "invalid hex number")
                                })?,
                            );
                        }
                    } else if *tkn != "," {
                        return ParseError::new(
                            line,
                            "should be a list of numbers separated by commas (',')",
                        );
                    }
                }
                Ok(Insn::Ddwords(values))
            }
            _ => {
                // text section
                let mut cmd = tokens[0].to_string();
                let is_call = cmd == "call";
                while tokens.len() >= 3 && tokens[1] == "." {
                    cmd = format!("{}.{}", cmd, tokens[2]);
                    tokens.remove(1);
                    tokens.remove(1);
                }

                if is_call {
                    if tokens.len() != 2 {
                        return ParseError::new(line, "invalid number of operands");
                    }
                    return Ok(Insn::Insn(
                        cmd,
                        tokens[1].to_string(),
                        1,
                        0.to_string(),
                        "".to_string(),
                        1,
                        0.to_string(),
                    ));
                }

                let mut tidx = 1;
                let dst = tokens[tidx];
                tidx += 1;
                if tidx >= tokens.len() {
                    return ParseError::new(line, "invalid number of operands");
                }
                let (dst_sign, dst_off) = if tokens[tidx] == "+" || tokens[tidx] == "-" {
                    let sign: isize = if tokens[tidx] == "+" { 1 } else { -1 };
                    tidx += 1;
                    if tidx >= tokens.len() {
                        return ParseError::new(line, "incomplete line");
                    }
                    let v = tokens[tidx];
                    tidx += 1;
                    if tidx >= tokens.len() {
                        return ParseError::new(line, "incomplete line");
                    }
                    (sign, v)
                } else {
                    (1, "0")
                };
                if tokens[tidx] != "," {
                    return ParseError::new(
                        line,
                        &format!("expect a comma after {}", tokens[tidx - 1]),
                    );
                }
                tidx += 1;
                if tidx >= tokens.len() {
                    return ParseError::new(line, "expect one more operand");
                }

                let src = tokens[tidx];
                tidx += 1;
                let (src_sign, src_off) =
                    if tidx < tokens.len() && (tokens[tidx] == "+" || tokens[tidx] == "-") {
                        let sign: isize = if tokens[tidx] == "+" { 1 } else { -1 };
                        tidx += 1;
                        if tidx >= tokens.len() {
                            return ParseError::new(line, "invalid syntax");
                        }
                        let v = tokens[tidx];
                        tidx += 1;
                        (sign, v)
                    } else {
                        (1, "0")
                    };

                if tidx != tokens.len() {
                    return ParseError::new(line, "invalid syntax");
                }

                Ok(Insn::Insn(
                    cmd,
                    dst.to_string(),
                    dst_sign,
                    dst_off.to_string(),
                    src.to_string(),
                    src_sign,
                    src_off.to_string(),
                ))
            }
        }
    }
}

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
        | ((off & 0xffff) as u64) << SH_OFF
        | parse_u64(src)? << SH_IMM;
    buf.extend(code.to_ne_bytes());
    Ok(())
}

fn ebpf_code_gen(
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

fn assembly(lines: Vec<String>) -> Result<Program, ParseError> {
    let mut prog = Program {
        syms: vec![],
        sects: vec![],
        temp_rels: vec![],
    };
    prog.create_section("", SectionType::NULL)
        .map_err(|_| ParseError::new_p(0, "", "Fail to create an empty section"))?;
    prog.create_section(".strtab", SectionType::STRTAB)
        .map_err(|_| ParseError::new_p(0, "", "Fail to create .strtab section"))?;

    prog.syms.push(Symbol {
        stype: SymbolType::NoType,
        name: "".to_string(),
        off: 0,
        sect: 0,
        size: 0,
    });
    let mut sect_idx = 0;
    let mut sym_func_data_idx: Option<usize> = None;

    for (line_no, line) in lines.iter().enumerate() {
        let insn = parse_line(line).map_err(|mut e| {
            e.line_no = line_no;
            e
        })?;

        match insn {
            Insn::Label(label, ltype) => {
                if sect_idx >= prog.sects.len() {
                    return ParseError::new_prog(line_no, line, "unknown error");
                }
                let mut stype = SymbolType::NoType;
                match ltype {
                    LabelType::Func => {
                        if let Some(sym_data_idx) = sym_func_data_idx {
                            prog.syms[sym_data_idx].size =
                                prog.sects[sect_idx].data.len() - prog.syms[sym_data_idx].off;
                        }
                        sym_func_data_idx = Some(prog.syms.len());
                        stype = SymbolType::Func;
                    }
                    LabelType::Data => {
                        if let Some(sym_data_idx) = sym_func_data_idx {
                            prog.syms[sym_data_idx].size =
                                prog.sects[sect_idx].data.len() - prog.syms[sym_data_idx].off;
                        }
                        sym_func_data_idx = Some(prog.syms.len());
                        stype = SymbolType::Object;
                    }
                    _ => {}
                }
                prog.syms.push(Symbol {
                    stype,
                    name: label,
                    off: prog.sects[sect_idx].data.len(),
                    sect: sect_idx,
                    size: 0,
                });
            }
            Insn::Insn(cmd, dst, dst_sign, dst_off, src, src_sign, src_off) => {
                if sect_idx >= prog.sects.len() {
                    return ParseError::new_prog(line_no, line, "unknown error");
                }
                let saved_rels_len = prog.temp_rels.len();
                let dst = if &dst[0..1] == "@" {
                    let off = prog.sects[sect_idx].data.len();
                    prog.temp_rels.push(Relocation {
                        name: dst[1..].to_string(),
                        off,
                        rtype: if cmd == "call" {
                            ReloType::DISP32
                        } else {
                            ReloType::IMM
                        },
                        sect: sect_idx,
                    });
                    "0x0"
                } else {
                    &dst
                };
                let dst_off = if &dst_off[0..1] == "@" {
                    let off = prog.sects[sect_idx].data.len();
                    prog.temp_rels.push(Relocation {
                        name: dst_off[1..].to_string(),
                        off,
                        rtype: ReloType::OFF,
                        sect: sect_idx,
                    });
                    0x0
                } else {
                    let v: isize = dst_off
                        .parse()
                        .map_err(|_| ParseError::new_p(line_no, line, "invalid offset"))?;
                    v * dst_sign
                };
                let src = if !src.is_empty() && &src[0..1] == "@" {
                    let off = prog.sects[sect_idx].data.len();
                    prog.temp_rels.push(Relocation {
                        name: src[1..].to_string(),
                        off,
                        rtype: ReloType::IMM,
                        sect: sect_idx,
                    });
                    "0x0"
                } else {
                    &src
                };
                let src_off = if &src_off[0..1] == "@" {
                    let off = prog.sects[sect_idx].data.len();
                    prog.temp_rels.push(Relocation {
                        name: src_off[1..].to_string(),
                        off,
                        rtype: ReloType::OFF,
                        sect: sect_idx,
                    });
                    0x0
                } else {
                    let v: isize = src_off
                        .parse()
                        .map_err(|_| ParseError::new_p(line_no, line, "invalid source offset"))?;
                    v * src_sign
                };
                let rels_cnt = prog.temp_rels.len() - saved_rels_len;
                if rels_cnt > 2 {
                    eprintln!("Too many references to symbols. ({})", rels_cnt);
                    return ParseError::new_prog(line_no, line, "too many references to symbols");
                }

                let saved_sect_len = prog.sects[sect_idx].data.len();

                ebpf_code_gen(
                    &cmd,
                    dst,
                    dst_off,
                    src,
                    src_off,
                    &mut prog.sects[sect_idx].data,
                )
                .map_err(|_| ParseError::new_p(line_no, line, "fail to generate code"))?;

                let insn_len = prog.sects[sect_idx].data.len() - saved_sect_len;
                if insn_len == 16 {
                    for rel in &mut prog.temp_rels[saved_rels_len..] {
                        if rel.rtype == ReloType::IMM {
                            rel.rtype = ReloType::IMM64;
                        }
                    }
                }
            }
            Insn::Section(name) => {
                if let Some(sym_data_idx) = sym_func_data_idx {
                    prog.syms[sym_data_idx].size =
                        prog.sects[sect_idx].data.len() - prog.syms[sym_data_idx].off;
                }
                sym_func_data_idx = None;
                sect_idx = match prog.find_section(&name) {
                    Some(idx) => idx,
                    _ => {
                        let idx = prog
                            .create_section(&name, SectionType::PROGBITS)
                            .map_err(|_| ParseError::new_p(0, line, "fail to create a section"))?;
                        prog.syms.push(Symbol {
                            stype: SymbolType::Section,
                            name,
                            off: 0,
                            sect: idx,
                            size: 0,
                        });
                        idx
                    }
                };
            }
            Insn::Dbytes(mut v_u8v) => {
                if sect_idx >= prog.sects.len() {
                    return ParseError::new_prog(line_no, line, "Unknown error");
                }
                prog.sects[sect_idx].data.append(&mut v_u8v);
            }
            Insn::Dwords(u32v) => {
                if sect_idx >= prog.sects.len() {
                    return ParseError::new_prog(line_no, line, "Unknown error");
                }
                for v in u32v {
                    prog.sects[sect_idx].data.extend(&v.to_ne_bytes());
                }
            }
            Insn::Ddwords(u64v) => {
                if sect_idx >= prog.sects.len() {
                    return ParseError::new_prog(line_no, line, "Unknown error");
                }
                for v in u64v {
                    prog.sects[sect_idx].data.extend(&v.to_ne_bytes());
                }
            }
            Insn::None => {}
        }
    }

    if let Some(sym_data_idx) = sym_func_data_idx {
        prog.syms[sym_data_idx].size =
            prog.sects[sect_idx].data.len() - prog.syms[sym_data_idx].off;
    }

    prog.create_section(".symtab", SectionType::SYMTAB)
        .map_err(|_| ParseError::new_p(0, "", "Fail to create .symtab section"))?;

    Ok(prog)
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_line() {
        let r = parse_line("my_label:");
        assert_eq!(
            r,
            Ok(Insn::Label("my_label".to_string(), LabelType::NoType))
        );

        let r = parse_line(" my_label : // sfaf");
        assert_eq!(
            r,
            Ok(Insn::Label("my_label".to_string(), LabelType::NoType))
        );

        let r = parse_line(".section text");
        assert_eq!(r, Ok(Insn::Section("text".to_string())));

        let r = parse_line(" . section data //");
        assert_eq!(r, Ok(Insn::Section("data".to_string())));

        let r = parse_line("db 33, 0x22 //foobar");
        assert_eq!(r, Ok(Insn::Dbytes(vec![33, 0x22])));

        let r = parse_line("dw 33,22");
        assert_eq!(r, Ok(Insn::Dwords(vec![33, 22])));

        let r = parse_line("dd 0x33 //");
        assert_eq!(r, Ok(Insn::Ddwords(vec![0x33])));

        let r = parse_line("ld r3, 22 //");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "ld".to_string(),
                "r3".to_string(),
                1,
                "0".to_string(),
                "22".to_string(),
                1,
                "0".to_string(),
            ))
        );

        let r = parse_line("\tld r3,22 //");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "ld".to_string(),
                "r3".to_string(),
                1,
                "0".to_string(),
                "22".to_string(),
                1,
                "0".to_string(),
            ))
        );

        let r = parse_line("\tld r3,r4+7 //");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "ld".to_string(),
                "r3".to_string(),
                1,
                "0".to_string(),
                "r4".to_string(),
                1,
                7.to_string(),
            ))
        );

        let r = parse_line("\tld r3-7,r4 //");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "ld".to_string(),
                "r3".to_string(),
                -1,
                7.to_string(),
                "r4".to_string(),
                1,
                0.to_string(),
            ))
        );

        let r = parse_line("\tld r3,r4 + 57 //");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "ld".to_string(),
                "r3".to_string(),
                1,
                0.to_string(),
                "r4".to_string(),
                1,
                57.to_string(),
            ))
        );

        let r = parse_line("\tld.w r3,r4 + 57 //");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "ld.w".to_string(),
                "r3".to_string(),
                1,
                0.to_string(),
                "r4".to_string(),
                1,
                57.to_string(),
            ))
        );

        let r = parse_line("\tld.w.64 r3,r4 + 57 //");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "ld.w.64".to_string(),
                "r3".to_string(),
                1,
                0.to_string(),
                "r4".to_string(),
                1,
                57.to_string(),
            ))
        );

        let r = parse_line("\tld.w.64 r3 + 3,r4 //");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "ld.w.64".to_string(),
                "r3".to_string(),
                1,
                3.to_string(),
                "r4".to_string(),
                1,
                0.to_string(),
            ))
        );

        let r = parse_line(" call 0x33");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "call".to_string(),
                "0x33".to_string(),
                1,
                0.to_string(),
                "".to_string(),
                1,
                0.to_string()
            ))
        );

        let r = parse_line(" call.helper 0x33");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "call.helper".to_string(),
                "0x33".to_string(),
                1,
                0.to_string(),
                "".to_string(),
                1,
                0.to_string()
            ))
        );

        let r = parse_line(" call.helper @LAB");
        assert_eq!(
            r,
            Ok(Insn::Insn(
                "call.helper".to_string(),
                "@LAB".to_string(),
                1,
                0.to_string(),
                "".to_string(),
                1,
                0.to_string(),
            ))
        );

        let r = parse_line(" call.helper L@LAB");
        assert!(r.is_err());
    }

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
        let r = ebpf_code_gen("jeq", "r1", 0, "0", 28, &mut buf);
        assert_eq!(r, Ok(()));
        assert_eq!(buf, [BPF_JMP | BPF_JEQ, 0x1, 0x1c, 0, 0, 0, 0, 0]);

        buf.clear();
        let r = ebpf_code_gen("jsgt.32", "r1", 0, "100", 24, &mut buf);
        assert_eq!(r, Ok(()));
        assert_eq!(buf, [BPF_JMP32 | BPF_JSGT, 0x1, 0x18, 0, 0x64, 0, 0, 0]);

        buf.clear();
        let r = ebpf_code_gen("call", "0x33", 0, "", 0, &mut buf);
        assert_eq!(r, Ok(()));
        assert_eq!(buf, [BPF_JMP | BPF_CALL, 0x10, 0, 0, 0x33, 0, 0, 0]);

        buf.clear();
        let r = ebpf_code_gen("call.helper", "0x33", 0, "", 0, &mut buf);
        assert_eq!(r, Ok(()));
        assert_eq!(buf, [BPF_JMP | BPF_CALL, 0x0, 0, 0, 0x33, 0, 0, 0]);
    }

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
                BPF_LD | BPF_DW | BPF_IMM,
                0x0a,
                0,
                0,
                0,
                0,
                0,
                0,
                0x0,
                0x0,
                0x0,
                0x0,
                0x0,
                0x0,
                0x0,
                0x0,
                BPF_ALU | BPF_MOV | BPF_K,
                0x1,
                0,
                0,
                0xa,
                0,
                0,
                0,
                BPF_ALU | BPF_MOV | BPF_K,
                0x7,
                0,
                0,
                0x0,
                0x0,
                0x0,
                0x0,
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
