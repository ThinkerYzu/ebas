// https://www.kernel.org/doc/html/latest/bpf/btf.html
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::mem;
use std::slice;

use crate::parser::MapType;

#[allow(dead_code, non_camel_case_types)]
mod types {
    use std::hash::{Hash, Hasher};

    #[repr(C)]
    pub struct btf_header {
        pub magic: u16,
        pub version: u8,
        pub flags: u8,
        pub hdr_len: u32,

        // All offsets are in bytes relative to the end of this header
        pub type_off: u32, // offset of type section
        pub type_len: u32, // length of type section
        pub str_off: u32,  // offset of string section
        pub str_len: u32,  // length of string section
    }

    #[allow(clippy::upper_case_acronyms)]
    pub enum BTF_KIND {
        INVALID = 0,
        INT = 1,
        PTR = 2,
        ARRAY = 3,
        STRUCT = 4,
        UNION = 5,
        ENUM = 6,
        FWD = 7,
        TYPEDEF = 8,
        VOLATILE = 9,
        CONST = 10,
        RESTRICT = 11,
        FUNC = 12,
        FUNC_PROTO = 13,
        VAR = 14,
        DATASEC = 15,
        FLOAT = 16,
        DECL_TAG = 17,
        TYPE_TAG = 18,
        ENUM64 = 19,
    }

    impl BTF_KIND {
        pub fn from_u8(v: u8) -> BTF_KIND {
            match v {
                1 => BTF_KIND::INT,
                2 => BTF_KIND::PTR,
                3 => BTF_KIND::ARRAY,
                4 => BTF_KIND::STRUCT,
                5 => BTF_KIND::UNION,
                6 => BTF_KIND::ENUM,
                7 => BTF_KIND::FWD,
                8 => BTF_KIND::TYPEDEF,
                9 => BTF_KIND::VOLATILE,
                10 => BTF_KIND::CONST,
                11 => BTF_KIND::RESTRICT,
                12 => BTF_KIND::FUNC,
                13 => BTF_KIND::FUNC_PROTO,
                14 => BTF_KIND::VAR,
                15 => BTF_KIND::DATASEC,
                16 => BTF_KIND::FLOAT,
                17 => BTF_KIND::DECL_TAG,
                18 => BTF_KIND::TYPE_TAG,
                19 => BTF_KIND::ENUM64,
                _ => BTF_KIND::INVALID,
            }
        }
    }

    #[allow(clippy::upper_case_acronyms)]
    pub enum BPF_MAP_TYPE {
        UNSPEC = 0,
        HASH = 1,
        ARRAY = 2,
        PROG_ARRAY = 3,
        PERF_EVENT_ARRAY = 4,
        PERCPU_HASH = 5,
        PERCPU_ARRAY = 6,
        STACK_TRACE = 7,
        CGROUP_ARRAY = 8,
        LRU_HASH = 9,
        LRU_PERCPU_HASH = 10,
        LPM_TRIE = 11,
        ARRAY_OF_MAPS = 12,
        HASH_OF_MAPS = 13,
        DEVMAP = 14,
        SOCKMAP = 15,
        CPUMAP = 16,
        XSKMAP = 17,
        SOCKHASH = 18,
        CGROUP_STORAGE = 19,
        REUSEPORT_SOCKARRAY = 20,
        PERCPU_CGROUP_STORAGE = 21,
        QUEUE = 22,
        STACK = 23,
        SK_STORAGE = 24,
        DEVMAP_HASH = 25,
        STRUCT_OPS = 26,
        RINGBUF = 27,
        INODE_STORAGE = 28,
        TASK_STORAGE = 29,
        BLOOM_FILTER = 30,
        USER_RINGBUF = 31,
        CGRP_STORAGE = 32,
    }

    #[repr(C)]
    pub union size_or_type {
        pub size: u32,
        pub typ: u32,
    }

    impl Hash for size_or_type {
        fn hash<H: Hasher>(&self, state: &mut H) {
            unsafe {
                self.size.hash(state);
            }
        }
    }

    impl PartialEq for size_or_type {
        fn eq(&self, other: &Self) -> bool {
            unsafe { self.size == other.size }
        }
    }

    #[derive(Hash, PartialEq)]
    #[repr(C)]
    pub struct btf_type {
        pub name_off: u32,
        /* "info" bits arrangement
         * bits  0-15: vlen (e.g. # of struct's members)
         * bits 16-23: unused
         * bits 24-28: kind (e.g. int, ptr, array...etc)
         * bits 29-30: unused
         * bit     31: kind_flag, currently used by
         *             struct, union, fwd, enum and enum64.
         */
        pub info: u32,
        /* "size" is used by INT, ENUM, STRUCT, UNION and ENUM64.
         * "size" tells the size of the type it is describing.
         *
         * "type" is used by PTR, TYPEDEF, VOLATILE, CONST, RESTRICT,
         * FUNC, FUNC_PROTO, DECL_TAG and TYPE_TAG.
         * "type" is a type_id referring to another type.
         */
        pub size_type: size_or_type,
    }

    impl btf_type {
        pub fn make_info(vlen: u32, kind: u32, kind_flag: u32) -> u32 {
            vlen | (kind << 24) | (kind_flag << 31)
        }

        pub fn get_vlen(&self) -> u32 {
            self.info & 0xffff
        }

        pub fn get_kind(&self) -> u32 {
            (self.info >> 16) & 0xff
        }

        pub fn get_kind_flag(&self) -> u32 {
            self.info >> 31
        }
    }

    #[derive(Hash, PartialEq)]
    #[repr(C)]
    pub struct btf_array {
        pub typ: u32,
        pub index_type: u32,
        pub nelems: u32,
    }

    #[derive(Hash, PartialEq)]
    #[repr(C)]
    pub struct btf_member {
        pub name_off: u32,
        pub typ: u32,
        pub offset: u32,
    }

    #[derive(Hash, PartialEq)]
    #[repr(C)]
    pub struct btf_enum {
        pub name_off: u32,
        pub val: i32,
    }

    #[derive(Hash, PartialEq)]
    #[repr(C)]
    pub struct btf_param {
        pub name_off: u32,
        pub typ: u32,
    }

    #[derive(Hash, PartialEq)]
    #[repr(C)]
    pub struct btf_var {
        pub linkage: u32,
    }

    #[derive(Hash, PartialEq)]
    #[repr(C)]
    pub struct btf_var_secinfo {
        pub typ: u32,
        pub offset: u32,
        pub size: u32,
    }

    #[derive(Hash, PartialEq)]
    #[repr(C)]
    pub struct btf_decl_tag {
        pub component_idx: i32,
    }

    #[derive(Hash, PartialEq)]
    #[repr(C)]
    pub struct btf_enum64 {
        pub name_off: u32,
        pub val_lo32: u32,
        pub val_hi32: u32,
    }

    pub enum btf_func_linkage {
        BTF_FUNC_STATIC = 0,
        BTF_FUNC_GLOBAL = 1,
        BTF_FUNC_EXTERN = 2,
    }

    pub enum btf_var_linkage {
        BTF_VAR_STATIC = 0,
        BTF_VAR_GLOBAL = 1,
    }
}

#[derive(Hash, PartialEq)]
#[allow(dead_code)]
enum BTFExtra {
    None,
    U32(u32),
    Array(types::btf_array),
    Members(Vec<types::btf_member>),
    Enum(Vec<types::btf_enum>),
    Params(Vec<types::btf_param>),
    Var(types::btf_var),
    Secinfos(Vec<types::btf_var_secinfo>),
    DeclTag(types::btf_decl_tag),
    Enum64(Vec<types::btf_enum64>),
}

impl BTFExtra {
    #[allow(clippy::useless_transmute)]
    fn as_bytes(&self) -> &[u8] {
        match self {
            BTFExtra::None => &[],
            BTFExtra::U32(v) => unsafe {
                slice::from_raw_parts(mem::transmute::<_, *const u8>(v), mem::size_of::<u32>())
            },
            BTFExtra::Array(v) => unsafe {
                slice::from_raw_parts(
                    mem::transmute::<_, *const u8>(v),
                    mem::size_of::<types::btf_array>(),
                )
            },
            BTFExtra::Members(v) => unsafe {
                slice::from_raw_parts(
                    mem::transmute::<_, *const u8>(v.as_ptr()),
                    mem::size_of::<types::btf_member>() * v.len(),
                )
            },
            BTFExtra::Enum(v) => unsafe {
                slice::from_raw_parts(
                    mem::transmute::<_, *const u8>(v.as_ptr()),
                    mem::size_of::<types::btf_enum>() * v.len(),
                )
            },
            BTFExtra::Params(v) => unsafe {
                slice::from_raw_parts(
                    mem::transmute::<_, *const u8>(v.as_ptr()),
                    mem::size_of::<types::btf_param>() * v.len(),
                )
            },
            BTFExtra::Var(v) => unsafe {
                slice::from_raw_parts(
                    mem::transmute::<_, *const u8>(v),
                    mem::size_of::<types::btf_var>(),
                )
            },
            BTFExtra::Secinfos(v) => unsafe {
                slice::from_raw_parts(
                    mem::transmute::<_, *const u8>(v.as_ptr()),
                    mem::size_of::<types::btf_var_secinfo>() * v.len(),
                )
            },
            BTFExtra::DeclTag(v) => unsafe {
                slice::from_raw_parts(
                    mem::transmute::<_, *const u8>(v),
                    mem::size_of::<types::btf_decl_tag>(),
                )
            },
            BTFExtra::Enum64(v) => unsafe {
                slice::from_raw_parts(
                    mem::transmute::<_, *const u8>(v.as_ptr()),
                    mem::size_of::<types::btf_enum64>() * v.len(),
                )
            },
        }
    }
}

#[derive(Hash, PartialEq)]
#[allow(dead_code, clippy::upper_case_acronyms)]
pub struct BTF {
    typ: types::btf_type,
    extra: BTFExtra,
}

const MACHINE_PTR_SIZE: usize = 8;

#[allow(dead_code)]
impl BTF {
    pub fn calc_code(&self) -> u64 {
        let mut s = DefaultHasher::new();
        self.hash(&mut s);
        s.finish()
    }

    pub fn type_size(&self, btf_type_data: &[BTF]) -> usize {
        let typ = (self.typ.info >> 24) & 0xf;
        match types::BTF_KIND::from_u8(typ as u8) {
            types::BTF_KIND::INT => unsafe { self.typ.size_type.size as usize },
            types::BTF_KIND::PTR => MACHINE_PTR_SIZE,
            types::BTF_KIND::ARRAY => {
                if let BTFExtra::Array(extra) = &self.extra {
                    let back_tid = extra.typ;
                    let back = &btf_type_data[(back_tid - 1) as usize];
                    back.type_size(btf_type_data) * extra.nelems as usize
                } else {
                    panic!("Should be an BTFExtra::Array");
                }
            }
            types::BTF_KIND::STRUCT => {
                if let BTFExtra::Members(members) = &self.extra {
                    if members.is_empty() {
                        0
                    } else {
                        let back_tid = members.last().unwrap().typ as usize;
                        assert!((members.last().unwrap().offset % 8) == 0);
                        let sz = btf_type_data[back_tid - 1].type_size(btf_type_data)
                            + members.last().unwrap().offset as usize / 8;
                        (sz + MACHINE_PTR_SIZE - 1) & !(MACHINE_PTR_SIZE - 1)
                    }
                } else {
                    panic!("Should be an BTFExtra::Members");
                }
            }
            types::BTF_KIND::VAR => {
                let back_tid = unsafe { self.typ.size_type.typ };
                let back = &btf_type_data[(back_tid - 1) as usize];
                back.type_size(btf_type_data)
            }
            _ => {
                panic!("Unknown type");
            }
        }
    }

    pub fn new_int(name_off: u32, size: u32) -> BTF {
        BTF {
            typ: types::btf_type {
                name_off,
                info: types::btf_type::make_info(0, types::BTF_KIND::INT as u32, 0),
                size_type: types::size_or_type { size },
            },
            extra: BTFExtra::U32(size * 8),
        }
    }
    pub fn new_ptr(type_id: u32) -> BTF {
        BTF {
            typ: types::btf_type {
                name_off: 0,
                info: types::btf_type::make_info(0, types::BTF_KIND::PTR as u32, 0),
                size_type: types::size_or_type { typ: type_id },
            },
            extra: BTFExtra::None,
        }
    }

    pub fn new_array(type_id: u32, index_type: u32, nelems: u32) -> BTF {
        BTF {
            typ: types::btf_type {
                name_off: 0,
                info: types::btf_type::make_info(0, types::BTF_KIND::ARRAY as u32, 0),
                size_type: types::size_or_type { size: 0 },
            },
            extra: BTFExtra::Array(types::btf_array {
                typ: type_id,
                index_type,
                nelems,
            }),
        }
    }

    pub fn new_struct(name_off: u32, members: &[(u32, u32)], btf_type_data: &[BTF]) -> BTF {
        let mut size_type = 0;
        let mut extra = vec![];
        for (name_off, type_id) in members {
            let typ = &btf_type_data[(*type_id - 1) as usize];
            extra.push(types::btf_member {
                name_off: *name_off,
                typ: *type_id,
                offset: size_type * 8,
            });
            size_type += (typ.type_size(btf_type_data) as u32 + MACHINE_PTR_SIZE as u32 - 1)
                & !(MACHINE_PTR_SIZE as u32 - 1);
        }
        BTF {
            typ: types::btf_type {
                name_off,
                info: types::btf_type::make_info(
                    members.len() as u32,
                    types::BTF_KIND::STRUCT as u32,
                    size_type,
                ),
                size_type: types::size_or_type { size: size_type },
            },
            extra: BTFExtra::Members(extra),
        }
    }

    pub fn new_union(name_off: u32, members: &[(u32, u32)], btf_type_data: &[BTF]) -> BTF {
        let mut size_type = 0;
        let mut extra = vec![];
        for (name_off, type_id) in members {
            let typ = &btf_type_data[(*type_id - 1) as usize].typ;
            extra.push(types::btf_member {
                name_off: *name_off,
                typ: *type_id,
                offset: size_type,
            });
            size_type += unsafe { typ.size_type.size };
        }
        BTF {
            typ: types::btf_type {
                name_off,
                info: types::btf_type::make_info(
                    members.len() as u32,
                    types::BTF_KIND::UNION as u32,
                    size_type,
                ),
                size_type: types::size_or_type { size: size_type },
            },
            extra: BTFExtra::Members(extra),
        }
    }

    pub fn new_enum(name_off: u32, size: u32, members: &[(u32, i32)]) -> BTF {
        BTF {
            typ: types::btf_type {
                name_off,
                info: types::btf_type::make_info(
                    members.len() as u32,
                    types::BTF_KIND::ENUM as u32,
                    0,
                ),
                size_type: types::size_or_type { size },
            },
            extra: BTFExtra::Enum(
                members
                    .iter()
                    .map(|(name_off, val)| types::btf_enum {
                        name_off: *name_off,
                        val: *val,
                    })
                    .collect(),
            ),
        }
    }

    pub fn new_fwd(name_off: u32, is_struct: bool) -> BTF {
        BTF {
            typ: types::btf_type {
                name_off,
                info: types::btf_type::make_info(
                    0,
                    types::BTF_KIND::FWD as u32,
                    u32::from(!is_struct),
                ),
                size_type: types::size_or_type { size: 0 },
            },
            extra: BTFExtra::None,
        }
    }

    pub fn new_typedef(name_off: u32, type_id: u32) -> BTF {
        BTF {
            typ: types::btf_type {
                name_off,
                info: types::btf_type::make_info(0, types::BTF_KIND::TYPEDEF as u32, 0),
                size_type: types::size_or_type { typ: type_id },
            },
            extra: BTFExtra::None,
        }
    }

    pub fn new_volatile(type_id: u32) -> BTF {
        BTF {
            typ: types::btf_type {
                name_off: 0,
                info: types::btf_type::make_info(0, types::BTF_KIND::VOLATILE as u32, 0),
                size_type: types::size_or_type { typ: type_id },
            },
            extra: BTFExtra::None,
        }
    }

    pub fn new_const(type_id: u32) -> BTF {
        BTF {
            typ: types::btf_type {
                name_off: 0,
                info: types::btf_type::make_info(0, types::BTF_KIND::CONST as u32, type_id),
                size_type: types::size_or_type { typ: type_id },
            },
            extra: BTFExtra::None,
        }
    }

    pub fn new_restrict(type_id: u32) -> BTF {
        BTF {
            typ: types::btf_type {
                name_off: 0,
                info: types::btf_type::make_info(0, types::BTF_KIND::RESTRICT as u32, 0),
                size_type: types::size_or_type { typ: type_id },
            },
            extra: BTFExtra::None,
        }
    }

    pub fn new_func(name_off: u32, linkage: types::btf_func_linkage, type_id: u32) -> BTF {
        BTF {
            typ: types::btf_type {
                name_off,
                info: types::btf_type::make_info(
                    linkage as u32,
                    types::BTF_KIND::FUNC as u32,
                    type_id,
                ),
                size_type: types::size_or_type { size: 0 },
            },
            extra: BTFExtra::None,
        }
    }

    pub fn new_func_proto(name_off: u32, type_id: u32, params: &[(u32, u32)]) -> BTF {
        BTF {
            typ: types::btf_type {
                name_off,
                info: types::btf_type::make_info(
                    params.len() as u32,
                    types::BTF_KIND::FUNC_PROTO as u32,
                    0,
                ),
                size_type: types::size_or_type { typ: type_id },
            },
            extra: BTFExtra::Params(
                params
                    .iter()
                    .map(|(name_off, typ)| types::btf_param {
                        name_off: *name_off,
                        typ: *typ,
                    })
                    .collect(),
            ),
        }
    }

    pub fn new_var(name_off: u32, linkage: types::btf_var_linkage, type_id: u32) -> BTF {
        BTF {
            typ: types::btf_type {
                name_off,
                info: types::btf_type::make_info(0, types::BTF_KIND::VAR as u32, 0),
                size_type: types::size_or_type { typ: type_id },
            },
            extra: BTFExtra::Var(types::btf_var {
                linkage: linkage as u32,
            }),
        }
    }

    pub fn new_datasec(name_off: u32, vars: &[u32], btf_type_data: &[BTF]) -> BTF {
        let mut extra = vec![];
        for type_id in vars {
            let typ = &btf_type_data[(*type_id - 1) as usize];
            extra.push(types::btf_var_secinfo {
                typ: *type_id,
                offset: 0,
                size: typ.type_size(btf_type_data) as u32,
            });
        }
        BTF {
            typ: types::btf_type {
                name_off,
                info: types::btf_type::make_info(
                    vars.len() as u32,
                    types::BTF_KIND::DATASEC as u32,
                    0,
                ),
                size_type: types::size_or_type { size: 0 },
            },
            extra: BTFExtra::Secinfos(extra),
        }
    }

    pub fn new_float(name_off: u32, size: u32) -> BTF {
        assert!([1_u32, 2, 4, 8, 12, 16].contains(&size));
        BTF {
            typ: types::btf_type {
                name_off,
                info: types::btf_type::make_info(0, types::BTF_KIND::FLOAT as u32, 0),
                size_type: types::size_or_type { size },
            },
            extra: BTFExtra::None,
        }
    }

    pub fn new_decl_tag(name_off: u32, type_id: u32, component_idx: i32) -> BTF {
        BTF {
            typ: types::btf_type {
                name_off,
                info: types::btf_type::make_info(0, types::BTF_KIND::DECL_TAG as u32, 0),
                size_type: types::size_or_type { typ: type_id },
            },
            extra: BTFExtra::DeclTag(types::btf_decl_tag { component_idx }),
        }
    }

    pub fn new_type_tag(name_off: u32, type_id: u32) -> BTF {
        BTF {
            typ: types::btf_type {
                name_off,
                info: types::btf_type::make_info(0, types::BTF_KIND::TYPE_TAG as u32, 0),
                size_type: types::size_or_type { typ: type_id },
            },
            extra: BTFExtra::None,
        }
    }

    pub fn new_enum64(name_off: u32, size: u32, members: &[(u32, u64)]) -> BTF {
        assert!([1_u32, 2, 4, 8].contains(&size));
        BTF {
            typ: types::btf_type {
                name_off,
                info: types::btf_type::make_info(
                    members.len() as u32,
                    types::BTF_KIND::ENUM64 as u32,
                    8,
                ),
                size_type: types::size_or_type { size },
            },
            extra: BTFExtra::Enum64(
                members
                    .iter()
                    .map(|(name_off, val)| types::btf_enum64 {
                        name_off: *name_off,
                        val_lo32: (*val & 0xffffffff) as u32,
                        val_hi32: (*val >> 32) as u32,
                    })
                    .collect(),
            ),
        }
    }

    fn as_bytes(&self) -> Vec<u8> {
        let mut bin = vec![];
        bin.extend_from_slice(unsafe {
            slice::from_raw_parts(
                &self.typ as *const types::btf_type as *const u8,
                mem::size_of::<types::btf_type>(),
            )
        });
        bin.extend_from_slice(self.extra.as_bytes());
        bin
    }
}

pub struct BTFBuilder {
    strtab: HashMap<String, usize>,
    strtab_sz: usize,
    btf_type_data: Vec<BTF>,
    code_to_type_id: HashMap<u64, usize>,
    map_types: Vec<u32>,
}

impl BTFBuilder {
    pub fn new() -> BTFBuilder {
        BTFBuilder {
            strtab: HashMap::new(),
            strtab_sz: 1,
            btf_type_data: vec![],
            code_to_type_id: HashMap::new(),
            map_types: vec![],
        }
    }

    pub fn len(&self) -> usize {
        self.btf_type_data.len()
    }

    pub fn type_size(&self, type_id: usize) -> usize {
        self.btf_type_data[type_id - 1].type_size(&self.btf_type_data)
    }

    pub fn add_or_find_str(&mut self, name: &str) -> usize {
        self.strtab
            .get(name)
            .copied()
            .or_else(|| {
                let off = self.strtab_sz;
                self.strtab.insert(name.to_string(), off);
                self.strtab_sz += name.as_bytes().len() + 1;
                Some(off)
            })
            .unwrap()
    }

    fn gen_strtab(&self) -> Vec<u8> {
        let mut kvs: Vec<_> = self.strtab.iter().collect();
        kvs.sort_by_key(|(_key, off)| *off);
        let mut strtab = vec![0];
        for (key, off) in kvs {
            assert_eq!(*off, strtab.len());
            strtab.extend_from_slice(key.as_bytes());
            strtab.push(0);
        }
        strtab
    }

    pub fn add_or_find_type(&mut self, btf: BTF) -> usize {
        let mut code = btf.calc_code();
        while let Some(type_id) = self.code_to_type_id.get(&code).copied() {
            if btf == self.btf_type_data[type_id - 1] {
                return type_id;
            }
            // Having two types with the same code point is a
            // collision.  Try next code point until empty one
            // or exactly same type.
            code += 1;
        }
        self.btf_type_data.push(btf);
        let type_id = self.btf_type_data.len();
        self.code_to_type_id.insert(code, type_id);
        type_id
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bin = vec![];
        let type_off = mem::size_of::<types::btf_header>() as u32;
        bin.resize(type_off as usize, 0);

        for typ in &self.btf_type_data {
            bin.append(&mut typ.as_bytes());
        }
        let type_len = bin.len() as u32 - type_off;

        let mut strtab = self.gen_strtab();
        let str_off = bin.len() as u32;
        let str_len = strtab.len() as u32;
        bin.append(&mut strtab);

        let hdr_len = mem::size_of::<types::btf_header>() as u32;
        let hdr = types::btf_header {
            magic: 0xeb9f,
            version: 0x1,
            flags: 0,
            hdr_len,
            type_off: type_off - hdr_len,
            type_len,
            str_off: str_off - hdr_len,
            str_len,
        };
        bin[..(type_off as usize)].copy_from_slice(unsafe {
            slice::from_raw_parts(
                &hdr as *const types::btf_header as *const u8,
                type_off as usize,
            )
        });
        bin
    }

    fn add_or_find_u8_array(&mut self, size: usize) -> usize {
        let uint8_id = self.add_or_find_type(BTF::new_int(0, 1)) as u32;
        let uint_id = self.add_or_find_type(BTF::new_int(0, 4)) as u32;
        self.add_or_find_type(BTF::new_array(uint8_id, uint_id, size.try_into().unwrap()))
    }

    pub fn add_map(
        &mut self,
        name: String,
        map_type: MapType,
        key_sz: u32,
        value_sz: u32,
        max_entries: u32,
    ) -> Result<usize, String> {
        let tid = match map_type {
            MapType::Array | MapType::Hash => {
                let int_str_off = self.add_or_find_str("int") as u32;
                let int_id = self.add_or_find_type(BTF::new_int(int_str_off, 4)) as u32;
                let map_type = match map_type {
                    MapType::Array => types::BPF_MAP_TYPE::ARRAY as u32,
                    MapType::Hash => types::BPF_MAP_TYPE::HASH as u32,
                    _ => 0_u32,
                };
                let array_id =
                    self.add_or_find_type(BTF::new_array(int_id, int_id, map_type)) as u32;
                let type_id = self.add_or_find_type(BTF::new_ptr(array_id)) as u32;
                let kint_id = match key_sz {
                    1 => self.add_or_find_type(BTF::new_int(int_str_off, 1)),
                    2 => self.add_or_find_type(BTF::new_int(int_str_off, 2)),
                    4 => self.add_or_find_type(BTF::new_int(int_str_off, 4)),
                    8 => self.add_or_find_type(BTF::new_int(int_str_off, 8)),
                    _ => {
                        return Err("Unknown key size".to_string());
                    }
                } as u32;
                let key_id = self.add_or_find_type(BTF::new_ptr(kint_id));
                let value_id = {
                    let ar_id = self.add_or_find_u8_array(value_sz.try_into().unwrap()) as u32;
                    self.add_or_find_type(BTF::new_ptr(ar_id))
                };
                let array_id =
                    self.add_or_find_type(BTF::new_array(int_id, int_id, max_entries)) as u32;
                let max_id = self.add_or_find_type(BTF::new_ptr(array_id)) as u32;
                let name_off = self.add_or_find_str(&name) as u32;
                let type_off = self.add_or_find_str("type") as u32;
                let key_off = self.add_or_find_str("key") as u32;
                let value_off = self.add_or_find_str("value") as u32;
                let max_off = self.add_or_find_str("max_entries") as u32;

                let maptype_id = self.add_or_find_type(BTF::new_struct(
                    0,
                    &[
                        (type_off, type_id),
                        (key_off, key_id as u32),
                        (value_off, value_id as u32),
                        (max_off, max_id),
                    ],
                    &self.btf_type_data,
                ));
                let mapval_id = self.add_or_find_type(BTF::new_var(
                    name_off,
                    types::btf_var_linkage::BTF_VAR_GLOBAL,
                    maptype_id as u32,
                ));
                self.map_types.push(mapval_id as u32);
                mapval_id
            }
            _ => {
                return Err("unknown map type".to_string());
            }
        };

        Ok(tid)
    }

    pub fn add_datasec_maps(&mut self) {
        if self.map_types.is_empty() {
            return;
        }
        let name_off = self.add_or_find_str(".maps") as u32;
        self.add_or_find_type(BTF::new_datasec(
            name_off,
            &self.map_types,
            &self.btf_type_data,
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_or_find_str() {
        let data = ["abc", "def", "ghijk", "lmnop", "qr"];
        let mut offs = vec![];
        let mut builder = BTFBuilder::new();
        for v in data {
            offs.push(builder.add_or_find_str(v));
        }
        assert_eq!(offs, [1, 5, 9, 15, 21]);
        for (i, v) in data.iter().enumerate() {
            assert_eq!(builder.add_or_find_str(v), offs[i]);
        }

        assert_eq!(builder.gen_strtab().len(), 24);
    }

    #[test]
    fn test_add_or_find_type() {
        let types = [
            BTF::new_int(11, 8),
            BTF::new_int(12, 8),
            BTF::new_int(13, 8),
            BTF::new_int(14, 8),
        ];
        assert!(types[0].calc_code() != types[1].calc_code());
        let mut type_ids = vec![];
        let mut builder = BTFBuilder::new();
        for t in types {
            type_ids.push(builder.add_or_find_type(t));
        }

        assert_eq!(type_ids, [1, 2, 3, 4]);
        for i in 1..type_ids.len() {
            assert_ne!(type_ids[i - 1], type_ids[i]);
        }

        let types = [
            BTF::new_int(11, 8),
            BTF::new_int(12, 8),
            BTF::new_int(13, 8),
            BTF::new_int(14, 8),
        ];
        for t in types {
            assert_eq!(builder.add_or_find_type(t), type_ids.remove(0));
        }
    }
}
