#[repr(C)]
struct btf_header {
    magic: u16,
    version: u8,
    flags: u8,
    hdr_len: u32,

    // All offsets are in bytes relative to the end of this header
    type_off: u32, // offset of type section
    type_len: u32, // length of type section
    str_off: u32,  // offset of string section
    str_len: u32,  // length of string section
}

#[allow(clippy::upper_case_acronyms)]
enum BTF_KIND {
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

#[repr(C)]
union size_or_type {
    size: u32,
    typ: u32,
}

#[repr(C)]
struct btf_type {
    name_off: u32,
    /* "info" bits arrangement
     * bits  0-15: vlen (e.g. # of struct's members)
     * bits 16-23: unused
     * bits 24-28: kind (e.g. int, ptr, array...etc)
     * bits 29-30: unused
     * bit     31: kind_flag, currently used by
     *             struct, union, fwd, enum and enum64.
     */
    info: u32,
    /* "size" is used by INT, ENUM, STRUCT, UNION and ENUM64.
     * "size" tells the size of the type it is describing.
     *
     * "type" is used by PTR, TYPEDEF, VOLATILE, CONST, RESTRICT,
     * FUNC, FUNC_PROTO, DECL_TAG and TYPE_TAG.
     * "type" is a type_id referring to another type.
     */
    size_type: size_or_type,
}

impl btf_type {
    fn make_info(vlen: u32, kind: u32, kind_flag: u32) -> u32{
        vlen | (kind << 24) | (kind_flag << 31)
    }

    fn get_vlen(&self) -> u32 {
        self.info & 0xffff
    }

    fn get_kind(&self) -> u32 {
        (self.info >> 16) & 0xff
    }

    fn get_kind_flag(&self) -> u32 {
        self.info >> 31
    }
}

struct btf_array {
    typ: u32,
    index_type: u32,
    nelems: u32,
}

struct btf_member {
    name_off: u32,
    typ: u32,
    offset: u32,
}

struct btf_enum {
    name_off: u32,
    val: i32,
}

struct btf_param {
    name_off: u32,
    typ: u32,
}

struct btf_var {
    linkage: u32,
}

struct btf_var_secinfo {
    typ: u32,
    offset: u32,
    size: u32,
}

struct btf_decl_tag {
    component_idx: u32,
}

struct btf_enum64 {
    name_off: u32,
    val_lo32: u32,
    val_hi32: u32,
}
