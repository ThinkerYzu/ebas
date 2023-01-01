**ebas** is an assembler for Extended Berkeley Packet Filtering (eBPF)
programs. It helps you write and compile eBPF programs that can run on
Linux systems. You can use it by typing in the command
"./target/debug/ebas <input-file> <output-file>" followed by the name
of your input file and output file, then press enter. The assembler
will help you create a program that can be used in Linux systems.

## Build

**ebas** is implemented in Rust. You need to install Rust first.  The
way to install Rust varies depending on your environment.  Once Rust
is installed, you can use `cargo` command to build **ebas**. Just type
`cargo build --release`. With this command `ebas` binary will be
generated in the `target/release` directory of your project.

## Compile Programs

Use **ebas** to compile ebpf assembly program. For example, `ebas
ebpf_program.s ebpf_program.o` will compile `ebpf_program.s` and
generate an ebpf object file `ebpf_program.o`. This ebpf object file
can be loaded at run-time with libbpf library.

Check the file *ex-apps/nanosleep.c* in the repository for loading an
ebpf program.

## Instructions

There are three major caegories of instructions.

 - Load and Store
 - Arithmatic
 - Jump

There are 10 64-bits general purpose registers. `r0`, `r1`, ..., `r91.
`r10` is a read-only frame pointer to access stack.

### Load and Store

Load instructions are used to load data from a memory address to a
register.  Contrastly, store instructions copies the value of a
register to a memory address.

You can load 4 different size of data from memory.

 - `ld.b` loads 1 byte

 - `ld.h` loads 2 bytes

 - `ld.w` loads 4 bytes

 - `ld.dw` loads 8 bytes

For every `ld` instructions, it loads data to a register. For example,

 - `ld.b r1, r2` loads one byte from the address given by the register
   `r2` to the register `r1`.

 - `ld.h r1, r2 + 4` loads 2 bytes from the address given by `r2`
   with an offset `4`.

`ld.dw` has a special function to load an 8 bytes immediate value to a
register.  `ld.b`, `ld.h`, and `ld.w` can not load an immediate value.

 - `ld.dw r1, 0xffffffffffffffff` loads `0xffffffffffffffff` (8 bytes
   immediate value) to `r1`.

You can store 4 different size of data to memory as well.

 - `st.b` is an 1 byte instruction

 - `st.h` is a 2 bytes instruction

 - `st.w` is a 4 bytes instruction

 - `st.dw` is a 8 bytes instruction

`st` instructions can use data from a register or an immediate value
(32-bits at most).

 - `st.b r1, r2` read the lowest byte of r2 and store it to the
   address given by `r1`.

 - `st.w r1 + 4, r2` read the lowest 4 bytes of r2 and store them to
   the address given by `r1` with an offset `4`.

 - `st.w r1 + 8, 0xdeadbeef` store `0xdeadbeef` to the address given
   by `r1` with an offset `8`.

### Arithmatic

Following are arithmatic instructions.

 - `add` add two operands and keep the result at the first register.

 - `sub` substract two operands and keep the result at the first
   reigster.

 - `mul` multiples two operands.

 - `div` divides first operand by the second operand.

 - `or`

 - `and`

 - `lsh` bitwise shifts the first operand left with by n-bits given by
   the second operand.

 - `rsh` bitwise shifts the first operand right.

 - `neg` do bitwise not on the second operand and store the result at
   the first register.

 - `mod` modulo.

 - `xor`

 - `arsh` do sign-aware shift right.

 - `end` do byte swapping.

 - `mov` moves the value of the second operand to the first register.

The second operand should be a register or a 32-bits immediate value.

 - `add r1, r2` adds `r2` to `r1`.

 - `add r1, 0xff` adds `0xff` to `r1`.

 - `mov r1, r3` move the value of `r3` to `r1`.

 - `mov r1, 0x1f1f` move `0x1f1f` (32-bits) to `r1`.

All these instructions are 3-bits.  They read 32-bits from both
operands, but write to the first operand, a register, as a 64-bits
value.

There are 64-bits versions to read 64-bits from both operands.

 - `add.64 r1, r2` adds the 64-bits value of `r2` to `r1`.

 - `div.64 r1, r2` divide `r1` with the 64-bits value of `r2`.

 - `div.64 r1, r2` move the 64-bits value of `r2` to `r1`.

However, you can not use 64-bits immedate value.

### Jump

Most jump instructions compare two operand and jump to the location
given by an offset related PC.

 - `ja` is an unconditional jump.

 - `jeq` jump if two operands are equal.

 - `jgt` jump if the first operand is greater than the second one.

 - `jge` jump if the first operand is greater than or equal to the
   second one.

 - `jset` jump if any bits set in the first operand is also set in the
   second one.

 - `jne` jump if two operands are not equal.

 - `jsgt` jump if the first operand is greater than the second one
   (signed).

 - `jsge` jump if the first operand is greater than or equal to the
   second one (signed).

 - `jlt` jump if the first operand is lesser than the second one.

 - `jle` jump if the first operand is lesser than or equal to the
   second one.

 - `jslt` jump if the first operand is lesser than the second one
   (signed).

 - `jsle` jump if the first operand is lesser than or equal to the
   second one (signed).

These instructions are used with two operands and one offset. The
followings are examples.

    jeq r0, 0x20, +1  // jump to the next instruction if r0 == 0x20
    jsgt r2, r3, -4  // jump 4 instructions backward if r2 > r3 (signed)


The `call` instruction is special to call a function.  It has only one
operand which should be the address of a function.  A variant
`call.helper` is used to call BPF helper functions.

    call 0xdeadbeef // call a function which is at `0xdeadbeef`.
    call.helper 123   // call a helper function numbered `123`

The `exit` instruction terminates the ebpf program and returns to the
original calling context.

    exit // terminate ebpf program execution

## The Syntax of ebas

A program includes sections that comprise functions or data objects
exclusively.  The keyword `.section` followed by a section name starts
a new section.  A section ends by end-of-file or another `.section`
keyword.  `.bss` is a variant of `.section` to create a BSS section
with the section name `.bss` by default.  However, you can change the
section name by providing a section name after the `.bss` keyword.
The section started by the `.bss` keyword should contains only data
objects while you can add functions or data objects exclusively to a
section started by the `.section` keyword.  Following is an example
that defines a `fentry` program attached to `__x64_sys_nanosleep`.

    .section "fentry/__x64_sys_nanosleep"
    .function nanosleep_fentry
        call.helper   14
        rsh.64     r0, 32
        ld.dw      r1, @pid
        ld.w      r1, r1
        lsh.64     r1, 32
        arsh.64     r1, 32
        jne       r0, r1, @LBB0_2
        ld.dw      r1, @fentry_cnt
        ld.w      r2, r1
        add       r2, 1
        st.w      r1, r2
   
    LBB0_2:
        mov       r0, 0
        exit
   
    .bss
    .data pid
        dw   0
    .data fentry_cnt
        dw   0

`.function` followed by a function name starts a new function. `.data`
followed by a name starts a new data object.  They define the scope of
functions or data objects so that a loader like libbpf knows how to
load it.

### Labels and Names

You can refer to function names, data object names, and label names by
prefixing name with a `@` character. **ebas** will expand these names to
the address or offset of functions, data objects, or labels.

Labels are defined by a name followed by a `:` character in a separate
line.

For example,

    foo:

defines a label `foo`.  Labels help in creating relative jumps and
calls within the ebpf program. You can refer to labels by prefixing
the label name with an `@` character. For example, if you have a jump
instruction like `jne`, you can use `jne r1, r2, @foo` to jump to the
label `foo` if `r1` doesn't equal to `r2`.

## Data Objects

There are four keywords to define the content of data objects; `db`,
`dh`, `dw`, and `dd`.

They are integers of 1 byte, 2 bytes, 4 bytes, and 8 bytes
respectively.  They are followed by numbers separated by commas
`,`. For example, `db 0x02, 0xde, 0xa0` defines an integer of 3 bytes
that starts with 2 and ends with a 0. `dw 0xdeadbeef, 0x0` defines two
4-byte integers, 0xdeadbeef and 0x0.

### Examples

Please check the `ex-apps/` directory of the repository.
