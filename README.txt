ebas is an assembler for Extended Berkeley Packet Filtering (eBPF)
programs. It helps you write and compile eBPF programs that can run on
Linux systems. You can use it by typing in the command
"./target/debug/ebas <input-file> <output-file>" followed by the name
of your input file and output file, then press enter. The assembler
will help you create a program that can be used in Linux systems.

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
register.  `ld.b`, `ld.h`, and `ld.w` can load an immediate value.

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

### Jump
