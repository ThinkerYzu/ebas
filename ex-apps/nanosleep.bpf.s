.section "fentry/__x64_sys_nanosleep"
.function nanosleep_fentry
        call.helper     14
        rsh.64          r0, 32
        ld.dw           r1, @pid        // immediate value (addr)
        ld.w            r1, r1          // load 32-bits from memory
        lsh.64          r1, 32          // expand to 64-bits
        arsh.64         r1, 32
        jne             r0, r1, @LBB0_2 // goto LBB0_2 if r0 != r1
        ld.dw           r1, @fentry_cnt // immediate value (addr)
        ld.w            r2, r1          // load 32-bits from memory
        add             r2, 1
        st.w            r1, r2          // store 32-bits to memory

LBB0_2:
        mov             r0, 0
        exit

.bss
.data pid
        dw      0
.data fentry_cnt
        dw      0
