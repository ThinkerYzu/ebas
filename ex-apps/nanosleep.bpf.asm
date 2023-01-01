.section "fentry/__x64_sys_nanosleep"
.function nanosleep_fentry
        call.helper     14
        rsh.64          r0, 32
        ld.dw           r1, @pid
        ld.w            r1, r1
        lsh.64          r1, 32
        arsh.64         r1, 32
        jne             r0, r1 + @LBB0_2
        ld.dw           r1, @fentry_cnt
        ld.w            r2, r1
        add             r2, 1
        st.w            r1, r2

LBB0_2:
        mov             r0, 0
        exit

.bss
.data pid
        dw      0
.data fentry_cnt
        dw      0
