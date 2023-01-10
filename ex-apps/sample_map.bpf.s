.section "fentry/__x64_sys_nanosleep"
.function nanosleep_fentry
        // Initialize a local variable
        mov.64          r1, 0
        st.w            r10 - 4, r1
        call.helper     14              // bpf_get_current_pid_tgid

        rsh.64          r0, 32
        ld.dw           r1, @pid        // immediate value (addr)
        ld.w            r1, r1          // load 32-bits from memory
        lsh.64          r1, 32          // expand to 64-bits
        arsh.64         r1, 32
        jne             r0, r1, @LBB0_2 // goto LBB0_2 if r0 != r1

        // Load the counter value from the map
        ld.dw           r1, @array      // load `array` map
        // Set up key at a local variable on the stack.
        mov.64          r2, r10
        add.64          r2, -4
        call.helper     1               // bpf_map_lookup_elem

        jeq             r0, 0, @LBB0_2
        ld.dw           r1, r0          // load value from the pointer
        // Increase the value
        add.64          r1, 1

        // Update map
        mov.64          r3, r10
        add.64          r3, -16
        st.dw           r3, r1
        ld.dw           r1, @array
        mov.64          r2, r10
        add.64          r2, -4
        mov.64          r4, 0
        call.helper     2               // bpf_map_update_elem

LBB0_2:
        mov             r0, 0
        exit

.bss
.data pid
        dw      0

.section ".maps"
.map array, array, 4, 8, 256
