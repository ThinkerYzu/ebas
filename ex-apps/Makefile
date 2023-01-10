
BINS := nanosleep sample_map traceloader
BPFS := nanosleep.bpf.o sample_map.bpf.o

all:: $(BINS) $(BPFS)

$(BPFS):%.bpf.o: %.bpf.s
	cargo run $< $@

$(BINS):%: %.c
	$(CC) -o $@ $< -lbpf -lelf

clean::
	for i in $(BINS) $(BPFS); do if [ -e $$i ]; then rm $$i; fi; done
