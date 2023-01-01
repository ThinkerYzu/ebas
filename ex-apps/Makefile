
BINS := nanosleep
BPFS := nanosleep.bpf.o

all:: $(BINS) $(BPFS)

$(BPFS):%.bpf.o: %.bpf.s
	cargo run $< $@

$(BINS):%: %.c
	$(CC) -o $@ $< -lbpf

clean::
	for i in $(BINS) $(BPFS); do if [ -e $$i ]; then rm $$i; fi; done
