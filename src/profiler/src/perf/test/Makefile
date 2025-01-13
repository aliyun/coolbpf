CC := gcc
CFLAG := -g
LIB := -L../ -lperf_sample
LIBFILE := ../libperf_sample.a

EXEC := testPerfSample

TSTS := $(EXEC:%=%.test)

all: $(TSTS)

%.test: %.c $(LIBFILE)
	$(CC) $(CFLAG) -o $@ $< $(LIB)

run_tests: $(TSTS)
	@echo "Running tests..."
	./forks.fork &
	./userHigh.fork &
	for i in $^; do \
        echo "Running $$i"; \
        valgrind --leak-check=full --track-origins=yes --show-leak-kinds=all --error-exitcode=1 ./$$i; \
		if [ $$? -ne 0 ]; then \
            echo "Error: $$i failed"; \
            exit 1; \
        fi; \
    done; echo -e "\n+++++++++++++++++++++++++\nAll tests1 passed.\n+++++++++++++++++++++++++"

clean:
	rm -f $(TSTS)
