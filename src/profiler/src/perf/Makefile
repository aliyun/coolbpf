CC := gcc
CXX := g++
AR := ar
CFLAG := -g -fpic
OBJS := perf_sample.o
LIB := libperf_sample.a

all: $(LIB)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAG)

$(LIB): $(OBJS)
	$(AR) cr $@ $(OBJS)

clean:
	make -C test clean
	rm -f $(OBJS) $(LIB)