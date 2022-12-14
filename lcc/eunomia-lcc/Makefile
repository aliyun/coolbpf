.PHONY: all build
all: build

EUNOMIA_SOURCE := ../../third/eunomia-bpf
LIBBPF_SRC := $(abspath  ../../third/libbpf/src)

ecli:
	cd $(EUNOMIA_SOURCE)/ecli && \
		cmake -Bbuild -DCMAKE_INSTALL_PREFIX=$(INSTALL_LOCATION)\
		-DCMAKE_BUILD_TYPE=Release\
		-DLIBBPF_SOURCE_DIR=$(LIBBPF_SRC)
	cd $(EUNOMIA_SOURCE)/ecli && cmake --build build --config Release
	cp $(EUNOMIA_SOURCE)/ecli/build/bin/Release/ecli ecli

ecc:
	cd $(EUNOMIA_SOURCE)/eunomia-cc && make
	cp $(EUNOMIA_SOURCE)/eunomia-cc/workspace/bin/ecc ecc

build: ecli ecc
