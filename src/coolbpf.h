
#ifndef __COOLBPF_H
#define __COOLBPF_H

#ifdef __VMLINUX_H__



#else



#define COOLBPF_MAJOR_VERSION 0
#define COOLBPF_MINOR_VERSION 1
uint32_t coolbpf_major_version();
uint32_t coolbpf_minor_version();
const char *coolbpf_version_string(void);
#endif

#endif
