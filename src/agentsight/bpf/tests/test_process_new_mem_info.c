/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * Unit tests for process_new/mem_info.h:
 *   - read_proc_mem_info() reads /proc/<pid>/statm correctly
 *   - read_proc_mem_info() returns false for non-existent PID
 *   - read_proc_mem_info() populates rss_pages, shared_pages, etc.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "process_ext/mem_info.h"

/* ---- test harness ------------------------------------------------------ */
#define RESET  "\033[0m"
#define RED    "\033[31m"
#define GREEN  "\033[32m"
#define YELLOW "\033[33m"
#define BLUE   "\033[34m"

static int tests_passed = 0;
static int tests_failed = 0;

static void test_assert(bool condition, const char *test_name)
{
	if (condition) {
		printf("[" GREEN "PASS" RESET "] %s\n", test_name);
		tests_passed++;
	} else {
		printf("[" RED "FAIL" RESET "] %s\n", test_name);
		tests_failed++;
	}
}

/* ======================================================================== */
/* Tests                                                                     */
/* ======================================================================== */

static void test_read_self_succeeds(void)
{
	printf("\n" BLUE "Testing read_proc_mem_info() — current process (self):" RESET "\n");

	struct proc_mem_info info;
	pid_t self = getpid();

	bool ok = read_proc_mem_info(self, &info);
	test_assert(ok, "read_proc_mem_info returns true for current process");
}

static void test_read_self_populates_rss(void)
{
	printf("\n" BLUE "Testing read_proc_mem_info() — rss_pages populated:" RESET "\n");

	struct proc_mem_info info;
	memset(&info, 0, sizeof(info));

	bool ok = read_proc_mem_info(getpid(), &info);
	if (!ok) {
		/* If it failed, mark the sub-tests as failed. */
		test_assert(false, "read_proc_mem_info should succeed (prerequisite)");
		return;
	}

	/*
	 * rss_pages is the resident set size in pages; for any running process
	 * it should be > 0.
	 */
	test_assert(info.rss_pages > 0,
	            "rss_pages is positive for current process");
	printf("  rss_pages   = %ld\n", info.rss_pages);
}

static void test_read_self_populates_shared_pages(void)
{
	printf("\n" BLUE "Testing read_proc_mem_info() — shared_pages field:" RESET "\n");

	struct proc_mem_info info;
	memset(&info, 0xFF, sizeof(info)); /* poison */

	bool ok = read_proc_mem_info(getpid(), &info);
	test_assert(ok, "read_proc_mem_info returns true");
	/*
	 * shared_pages can be 0, but the field must have been written
	 * (not left as 0xFF).  We just check it is a plausible value.
	 */
	test_assert(info.shared_pages >= 0,
	            "shared_pages is non-negative");
	printf("  shared_pages = %ld\n", info.shared_pages);
}

static void test_read_self_populates_text_pages(void)
{
	printf("\n" BLUE "Testing read_proc_mem_info() — text_pages field:" RESET "\n");

	struct proc_mem_info info;
	memset(&info, 0, sizeof(info));

	bool ok = read_proc_mem_info(getpid(), &info);
	test_assert(ok, "read_proc_mem_info returns true");
	test_assert(info.text_pages >= 0,
	            "text_pages is non-negative");
	printf("  text_pages  = %ld\n", info.text_pages);
}

static void test_read_self_populates_data_pages(void)
{
	printf("\n" BLUE "Testing read_proc_mem_info() — data_pages field:" RESET "\n");

	struct proc_mem_info info;
	memset(&info, 0, sizeof(info));

	bool ok = read_proc_mem_info(getpid(), &info);
	test_assert(ok, "read_proc_mem_info returns true");
	test_assert(info.data_pages >= 0,
	            "data_pages is non-negative");
	printf("  data_pages  = %ld\n", info.data_pages);
}

static void test_read_self_zeroes_on_entry(void)
{
	printf("\n" BLUE "Testing read_proc_mem_info() — struct zeroed on entry:" RESET "\n");

	struct proc_mem_info info;
	/* Poison the struct; the function must memset it before filling. */
	memset(&info, 0xFF, sizeof(info));

	bool ok = read_proc_mem_info(getpid(), &info);
	test_assert(ok, "read_proc_mem_info returns true");
	/*
	 * vm_hwm_kb may be 0 for processes that haven't grown their heap yet,
	 * but it must at least be a reasonable number (not 0xFFFF…).
	 */
	test_assert(info.vm_hwm_kb >= 0,
	            "vm_hwm_kb has been written (not still poisoned)");
	printf("  vm_hwm_kb   = %ld kB\n", info.vm_hwm_kb);
}

static void test_read_nonexistent_pid_fails(void)
{
	printf("\n" BLUE "Testing read_proc_mem_info() — non-existent PID:" RESET "\n");

	struct proc_mem_info info;

	/*
	 * PID 999999999 is virtually guaranteed not to exist.  On Linux the
	 * kernel PID limit is 4194304, so this is safely out of range.
	 */
	bool ok = read_proc_mem_info(999999999, &info);
	test_assert(!ok, "read_proc_mem_info returns false for non-existent PID");
}

static void test_read_pid_zero_fails(void)
{
	printf("\n" BLUE "Testing read_proc_mem_info() — PID 0:" RESET "\n");

	struct proc_mem_info info;
	/*
	 * /proc/0/statm does not exist on Linux.  The function should fail
	 * gracefully.
	 */
	bool ok = read_proc_mem_info(0, &info);
	test_assert(!ok, "read_proc_mem_info returns false for PID 0");
}

static void test_read_negative_pid_fails(void)
{
	printf("\n" BLUE "Testing read_proc_mem_info() — negative PID:" RESET "\n");

	struct proc_mem_info info;
	bool ok = read_proc_mem_info(-1, &info);
	test_assert(!ok, "read_proc_mem_info returns false for pid -1");
}

static void test_read_init_process(void)
{
	printf("\n" BLUE "Testing read_proc_mem_info() — init process (PID 1):" RESET "\n");

	struct proc_mem_info info;
	memset(&info, 0, sizeof(info));

	bool ok = read_proc_mem_info(1, &info);
	/*
	 * PID 1 always exists, but the test runner might not have permission
	 * to read /proc/1/statm (e.g. non-root inside some containers).
	 * If it fails, we treat that as a skip rather than a hard failure.
	 */
	if (!ok) {
		printf("  [SKIP] Cannot read /proc/1/statm (permission denied or PID 1 missing)\n");
		return;
	}
	test_assert(ok, "read_proc_mem_info succeeds for PID 1");
	test_assert(info.rss_pages > 0, "PID 1 has non-zero rss_pages");
	printf("  PID 1 rss_pages = %ld\n", info.rss_pages);
}

static void test_read_forked_child(void)
{
	printf("\n" BLUE "Testing read_proc_mem_info() — forked child process:" RESET "\n");

	pid_t child = fork();
	if (child < 0) {
		printf("  [SKIP] fork() failed, skipping test\n");
		return;
	}

	if (child == 0) {
		/* Child: sleep briefly so parent can read our info. */
		usleep(200000); /* 200 ms */
		_exit(0);
	}

	/* Parent: give child a moment to settle. */
	usleep(50000); /* 50 ms */

	struct proc_mem_info info;
	memset(&info, 0, sizeof(info));
	bool ok = read_proc_mem_info(child, &info);

	int status;
	waitpid(child, &status, 0);

	test_assert(ok, "read_proc_mem_info succeeds for forked child");
	if (ok) {
		test_assert(info.rss_pages > 0,
		            "forked child has non-zero rss_pages");
		printf("  Child (PID %d) rss_pages = %ld\n", child, info.rss_pages);
	}
}

static void test_info_struct_size(void)
{
	printf("\n" BLUE "Testing proc_mem_info struct layout:" RESET "\n");

	/*
	 * The struct has 5 long fields: rss_pages, shared_pages, text_pages,
	 * data_pages, vm_hwm_kb.  Its size must be exactly 5 * sizeof(long).
	 */
	test_assert(sizeof(struct proc_mem_info) == 5 * sizeof(long),
	            "proc_mem_info size matches 5 long fields");
}

/* ======================================================================== */
/* Summary                                                                   */
/* ======================================================================== */

static void print_test_summary(void)
{
	printf("\n" YELLOW "===== Test Summary =====" RESET "\n");
	printf("Tests passed: " GREEN "%d" RESET "\n", tests_passed);
	printf("Tests failed: " RED   "%d" RESET "\n", tests_failed);
	printf("Total tests:  %d\n", tests_passed + tests_failed);
	if (tests_failed == 0)
		printf(GREEN "All tests passed!" RESET "\n");
	else
		printf(RED "Some tests failed!" RESET "\n");
}

int main(void)
{
	printf(BLUE "===== mem_info.h Test Suite =====" RESET "\n");
	printf("Testing functions from process_new/mem_info.h\n");

	test_read_self_succeeds();
	test_read_self_populates_rss();
	test_read_self_populates_shared_pages();
	test_read_self_populates_text_pages();
	test_read_self_populates_data_pages();
	test_read_self_zeroes_on_entry();
	test_read_nonexistent_pid_fails();
	test_read_pid_zero_fails();
	test_read_negative_pid_fails();
	test_read_init_process();
	test_read_forked_child();
	test_info_struct_size();

	print_test_summary();
	return (tests_failed > 0) ? 1 : 0;
}
