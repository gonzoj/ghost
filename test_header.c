#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdint.h>

#include "ghost.h"

struct hstring {
	unsigned long addr;
	char *str;
};

#define _STRING(s) (struct hstring) { .addr = (unsigned long) &s }

/*
 		f = va == (unsigned long) print_a ? "print_a" : va == (unsigned long) print_b ? "print_b" : "unknown";
		printf("### read access: calling %s (%lX) ###\n", f, va);
		printf("### executing: ");
		func();
		printf("           ###\n");
		if (virgin) {
			va = get_called_address((void *) (virgin + ((unsigned long) lcall - ((unsigned long) func & PAGE_MASK))), lcall);
			f = va == (unsigned long) print_a ? "print_a" : va == (unsigned long) print_b ? "print_b" : "unknown";
			printf("### virgin: calling %s (%lX)      ###\n", f, va);
			printf("### virgin (raw): %lX             ###\n", *(unsigned long *)(virgin + ((unsigned long) lcall - ((unsigned long) func & PAGE_MASK))));
*/

static struct hstring _strings[] = {
	_STRING("(undefined)"),
	_STRING("print_a (%lX)"),
	_STRING("print_b (%lX)"),
	_STRING("print_a"),
	_STRING("print_b"),
	_STRING("unknown"),
	_STRING("### read access: calling %s (%lX) ###\n"),
	_STRING("### executing: "),
	_STRING("           ###\n"),
	_STRING("### virgin: calling %s (%lX)      ###\n"),
	_STRING("### virgin (raw): %lX             ###\n"),
	_STRING("ghost_register_page: %s\n")
};

char * hstring_get(char *s) {
	int i;
	for (i = 0; i < sizeof(_strings); i++) {
		if ((unsigned long) s == _strings[i].addr) {
			return _strings[i].str;
		}
	}
	return _strings->str;
}

#define _s(s) (hstring_get(s))

void hstring_init() {
	int i;
	for (i = 0; i < sizeof(_strings) / sizeof(struct hstring); i++) {
		_strings[i].str = strdup((char *) _strings[i].addr);
	}
};

void lcall(void);
void lret(void);

int print_a_exe = 0;
int print_b_exe = 0;

static void print_a(void) {
	printf(_s("print_a (%lX)"), (unsigned long) print_a);
	print_a_exe = 1;
}

static void print_b(void) {
	printf(_s("print_b (%lX)"), (unsigned long) print_b);
	print_b_exe = 1;
}

static void func(void) {
	__asm__ __volatile__ (
		".globl lcall\n"
		"lcall:\n"
		"call print_a\n"
	);
}

int ret(void) {
	return 42;
}

void lret_stub(void) {
	__asm__ __volatile__ (
		".globl lret\n"
		"lret:\n"
		"ret\n"
	);
}

unsigned long get_called_address(void *base, void *label) {
	return  *(int32_t *)&((unsigned char *)base)[1] + (unsigned long) label + sizeof(unsigned char) + sizeof(int32_t);
}

void set_calling_address(void *va) {
	int32_t *f = (int32_t *) &((unsigned char *)lcall)[1];
	*f = ((unsigned long) va - ((unsigned long) lcall + sizeof(unsigned char) + sizeof(int32_t)));
}

unsigned char * create_virgin_page(void *va) {
	unsigned char *vp = (unsigned char *) malloc(page_size * 2);
	vp = (unsigned char *) ((unsigned long) (vp + page_size) & PAGE_MASK);
	memcpy(vp, (unsigned char *) ((unsigned long) va & PAGE_MASK), page_size);
	return vp;
}

unsigned char * create_zero_page() {
	unsigned char *zp = (unsigned char *) malloc(page_size * 2);
	zp = (unsigned char *) ((unsigned long) (zp + page_size) & PAGE_MASK);
	memset(zp, 0, page_size);
	return zp;
}

int modify(void *addr, void *arg) {
	set_calling_address(print_b);
	return 0;
}

void print_string_addr(void *s) {
	printf("string at %lX\n", (unsigned long) s);
}

#include <errno.h>
int main(int argc, char **argv) {
	/*printf("%X\n", ERROR_SYSTEM_ERRNO);
	int inval = EINVAL * -1;
	printf("%X\n", inval);
	MASK_SYS_ERRNO(inval);
	printf("%X\n", inval);
	printf("%X\n", SYS_ERRNO(inval));
	printf("error: %s\n", ghost_error(SYS_ERRNO(inval)));*/

	hstring_init();

	printf("%s at %lX\n", "hello", (unsigned long) &"hello");
	print_string_addr((void *) "hello");

	printf("ghost_init: %s\n", ghost_error(ghost_init()));

	printf("page size: %lX bytes\n", page_size);

	void *_virgin;
	void *virgin = NULL;
	printf("pid: %i\n", getpid());
	printf("func at %lX (%lX) - %lu\n", (unsigned long) func, (unsigned long) func & PAGE_MASK, (unsigned long) func);
	printf("lret at %lX (%lX) - %lu\n", (unsigned long) lret, (unsigned long) lret & PAGE_MASK, (unsigned long) lret);
	printf("ret at %lX (%lX) - %lu\n", (unsigned long) ret, (unsigned long) ret & PAGE_MASK, (unsigned long) ret);
	if (virgin) printf("copy at %lX - %lu\n", (unsigned long) virgin, (unsigned long) virgin);

	//printf("ghost_register_page: %s\n", ghost_error(ghost_register_page((unsigned long) func, &_virgin, NULL, NULL)));
	ghost_register_page((unsigned long) func, &_virgin, NULL, NULL);
	if (_virgin) virgin = (void *) ((unsigned long) ((unsigned char *) _virgin + page_size) & PAGE_MASK);

	unsigned long va;
	char *f;

	int print_a_read = 0;
	int print_b_read = 0;
	int garb_read = 0;
	unsigned long read;

	while (getc(stdin) != 'q') {
		va = get_called_address(lcall, lcall);
		if (va == (unsigned long) print_a) {
			print_a_read = 1;
		}
		if (va == (unsigned long) print_b) {
			print_b_read = 1;
		} else {
			garb_read = 1;
			read = *(unsigned long *)func;
		}
		f = va == (unsigned long) print_a ? _s("print_a") : va == (unsigned long) print_b ? _s("print_b") : _s("unknown");
		printf(_s("### read access: calling %s (%lX) ###\n"), f, va);
		printf(_s("### executing: "));
		func();
		printf(_s("           ###\n"));
		if (virgin) {
			va = get_called_address((void *) (virgin + ((unsigned long) lcall - ((unsigned long) func & PAGE_MASK))), lcall);
			f = va == (unsigned long) print_a ? _s("print_a") : va == (unsigned long) print_b ? _s("print_b") : _s("unknown");
			printf(_s("### virgin: calling %s (%lX)      ###\n"), f, va);
			printf(_s("### virgin (raw): %lX             ###\n"), *(unsigned long *)(virgin + ((unsigned long) lcall - ((unsigned long) func & PAGE_MASK))));
		}
	}

	printf("ghost_release_page: %s\n", ghost_error(ghost_release_page((unsigned long) func, &_virgin, 0)));
	if (!_virgin) virgin = NULL;

	printf("print_a executed? %s\n", print_a_exe ? "yes" : "no");
	printf("print_b executed? %s\n", print_b_exe ? "yes" : "no");
	printf("print_a read? %s\n", print_a_read ? "yes" : "no");
	printf("print_b read? %s\n", print_b_read ? "yes" : "no");
	printf("garbage read? %s (%lX)\n", garb_read ? "yes" : "no", read);

	va = get_called_address(lcall, lcall);
	f = va == (unsigned long) print_a ? "print_a" : va == (unsigned long) print_b ? "print_b" : "unknown";
	printf("### read access: calling %s (%lX) ###\n", f, va);
	printf("### executing: ");
	func();
	printf("           ###\n");
	if (virgin) {
		va = get_called_address((void *) (virgin + ((unsigned long) lcall - ((unsigned long) func & PAGE_MASK))), lcall);
		f = va == (unsigned long) print_a ? "print_a" : va == (unsigned long) print_b ? "print_b" : "unknown";
		printf("### virgin: calling %s (%lX)      ###\n", f, va);
		printf("### virgin (raw): %lX             ###\n", *(unsigned long *)(virgin + ((unsigned long) lcall - ((unsigned long) func & PAGE_MASK))));
	}

	ghost_exit();

	return 0;
}
