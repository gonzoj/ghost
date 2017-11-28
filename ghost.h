/*
 * Copyright (C) 2012 gonzoj
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GHOST_H_
#define GHOST_H_

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/attr.h>
#include <netlink/utils.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>

enum {
	SUCCESS,
	ERROR,
	ERROR_MISSING_PARAMETERS,
	ERROR_INVALID_PARAMETERS,
	ERROR_PAGE_IN_LIST,
	ERROR_OUT_OF_MEMORY,
	ERROR_INVALID_ADDRESS,
	ERROR_PAGE_NOT_IN_LIST,
	ERROR_TASK_NOT_IN_LIST,
};

static const char * nl_error_string[] = {
	"success",
	"generic error",
	"critical parameters in netlink request are missing",
	"critical parameters in netlink request are invalid",
	"page is already managed",
	"out of memory",
	"specified address is invalid",
	"page is not managed",
	"task is not managed",
	"unknown error"
};

#define _UNKNOWN_ERROR ((sizeof(nl_error_string) / sizeof(const char *)) - 1)

enum {
	_NLA_UNSPEC,
	NLA_PID,
	NLA_I_ADDR,
	NLA_D_PAGE,
	NLA_Z_PAGE,
	NLA_RET,
	__NLA_MAX,
};

#define NLA_MAX (__NLA_MAX - 1)

enum {
	_NLO_UNSPEC,
	NLO_REGISTER_PAGE,
	NLO_RELEASE_PAGE,
	__NLO_MAX,
};

#define NLO_MAX (__NLO_MAX - 1)

#define NL_FAMILY_NAME "ghost"

#define NL_INTERFACE_VERSION 1

static struct nl_sock *nls;
static int nl_family;

static long page_size;
#define PAGE_MASK ~(page_size - 1)

static void *_zero_page;
static void *zero_page;

static const char * ghost_error(int err) {
	if (err >= 0 && err < _UNKNOWN_ERROR) {
		return nl_error_string[err];
	} else if (err < 0) {
		return nl_geterror(err);
	} else {
		return nl_error_string[_UNKNOWN_ERROR];
	}
}

static int ghost_init() {
	int rc;

	_zero_page = NULL;
	zero_page = NULL;

	page_size = sysconf(_SC_PAGE_SIZE);
	if (page_size < 0) {
		return ERROR;
	}

	nls = NULL;
	nls = nl_socket_alloc();

	if (nls) {
		if ((rc = genl_connect(nls))) {
			nl_socket_free(nls);
			nls = NULL;
			return rc;
		}

		if ((rc = genl_ctrl_resolve(nls, NL_FAMILY_NAME)) < 0) {
			nl_close(nls);
			nl_socket_free(nls);
			nls = NULL;
			return rc;
		}
		nl_family = rc;

		return SUCCESS;
	}

	return ERROR;
}

static void ghost_exit() {
	if (nls) {
		nl_close(nls);
		nl_socket_free(nls);
		nls = NULL;
	}
	if (_zero_page) {
		free(_zero_page);
		_zero_page = NULL;
		zero_page = NULL;
	}
}

#define PAGE_ALIGN(addr) ((void *) ((unsigned long) ((unsigned char *) (addr) + page_size) & PAGE_MASK))

static void * alloc_page(void **p) {
	 *p = calloc(2, page_size);
	if (!*p) {
		return NULL;
	} else {
		return PAGE_ALIGN(*p);
	}
}

static void * clone_page(void *page, void **p) {
	void *clone = alloc_page(p);
	if (!clone) {
		return NULL;
	} else {
		memcpy(clone, page, page_size);
		return clone;
	}
}

/*
 * we should look for spots to inject a return instruction in case there is none
 */
static void * find_ret_opcode(unsigned char *page) {
	int i;

	for (i = 0; i < page_size; i++) {
		if (page[i] == 0xC3) return (void *) (page + i);
	}

	return NULL;
}

void set_calling_address(void *);
static void print_a(void);
static void print_b(void);

static int ghost_register_page(unsigned long address, void **page, int(*modify)(void *, void *), void *arg) {
	unsigned long i_page, d_page;
	void(*ret)(void);
	int rc = SUCCESS;
	int modified = 0;
	struct nl_msg *msg = NULL;

	*page = NULL;

	if (!nls) return ERROR;

	i_page = address & PAGE_MASK;
	if (mlock((void *) i_page, page_size)) return ERROR;

	if (modify) {
		d_page = (unsigned long) clone_page((void *) i_page, page);
	} else {
		d_page = (unsigned long) alloc_page(page);
		memset((void *) d_page, 'a', page_size);
	}
	if (!d_page) return ERROR;
	if (mlock((void *) d_page, page_size)) {
		rc = ERROR;
		goto out;
	}

	if (modify) {
		if (mprotect((void *) i_page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC)) {
			rc = ERROR;
			goto out;
		} else {
			if (modify((void *) address, arg)) {
				rc = ERROR;
			}
			mprotect((void *) i_page, page_size, PROT_READ | PROT_EXEC);
			if (rc) goto out;
			modified = 1;
		}
	}

	ret = find_ret_opcode((unsigned char *) i_page);
	if (!ret) {
		rc = ERROR;
		goto out;
	}

	if (modify && !zero_page) {
		zero_page = alloc_page(&_zero_page);

		if (zero_page) {
			if (mlock((void *) zero_page, page_size)) {
				rc = ERROR;
				goto out;
			}
		} else {
			rc = ERROR;
			goto out;
		}
	}

	msg = nlmsg_alloc();
	if (!msg) {
		rc = ERROR;
		goto out;
	}

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl_family, 0, 0, NLO_REGISTER_PAGE, NL_INTERFACE_VERSION)) {
		rc = ERROR;
		goto out;
	}

	rc = ERROR;
	NLA_PUT_U32(msg, NLA_PID, (uint32_t) getpid());
	NLA_PUT_U64(msg, NLA_I_ADDR, (uint64_t) i_page);
	NLA_PUT_U64(msg, NLA_D_PAGE, (uint64_t) d_page);
	NLA_PUT_U64(msg, NLA_RET, (uint64_t) (unsigned long) ret);
	if (modify) {
		NLA_PUT_U64(msg, NLA_Z_PAGE, (uint64_t) (unsigned long) zero_page);
	} else {
		NLA_PUT_U64(msg, NLA_Z_PAGE, (uint64_t) 0);
	}

	rc = nl_send_sync(nls, msg);

	nla_put_failure:

	out:

	if (rc) {
		if (modified) {
			memcpy((void *) i_page, (void *) d_page, page_size);
		}

		if (*page) {
			free(*page);
			*page = NULL;
		}

		if (msg) {
			nlmsg_free(msg);
		}
	}

	return rc;
}

static int ghost_release_page(unsigned long address, void **page, int modified) {
	unsigned long i_page;
	int rc;
	struct nl_msg *msg;

	if (!modified && *page) {
		free(*page);

		*page = NULL;
	}

	if (!nls) return ERROR;

	i_page = address & PAGE_MASK;

	msg = nlmsg_alloc();
	if (!msg) return ERROR;

	if (!genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl_family, 0, 0, NLO_RELEASE_PAGE, NL_INTERFACE_VERSION)) {
		nlmsg_free(msg);

		return ERROR;
	}

	NLA_PUT_U32(msg, NLA_PID, (uint32_t) getpid());
	NLA_PUT_U64(msg, NLA_I_ADDR, (uint64_t) i_page);

	rc = nl_send_sync(nls, msg);

	if (!rc) {
		munlock((void *) i_page, page_size);
		if (modified) {
			if (mprotect((void *) i_page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC)) {
				rc = ERROR;
			} else {
				rc |= !memcpy((void *) i_page, PAGE_ALIGN(*page), page_size);
				mprotect((void *) i_page, page_size, PROT_READ | PROT_EXEC);
			}
		}
	}

	if (*page) {
		free(*page);

		*page = NULL;
	}

	return rc;

	nla_put_failure:

	nlmsg_free(msg);

	return ERROR;
}

#endif /* GHOST_H_ */
