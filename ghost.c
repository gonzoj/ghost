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

#include <generated/autoconf.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/semaphore.h>
#include <linux/list.h>
/* what the fuck? defines kunmap_atomic */
#include <linux/hugetlb.h>

#include <asm/desc.h>
#include <asm/segment.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/page.h>
#include <asm/processor.h> 
#include <asm/traps.h>
#include <asm/highmem.h>

#include <net/netlink.h>
#include <net/genetlink.h>

#define MODULE_NAME "ghost"

/* un-/comment to toggle debug output */
#define _DEBUG_BUILD

#ifdef _DEBUG_BUILD
#define __WARNING KERN_ALERT
#define __ERROR KERN_ALERT
#define __DEBUG KERN_ALERT
#define __INFO KERN_ALERT
#define debugk printk
#else
#define __WARNING KERN_WARNING
#define __ERROR KERN_ERR
#define __DEBUG KERN_DEBUG
#define __INFO KERN_INFO
#define debugk if (_debug) printk
#endif

#define _WARNING __WARNING "["MODULE_NAME"] warning: "
#define _ERROR __ERROR "["MODULE_NAME"] error: "
#define _DEBUG __DEBUG "["MODULE_NAME"] debug: "
#define _INFO __INFO "["MODULE_NAME"] info: "

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

/* module parameters */

static int _debug = 0;
module_param(_debug, bool, 0);

static int _log = 1;
module_param(_log, bool, 0);

/* netlink family definitions */

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

#define NL_INTERFACE_VERSION 1

struct _page {
	unsigned long i_page;
	unsigned long d_page;
	unsigned long i_frame;
	unsigned long d_frame;
	int (*ret)(void);
	unsigned long z_frame;
	struct list_head lpages;
};

struct _task {
	pid_t pid;
	struct timespec start_time;
	struct list_head managed_pages;
	struct list_head ltasks;
};

enum X86_PF_ERROR_CODE {
	PF_PROT   = 1 << 0, // 0: no page found       1: protection fault
	PF_WRITE  = 1 << 1, // 0: read access         1: write access
	PF_USER   = 1 << 2, // 0: kernel-mode access  1: user-mode access
	PF_RSVD   = 1 << 3, //                        1: use of reserved bit detected
	PF_INSTR  = 1 << 4, //                        1: fault was an instruction fetch
};

/* netlink family declarations */

static struct genl_family genl_family_mod = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = MODULE_NAME,
	.version = NL_INTERFACE_VERSION,
	.maxattr = NLA_MAX
};

static struct nla_policy nla_policy_mod[__NLA_MAX] = {
	[NLA_PID]    = { .type = NLA_U32 },
	[NLA_I_ADDR] = { .type = NLA_U64 },
	[NLA_D_PAGE] = { .type = NLA_U64 },
	[NLA_Z_PAGE] = { .type = NLA_U64 },
	[NLA_RET]    = { .type = NLA_U64 }
};

static int nlo_register_page(struct sk_buff *, struct genl_info *);
static int nlo_release_page(struct sk_buff *, struct genl_info *);

static struct genl_ops genl_ops_register_page = {
	.cmd = NLO_REGISTER_PAGE,
	.flags = 0,
	.policy = nla_policy_mod,
	.doit = nlo_register_page,
	.dumpit = NULL
};

static struct genl_ops genl_ops_release_page = {
	.cmd = NLO_RELEASE_PAGE,
	.flags = 0,
	.policy = nla_policy_mod,
	.doit = nlo_release_page,
	.dumpit = NULL
};

/* pattern declaratins for resolving unexported kernel symbols */

#ifdef CONFIG_X86_64
/*
 * sub $0x78, %rsp
 * callq ...
 */
static unsigned char call_error_entry[] =     { 0x48, 0x83, 0xEC, 0x78, 0xE8 };

/*
 * mov %rsp, %rdi
 * mov 0x78(%rsp), %rsi
 * movq $0xffffffffffffffff, 0x78(%rsp)
 * callq ...
 */
static unsigned char call_do_page_fault[] =     { 0x48, 0x89, 0xE7, 0x48, 0x8B, 0x74, 0x24, 0x78, 0x48, 0xC7, 0x44, 0x24, 0x78, 0xFF, 0xFF, 0xFF, 0xFF, 0xE8 };

/*
 * movq $0xffffffffffffffff, 0x78(%rsp)
 * callq ?? ?? ?? ??
 * jmpq ...
 */
static unsigned char jmp_error_exit[] =     { 0x48, 0xC7, 0x44, 0x24, 0x78, 0xFF, 0xFF, 0xFF, 0xFF, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xE9 };
static unsigned int jmp_error_exit_mask[] = { 1,    1,    1,    1,    1,    1,    1,    1,    1,    1,    0,    0,    0,    0,    1    };
#else
/*
 * mov %esp, %eax
 * call *%edi
 * jmp ...
 */ 
static unsigned char jmp_ret_from_exception[] =     { 0x89, 0xE0, 0xFF, 0xD7, 0xE9 };
#endif

LIST_HEAD(managed_tasks);

static struct rw_semaphore manage_s;

static void *kernel_isr0x0E_stub = NULL;

#ifdef CONFIG_X86_64
static void *kernel64_error_entry;
static void *kernel64_do_page_fault;
static void *kernel64_error_exit;
#else
static void *kernel32_ret_from_exception;
#endif

static int register_managed_page(pid_t, unsigned long, unsigned long, int(*)(void), unsigned long);
static int release_managed_page(pid_t, unsigned long);

static int nlo_register_page(struct sk_buff *skb, struct genl_info *info) {
	pid_t pid;
	unsigned long i_addr, d_page, z_page;
	int (*ret)(void);

	printk(_INFO "netlink: received register request\n");

	if (!info) {
		printk(_ERROR "no netlink info available\n");
		return ERROR;
	}

	if (!info->attrs[NLA_PID] || !info->attrs[NLA_I_ADDR] || !info->attrs[NLA_D_PAGE] || !info->attrs[NLA_Z_PAGE] || !info->attrs[NLA_RET]) {
		printk(_ERROR "critical parameters are missing\n");
		return ERROR_MISSING_PARAMETERS;
	}

	pid = (pid_t) nla_get_u32(info->attrs[NLA_PID]);
	i_addr = (unsigned long) nla_get_u64(info->attrs[NLA_I_ADDR]);
	d_page = (unsigned long) nla_get_u64(info->attrs[NLA_D_PAGE]);
	ret = (int(*)(void)) (unsigned long) nla_get_u64(info->attrs[NLA_RET]);
	z_page = (unsigned long) nla_get_u64(info->attrs[NLA_Z_PAGE]);

	printk(_INFO "[%i] registering %lX (read/write %lX) using return at %lX\n", pid, i_addr, d_page, (unsigned long) ret);
	if (z_page) printk(_INFO "using zero page %lX\n", z_page);

	if (!i_addr || !d_page || !ret) {
		printk(_ERROR "one or more critical parameters are not set\n");
		return ERROR_INVALID_PARAMETERS;
	}

	return register_managed_page(pid, i_addr, d_page, ret, z_page);
}

static int nlo_release_page(struct sk_buff *skb, struct genl_info *info) {
	pid_t pid;
	unsigned long i_addr;

	printk(_INFO "netlink: received release request\n");

	if (!info) {
		printk(_ERROR "no netlink info availabe\n");
		return ERROR;
	}

	if (!info->attrs[NLA_PID] || !info->attrs[NLA_I_ADDR]) {
		printk(_ERROR "critical parameters are missing\n");
		return ERROR_MISSING_PARAMETERS;
	}

	pid = (pid_t) nla_get_u32(info->attrs[NLA_PID]);
	i_addr = (unsigned long) nla_get_u64(info->attrs[NLA_I_ADDR]);

	printk(_INFO "[%i] releasing %lX\n", pid, i_addr);

	if (!i_addr) {
		printk(_ERROR "one or more critical parameters are not set\n");
		return ERROR_INVALID_PARAMETERS;
	}

	return release_managed_page(pid, i_addr);
}

/* fix for 2.6.36 */

#include <linux/rcupdate.h>

static struct task_struct * _get_pid_task(struct pid *pid, enum pid_type type) {
	struct task_struct *result;
	rcu_read_lock();
	result = pid_task(pid, type);
	if (result) get_task_struct(result);
	rcu_read_unlock();
	return result;
}

/* end fix */

static struct task_struct * get_task_by_pid(pid_t pid) {
	struct task_struct *tsk;
	struct pid *_pid;

	_pid = find_get_pid(pid);
	if (!_pid) return NULL;

	/* fix for 2.6.36 */
	tsk = _get_pid_task(_pid, PIDTYPE_PID);
	
	return tsk;
}

/*
 * NOTE: we can't handle hugetlb pages at the moment
 */
static pte_t * resolve_address_to_pte(struct mm_struct *mm, unsigned long address, pmd_t **pmd) {
	pgd_t *pgd;
	pud_t *pud;
	/* 2.6.36: no transparent hugepage support yet */
	//pmd_t orig_pmd;
	pte_t *pte = NULL;

	/* we might wanna hold page_table_lock while doing a page table walk */

	pgd = pgd_offset(mm, address);

	/* 
	 * we require clients to lock managed pages in memory, so the corresponding
	 * page table should be in memory at any time.
	 * if it's not, we assume the kernel page fault handler will deal with it
	 */
	if (!pgd_present(*pgd)) {
		printk(_WARNING "when retrievig PTE: PGD not present\n");
	}

	pud = pud_offset(pgd, address);
	if (!pud_present(*pud)) {
		printk(_WARNING "when retrieving PTE: PUD not presend\n");
	} else if (pud_large(*pud)) {
		printk(_WARNING "when retrieving PTE: large page (PUD) detected\n");
		goto out;
	} else if (pud_none(*pud)) {
		printk(_WARNING "when retrieving PTE: PUD invalid\n");
		goto out;
	}

	*pmd = pmd_offset(pud, address);
	//orig_pmd = **pmd;
	if (!pmd_present(**pmd)) {
		printk(_WARNING "when retrieving PTE: PMD not present\n");
	} else if (pmd_large(**pmd)) {
		printk(_WARNING "when retrieving PTE: large page (PMD) detected\n");
		goto out;
	} else if (pmd_none(**pmd)) {
		printk(_WARNING "when retrieving PTE: PMD invalid\n");
		goto out;
	}/* else if (pmd_trans_huge(orig_pmd)) {
		printk(_WARNING "when retrieving PTE: transparent hugepage detected\n");
		goto out;
	}*/
	
	pte = pte_offset_map(*pmd, address);

	debugk(_DEBUG "resolving %lX: PTE (%lX): %lX\n", address, (unsigned long) pte, (unsigned long) pte->pte);
	
	out:

	return pte;
}

static int resolve_linear_address(struct mm_struct *mm, unsigned long laddr, unsigned long *paddr) {
	pmd_t *pmd;
	pte_t *pte;

	/* just in case ;-) */
	spin_lock(&mm->page_table_lock);

	pte = resolve_address_to_pte(mm, laddr, &pmd);

	if (!pte) {
		spin_unlock(&mm->page_table_lock);

		return ERROR;
	}

	if (pte_none(*pte)) {
		pte_unmap(pte);

		spin_unlock(&mm->page_table_lock);

		return ERROR;
	}

	*paddr = pte_pfn(*pte);

	pte_unmap(pte);

	spin_unlock(&mm->page_table_lock);

	return SUCCESS;
}

static void _flush_tlb(void *laddr) {
	__flush_tlb_one((unsigned long) laddr);
}

static void _flush_tlb_page(unsigned long laddr) {
	/* do we have to flush the cpu's TLB we're running on? -- I don't think so */
	_flush_tlb((void *) laddr);
	on_each_cpu(_flush_tlb, (void *) laddr, 1);
}

static int prepare_page_table(struct mm_struct *mm, struct _page *p) {
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;

	debugk(_DEBUG "locking mm->mmap_sem\n");
	down_read(&mm->mmap_sem);

	pte = resolve_address_to_pte(mm, p->i_page, &pmd);
	if (!pte) {
		up_read(&mm->mmap_sem);

		return ERROR;
	}

	ptl = pte_lockptr(mm, pmd);
	debugk(_DEBUG "locking PTE spinlock %lX\n", (unsigned long) ptl);
	spin_lock(ptl);

	printk(_INFO "marking page non present\n");

	pte->pte &= ~_PAGE_PRESENT;
	//pte->pte |= _PAGE_GLOBAL;
	
	printk(_INFO "flushing TLBs (%lX)\n", p->i_page);

	_flush_tlb_page(p->i_page);

	pte_unmap(pte);

	spin_unlock(ptl);

	if (p->z_frame) {
		pte = resolve_address_to_pte(mm, p->d_page, &pmd);
		if (!pte) {
			up_read(&mm->mmap_sem);

			return ERROR;
		}

		ptl = pte_lockptr(mm, pmd);
		debugk(_DEBUG "locking PTE spinlock %lX\n", (unsigned long) ptl);
		spin_lock(ptl);	

		printk(_INFO "replacing read/write frame number\n");

		pte->pte |= PTE_PFN_MASK;
		pte->pte &= ((p->z_frame << PAGE_SHIFT) | ~PTE_PFN_MASK);

		printk(_INFO "flushing TLBs (%lX)\n", p->d_page);

		_flush_tlb_page(p->d_page);

		pte_unmap(pte);

		spin_unlock(ptl);
	}

	up_read(&mm->mmap_sem);

	return SUCCESS;
}

static int fixup_page_table(struct mm_struct *mm, struct _page *p) {
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;

	debugk(_DEBUG "locking mm->mmap_sem\n");
	down_read(&mm->mmap_sem);

	pte = resolve_address_to_pte(mm, p->i_page, &pmd);
	if (!pte) {
		up_read(&mm->mmap_sem);

		return ERROR;
	}

	ptl = pte_lockptr(mm, pmd);
	debugk(_DEBUG "locking PTE spinlock %lX\n", (unsigned long) ptl);
	spin_lock(ptl);

	printk(_INFO "adjusting frame number and marking page present\n");

	pte->pte |= PTE_PFN_MASK;
	pte->pte &= ((p->i_frame << PAGE_SHIFT) | ~PTE_PFN_MASK);

	pte->pte |= _PAGE_PRESENT;

	printk(_INFO "flushing TLBs (%lX)\n", p->i_page);
	
	_flush_tlb_page(p->i_page);

	pte_unmap(pte);

	spin_unlock(ptl);

	if (p->z_frame) {
		pte = resolve_address_to_pte(mm, p->d_page, &pmd);
		if (!pte) {
			up_read(&mm->mmap_sem);

			return ERROR;
		}

		ptl = pte_lockptr(mm, pmd);
		debugk(_DEBUG "locking PTE spinlock %lX\n", (unsigned long) ptl);
		spin_lock(ptl);

		printk(_INFO "restoring original read/write frame number\n");

		pte->pte |= PTE_PFN_MASK;
		pte->pte &= ((p->d_frame << PAGE_SHIFT) | ~PTE_PFN_MASK);

		printk(_INFO "flushing TLBs (%lX)\n", p->d_page);

		_flush_tlb_page(p->d_page);

		pte_unmap(pte);

		spin_unlock(ptl);
	}

	up_read(&mm->mmap_sem);

	return SUCCESS;
}

static int is_task_equal_to(struct _task *t, struct task_struct *tsk) {
	return ((t->pid == tsk->pid) && (t->start_time.tv_sec == tsk->start_time.tv_sec) && (t->start_time.tv_nsec == tsk->start_time.tv_nsec));
}

static struct _task * is_task_in_list(struct task_struct *tsk) {
	struct _task *t;

	t = NULL;
	list_for_each_entry(t, &managed_tasks, ltasks) {
		if (is_task_equal_to(t, tsk)) return t;
	}

	return NULL;
}

static int register_managed_page(pid_t pid, unsigned long i_addr, unsigned long d_addr, int (*ret)(void), unsigned long z_page) {
	struct _task *t, *t_new;
	struct _page *p, *p_new;
	struct task_struct *tsk;

	tsk = get_task_by_pid(pid);
	if (!tsk || !tsk->mm) return ERROR;

	down_read(&manage_s);

	t = NULL;
	list_for_each_entry(t, &managed_tasks, ltasks) {
		if (is_task_equal_to(t, tsk)) goto register_page;
	}

	t_new = (struct _task *) kmalloc(sizeof(struct _task), GFP_KERNEL);
	if (!t_new) {
		printk(_ERROR "out of memory\n");
		return ERROR_OUT_OF_MEMORY;
	}
	t_new->pid = pid;
	t_new->start_time = tsk->start_time;
	INIT_LIST_HEAD(&t_new->managed_pages);

	up_read(&manage_s);
	down_write(&manage_s);

	list_add(&t_new->ltasks, &managed_tasks);

	up_write(&manage_s);
	down_read(&manage_s);

	t = t_new;

	register_page:

	p = NULL;
	list_for_each_entry(p, &t->managed_pages, lpages) {
		if ((i_addr & PAGE_MASK) == p->i_page) {

			up_read(&manage_s);

			return ERROR_PAGE_IN_LIST;
		}
	}

	p_new = (struct _page *) kmalloc(sizeof(struct _page), GFP_KERNEL);
	if (!p_new) {
		printk(_ERROR "out of memory\n");
		return ERROR_OUT_OF_MEMORY;
	}
	p_new->i_page = i_addr & PAGE_MASK;
	p_new->d_page = d_addr & PAGE_MASK;
	down_read(&tsk->mm->mmap_sem);
	if (resolve_linear_address(tsk->mm, p_new->i_page, &p_new->i_frame) || resolve_linear_address(tsk->mm, p_new->d_page, &p_new->d_frame)) {
		kfree(p_new);

		up_read(&tsk->mm->mmap_sem);

		up_read(&manage_s);

		return ERROR_INVALID_ADDRESS;
	}
	p_new->z_frame = 0;
	if (z_page && resolve_linear_address(tsk->mm, z_page, &p_new->z_frame)) {
		kfree(p_new);

		up_read(&tsk->mm->mmap_sem);

		up_read(&manage_s);

		return ERROR_INVALID_ADDRESS;;
	}
	up_read(&tsk->mm->mmap_sem);
	p_new->ret = ret;
	INIT_LIST_HEAD(&p_new->lpages);

	/* moved */
	up_read(&manage_s);
	down_write(&manage_s);

	if (prepare_page_table(tsk->mm, p_new)) {
		up_read(&tsk->mm->mmap_sem);

		up_read(&manage_s);

		printk(_ERROR "failed to prepare page table entries\n");

		return ERROR;
	}
	
	list_add(&p_new->lpages, &t->managed_pages);

	up_write(&manage_s);

	printk(_INFO "[%i] managing page %lX (%lX)", t->pid, p_new->i_page, p_new->i_frame);
	printk(_INFO "read/write page: %lX (%lX)\n", p_new->d_page, p_new->d_frame);
	if (z_page) {
		printk(_INFO "using zero page %lX (%lX)\n", z_page, p_new->z_frame);
	}

	return SUCCESS;
}

static int release_managed_page(pid_t pid, unsigned long i_addr) {
	struct _task *t;
	struct _page *p;
	struct task_struct *tsk;
	int task_in_list = 0;

	tsk = get_task_by_pid(pid);
	if (!tsk || !tsk->mm) {
		down_read(&manage_s);

		if ((t = is_task_in_list(tsk))) {
			up_read(&manage_s);
			down_write(&manage_s);

			p = NULL;
			list_for_each_entry(p, &t->managed_pages, lpages) {
				list_del(&p->lpages);
				kfree(p);
			}

			list_del(&t->ltasks);
			kfree(t);

			up_write(&manage_s);

			return SUCCESS;
		} else {
			up_read(&manage_s);

			return ERROR_TASK_NOT_IN_LIST;
		}
	}

	down_read(&manage_s);

	t = NULL;
	list_for_each_entry(t, &managed_tasks, ltasks) {
		if (is_task_equal_to(t, tsk)) {
			task_in_list = 1;

			p = NULL;
			list_for_each_entry(p, &t->managed_pages, lpages) {
				if ((i_addr & PAGE_MASK) == p->i_page) {
					/* moved */
					up_read(&manage_s);
					down_write(&manage_s);

					if (fixup_page_table(tsk->mm, p)) {
						printk(_WARNING "failed to restore valid page table state\n");
					}

					list_del(&p->lpages);
					kfree(p);

					if (list_empty(&t->managed_pages)) {
						list_del(&t->ltasks);
						kfree(t);
					}

					up_write(&manage_s);

					return SUCCESS;
				}
			}
		}
	}

	up_read(&manage_s);

	return task_in_list ? ERROR_PAGE_NOT_IN_LIST : ERROR_TASK_NOT_IN_LIST;
}

static void release_managed_tasks(void) {
	struct _task *t;
	struct _page *p;
	struct task_struct *tsk;

	down_write(&manage_s);

	t = NULL;
	list_for_each_entry(t, &managed_tasks, ltasks) {
		tsk = get_task_by_pid(t->pid);
		p = NULL;
		if (!tsk || !tsk->mm) {
			list_for_each_entry(p, &t->managed_pages, lpages) {
				list_del(&p->lpages);
				kfree(p);
			}

			list_del(&t->ltasks);
			kfree(t);
		} else {
			list_for_each_entry(p, &t->managed_pages, lpages) {
				if (fixup_page_table(tsk->mm, p)) {
					printk(_WARNING "failed to restore valid page table state\n");
				}

				list_del(&p->lpages);
				kfree(p);
			}

			list_del(&t->ltasks);
			kfree(t);
		}
	}

	up_write(&manage_s);
}

static void * get_registered_isr(int gate) {
	struct desc_ptr __idtr;
	gate_desc *__idt, entry;

	store_idt(&__idtr);
	__idt = (gate_desc *) __idtr.address;

	memcpy(&entry, &__idt[gate], sizeof(entry));

	return (void *) gate_offset(entry);
}

/* fix for 2.6.36 */

typedef void (*smp_call_func_t)(void *info);

static inline void _load_idt(const struct desc_ptr *dtr) {
	asm volatile("lidt %0"::"m" (*dtr));
}

/* end fix */

static void * register_isr(int gate, void *new, void **old) {
	struct desc_ptr __idtr;
	gate_desc *__idt, entry;
	void *isr;

	store_idt(&__idtr);
	__idt = (gate_desc *) __idtr.address;

	memcpy(&entry, &__idt[gate], sizeof(entry));
	
	isr = (void *) gate_offset(entry);
	if (old) {
		*old = isr;
		printk(_INFO "saving ISR %lX\n", (unsigned long) *old);
	}

#ifdef CONFIG_X86_64
	pack_gate(&entry, __idt[gate].type, (unsigned long) new, __idt[gate].dpl, __idt[gate].ist, gate_segment(__idt[gate]));
#else
	pack_gate(&entry, __idt[gate].type, (unsigned long) new, __idt[gate].dpl, 0, gate_segment(__idt[gate]));
#endif

	printk(_INFO "registering ISR %lX\n", (unsigned long) new);

	/* not necessary, smp_call_function should do the trick */
	asm("cli");
	write_idt_entry(__idt, gate, &entry);
	asm("sti");

	/* fix for 2.6.36 */
	smp_call_function((smp_call_func_t) _load_idt, &__idtr, 1);

	return isr;
}

static void * find_pattern(unsigned char *base, int range, unsigned char *pattern, int size, int *mask) {
	int i, j;

	for (i = 0; i < range - size; i++) {
		if (!mask) {
			if (!memcmp(&base[i], pattern, size)) {
				return (void *) (base + i + size);
			}
		} else {
			for (j = 0; j < size; j++) {
				if (mask[j] && (&base[i])[j] != pattern[j]) break;
			}

			if (j == size) return (void *) (base + i + size);
		}
	}

	return NULL;
}

static int resolve_kernel_symbol(unsigned char *base, int range, unsigned char *pattern, int length, int *mask, void **symbol) {
	unsigned long *label = find_pattern(base, range, pattern, length, mask);
	if (label) {
		*(unsigned long *)symbol = (*(int32_t *)label + (unsigned long) label + sizeof(int32_t));
		if (*(unsigned long *)symbol % 4) {
			printk(_WARNING "resolved kernel symbol is not aligned\n");
		}
		return SUCCESS;
	} else {
		return ERROR;
	}
}

static void noinline load_dtlb(unsigned long address) {
	__asm__ __volatile__ (
	
#ifdef CONFIG_X86_64
		"movq (%0), %%rax\n"
		:
		: "r"(address)
		: "%rax"
#else
		"movl (%0), %%eax\n"
		:
		: "r"(address)
		: "%eax"
#endif

	);
}

/*static void noinline load_itlb(void *address) {
	__asm__ __volatile__ (
		"call *%0\n"
		:
		: "r"(address)
	);
}*/

static int fault_in_kernel_space(unsigned long address) {
	return address >= TASK_SIZE_MAX;
}

int dotraplinkage isr0x0E(unsigned long error_code, unsigned long ip) {
	struct task_struct *tsk;
	unsigned long address;
	unsigned long frame;
	struct _task *t;
	struct _page *p;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;

	address = read_cr2();

	/* we don't handle page faults in kernel space, pass it down */
	if (fault_in_kernel_space(address)) {
		debugk(_DEBUG "page fault in kernelspace (%i)\n", current->pid);
		return 0;
	}

	/* pass the page fault down if there is no valid user context */
	tsk = current;
	if (!tsk->mm) {
		printk(_ERROR "no context for process %i\n", tsk->pid);
		return 0;
	}

	down_read(&manage_s);

	//debugk(_DEBUG "locking mm->mmap_sem\n");
	down_read(&tsk->mm->mmap_sem);

	/* we identify access to managed pages by the faulting linear address and the corresponding physical frame - meh, this is error-prone; maybe we should use the PTE's address instead? */
	t = NULL;
	list_for_each_entry(t, &managed_tasks, ltasks) {
		if (is_task_equal_to(t, tsk)) {
			debugk(_DEBUG "%s: page fault in managed process (%lX: %lX)\n", error_code & PF_USER ? "userspace" : "kernelspace", ip, address);
		}

		p = NULL;
		list_for_each_entry(p, &t->managed_pages, lpages) {
			
			/* expect odd behaviour if a client failed to release a managed page and we hit a matching linear address resp. physical frame */
			if ((address & PAGE_MASK) != p->i_page) continue;

			/* we ignore page table present flags when resolving addresses */
			if (!resolve_linear_address(tsk->mm, address, &frame)) {
				if (frame == p->i_frame) {
					debugk(_DEBUG "page fault on managed page (%lX: %lX)\n", ip, address);

					/* is this necessary? */
					__set_current_state(TASK_RUNNING);

					pte = resolve_address_to_pte(tsk->mm, address, &pmd);

					ptl = pte_lockptr(tsk->mm, pmd);
					debugk(_DEBUG "locking PTE spinlock %lX\n", (unsigned long) ptl);
					spin_lock(ptl);

					if (address == ip && !(error_code & PF_WRITE)) {
						/* execute access */

						debugk(_DEBUG "loading ITLB\n");
						/* mark the page present temporarily and load ITLB */
						pte->pte |= _PAGE_PRESENT;
						/* call into managed page */
						p->ret();
						pte->pte &= ~_PAGE_PRESENT;
					} else {
						/* read/write access */

						debugk(_DEBUG "loading DTLB\n");
						/* replace the page frame number with the fake */
						pte->pte |= PTE_PFN_MASK;
						pte->pte &= ((p->d_frame << PAGE_SHIFT) | ~PTE_PFN_MASK);
						/* mark the page present temporarily and load DTLB */
						pte->pte |= _PAGE_PRESENT;
						//printk(KERN_ALERT "pte when loading %lX: %lX\n", (unsigned long) pte, (unsigned long) pte->pte);
						load_dtlb(address);
						pte->pte &= ~_PAGE_PRESENT;
						/* restore the original page frame number */
						pte->pte |= PTE_PFN_MASK;
						pte->pte &= ((p->i_frame << PAGE_SHIFT) | ~PTE_PFN_MASK);

						if (_log) {
							/* we might want to notify our client that a managed page has been accessed via netlink */
							printk(_INFO "%lX accessing (%s) %lX\n", ip, (error_code & PF_WRITE) ? "write" : "read", address);
						}
					}

					pte_unmap(pte);

					spin_unlock(ptl);

					up_read(&tsk->mm->mmap_sem);

					//local_irq_enable();
	
					up_read(&manage_s);

					debugk(_DEBUG "successfully handled page fault\n");

					/* we handled the page fault, return from the interrupt */
					return 1;
				}
			} else {

				/* 
				 * actually we don't have to worry about that particular situation; in case we miss a page fault that
				 * we should handle, the kernel page fault handler will fail to proccess it and just kill the offending process
				 */
				printk(_WARNING "couldn't resolve matching linear address\n");
			}
		}
	}

	up_read(&tsk->mm->mmap_sem);

	up_read(&manage_s);

	/* page fault on unmanaged page, pass it down to the kernel page fault handler */
	return 0;
}

extern void isr0x0E_stub(void);

#ifdef CONFIG_X86_32_LAZY_GS
#define _SET_KERNEL_GS
#else
#define _SET_KERNEL_GS \
	"movl %7, %%ecx\n" \
	"movl %%ecx, %%gs\n"
#endif

#ifdef CONFIG_TRACE_IRQFLAGS
#define _TRACE_IRQS_OFF "call trace_hardirqs_off_thunk\n"
#else
#define _TRACE_IRQS_OFF
#endif

/*
c14c524b:	8c d0                	mov    %ss,%eax
c14c524d:	66 3d d0 00          	cmp    $0xd0,%ax
c14c5251:	75 22                	jne    c14c5275 <error_code+0x3d>
c14c5253:	b8 68 00 00 00       	mov    $0x68,%eax
c14c5258:	8e d8                	mov    %eax,%ds
c14c525a:	8e c0                	mov    %eax,%es
c14c525c:	64 a0 d4 00 76 c1    	mov    %fs:0xc17600d4,%al
c14c5262:	64 8a 25 d7 00 76 c1 	mov    %fs:0xc17600d7,%ah
c14c5269:	c1 e0 10             	shl    $0x10,%eax
c14c526c:	01 e0                	add    %esp,%eax
c14c526e:	6a 68                	push   $0x68
c14c5270:	50                   	push   %eax
c14c5271:	0f b2 24 24          	lss    (%esp),%esp
*/
#ifdef CONFIG_SMP
#define _READ_SEGMENT_BASE \
	"mov %%fs:0x4(%%ecx), %%al\n" \
	"mov %%fs:0x7(%%ecx), %%ah\n"
#else
#define _READ_SEGMENT_BASE \
	"mov 0x4(%%ecx), %%al\n" \
	"mov 0x7(%%ecx), %%ah\n"
#endif

#define _UNWIND_ESPFIX_STACK \
	"movl %%ss, %%eax\n" \
	"cmpw %4, %%ax\n" \
	"jne skip\n" \
	"movl %5, %%eax\n" \
	"movl %%eax, %%ds\n" \
	"movl %%eax, %%es\n" \
	"leal gdt_page, %%ecx\n" \
	"addl %6, %%ecx\n" \
	_READ_SEGMENT_BASE \
	"shl $16, %%eax\n" \
	"addl %%esp, %%eax\n" \
	"pushl %5\n" \
	"pushl %%eax\n" \
	"lss (%%esp), %%esp\n" \
	"skip:\n"

void isr0x0E_stub_wrapper(void) {
	__asm__ __volatile__ (

	".globl isr0x0E_stub\n"
	".type isr0x0E_stub, @function\n"
	".align 4,0x90\n"
	"isr0x0E_stub:\n"

#ifdef CONFIG_X86_64
	"sub $0x78, %%rsp\n"
	"callq *kernel64_error_entry\n"
	"movq 0x78(%%rsp), %%rdi\n"
	"movq %0, %%rsi\n"
	"or %1, %%rsi\n"
	"test %%rsi, %%rdi\n"
	"jnz pass_down\n"
	"movq 0x80(%%rsp), %%rsi\n"
	"callq isr0x0E\n"
	"test %%rax, %%rax\n"
	"jz pass_down\n"
	"movq $-1, 0x78(%%rsp)\n"
	"jmpq *kernel64_error_exit\n"

	"pass_down:\n"
	"mov %%rsp, %%rdi\n"
	"mov 0x78(%%rsp), %%rsi\n"
	"movq $-1, 0x78(%%rsp)\n"
	"callq *kernel64_do_page_fault\n"
	"jmpq *kernel64_error_exit\n"
#else
	"pushl %%eax\n"
	"pushl %%ebx\n"
	"movl 0x8(%%esp), %%eax\n"
	"mov %0, %%ebx\n"
	"or %1, %%ebx\n"
	"test %%ebx, %%eax\n"
	"jz page_not_found\n"
	"popl %%ebx\n"
	"popl %%eax\n"
	"jmp pass_down\n"

	"page_not_found:\n"
	"popl %%ebx\n"
	"popl %%eax\n"
	"pushl %%gs\n"
	"pushl %%fs\n"
	"pushl %%es\n"
	"pushl %%ds\n"
	"pushl %%eax\n"
	"pushl %%ebp\n"
	"pushl %%edi\n"
	"pushl %%esi\n"
	"pushl %%edx\n"
	"pushl %%ecx\n"
	"pushl %%ebx\n"
	"cld\n"
	"movl %2, %%ecx\n"
	"movl %%ecx, %%fs\n"
	_UNWIND_ESPFIX_STACK
	_SET_KERNEL_GS
	"movl %3, %%ecx\n"
	"movl %%ecx, %%ds\n"
	"movl %%ecx, %%es\n"
	_TRACE_IRQS_OFF
	"movl 0x2c(%%esp), %%eax\n"
	"movl 0x30(%%esp), %%edx\n"
	"call isr0x0E\n"
	"test %%eax, %%eax\n"
	"jz restore\n"
	"movl $-1, 0x2c(%%esp)\n"
	"jmp *kernel32_ret_from_exception\n"

	"restore:\n"
	"popl %%ebx\n"
	"popl %%ecx\n"
	"popl %%edx\n"
	"popl %%esi\n"
	"popl %%edi\n"
	"popl %%ebp\n"
	"popl %%eax\n"
	"popl %%ds\n"
	"popl %%es\n"
	"popl %%fs\n"
	"popl %%gs\n"

	"pass_down:\n"
	"jmp *kernel_isr0x0E_stub\n"
#endif

	:
#ifdef CONFIG_X86_64
	: "i"(PF_PROT), "i"(PF_RSVD)
#else
#ifdef CONFIG_X86_32_LAZY_GS
	: "i"(PF_PROT), "i"(PF_RSVD), "i"(__KERNEL_PERCPU), "i"(__USER_DS), "i"(__ESPFIX_SS), "i"(__KERNEL_DS), "i"(GDT_ENTRY_ESPFIX_SS * 8)
#else
	: "i"(PF_PROT), "i"(PF_RSVD), "i"(__KERNEL_PERCPU), "i"(__USER_DS), "i"(__ESPFIX_SS), "i"(__KERNEL_DS), "i"(GDT_ENTRY_ESPFIX_SS * 8), "i"(__KERNEL_STACK_CANARY)
#endif
#endif

	);
}

static int __init ghost_init(void) {
	unsigned char *kisr;

	printk(_INFO "loading\n");

	kisr = get_registered_isr(0x0E);

#ifdef CONFIG_X86_64
	if (resolve_kernel_symbol(kisr, 0x100, jmp_error_exit, sizeof(jmp_error_exit), jmp_error_exit_mask, &kernel64_error_exit)) {
		printk(_ERROR "failed to resolve kernel symbol error_exit\n");
		return ERROR;
	} else {
		debugk(_DEBUG "resolved kernel symbol error_exit: %lX\n", (unsigned long) kernel64_error_exit);
	}
	if (resolve_kernel_symbol(kisr, 0x100, call_error_entry, sizeof(call_error_entry), NULL, &kernel64_error_entry)) {
		printk(_ERROR "failed to resolve kernel symbol error_entry\n");
		return ERROR;
	} else {
		debugk(_DEBUG "resolved kernel symbol error_entry: %lX\n", (unsigned long) kernel64_error_entry);
	}
	if (resolve_kernel_symbol(kisr, 0x100, call_do_page_fault, sizeof(call_do_page_fault), NULL, &kernel64_do_page_fault)) {
		printk(_ERROR "failed to resolve kernel symbol do_page_fault\n");
		return ERROR;
	} else {
		debugk(_DEBUG "resolved kernel symbol do_page_fault: %lX\n", (unsigned long) kernel64_do_page_fault);
	}
#else
	if (resolve_kernel_symbol(kisr, 0x100, jmp_ret_from_exception, sizeof(jmp_ret_from_exception), NULL, &kernel32_ret_from_exception)) {
		printk(_ERROR "failed to resolve kernel symbol ret_from_exception\n");
		return ERROR;
	} else {
		debugk(_DEBUG "resolved kernel symbol ret_from_exception: %lX\n", (unsigned long) kernel32_ret_from_exception);
	}
#endif

	init_rwsem(&manage_s);

	printk(_INFO "registering netlink family\n");

	if (genl_register_family(&genl_family_mod)) {
		printk(_ERROR "failed to register netlink family\n");
		return ERROR;
	}
	if (genl_register_ops(&genl_family_mod, &genl_ops_register_page)) {
		printk(_ERROR "failed to register netlink request callback\n");
		return ERROR;
	}
	if (genl_register_ops(&genl_family_mod, &genl_ops_release_page)) {
		printk(_ERROR "failed to register netlink request callback\n");
		return ERROR;
	}

	printk(_INFO "registering custom page fault handler\n");
	
	register_isr(0x0E, isr0x0E_stub, &kernel_isr0x0E_stub);

	return SUCCESS;
}

static void __exit ghost_exit(void) {
	printk(_INFO "unloading\n");

	printk(_INFO "unregistering netlink family\n");

	genl_unregister_ops(&genl_family_mod, &genl_ops_register_page);
	genl_unregister_ops(&genl_family_mod, &genl_ops_release_page);
	genl_unregister_family(&genl_family_mod);

	if (kernel_isr0x0E_stub) {
		printk(_INFO "restoring kernel page fault handler\n");

		register_isr(0x0E, kernel_isr0x0E_stub, NULL);
	}

	printk(_INFO "releasing managed tasks\n");
	release_managed_tasks();
}

module_init(ghost_init);
module_exit(ghost_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("gonzoj <gonzoj@lavabit.com>");
