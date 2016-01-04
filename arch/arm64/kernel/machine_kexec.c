/*
 * kexec for arm64
 *
 * Copyright (C) Linaro.
 * Copyright (C) Huawei Futurewei Technologies.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define DEBUG 1
#define DUMP_VERBOSITY 1 /* 1..4 */

/* Bypass purgatory for debugging. */
static const int bypass_purgatory = 1;

#include <linux/highmem.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/kexec.h>
#include <linux/libfdt_env.h>
#include <linux/of_fdt.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <asm/cacheflush.h>
#include <asm/system_misc.h>

#include "cpu-reset.h"

/* Global variables for the arm64_relocate_new_kernel routine. */
extern const unsigned char arm64_relocate_new_kernel[];
extern const unsigned long arm64_relocate_new_kernel_size;
extern unsigned long arm64_kexec_dtb_addr;
extern unsigned long arm64_kexec_kimage_head;
extern unsigned long arm64_kexec_kimage_start;
#ifdef CONFIG_KEXEC_HARDBOOT
extern unsigned long arm64_kexec_hardboot;
void (*kexec_hardboot_hook)(void);
#endif

bool in_crash_kexec;
static unsigned long kimage_start;

/**
 * kexec_is_kernel - Helper routine to check the kernel header signature.
 */
static bool kexec_is_kernel(const void *image)
{
	struct arm64_image_header {
		uint8_t pe_sig[2];
		uint16_t branch_code[3];
		uint64_t text_offset;
		uint64_t image_size;
		uint8_t flags[8];
		uint64_t reserved_1[3];
		uint8_t magic[4];
		uint32_t pe_header;
	} h;

        if (copy_from_user(&h, image, sizeof(struct arm64_image_header)))
		return false;

	if (!h.text_offset)
		return false;

	return (h.magic[0] == 'A'
		&& h.magic[1] == 'R'
		&& h.magic[2] == 'M'
		&& h.magic[3] == 0x64U);
}

/**
 * kexec_find_kernel_seg - Helper routine to find the kernel segment.
 */
static const struct kexec_segment *kexec_find_kernel_seg(
	const struct kimage *kimage)
{
	int i;

	for (i = 0; i < kimage->nr_segments; i++) {
		if (kexec_is_kernel(kimage->segment[i].buf))
			return &kimage->segment[i];
	}

	BUG();
	return NULL;
}

/**
 * kexec_is_dtb - Helper routine to check the device tree header signature.
 */
static bool kexec_is_dtb(const void *dtb)
{
	__be32 magic;

	if (get_user(magic, (__be32 *)dtb))
		return false;

	return fdt32_to_cpu(magic) == OF_DT_HEADER;
}

/**
 * kexec_find_dtb_seg - Helper routine to find the dtb segment.
 */
static const struct kexec_segment *kexec_find_dtb_seg(
	const struct kimage *kimage)
{
	int i;

	for (i = 0; i < kimage->nr_segments; i++) {
		if (kexec_is_dtb(kimage->segment[i].buf))
			return &kimage->segment[i];
	}

	BUG();
	return NULL;
}

static struct bypass {
	unsigned long kernel;
	unsigned long dtb;
} bypass;

static void fill_bypass(const struct kimage *kimage)
{
	const struct kexec_segment *seg;

	seg = kexec_find_kernel_seg(kimage);
	BUG_ON(!seg || !seg->mem);
	bypass.kernel = seg->mem;

	seg = kexec_find_dtb_seg(kimage);
	BUG_ON(!seg || !seg->mem);
	bypass.dtb = seg->mem;

	pr_debug("%s: kernel: %016lx\n", __func__, bypass.kernel);
	pr_debug("%s: dtb:    %016lx\n", __func__, bypass.dtb);
}

/**
 * kexec_list_walk - Helper to walk the kimage page list.
 */
static void kexec_list_walk(void *ctx, unsigned long kimage_head,
	void (*cb)(void *ctx, unsigned int flag, void *addr, void *dest))
{
	void *dest;
	unsigned long *entry;

	for (entry = &kimage_head, dest = NULL; ; entry++) {
		unsigned int flag = *entry & IND_FLAGS;
		void *addr = phys_to_virt(*entry & PAGE_MASK);

		switch (flag) {
		case IND_INDIRECTION:
			entry = (unsigned long *)addr - 1;
			cb(ctx, flag, addr, NULL);
			break;
		case IND_DESTINATION:
			dest = addr;
			cb(ctx, flag, addr, NULL);
			break;
		case IND_SOURCE:
			cb(ctx, flag, addr, dest);
			dest += PAGE_SIZE;
			break;
		case IND_DONE:
			cb(ctx, flag , NULL, NULL);
			return;
		default:
			break;
		}
	}
}

/**
 * kexec_image_info - For debugging output.
 */
#define kexec_image_info(_i) _kexec_image_info(__func__, __LINE__, _i)
static void _kexec_image_info(const char *func, int line,
	const struct kimage *kimage)
{
	unsigned long i;

#ifndef DEBUG
	return;
#endif
	pr_debug("%s:%d:\n", func, line);
	pr_debug("  kexec kimage info:\n");
	pr_debug("    type:        %d\n", kimage->type);
	pr_debug("    start:       %lx\n", kimage->start);
	pr_debug("    head:        %lx\n", kimage->head);
	pr_debug("    nr_segments: %lu\n", kimage->nr_segments);

	for (i = 0; i < kimage->nr_segments; i++) {
		pr_debug("      segment[%lu]: %016lx - %016lx, %lx bytes, %lu pages%s\n",
			i,
			kimage->segment[i].mem,
			kimage->segment[i].mem + kimage->segment[i].memsz,
			kimage->segment[i].memsz,
			kimage->segment[i].memsz /  PAGE_SIZE,
			(kexec_is_dtb(kimage->segment[i].buf) ?
				", dtb segment" : ""));
	}
}

/**
 * kexec_list_dump - Debugging dump of the kimage page list.
 */
static void kexec_list_dump_cb(void *ctx, unsigned int flag, void *addr,
	void *dest)
{
	unsigned int verbosity = (unsigned long)ctx;
	phys_addr_t paddr = virt_to_phys(addr);
	phys_addr_t pdest = virt_to_phys(dest);

	switch (flag) {
	case IND_INDIRECTION:
		pr_debug("  I: %pa (%p)\n", &paddr, addr);
		break;
	case IND_DESTINATION:
		pr_debug("  D: %pa (%p)\n",
			&paddr, addr);
		break;
	case IND_SOURCE:
		if (verbosity == 2)
			pr_debug("S");
		if (verbosity == 3)
			pr_debug("  S -> %pa (%p)\n", &pdest, dest);
		if (verbosity == 4)
			pr_debug("  S: %pa (%p) -> %pa (%p)\n", &paddr, addr,
				&pdest, dest);
		break;
	case IND_DONE:
		pr_debug("  DONE\n");
		break;
	default:
		pr_debug("  ?: %pa (%p)\n", &paddr, addr);
		break;
	}
}

#define kexec_list_dump(_i, _v) _kexec_list_dump(__func__, __LINE__, _i, _v)
static void _kexec_list_dump(const char *func, int line,
	unsigned long kimage_head, unsigned int verbosity)
{
#if !defined(DEBUG)
	return;
#endif

	pr_debug("%s:%d: kexec_list_dump:\n", func, line);

	kexec_list_walk((void *)(unsigned long)verbosity, kimage_head,
		kexec_list_dump_cb);
}

static void dump_cpus(void)
{
	unsigned int cpu;
	char s[1024];
	char *p;

	p = s + sprintf(s, "%s: all:       ", __func__);
	for_each_cpu(cpu, cpu_all_mask)
		p += sprintf(p, " %d", cpu);
	pr_debug("%s\n", s);

	p = s + sprintf(s, "%s: possible:  ", __func__);
	for_each_possible_cpu(cpu)
		p += sprintf(p, " %d", cpu);
	pr_debug("%s\n", s);

	p = s + sprintf(s, "%s: present:   ", __func__);
	for_each_present_cpu(cpu)
		p += sprintf(p, " %d", cpu);
	pr_debug("%s\n", s);

	p = s + sprintf(s, "%s: active:    ", __func__);
	for_each_cpu(cpu, cpu_active_mask)
		p += sprintf(p, " %d", cpu);
	pr_debug("%s\n", s);

	p = s + sprintf(s, "%s: online:    ", __func__);
	for_each_online_cpu(cpu)
		p += sprintf(p, " %d", cpu);
	pr_debug("%s\n", s);

	p = s + sprintf(s, "%s: not online:", __func__);
	for_each_cpu_not(cpu, cpu_online_mask)
		p += sprintf(p, " %d", cpu);
	pr_debug("%s\n", s);
}

void machine_kexec_cleanup(struct kimage *kimage)
{
	/* Empty routine needed to avoid build errors. */
}

/**
 * machine_kexec_prepare - Prepare for a kexec reboot.
 *
 * Called from the core kexec code when a kernel image is loaded.
 */
int machine_kexec_prepare(struct kimage *kimage)
{
	kexec_image_info(kimage);
	fill_bypass(kimage);
	if (bypass_purgatory) {
		arm64_kexec_kimage_start = bypass.kernel;
		arm64_kexec_dtb_addr = bypass.dtb;
	} else {
		arm64_kexec_kimage_start = kimage->start;
		arm64_kexec_dtb_addr = 0;
	}
#ifdef CONFIG_KEXEC_HARDBOOT
	arm64_kexec_hardboot = kimage->hardboot;
#endif

	return 0;
}

/**
 * kexec_list_flush - Helper to flush the kimage list to PoC.
 */
static void kexec_list_flush(kimage_entry_t kimage_head)
{
	kimage_entry_t *entry;
	unsigned int flag;

	for (entry = &kimage_head, flag = 0; flag != IND_DONE; entry++) {
		void *addr = kmap(phys_to_page(*entry & PAGE_MASK));

		flag = *entry & IND_FLAGS;

		switch (flag) {
		case IND_INDIRECTION:
			entry = (kimage_entry_t *)addr - 1;
			__flush_dcache_area(addr, PAGE_SIZE);
			break;
		case IND_DESTINATION:
			break;
		case IND_SOURCE:
			__flush_dcache_area(addr, PAGE_SIZE);
			break;
		case IND_DONE:
			break;
		default:
			BUG();
		}
		kunmap(addr);
	}
}

/**
 * kexec_segment_flush - Helper to flush the kimage segments to PoC.
 */
static void kexec_segment_flush(const struct kimage *kimage)
{
	unsigned long i;

	pr_debug("%s:\n", __func__);

	for (i = 0; i < kimage->nr_segments; i++) {
		pr_debug("  segment[%lu]: %016lx - %016lx, %lx bytes, %lu pages\n",
			i,
			kimage->segment[i].mem,
			kimage->segment[i].mem + kimage->segment[i].memsz,
			kimage->segment[i].memsz,
			kimage->segment[i].memsz /  PAGE_SIZE);

		__flush_dcache_area(phys_to_virt(kimage->segment[i].mem),
			kimage->segment[i].memsz);
	}
}


/**
 * kexec_list_hardboot_create_post_reboot_list -
 * modify existing destination list to copy kernel to temp region;
 * create new destination list in hardboot page to copy from temp region
 * to final location
 */
static void kexec_list_hardboot_create_post_reboot_list(
	unsigned long kimage_head, unsigned long *newlist_start,
	unsigned long tempdest_phys)
{
	/* so the entries are in the format:
	 * IND_DESTINATION -> where to go
	 * IND_SOURCE -> where to read one page
	 * IND_SOURCE -> where to read the next page (and so on)
	 * For existing: rewrite IND_DESTINATION to store to temp location; leave IND_SOURCE intact
	 * For new: copy original IND_DESTINATION, rewrite new IND_SOURCE to read from temp location
	 * We do not copy indirection (new list will be flat)
	 */
	void *dest;
	unsigned long *entry;
	unsigned long *newlist = newlist_start;

	for (entry = &kimage_head, dest = NULL; ; entry++) {
		unsigned int flag = *entry &
			(IND_DESTINATION | IND_INDIRECTION | IND_DONE |
			IND_SOURCE);
		void *addr = phys_to_virt(*entry & PAGE_MASK);

		switch (flag) {
		case IND_INDIRECTION:
			entry = (unsigned long *)addr - 1;
			break;
		case IND_DESTINATION:
			// new list: copy original IND_DESTINATION
			*newlist++ = *entry;
			// old list: rewrite to store to temp location
			*entry = flag | tempdest_phys;
			break;
		case IND_SOURCE:
			// new list: rewrite to read from temp location
			*newlist++ = flag | tempdest_phys;
			// new list: add to new temp destination address
			tempdest_phys += PAGE_SIZE;
			break;
		case IND_DONE:
			*newlist++ = *entry; // new list: copy original IND_DONE
			return;
		default:
			BUG();
		}
	}
}

/**
 * machine_kexec - Do the kexec reboot.
 *
 * Called from the core kexec code for a sys_reboot with LINUX_REBOOT_CMD_KEXEC.
 */
void machine_kexec(struct kimage *kimage)
{
	phys_addr_t reboot_code_buffer_phys;
	void *reboot_code_buffer;

	if (num_online_cpus() > 1) {
		if (in_crash_kexec)
			pr_warn("crash dump might get corrupted because %d cpus are still online\n",
					num_online_cpus());
		else
			BUG();
	}

	reboot_code_buffer_phys = page_to_phys(kimage->control_code_page);
	reboot_code_buffer = kmap(kimage->control_code_page);

	kexec_image_info(kimage);

	pr_debug("%s:%d: control_code_page:        %p\n", __func__, __LINE__,
		kimage->control_code_page);
	pr_debug("%s:%d: reboot_code_buffer_phys:  %pa\n", __func__, __LINE__,
		&reboot_code_buffer_phys);
	pr_debug("%s:%d: reboot_code_buffer:       %p\n", __func__, __LINE__,
		reboot_code_buffer);
	pr_debug("%s:%d: relocate_new_kernel:      %p\n", __func__, __LINE__,
		arm64_relocate_new_kernel);
	pr_debug("%s:%d: relocate_new_kernel_size: 0x%lx(%lu) bytes\n",
		__func__, __LINE__, arm64_relocate_new_kernel_size,
		arm64_relocate_new_kernel_size);

	pr_debug("%s:%d: kimage_head:              %lx\n", __func__, __LINE__,
		kimage->head);
	pr_debug("%s:%d: kimage_start:             %lx\n", __func__, __LINE__,
		kimage_start);

	kexec_list_dump(kimage->head, DUMP_VERBOSITY);
	dump_cpus();

	arm64_kexec_kimage_head = kimage->head;

	/*
	 * Copy arm64_relocate_new_kernel to the reboot_code_buffer for use
	 * after the kernel is shut down.
	 */
	memcpy(reboot_code_buffer, arm64_relocate_new_kernel,
		arm64_relocate_new_kernel_size);

	/* Flush the reboot_code_buffer in preparation for its execution. */
	__flush_dcache_area(reboot_code_buffer, arm64_relocate_new_kernel_size);
	flush_icache_range((uintptr_t)reboot_code_buffer, arm64_relocate_new_kernel_size);

#ifdef CONFIG_KEXEC_HARDBOOT
	if (kimage->hardboot) {
		// hardboot reserve should be 1MB.
		unsigned long hardboot_reserve = KEXEC_HB_PAGE_ADDR;
		void *hardboot_map = phys_to_virt(hardboot_reserve);
		// post reboot reloc code is 4K inside the hardboot page
		void* post_reboot_code_buffer = hardboot_map + PAGE_SIZE;
		// post reboot reloc list is 8K after the hardboot page.
		unsigned long post_reboot_list_loc = hardboot_reserve +
			(PAGE_SIZE * 2);
		unsigned long *hardboot_list_loc_virt = hardboot_map +
			(PAGE_SIZE * 2);

		// temp space is 64MB in front of hardboot reserve.
		// Must be big enough to hold kernel, initrd, and dtb.
		unsigned long tempdest = hardboot_reserve - (SZ_1M * 64);

		// create new relocation list for post reboot reloc
		// TODO: check for overflow of temp space and hardboot page
		kexec_list_hardboot_create_post_reboot_list(kimage->head,
			hardboot_list_loc_virt, tempdest);

		// setup post-reboot reloc code
		arm64_kexec_kimage_head = IND_INDIRECTION | post_reboot_list_loc;
		arm64_kexec_hardboot = 0;

		// copy relocation code to hardboot page for post-reboot reloc
		memcpy(post_reboot_code_buffer, arm64_relocate_new_kernel,
			arm64_relocate_new_kernel_size);

		// flush the entire hardboot page
		__flush_dcache_area(hardboot_map, SZ_1M);

		kexec_list_dump(kimage->head, DUMP_VERBOSITY);
		kexec_list_dump(arm64_kexec_kimage_head, DUMP_VERBOSITY);
	}
#endif

	/* Flush the kimage list. */
	kexec_list_flush(kimage->head);

	/* Flush the new image if already in place. */
	if (kimage->head & IND_DONE)
		kexec_segment_flush(kimage);

#ifdef CONFIG_KEXEC_HARDBOOT
	/* Run any final machine-specific shutdown code. */
	if (kimage->hardboot && kexec_hardboot_hook)
		kexec_hardboot_hook();
#endif

	pr_info("Bye!\n");

	/* Disable all DAIF exceptions. */
	asm volatile ("msr daifset, #0xf" : : : "memory");

	setup_mm_for_reboot();

	/*
	 * cpu_soft_restart will shutdown the MMU, disable data caches, then
	 * transfer control to the reboot_code_buffer which contains a copy of
	 * the arm64_relocate_new_kernel routine.  arm64_relocate_new_kernel
	 * uses physical addressing to relocate the new image to its final
	 * position and transfers control to the image entry point when the
	 * relocation is complete.
	 */

	if (bypass_purgatory)
		cpu_soft_restart(in_crash_kexec ? 0 : is_hyp_mode_available(),
			reboot_code_buffer_phys, kimage->head, bypass.kernel,
			bypass.dtb);
	else
		cpu_soft_restart(in_crash_kexec ? 0 : is_hyp_mode_available(),
			reboot_code_buffer_phys, kimage->head, kimage_start, 0);

	BUG(); /* Should never get here. */
}

static void machine_kexec_mask_interrupts(void)
{
	unsigned int i;
	struct irq_desc *desc;

	for_each_irq_desc(i, desc) {
		struct irq_chip *chip;
		int ret;

		chip = irq_desc_get_chip(desc);
		if (!chip)
			continue;

		/*
		 * First try to remove the active state. If this
		 * fails, try to EOI the interrupt.
		 */
		ret = irq_set_irqchip_state(i, IRQCHIP_STATE_ACTIVE, false);

		if (ret && irqd_irq_inprogress(&desc->irq_data) &&
		    chip->irq_eoi)
			chip->irq_eoi(&desc->irq_data);

		if (chip->irq_mask)
			chip->irq_mask(&desc->irq_data);

		if (chip->irq_disable && !irqd_irq_disabled(&desc->irq_data))
			chip->irq_disable(&desc->irq_data);
	}
}

/**
 * machine_crash_shutdown - shutdown non-crashing cpus and save registers
 */
void machine_crash_shutdown(struct pt_regs *regs)
{
	struct pt_regs dummy_regs;
	int cpu;

	local_irq_disable();

	in_crash_kexec = true;

	/*
	 * clear and initialize the per-cpu info. This is necessary
	 * because, otherwise, slots for offline cpus would never be
	 * filled up. See smp_send_stop().
	 */
	memset(&dummy_regs, 0, sizeof(dummy_regs));
	for_each_possible_cpu(cpu)
		crash_save_cpu(&dummy_regs, cpu);

	/* shutdown non-crashing cpus */
	smp_send_stop();

	/* for crashing cpu */
	crash_save_cpu(regs, smp_processor_id());
	machine_kexec_mask_interrupts();

	pr_info("Starting crashdump kernel...\n");
}

bool arch_kexec_is_hardboot_buffer_range(unsigned long start,
	unsigned long end) {
	unsigned long hardboot_reserve = KEXEC_HB_PAGE_ADDR;
	unsigned long tempdest = hardboot_reserve - (SZ_1M * 64);
	// reserve is the end, tempdest is the start of the buffer
	return start < hardboot_reserve && end >= tempdest;
}
