// SPDX-License-Identifier: GPL-2.0

#include <linux/kvm_para.h>
#include <linux/io.h>
#include <asm/coco.h>
#include <asm/pkvm_guest.h>
#include <asm/pgtable.h>
#include <asm/apic.h>

DEFINE_STATIC_KEY_FALSE(pkvm_guest_detected);
EXPORT_SYMBOL(pkvm_guest_detected);

static struct pkvm_guest_mmio_info pkvm_mmio_info;
static struct pkvm_guest_mmio_allow_range
	pkvm_mmio_allow_ranges[PKVM_GUEST_MMIO_ALLOW_MAX_RANGES];
static u16 pkvm_mmio_allow_nr_ranges;

int pkvm_set_mem_host_visibility(unsigned long addr, int numpages, bool enc)
{
	unsigned long size = numpages * PAGE_SIZE;
	int ret;

	if (!enc) {
		int i;

		/*
		 * If the guest has never touched these pages before, they have
		 * not been donated to the guest yet, i.e. are still owned by
		 * the host. In such case the sharing will fail.
		 *
		 * So touch these pages first, to make sure they are owned by
		 * the guest before sharing.
		 */
		for (i = 0; i < numpages; i++)
			READ_ONCE(*(u8 *)(addr + i * PAGE_SIZE));

		/*
		 * pKVM may not have enough memory to perform the sharing. In such
		 * case it requests the host to provide more memory, and then may
		 * ask the guest to retry the hypercall.
		 */
		do {
			ret = kvm_hypercall2(PKVM_GHC_SHARE_MEM, __pa(addr), size);
		} while (ret == -EAGAIN);
	} else {
		ret = kvm_hypercall2(PKVM_GHC_UNSHARE_MEM, __pa(addr), size);
	}

	return ret;
}

static bool pkvm_mmio_allow_hit(unsigned long gpa, int size)
{
	u64 access_end = (u64)gpa + size;
	u16 i;

	if (access_end < gpa)
		return false;

	for (i = 0; i < pkvm_mmio_allow_nr_ranges; i++) {
		struct pkvm_guest_mmio_allow_range *range =
			&pkvm_mmio_allow_ranges[i];
		u64 range_end = range->guest_gpa + range->size;

		if (range_end < range->guest_gpa)
			continue;

		if (!(range->flags & PKVM_GUEST_MMIO_ALLOW_FLAG_DIRECT_BAR))
			continue;

		if (gpa >= range->guest_gpa && access_end <= range_end)
			return true;
	}

	return false;
}

static bool pkvm_direct_mmio_write(int size, unsigned long vaddr,
				   unsigned long val)
{
	switch (size) {
	case 1:
		raw_writeb(val, (void __iomem *)vaddr);
		return true;
	case 2:
		raw_writew(val, (void __iomem *)vaddr);
		return true;
	case 4:
		raw_writel(val, (void __iomem *)vaddr);
		return true;
#ifdef CONFIG_X86_64
	case 8:
		raw_writeq(val, (void __iomem *)vaddr);
		return true;
#endif
	default:
		return false;
	}
}

static bool pkvm_direct_mmio_read(int size, unsigned long vaddr,
				  unsigned long *val)
{
	switch (size) {
	case 1:
		*val = raw_readb((void __iomem *)vaddr);
		return true;
	case 2:
		*val = raw_readw((void __iomem *)vaddr);
		return true;
	case 4:
		*val = raw_readl((void __iomem *)vaddr);
		return true;
#ifdef CONFIG_X86_64
	case 8:
		*val = raw_readq((void __iomem *)vaddr);
		return true;
#endif
	default:
		return false;
	}
}

static void pkvm_init_mmio_allowlist(void)
{
	long ret;

	memset(&pkvm_mmio_info, 0, sizeof(pkvm_mmio_info));
	memset(pkvm_mmio_allow_ranges, 0, sizeof(pkvm_mmio_allow_ranges));
	pkvm_mmio_allow_nr_ranges = 0;

	ret = kvm_hypercall2(PKVM_GHC_PTDEV_MMIO_INFO, __pa(&pkvm_mmio_info),
			     sizeof(pkvm_mmio_info));
	if (ret)
		return;

	if (pkvm_mmio_info.nr_ranges > ARRAY_SIZE(pkvm_mmio_allow_ranges)) {
		memset(&pkvm_mmio_info, 0, sizeof(pkvm_mmio_info));
		return;
	}

	pkvm_mmio_allow_nr_ranges = pkvm_mmio_info.nr_ranges;
	if (!pkvm_mmio_allow_nr_ranges)
		return;

	ret = kvm_hypercall3(PKVM_GHC_PTDEV_MMIO_READ,
			     __pa(pkvm_mmio_allow_ranges),
			     pkvm_mmio_allow_nr_ranges, 0);
	if (ret) {
		memset(&pkvm_mmio_info, 0, sizeof(pkvm_mmio_info));
		memset(pkvm_mmio_allow_ranges, 0, sizeof(pkvm_mmio_allow_ranges));
		pkvm_mmio_allow_nr_ranges = 0;
	}
}

static int pkvm_virt_mmio(int size, bool write, unsigned long vaddr, unsigned long *val)
{
	unsigned long paddr;
	unsigned int level;
	pte_t *pte;

	pte = lookup_address(vaddr, &level);
	if (WARN_ON_ONCE(!pte || !(pte_flags(*pte) & _PAGE_PRESENT)))
		return -EIO;

	paddr = (pte_pfn(*pte) << PAGE_SHIFT) | (vaddr & ~page_level_mask(level));

	if (pkvm_mmio_allow_hit(paddr, size))
		return write ? pkvm_direct_mmio_write(size, vaddr, *val) :
			       pkvm_direct_mmio_read(size, vaddr, val);

	if (write)
		kvm_hypercall3(PKVM_GHC_IOWRITE, paddr, size, *val);
	else
		*val = kvm_hypercall2(PKVM_GHC_IOREAD, paddr, size);

	return 0;
}

static unsigned char pkvm_mmio_readb(const volatile void __iomem *addr)
{
	unsigned long val;

	if (pkvm_virt_mmio(1, false, (unsigned long)addr, &val))
		return 0xff;
	return val;
}

static unsigned short pkvm_mmio_readw(const volatile void __iomem *addr)
{
	unsigned long val;

	if (pkvm_virt_mmio(2, false, (unsigned long)addr, &val))
		return 0xffff;
	return val;
}

static unsigned int pkvm_mmio_readl(const volatile void __iomem *addr)
{
	unsigned long val;

	if (pkvm_virt_mmio(4, false, (unsigned long)addr, &val))
		return 0xffffffff;
	return val;
}

static u64 pkvm_mmio_readq(const volatile void __iomem *addr)
{
	unsigned long val;

	if (pkvm_virt_mmio(8, false, (unsigned long)addr, &val))
		return 0xffffffffffffffff;
	return val;
}

static void pkvm_mmio_writeb(unsigned char v, volatile void __iomem *addr)
{
	unsigned long val = v;

	pkvm_virt_mmio(1, true, (unsigned long)addr, &val);
}

static void pkvm_mmio_writew(unsigned short v, volatile void __iomem *addr)
{
	unsigned long val = v;

	pkvm_virt_mmio(2, true, (unsigned long)addr, &val);
}

static void pkvm_mmio_writel(unsigned int v, volatile void __iomem *addr)
{
	unsigned long val = v;

	pkvm_virt_mmio(4, true, (unsigned long)addr, &val);
}

static void pkvm_mmio_writeq(u64 v, volatile void __iomem *addr)
{
	unsigned long val = v;

	pkvm_virt_mmio(8, true, (unsigned long)addr, &val);
}

static int pkvm_wakeup_secondary_cpu(u32 apic_id, unsigned long start_ip, unsigned int cpu)
{
	return kvm_hypercall2(PKVM_GHC_START_CPU, apic_id, start_ip);
}

__init void pkvm_guest_init_coco(void)
{
	cc_vendor = CC_VENDOR_PKVM;

	static_branch_enable(&pkvm_guest_detected);

	pkvm_init_mmio_allowlist();

	pv_ops.mmio.raw_readb = pkvm_mmio_readb;
	pv_ops.mmio.raw_readw = pkvm_mmio_readw;
	pv_ops.mmio.raw_readl = pkvm_mmio_readl;
	pv_ops.mmio.raw_readb_relaxed = pkvm_mmio_readb;
	pv_ops.mmio.raw_readw_relaxed = pkvm_mmio_readw;
	pv_ops.mmio.raw_readl_relaxed = pkvm_mmio_readl;
	pv_ops.mmio.raw_writeb = pkvm_mmio_writeb;
	pv_ops.mmio.raw_writew = pkvm_mmio_writew;
	pv_ops.mmio.raw_writel = pkvm_mmio_writel;
	pv_ops.mmio.raw_writeb_relaxed = pkvm_mmio_writeb;
	pv_ops.mmio.raw_writew_relaxed = pkvm_mmio_writew;
	pv_ops.mmio.raw_writel_relaxed = pkvm_mmio_writel;
#ifdef CONFIG_X86_64
	pv_ops.mmio.raw_readq = pkvm_mmio_readq;
	pv_ops.mmio.raw_readq_relaxed = pkvm_mmio_readq;
	pv_ops.mmio.raw_writeq = pkvm_mmio_writeq;
	pv_ops.mmio.raw_writeq_relaxed = pkvm_mmio_writeq;
#endif
	pv_ops.mmio.pci_mmcfg_readb = pkvm_mmio_readb;
	pv_ops.mmio.pci_mmcfg_readw = pkvm_mmio_readw;
	pv_ops.mmio.pci_mmcfg_readl = pkvm_mmio_readl;
	pv_ops.mmio.pci_mmcfg_writeb = pkvm_mmio_writeb;
	pv_ops.mmio.pci_mmcfg_writew = pkvm_mmio_writew;
	pv_ops.mmio.pci_mmcfg_writel = pkvm_mmio_writel;

	static_branch_enable(&pv_mmio);

	apic_update_callback(wakeup_secondary_cpu, pkvm_wakeup_secondary_cpu);
}
