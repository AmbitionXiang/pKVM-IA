// SPDX-License-Identifier: GPL-2.0

#include <linux/kvm_para.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <asm/coco.h>
#include <asm/pkvm_guest.h>
#include <asm/pgtable.h>
#include <asm/apic.h>
#include <asm/insn.h>
#include <asm/insn-eval.h>
#include <asm/traps.h>

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

static bool pkvm_mmio_read(int size, unsigned long gpa, unsigned long *val)
{
	*val = kvm_hypercall2(PKVM_GHC_IOREAD, gpa, size);
	return true;
}

static bool pkvm_mmio_write(int size, unsigned long gpa, unsigned long val)
{
	kvm_hypercall3(PKVM_GHC_IOWRITE, gpa, size, val);
	return true;
}

int pkvm_handle_ve(struct pt_regs *regs)
{
	unsigned long *reg, val, vaddr, gpa;
	char buffer[MAX_INSN_SIZE];
	enum insn_mmio_type mmio;
	struct insn insn = {};
	int size, extend_size;
	u8 extend_val = 0;

	if (WARN_ON_ONCE(user_mode(regs)))
		return -EFAULT;

	gpa = kvm_hypercall1(PKVM_GHC_GET_VE_GPA, 0);

	if (copy_from_kernel_nofault(buffer, (void *)regs->ip, MAX_INSN_SIZE))
		return -EFAULT;

	if (insn_decode(&insn, buffer, MAX_INSN_SIZE, INSN_MODE_64))
		return -EINVAL;

	mmio = insn_decode_mmio(&insn, &size);
	if (WARN_ON_ONCE(mmio == INSN_MMIO_DECODE_FAILED))
		return -EINVAL;

	if (mmio != INSN_MMIO_WRITE_IMM && mmio != INSN_MMIO_MOVS) {
		reg = insn_get_modrm_reg_ptr(&insn, regs);
		if (!reg)
			return -EINVAL;
	}

	vaddr = (unsigned long)insn_get_addr_ref(&insn, regs);
	if (!fault_in_kernel_space(vaddr)) {
		WARN_ONCE(1, "Access to userspace address is not supported");
		return -EINVAL;
	}

	if (vaddr / PAGE_SIZE != (vaddr + size - 1) / PAGE_SIZE)
		return -EFAULT;

	switch (mmio) {
	case INSN_MMIO_WRITE:
		memcpy(&val, reg, size);
		if (!pkvm_mmio_write(size, gpa, val))
			return -EIO;
		return insn.length;
	case INSN_MMIO_WRITE_IMM:
		val = insn.immediate.value;
		if (!pkvm_mmio_write(size, gpa, val))
			return -EIO;
		return insn.length;
	case INSN_MMIO_READ:
	case INSN_MMIO_READ_ZERO_EXTEND:
	case INSN_MMIO_READ_SIGN_EXTEND:
		break;
	case INSN_MMIO_MOVS:
	case INSN_MMIO_DECODE_FAILED:
		return -EINVAL;
	default:
		WARN_ONCE(1, "Unknown insn_decode_mmio() decode value?");
		return -EINVAL;
	}

	if (!pkvm_mmio_read(size, gpa, &val))
		return -EIO;

	switch (mmio) {
	case INSN_MMIO_READ:
		extend_size = size == 4 ? sizeof(*reg) : 0;
		break;
	case INSN_MMIO_READ_ZERO_EXTEND:
		extend_size = insn.opnd_bytes;
		break;
	case INSN_MMIO_READ_SIGN_EXTEND:
		extend_size = insn.opnd_bytes;
		if (size == 1 && val & BIT(7))
			extend_val = 0xFF;
		else if (size > 1 && val & BIT(15))
			extend_val = 0xFF;
		break;
	default:
		WARN_ON_ONCE(1);
		return -EINVAL;
	}

	if (extend_size)
		memset(reg, extend_val, extend_size);
	memcpy(reg, &val, size);
	return insn.length;
}
