// SPDX-License-Identifier: GPL-2.0
#include <linux/acpi.h>
#include <linux/kvm_host.h>
#include <linux/memblock.h>
#include <linux/module.h>
#include <linux/sort.h>
#include <linux/pci.h>
#include <linux/pci_regs.h>
#include <linux/iommu.h>
#include <linux/vfio.h>
#include <asm/e820/api.h>
#include <asm/kvm_pkvm.h>

/* Kernel command-line parameter */
bool __read_mostly enable_pkvm;

/* Flag denoting pKVM successfully initialized */
DEFINE_STATIC_KEY_FALSE(pkvm_enabled_key);

static struct memblock_region *pkvm_memory = pkvm_sym(pkvm_memory);
static unsigned int pkvm_memblock_nr;

phys_addr_t pkvm_mem_base;
phys_addr_t pkvm_mem_size;

bool pvmfw_present;
phys_addr_t pvmfw_base;
phys_addr_t pvmfw_size;

static int cmp_pkvm_memblock(const void *p1, const void *p2)
{
	const struct memblock_region *r1 = p1;
	const struct memblock_region *r2 = p2;

	return r1->base < r2->base ? -1 : (r1->base > r2->base);
}

static void __init sort_memblock_regions(void)
{
	sort(pkvm_memory,
	     pkvm_memblock_nr,
	     sizeof(struct memblock_region),
	     cmp_pkvm_memblock,
	     NULL);
}

static int __init register_memblock_regions(void)
{
	struct memblock_region *reg;

	for_each_mem_region(reg) {
		if (pkvm_memblock_nr >= PKVM_MEMBLOCK_REGIONS)
			return -ENOMEM;

		pkvm_memory[pkvm_memblock_nr] = *reg;
		pkvm_memblock_nr++;
	}
	sort_memblock_regions();
	pkvm_sym(pkvm_memblock_nr) = pkvm_memblock_nr;

	return 0;
}

void __init pkvm_reserve(void)
{
	int ret;

	if (!enable_pkvm)
		return;

	ret = register_memblock_regions();
	if (ret) {
		pkvm_memblock_nr = 0;
		kvm_err("Failed to register pkvm memblocks: %d\n", ret);
		return;
	}

	/*
	 * Try to allocate a PMD-aligned region to reduce TLB pressure once
	 * this is unmapped from the host stage-2, and fallback to PAGE_SIZE.
	 */
	pkvm_mem_size = pkvm_total_reserve_pages() << PAGE_SHIFT;
	pkvm_mem_base = memblock_phys_alloc(ALIGN(pkvm_mem_size, PMD_SIZE),
					   PMD_SIZE);
	if (!pkvm_mem_base)
		pkvm_mem_base = memblock_phys_alloc(pkvm_mem_size, PAGE_SIZE);
	else
		pkvm_mem_size = ALIGN(pkvm_mem_size, PMD_SIZE);

	if (!pkvm_mem_base) {
		kvm_err("Failed to reserve pkvm memory\n");
		return;
	}

	kvm_info("Reserved %lld MiB at 0x%llx for pkvm\n", pkvm_mem_size >> 20,
		 pkvm_mem_base);
}

static phys_addr_t kvm_host_pa(void *addr)
{
	return __pa(addr);
}

static void *kvm_host_va(phys_addr_t phys)
{
	return __va(phys);
}

static void *kvm_alloc_pkvm_page(void *flags)
{
	void *addr = (void *)__get_free_page(GFP_KERNEL_ACCOUNT);

	if (addr && (unsigned long)flags & PKVM_MC_ACCOUNT_PGTABLE_PAGES)
		kvm_account_pgtable_pages(addr, 1);

	return addr;
}

static void kvm_free_pkvm_page_range(struct pkvm_page_range range, void *flags)
{
	void *vaddr = __va(range.addr);
	u64 nr_pages = range.nr_pages;

	if (WARN_ON_ONCE(!nr_pages))
		return;

	if ((unsigned long)flags & PKVM_MC_ACCOUNT_PGTABLE_PAGES)
		kvm_account_pgtable_pages(vaddr, -nr_pages);

	if (nr_pages > 1)
		free_pages_exact(vaddr, nr_pages << PAGE_SHIFT);
	else
		free_page((unsigned long)vaddr);
}

int kvm_topup_pkvm_memcache(struct pkvm_memcache *mc, unsigned long min_pages)
{
	return topup_pkvm_memcache(mc, min_pages, kvm_alloc_pkvm_page,
				   kvm_host_pa, (void *)mc->flags);
}

void kvm_free_pkvm_memcache(struct pkvm_memcache *mc)
{
	free_pkvm_memcache(mc, kvm_free_pkvm_page_range, kvm_host_va,
			   (void *)mc->flags);
}

static int pkvm_vm_ioctl_set_fw_gpa(struct kvm *kvm, u64 gpa)
{
	struct kvm_pkvm_vm *pkvm = &kvm->arch.pkvm;
	int ret = 0;

	if (!pvmfw_present)
		return -EINVAL;

	mutex_lock(&pkvm->finalized_lock);
	if (pkvm->finalized) {
		ret = -EBUSY;
		goto out;
	}
	pkvm->pvmfw_load_addr = gpa;
out:
	mutex_unlock(&pkvm->finalized_lock);
	return ret;
}

#ifdef CONFIG_PKVM_INTEL
static bool pkvm_ptdev_mmio_ranges_overlap(
	const struct kvm_protected_vm_ptdev_mmio_range *left,
	const struct kvm_protected_vm_ptdev_mmio_range *right)
{
	return left->guest_gpa < right->guest_gpa + right->size &&
	       right->guest_gpa < left->guest_gpa + left->size;
}

static int pkvm_validate_ptdev_mmio_range(
	const struct kvm_protected_vm_ptdev_mmio_range *range,
	const struct kvm_protected_vm_ptdev_mmio_range *ranges,
	u16 nr_prev)
{
	u16 i;

	if (!range->size || !PAGE_ALIGNED(range->guest_gpa) ||
	    !PAGE_ALIGNED(range->size) || !PAGE_ALIGNED(range->bar_offset))
		return -EINVAL;

	if (range->guest_gpa > U64_MAX - range->size ||
	    range->bar_offset > U64_MAX - range->size)
		return -EINVAL;

	if (range->bar_index >= PCI_STD_NUM_BARS)
		return -EINVAL;

	if (range->kind != KVM_PROTECTED_VM_PTDEV_MMIO_KIND_DIRECT_BAR)
		return -EINVAL;

	if (range->__reserved16 || range->__reserved32)
		return -EINVAL;

	for (i = 0; i < nr_prev; i++) {
		if (pkvm_ptdev_mmio_ranges_overlap(range, &ranges[i]))
			return -EINVAL;
	}

	return 0;
}

static bool pkvm_ptdev_mmio_metadata_equal(
	const struct kvm_ptdev_mmio_metadata *left,
	const struct kvm_ptdev_mmio_metadata *right)
{
	if (left->segment != right->segment || left->bdf != right->bdf ||
	    left->nr_ranges != right->nr_ranges ||
	    left->generation != right->generation || left->flags != right->flags)
		return false;

	return !memcmp(left->ranges, right->ranges,
		       left->nr_ranges * sizeof(left->ranges[0]));
}

static int pkvm_copy_ptdev_mmio_metadata_from_user(
	struct kvm_ptdev_mmio_metadata *kmeta,
	struct kvm_protected_vm_ptdev_mmio_metadata __user *umeta)
{
	struct kvm_protected_vm_ptdev_mmio_metadata meta;
	u16 i;

	if (!umeta)
		return -EINVAL;

	memset(kmeta, 0, sizeof(*kmeta));

	if (copy_from_user(&meta, umeta, sizeof(meta)))
		return -EFAULT;

	if (!meta.nr_ranges ||
	    meta.nr_ranges > KVM_PROTECTED_VM_PTDEV_MMIO_MAX_RANGES)
		return -EINVAL;

	if (!meta.ranges || meta.flags)
		return -EINVAL;

	if (meta.segment)
		return -EINVAL;

	if (meta.generation > 1)
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(meta.__reserved); i++) {
		if (meta.__reserved[i])
			return -EINVAL;
	}

	kmeta->segment = meta.segment;
	kmeta->bdf = meta.bdf;
	kmeta->nr_ranges = meta.nr_ranges;
	kmeta->generation = 1;
	kmeta->flags = meta.flags;

	if (copy_from_user(kmeta->ranges, u64_to_user_ptr(meta.ranges),
			   meta.nr_ranges * sizeof(kmeta->ranges[0])))
		return -EFAULT;

	for (i = 0; i < kmeta->nr_ranges; i++) {
		int ret = pkvm_validate_ptdev_mmio_range(&kmeta->ranges[i],
							 kmeta->ranges, i);
		if (ret)
			return ret;
	}

	return 0;
}

static int pkvm_split_msix_excluded_ranges(struct kvm_ptdev_mmio_metadata *kmeta)
{
	struct pci_dev *pdev;
	u16 msix_bar = 0xFF, pba_bar = 0xFF;
	u32 msix_offset = 0, pba_offset = 0, msix_size = 0, pba_size = 0;
	u32 table, pba;
	u8 msix_pos;
	u16 ctrl;
	u16 i, j;

	pdev = pci_get_domain_bus_and_slot(kmeta->segment,
					   PCI_BUS_NUM(kmeta->bdf),
					   kmeta->bdf & 0xff);
	if (!pdev)
		return 0;

	msix_pos = pdev->msix_cap;
	if (!msix_pos)
		goto out_put;

	pci_read_config_word(pdev, msix_pos + PCI_MSIX_FLAGS, &ctrl);
	pci_read_config_dword(pdev, msix_pos + PCI_MSIX_TABLE, &table);
	pci_read_config_dword(pdev, msix_pos + PCI_MSIX_PBA, &pba);

	msix_bar = table & PCI_MSIX_TABLE_BIR;
	msix_offset = table & PCI_MSIX_TABLE_OFFSET;
	msix_size = ((ctrl & PCI_MSIX_FLAGS_QSIZE) + 1) * 16;

	pba_bar = pba & PCI_MSIX_TABLE_BIR;
	pba_offset = pba & PCI_MSIX_TABLE_OFFSET;
	pba_size = 8;

	for (i = 0; i < kmeta->nr_ranges; i++) {
		struct kvm_protected_vm_ptdev_mmio_range *range = &kmeta->ranges[i];
		u64 range_start, range_end;
		u64 excl_start, excl_end;
		bool need_split = false;

		if (range->bar_index != msix_bar && range->bar_index != pba_bar)
			continue;

		range_start = range->bar_offset;
		range_end = range->bar_offset + range->size;

		if (range->bar_index == msix_bar) {
			excl_start = msix_offset;
			excl_end = msix_offset + msix_size;
			if (excl_start < range_end && excl_end > range_start)
				need_split = true;
		}

		if (range->bar_index == pba_bar && !need_split) {
			excl_start = pba_offset;
			excl_end = pba_offset + pba_size;
			if (excl_start < range_end && excl_end > range_start)
				need_split = true;
		}

		if (!need_split)
			continue;

		if (kmeta->nr_ranges + 1 > KVM_PROTECTED_VM_PTDEV_MMIO_MAX_RANGES) {
			pci_dev_put(pdev);
			return -ENOSPC;
		}

		if (excl_start > range_start) {
			u64 orig_end = range_end;

			range->size = excl_start - range_start;

			for (j = kmeta->nr_ranges; j > i + 1; j--)
				kmeta->ranges[j] = kmeta->ranges[j - 1];

			kmeta->ranges[i + 1].bar_index = range->bar_index;
			kmeta->ranges[i + 1].bar_offset = excl_end;
			kmeta->ranges[i + 1].size = orig_end - excl_end;
			kmeta->ranges[i + 1].guest_gpa =
				range->guest_gpa + (excl_end - range_start);
			kmeta->ranges[i + 1].kind =
				KVM_PROTECTED_VM_PTDEV_MMIO_KIND_DIRECT_BAR;
			kmeta->nr_ranges++;
			i++;
		} else {
			range->bar_offset = excl_end;
			range->size = range_end - excl_end;
			range->guest_gpa += (excl_end - range_start);
		}
	}

out_put:
	pci_dev_put(pdev);
	return 0;
}

static int pkvm_sync_ptdev_mmio_metadata(struct kvm *kvm)
{
	return pkvm_hypercall(sync_ptdev_mmio_metadata, kvm->arch.pkvm.handle);
}

static int pkvm_vm_ioctl_set_ptdev_mmio_metadata(
	struct kvm *kvm,
	struct kvm_protected_vm_ptdev_mmio_metadata __user *umeta)
{
	struct kvm_pkvm_vm *pkvm = &kvm->arch.pkvm;
	struct kvm_ptdev_mmio_metadata kmeta;
	int ret;

	ret = pkvm_copy_ptdev_mmio_metadata_from_user(&kmeta, umeta);
	if (ret)
		return ret;

	ret = pkvm_split_msix_excluded_ranges(&kmeta);
	if (ret)
		return ret;

	mutex_lock(&pkvm->finalized_lock);
	if (pkvm->finalized) {
		ret = -EBUSY;
		goto out;
	}

	if (pkvm->ptdev_mmio_metadata_valid) {
		ret = pkvm_ptdev_mmio_metadata_equal(&pkvm->ptdev_mmio_metadata,
						     &kmeta) ?
		      0 : -EBUSY;
		goto out;
	}

	pkvm->ptdev_mmio_metadata = kmeta;
	pkvm->ptdev_mmio_metadata_valid = true;

	ret = pkvm_sync_ptdev_mmio_metadata(kvm);
	if (ret) {
		memset(&pkvm->ptdev_mmio_metadata, 0,
		       sizeof(pkvm->ptdev_mmio_metadata));
		pkvm->ptdev_mmio_metadata_valid = false;
	}
out:
	mutex_unlock(&pkvm->finalized_lock);
	return ret;
}

static int add_device_to_pkvm(struct device *dev, void *data)
{
	struct kvm *kvm = data;
	struct pci_dev *pdev;
	u16 devid;

	if (!dev_is_pci(dev))
		return 0;

	pdev = to_pci_dev(dev);
	devid = PCI_DEVID(pdev->bus->number, pdev->devfn);

	return pkvm_hypercall(add_ptdev, kvm->arch.pkvm.handle, devid);
}

static int pkvm_apply_vfio_file(struct file *file, void *data,
				int (*fn)(struct device *dev, void *data))
{
	int (*vfio_fn)(struct file *file, void *data,
		       int (*fn)(struct device *dev, void *data));
	int ret;

	vfio_fn = symbol_get(vfio_file_apply_to_all);
	if (!vfio_fn)
		return -EINVAL;

	ret = vfio_fn(file, data, fn);
	symbol_put(vfio_file_apply_to_all);
	return ret;
}

int kvm_arch_add_device_to_pkvm(struct kvm *kvm, struct file *file)
{
	int ret = 0;

	if (!pkvm_is_protected_vm(kvm))
		return 0;

	kvm_get_kvm(kvm);
	ret = pkvm_apply_vfio_file(file, kvm, add_device_to_pkvm);
	kvm_put_kvm(kvm);

	return ret;
}

static int remove_device_from_pkvm(struct device *dev, void *data)
{
	struct kvm *kvm = data;
	struct pci_dev *pdev;
	u16 devid;

	if (!dev_is_pci(dev))
		return 0;

	pdev = to_pci_dev(dev);
	devid = PCI_DEVID(pdev->bus->number, pdev->devfn);

	return pkvm_hypercall(remove_ptdev, kvm->arch.pkvm.handle, devid);
}

int kvm_arch_remove_device_from_pkvm(struct kvm *kvm, struct file *file)
{
	int ret = 0;

	if (!pkvm_is_protected_vm(kvm))
		return 0;

	kvm_get_kvm(kvm);
	ret = pkvm_apply_vfio_file(file, kvm, remove_device_from_pkvm);
	kvm_put_kvm(kvm);

	return ret;
}
#endif

static int pkvm_vm_ioctl_info(struct kvm *kvm,
			      struct kvm_protected_vm_info __user *info)
{
	struct kvm_protected_vm_info kinfo = {
		.firmware_size = pvmfw_present ? pvmfw_size : 0,
	};

	return copy_to_user(info, &kinfo, sizeof(kinfo)) ? -EFAULT : 0;
}

int pkvm_vm_ioctl_enable_cap(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	if (!pkvm_is_protected_vm(kvm))
		return -EINVAL;

	if (cap->args[1] || cap->args[2] || cap->args[3])
		return -EINVAL;

	switch (cap->flags) {
	case KVM_CAP_X86_PROTECTED_VM_FLAGS_SET_FW_GPA:
		return pkvm_vm_ioctl_set_fw_gpa(kvm, cap->args[0]);
	case KVM_CAP_X86_PROTECTED_VM_FLAGS_INFO:
		return pkvm_vm_ioctl_info(kvm, (void __force __user *)cap->args[0]);
#ifdef CONFIG_PKVM_INTEL
	case KVM_CAP_X86_PROTECTED_VM_FLAGS_SET_PTDEV_MMIO_METADATA:
		return pkvm_vm_ioctl_set_ptdev_mmio_metadata(kvm,
				(void __force __user *)cap->args[0]);
#endif
	default:
		return -EINVAL;
	}
}

struct pkvm_ramoops_console_info {
	phys_addr_t start;
	size_t size;
};

/*
 * Console offset needs to be calculated manually since ACPI only provides the
 * overall region boundaries. Offset of the Console is effectively the size of
 * Dmesg area.
 *
 * Below definitions based on drivers/platform/chrome/chromeos_pstore.c:
 */
#define GOOG9999_RAMOOPS_PMSG_SIZE    0x20000
#define GOOG9999_RAMOOPS_FTRACE_SIZE  0x20000
#define GOOG9999_RAMOOPS_CONSOLE_SIZE 0x20000

#define GOOG9999_RAMOOPS_NON_DMESG_SIZE \
	(GOOG9999_RAMOOPS_PMSG_SIZE + \
	 GOOG9999_RAMOOPS_FTRACE_SIZE + \
	 GOOG9999_RAMOOPS_CONSOLE_SIZE)

/* The combined size of the fixed partitions at the end of the region */
#define GOOG9999_RAMOOPS_DMESG_SIZE(total_size) \
	((total_size) - GOOG9999_RAMOOPS_NON_DMESG_SIZE)

static void update_cros_ramoops_console_info(struct pkvm_ramoops_console_info *info,
					     struct resource_entry *rentry)
{
	size_t console_offset;
	size_t ramoops_size = resource_size(rentry->res);

	/*
	 * Note: The ChromeOS ramoops layout (for GOOG9999) partitions the
	 * memory region as:
	 * [Dmesg Area] [Console (128KB)] [Pmsg (128KB)] [Ftrace (128KB)]
	 *
	 * Since ramoops must recover logs across hardware resets and different
	 * kernel versions, this layout should be stable and has remained
	 * invariant for over a decade (chromeos_pstore.c's
	 * chromeos_ramoops_data hasn't changed for a decade).
	 *
	 * The console buffer is located 3 slots (384KB) before the end of the
	 * total region.
	 */
	if (ramoops_size >= GOOG9999_RAMOOPS_NON_DMESG_SIZE) {
		console_offset = GOOG9999_RAMOOPS_DMESG_SIZE(ramoops_size);
		info->start = rentry->res->start + console_offset;
		info->size = GOOG9999_RAMOOPS_CONSOLE_SIZE;
	}
}

static int find_cros_ramoops(struct pkvm_ramoops_console_info *info)
{
	struct acpi_device *adev;
	LIST_HEAD(resource_list);
	struct resource_entry *rentry;
	int ret = -ENODEV;

	adev = acpi_dev_get_first_match_dev("GOOG9999", NULL, -1);
	if (!adev)
		return ret;

	if (acpi_dev_get_resources(adev, &resource_list, NULL, NULL) < 0)
		goto out;

	list_for_each_entry(rentry, &resource_list, node) {
		if (resource_type(rentry->res) == IORESOURCE_MEM) {
			update_cros_ramoops_console_info(info, rentry);
			ret = 0;
			break;
		}
	}
	acpi_dev_free_resource_list(&resource_list);

out:
	acpi_dev_put(adev);

	return ret;
}

static void find_ramoops(struct pkvm_ramoops_console_info *info)
{
	/*
	 * Try chromeos pstore ramoops first.
	 *
	 * TODO: currently supporting only ACPI GOOG9999 chromeos_pstore but it can
	 * be extended to other pstores like ramoops cmdline options.
	 */
	if (!find_cros_ramoops(info))
		return;
}

void __init pkvm_ramoops_init(void)
{
	struct pkvm_ramoops_console_info r_info = {};

	find_ramoops(&r_info);
	if (r_info.start && r_info.size) {
		phys_addr_t end = r_info.start + r_info.size - 1;
		phys_addr_t pvmfw_end = pvmfw_base + pvmfw_size - 1;

		if (pvmfw_present && (r_info.start <= pvmfw_end) && (pvmfw_base <= end)) {
			pr_err("ramoops [0x%llx-0x%llx] overlaps with pvmfw region\n",
			       r_info.start, end);
			return;
		}

		if (!e820__mapped_all(r_info.start, end, E820_TYPE_RESERVED)) {
			pr_err("ramoops [0x%llx-0x%llx] is not reserved in e820\n",
			       r_info.start, end);
			return;
		}

		if (!PAGE_ALIGNED(r_info.start) || !PAGE_ALIGNED(r_info.size)) {
			pr_err("ramoops [0x%llx-0x%llx] is not page-aligned\n",
			       r_info.start, end);
			return;
		}

		pkvm_sym(pkvm_ramoops_console_pa) = r_info.start;
		pkvm_sym(pkvm_ramoops_console_size) = r_info.size;
	}
}
