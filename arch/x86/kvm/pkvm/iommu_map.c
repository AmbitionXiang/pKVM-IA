// SPDX-License-Identifier: GPL-2.0

#include <asm/pkvm_spinlock.h>
#include "iommu_map.h"
#include "memory.h"
#include "mmu.h"
#include "pkvm.h"

#ifdef CONFIG_PKVM_INTEL

/* Also serializes whole-range validation against registration/teardown. */
static DEFINE_PKVM_SPINLOCK(hpa_backing_lock);

static bool valid_hpa_range(u64 start, u64 end)
{
	return start < end && IS_ALIGNED(start, PAGE_SIZE) &&
		IS_ALIGNED(end, PAGE_SIZE);
}

/* Unlike is_memory_range(), allow coverage by adjacent RAM regions. */
static bool backing_is_ram(u64 start, u64 end)
{
	unsigned int i;

	for (i = 0; i < pkvm_memblock_nr && start < end; i++) {
		u64 base = pkvm_memory[i].base;
		u64 limit = base + pkvm_memory[i].size;

		if (start >= limit)
			continue;
		if (start < base)
			return false;
		start = min_t(u64, end, limit);
	}
	return start == end;
}

/* Caller holds host_mmu_lock and hpa_backing_lock. */
static bool reusable_backing(struct pkvm_page *page)
{
	struct pkvm_vm *old_vm;

	old_vm = pkvm_get_vm(page->backing_vm_id - 1);
	if (old_vm) {
		pkvm_put_vm(old_vm);
		return false;
	}

	/* A detached VM is not proof that its pages or DMA have been reclaimed. */
	return page->owner == PKVM_ID_HOST &&
		page->host_state == PKVM_PAGE_OWNED && !page->refcount &&
		!page->host_share_hyp_count && !page->host_share_guest_count;
}

int pkvm_register_hpa_vm(u64 hpa_start, u64 hpa_end, int vm_handle)
{
	struct pkvm_vm *vm;
	u8 id;
	int ret = 0;

	if (!valid_hpa_range(hpa_start, hpa_end) ||
	    !backing_is_ram(hpa_start, hpa_end))
		return -EINVAL;

	vm = pkvm_get_vm(vm_handle);
	if (!vm)
		return -ENOENT;
	id = vm_handle + 1;

	/* Serialize stale-ID reuse with ownership transitions and DMA pinning. */
	pkvm_host_mmu_lock();
	pkvm_spin_lock(&hpa_backing_lock);
	/* Validate first: a conflict must not leave a partially updated range. */
	for_each_pkvm_page(page, hpa_start, hpa_end - hpa_start) {
		if (page->backing_vm_id && page->backing_vm_id != id &&
		    !reusable_backing(page)) {
			ret = -EPERM;
			goto unlock;
		}
	}
	for_each_pkvm_page(page, hpa_start, hpa_end - hpa_start)
		page->backing_vm_id = id;
unlock:
	pkvm_spin_unlock(&hpa_backing_lock);
	pkvm_host_mmu_unlock();
	pkvm_put_vm(vm);
	return ret;
}

int pkvm_lookup_hpa_vm(u64 hpa_start, u64 hpa_end)
{
	struct pkvm_vm *vm;
	u8 id;
	int ret;

	if (!valid_hpa_range(hpa_start, hpa_end))
		return -EINVAL;
	/* MMIO has no pkvm_page; retain the existing unregistered classification. */
	if (!backing_is_ram(hpa_start, hpa_end))
		return is_mmio_range(hpa_start, hpa_end - hpa_start) ?
			-ENOENT : -EINVAL;

	pkvm_spin_lock(&hpa_backing_lock);
	id = pkvm_phys_to_page(hpa_start)->backing_vm_id;
	ret = id ? id - 1 : -ENOENT;
	for_each_pkvm_page(page, hpa_start, hpa_end - hpa_start) {
		if (page->backing_vm_id != id) {
			ret = -EXDEV;
			break;
		}
	}
	/* Take the reference before the ID can change or the handle be recycled. */
	if (ret >= 0) {
		vm = pkvm_get_vm(ret);
		if (!vm)
			ret = -ESHUTDOWN;
	}
	pkvm_spin_unlock(&hpa_backing_lock);
	/* The caller owns the reference represented by a nonnegative handle. */
	return ret;
}

/* Caller holds host_mmu_lock, before making reclaimed pages host-accessible. */
void pkvm_clear_hpa_backing(u64 start, u64 size, int vm_handle)
{
	u8 id = vm_handle + 1;

	pkvm_spin_lock(&hpa_backing_lock);
	for_each_pkvm_page(page, start, size) {
		if (page->backing_vm_id == id)
			page->backing_vm_id = 0;
	}
	pkvm_spin_unlock(&hpa_backing_lock);
}

void pkvm_destroy_hpa_backing(struct pkvm_vm *vm)
{
	u8 id = vm->kvm.arch.pkvm.handle + 1;
	unsigned int i;

	/* The handle stays reserved throughout this scan, including between batches. */
	for (i = 0; i < pkvm_memblock_nr; i++) {
		u64 start = pkvm_memory[i].base;
		u64 end = start + pkvm_memory[i].size;

		while (start < end) {
			u64 size = min_t(u64, end - start, PAGE_SIZE * 4096ULL);

			pkvm_spin_lock(&hpa_backing_lock);
			for_each_pkvm_page(page, start, size) {
				if (page->backing_vm_id == id)
					page->backing_vm_id = 0;
			}
			pkvm_spin_unlock(&hpa_backing_lock);
			start += size;
		}
	}
}

#endif /* CONFIG_PKVM_INTEL */
