// SPDX-License-Identifier: GPL-2.0

#include <asm/pkvm_spinlock.h>
#include <linux/bitmap.h>
#include "iommu_map.h"
#include "pkvm.h"
#include "debug.h"

#ifdef CONFIG_PKVM_INTEL

static struct pkvm_hpa_range hpa_range_pool[MAX_HPA_RANGES];
static DECLARE_BITMAP(hpa_range_bitmap, MAX_HPA_RANGES);
static DEFINE_PKVM_SPINLOCK(hpa_range_lock);

int pkvm_register_hpa_vm(u64 hpa_start, u64 hpa_end, int vm_handle)
{
	struct pkvm_vm *vm;
	struct pkvm_hpa_range *r;
	int i;

	if (hpa_start >= hpa_end)
		return -EINVAL;

	vm = pkvm_get_vm(vm_handle);
	if (!vm)
		return -ENOENT;

	pkvm_spin_lock(&hpa_range_lock);

	list_for_each_entry(r, &vm->hpa_range_head, node) {
		if (r->hpa_start == hpa_start && r->hpa_end == hpa_end) {
			pkvm_spin_unlock(&hpa_range_lock);
			pkvm_put_vm(vm);
			return 0;
		}
	}

	i = find_next_zero_bit(hpa_range_bitmap, MAX_HPA_RANGES, 0);
	if (i >= MAX_HPA_RANGES) {
		pkvm_err("%s: HPA range pool full\n", __func__);
		pkvm_spin_unlock(&hpa_range_lock);
		pkvm_put_vm(vm);
		return -ENOMEM;
	}

	__set_bit(i, hpa_range_bitmap);
	hpa_range_pool[i].hpa_start = hpa_start;
	hpa_range_pool[i].hpa_end = hpa_end;
	list_add(&hpa_range_pool[i].node, &vm->hpa_range_head);

	pkvm_spin_unlock(&hpa_range_lock);
	pkvm_put_vm(vm);
	return 0;
}

struct lookup_hpa_arg {
	u64 hpa_start;
	u64 hpa_end;
	int vm_handle;
};

static int lookup_hpa_in_vm(struct pkvm_vm *vm, void *arg)
{
	struct lookup_hpa_arg *a = arg;
	struct pkvm_hpa_range *r;
	int found = 0;

	pkvm_spin_lock(&hpa_range_lock);
	list_for_each_entry(r, &vm->hpa_range_head, node) {
		if (a->hpa_start >= r->hpa_start && a->hpa_end <= r->hpa_end) {
			a->vm_handle = vm->kvm.arch.pkvm.handle;
			found = 1;
			break;
		}
	}
	pkvm_spin_unlock(&hpa_range_lock);

	return found;
}

int pkvm_lookup_hpa_vm(u64 hpa_start, u64 hpa_end)
{
	struct lookup_hpa_arg arg = { hpa_start, hpa_end, -ENOENT };

	pkvm_walk_each_vm(lookup_hpa_in_vm, &arg);
	return arg.vm_handle;
}

void pkvm_destroy_hpa_ranges(struct pkvm_vm *vm)
{
	struct pkvm_hpa_range *r, *tmp;
	int i;

	pkvm_spin_lock(&hpa_range_lock);
	list_for_each_entry_safe(r, tmp, &vm->hpa_range_head, node) {
		i = r - hpa_range_pool;
		__clear_bit(i, hpa_range_bitmap);
		list_del(&r->node);
	}
	pkvm_spin_unlock(&hpa_range_lock);
}

#endif /* CONFIG_PKVM_INTEL */
