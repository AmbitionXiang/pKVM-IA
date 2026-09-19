// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2022 Intel Corporation. */

#include <linux/hashtable.h>
#include <linux/pci_regs.h>
#include <asm/pkvm_spinlock.h>
#include "pkvm.h"
#include "ptdev.h"
#include "debug.h"
#include "memory.h"
#include "pkvm_iommu.h"
#include "vmx/ept.h"

#define MAX_PTDEV_NUM	PKVM_MAX_BOOT_PTDEV_NUM
static DEFINE_HASHTABLE(ptdev_hasht, 8);
static DECLARE_BITMAP(ptdevs_bitmap, MAX_PTDEV_NUM);
static struct pkvm_ptdev pkvm_ptdev[MAX_PTDEV_NUM];
static pkvm_spinlock_t ptdev_lock = __PKVM_SPINLOCK_UNLOCKED;

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

static struct pkvm_ptdev *__pkvm_alloc_ptdev_locked(u16 bdf)
{
	struct pkvm_ptdev *ptdev = NULL;
	unsigned long index;

	index = find_next_zero_bit(ptdevs_bitmap, MAX_PTDEV_NUM, 0);
	if (index < MAX_PTDEV_NUM) {
		__set_bit(index, ptdevs_bitmap);
		ptdev = &pkvm_ptdev[index];
		ptdev->bdf = bdf;
		ptdev->index = index;
		ptdev->owner = PKVM_PTDEV_OWNER_HOST;
		ptdev->assignment_state = PKVM_PTDEV_DETACHED;
		ptdev->guest_contract_published = false;
		ptdev->managed_bar_mask = 0;
		ptdev->touched_bar_mask = 0;
		ptdev->touched_mmio_range_count = 0;
		ptdev->mmio_metadata_valid = false;
		memset(ptdev->bars, 0, sizeof(ptdev->bars));
		memset(ptdev->touched_mmio_ranges, 0,
		       sizeof(ptdev->touched_mmio_ranges));
		memset(&ptdev->mmio_metadata, 0, sizeof(ptdev->mmio_metadata));
		INIT_LIST_HEAD(&ptdev->vm_node);
		atomic_set(&ptdev->refcount, 1);
		pkvm_spin_lock_init(&ptdev->lock);
		hash_add(ptdev_hasht, &ptdev->hnode, bdf);
	}

	return ptdev;
}

static struct pkvm_ptdev *__pkvm_get_ptdev_locked(u16 bdf)
{
	struct pkvm_ptdev *ptdev = NULL, *tmp;

	hash_for_each_possible(ptdev_hasht, tmp, hnode, bdf) {
		if (match_ptdev(tmp, bdf)) {
			ptdev = atomic_inc_not_zero(&tmp->refcount) ? tmp : NULL;
			if (ptdev)
				break;
		}
	}

	return ptdev;
}

static const struct pkvm_boot_ptdev_manifest_entry *
pkvm_boot_ptdev_manifest_lookup(u16 bdf)
{
	int idx;

	for (idx = 0; idx < pkvm_hyp->boot_ptdev_cnt; idx++)
		if (pkvm_hyp->boot_ptdev_manifest[idx].bdf == bdf)
			return &pkvm_hyp->boot_ptdev_manifest[idx];

	return NULL;
}

static void pkvm_ptdev_clear_touched_mmio_ranges_locked(struct pkvm_ptdev *ptdev)
{
	ptdev->touched_bar_mask = 0;
	ptdev->touched_mmio_range_count = 0;
	memset(ptdev->touched_mmio_ranges, 0,
	       sizeof(ptdev->touched_mmio_ranges));
}

static void pkvm_ptdev_clear_bar_state_locked(struct pkvm_ptdev *ptdev)
{
	memset(ptdev->bars, 0, sizeof(ptdev->bars));
	ptdev->managed_bar_mask = 0;
	pkvm_ptdev_clear_touched_mmio_ranges_locked(ptdev);
}

static int pkvm_prepare_ptdev_bar_resources_locked(struct pkvm_ptdev *ptdev)
{
	const struct pkvm_boot_ptdev_manifest_entry *entry;
	int idx;

	if (ptdev->managed_bar_mask)
		return 0;

	entry = pkvm_boot_ptdev_manifest_lookup(ptdev->bdf);
	if (!entry)
		return -EPERM;

	pkvm_ptdev_clear_bar_state_locked(ptdev);
	for (idx = 0; idx < PCI_STD_NUM_BARS; idx++) {
		const struct pkvm_boot_ptdev_bar_entry *bar = &entry->bars[idx];

		if (!bar->size)
			continue;
		if (!PAGE_ALIGNED(bar->base) || !PAGE_ALIGNED(bar->size))
			return -EINVAL;

		ptdev->bars[idx].bar_index = idx;
		ptdev->bars[idx].hpa = bar->base;
		ptdev->bars[idx].size = bar->size;
		ptdev->bars[idx].progress = PKVM_PTDEV_BAR_HOST_VISIBLE;
		ptdev->managed_bar_mask |= BIT(idx);
	}

	return ptdev->managed_bar_mask ? 0 : -ENODEV;
}

static bool pkvm_ptdev_bar_contains_range_locked(struct pkvm_ptdev *ptdev,
						 u8 bar_index, u64 offset, u64 size)
{
	struct pkvm_ptdev_bar_resource *bar;

	if (bar_index >= PCI_STD_NUM_BARS || !size)
		return false;
	if (!(ptdev->managed_bar_mask & BIT(bar_index)))
		return false;
	bar = &ptdev->bars[bar_index];
	if (offset > U64_MAX - size)
		return false;

	return offset + size <= bar->size;
}

static int pkvm_ptdev_range_hpa_locked(struct pkvm_ptdev *ptdev,
				       const struct kvm_protected_vm_ptdev_mmio_range *range,
				       u64 *hpa)
{
	struct pkvm_ptdev_bar_resource *bar;

	if (!pkvm_ptdev_bar_contains_range_locked(ptdev, range->bar_index,
						  range->bar_offset, range->size))
		return -EPERM;

	bar = &ptdev->bars[range->bar_index];
	if (bar->hpa > U64_MAX - range->bar_offset)
		return -EINVAL;

	*hpa = bar->hpa + range->bar_offset;
	return 0;
}

static bool pkvm_ptdev_hpa_hits_direct_mmio_locked(struct pkvm_ptdev *ptdev,
						   u64 hpa, u64 size)
{
	u64 end;
	u16 idx;

	if (!ptdev->mmio_metadata_valid || !size || hpa > U64_MAX - size)
		return false;

	end = hpa + size;
	for (idx = 0; idx < ptdev->mmio_metadata.nr_ranges; idx++) {
		const struct kvm_protected_vm_ptdev_mmio_range *range =
			&ptdev->mmio_metadata.ranges[idx];
		u64 range_hpa;

		if (range->kind != KVM_PROTECTED_VM_PTDEV_MMIO_KIND_DIRECT_BAR)
			continue;
		if (pkvm_ptdev_range_hpa_locked(ptdev, range, &range_hpa))
			continue;
		if (range_hpa > U64_MAX - range->size)
			continue;
		if (hpa >= range_hpa && end <= range_hpa + range->size)
			return true;
	}

	return false;
}

static bool pkvm_ptdev_allows_guest_bar_mapping_locked(struct pkvm_ptdev *ptdev)
{
	enum pkvm_ptdev_owner owner = READ_ONCE(ptdev->owner);
	enum pkvm_ptdev_assignment_state state =
		READ_ONCE(ptdev->assignment_state);

	return owner == PKVM_PTDEV_OWNER_HYP &&
	       (state == PKVM_PTDEV_HOST_REVOKED ||
		state == PKVM_PTDEV_GUEST_ASSIGNED);
}

static bool pkvm_boot_ptdev_bar_contains(
	const struct pkvm_boot_ptdev_manifest_entry *entry,
	u64 hpa, u64 size)
{
	u64 end;
	int idx;

	if (!entry || !size)
		return false;

	if (hpa > U64_MAX - size)
		return false;

	end = hpa + size;
	for (idx = 0; idx < ARRAY_SIZE(entry->bars); idx++) {
		u64 bar_base = entry->bars[idx].base;
		u64 bar_size = entry->bars[idx].size;

		if (!bar_size)
			continue;
		if (bar_base > U64_MAX - bar_size)
			continue;
		if (hpa >= bar_base && end <= bar_base + bar_size)
			return true;
	}

	return false;
}

bool pkvm_host_hpa_hits_boot_ptdev_bar(u64 hpa, u64 size)
{
	int idx;

	for (idx = 0; idx < pkvm_hyp->boot_ptdev_cnt; idx++) {
		const struct pkvm_boot_ptdev_manifest_entry *entry;

		entry = &pkvm_hyp->boot_ptdev_manifest[idx];
		if (pkvm_boot_ptdev_bar_contains(entry, hpa, size))
			return true;
	}

	return false;
}

bool pkvm_is_boot_ptdev(u16 bdf)
{
	return pkvm_boot_ptdev_manifest_lookup(bdf) != NULL;
}

bool pkvm_vm_hpa_hits_attached_boot_ptdev_bar(struct kvm *kvm, u64 hpa, u64 size)
{
	struct pkvm_vm *vm;
	struct pkvm_ptdev *ptdev;
	bool hit = false;

	if (!kvm || !size)
		return false;

	vm = to_pkvm(kvm);

	pkvm_spin_lock(&vm->lock);
	list_for_each_entry(ptdev, &vm->ptdev_head, vm_node) {
		if (!pkvm_ptdev_allows_guest_bar_mapping_locked(ptdev))
			continue;

		if (pkvm_ptdev_hpa_hits_direct_mmio_locked(ptdev, hpa, size)) {
			hit = true;
			break;
		}
	}
	pkvm_spin_unlock(&vm->lock);

	return hit;
}

static void pkvm_clear_vm_mmio_allowlist(struct pkvm_vm *vm)
{
	pkvm_spin_lock(&vm->lock);
	vm->mmio_allow_nr_ranges = 0;
	vm->mmio_allow_generation = 0;
	vm->mmio_allow_flags = 0;
	memset(vm->mmio_allow_ranges, 0, sizeof(vm->mmio_allow_ranges));
	pkvm_spin_unlock(&vm->lock);
}

static void pkvm_update_vm_mmio_allowlist(
	struct pkvm_vm *vm,
	const struct kvm_ptdev_mmio_metadata *metadata)
{
	u16 nr_ranges = 0;
	u16 i;

	pkvm_spin_lock(&vm->lock);
	memset(vm->mmio_allow_ranges, 0, sizeof(vm->mmio_allow_ranges));

	for (i = 0; i < metadata->nr_ranges; i++) {
		const struct kvm_protected_vm_ptdev_mmio_range *range =
			&metadata->ranges[i];
		struct pkvm_guest_mmio_allow_range *allow;

		if (range->kind != KVM_PROTECTED_VM_PTDEV_MMIO_KIND_DIRECT_BAR)
			continue;

		if (nr_ranges >= ARRAY_SIZE(vm->mmio_allow_ranges))
			break;

		allow = &vm->mmio_allow_ranges[nr_ranges++];
		allow->guest_gpa = range->guest_gpa;
		allow->size = range->size;
		allow->flags = PKVM_GUEST_MMIO_ALLOW_FLAG_DIRECT_BAR;
	}

	vm->mmio_allow_nr_ranges = nr_ranges;
	vm->mmio_allow_generation = metadata->generation;
	vm->mmio_allow_flags = 0;
	pkvm_spin_unlock(&vm->lock);
}

struct pkvm_ptdev *pkvm_get_ptdev(u16 bdf)
{
	struct pkvm_ptdev *ptdev = NULL;

	pkvm_spin_lock(&ptdev_lock);

	ptdev = __pkvm_get_ptdev_locked(bdf);

	pkvm_spin_unlock(&ptdev_lock);
	return ptdev;
}

static int __pkvm_get_or_create_ptdev(u16 bdf,
				      struct pkvm_ptdev **ptdev)
{
	struct pkvm_ptdev *found;
	int ret;

	if (!ptdev)
		return -EINVAL;

	pkvm_spin_lock(&ptdev_lock);

	if (!pkvm_is_boot_ptdev(bdf)) {
		ret = -EPERM;
		goto out_unlock;
	}

	found = __pkvm_get_ptdev_locked(bdf);
	if (found) {
		*ptdev = found;
		ret = 0;
		goto out_unlock;
	}

	found = __pkvm_alloc_ptdev_locked(bdf);
	if (!found) {
		ret = -ENODEV;
		goto out_unlock;
	}

	*ptdev = found;
	ret = 0;

out_unlock:
	pkvm_spin_unlock(&ptdev_lock);
	return ret;
}

void pkvm_put_ptdev(struct pkvm_ptdev *ptdev)
{
	if (!atomic_dec_and_test(&ptdev->refcount))
		return;

	pkvm_spin_lock(&ptdev_lock);

	hlist_del(&ptdev->hnode);

	__clear_bit(ptdev->index, ptdevs_bitmap);

	memset(ptdev, 0, sizeof(struct pkvm_ptdev));

	pkvm_spin_unlock(&ptdev_lock);
}

void pkvm_vm_link_ptdev(struct pkvm_vm *vm, struct list_head *node)
{
	pkvm_spin_lock(&vm->lock);
	list_add_tail(node, &vm->ptdev_head);
	pkvm_spin_unlock(&vm->lock);
}

void pkvm_vm_unlink_ptdev(struct pkvm_vm *vm, struct list_head *node)
{
	pkvm_spin_lock(&vm->lock);
	list_del(node);
	pkvm_spin_unlock(&vm->lock);
}

static int pkvm_restore_ptdev_bars_locked(struct pkvm_vm *vm,
					  struct pkvm_ptdev *ptdev);
static int pkvm_publish_ptdev_mmio_contract_locked(struct pkvm_vm *vm,
						   struct pkvm_ptdev *ptdev);
static void pkvm_withdraw_ptdev_mmio_contract_locked(struct pkvm_vm *vm,
						     struct pkvm_ptdev *ptdev);

void pkvm_detach_ptdev(struct pkvm_ptdev *ptdev, struct pkvm_vm *vm)
{
	int ret;

	/* Reset what the attach API has set */
	pkvm_spin_lock(&ptdev->lock);
	ret = pkvm_restore_ptdev_bars_locked(vm, ptdev);
	if (ret) {
		pkvm_err("pkvm: detach ptdev restore failed bdf=0x%x ret=%d\n",
			 ptdev->bdf, ret);
		pkvm_spin_unlock(&ptdev->lock);
		return;
	}

	ptdev->vm_handle = 0;
	ptdev->mmio_metadata_valid = false;
	ptdev->guest_contract_published = false;
	memset(&ptdev->mmio_metadata, 0, sizeof(ptdev->mmio_metadata));
	pkvm_spin_unlock(&ptdev->lock);

	pkvm_vm_unlink_ptdev(vm, &ptdev->vm_node);

	pkvm_put_ptdev(ptdev);
}

static u64 pkvm_host_ept_mmio_prot(void)
{
	struct pkvm_pgtable *host_ept = pkvm_host_ept_get();

	return host_ept->pgt_ops->pte_mk_pgstate(PKVM_PAGE_OWNED) |
	       host_ept->pgt_ops->calc_pte_perm(true, true, true) |
	       host_ept->pgt_ops->calc_pte_memtype(true);
}

static int pkvm_restore_ptdev_mmio_ranges_locked(struct pkvm_ptdev *ptdev)
{
	u64 prot = pkvm_host_ept_mmio_prot();
	u16 idx;
	int ret;

	for (idx = 0; idx < ptdev->touched_mmio_range_count; idx++)
		ptdev->touched_mmio_ranges[idx].progress =
			PKVM_PTDEV_BAR_RESTORING;

	for (idx = 0; idx < ptdev->touched_mmio_range_count; idx++) {
		struct pkvm_ptdev_mmio_range_state *range =
			&ptdev->touched_mmio_ranges[idx];

		ret = pkvm_host_ept_restore_mmio_idmap(range->hpa, range->size,
						       prot);
		if (ret)
			return ret;
		pkvm_dbg("pkvm: ptdev MMIO range restored bdf=0x%x bar=%u hpa=0x%llx size=0x%llx\n",
			 ptdev->bdf, range->bar_index, range->hpa, range->size);
	}

	for (idx = 0; idx < ptdev->touched_mmio_range_count; idx++) {
		struct pkvm_ptdev_mmio_range_state *range =
			&ptdev->touched_mmio_ranges[idx];

		range->progress = PKVM_PTDEV_BAR_HOST_VISIBLE;
		ptdev->bars[range->bar_index].progress =
			PKVM_PTDEV_BAR_HOST_VISIBLE;
	}
	pkvm_ptdev_clear_touched_mmio_ranges_locked(ptdev);
	return 0;
}

static int pkvm_record_ptdev_mmio_range_locked(struct pkvm_ptdev *ptdev,
					       u8 bar_index, u64 hpa, u64 size)
{
	struct pkvm_ptdev_mmio_range_state *state;

	if (ptdev->touched_mmio_range_count >=
	    ARRAY_SIZE(ptdev->touched_mmio_ranges))
		return -E2BIG;

	state = &ptdev->touched_mmio_ranges[ptdev->touched_mmio_range_count++];
	state->bar_index = bar_index;
	state->hpa = hpa;
	state->size = size;
	state->progress = PKVM_PTDEV_BAR_REVOKED;
	ptdev->touched_bar_mask |= BIT(bar_index);
	ptdev->bars[bar_index].progress = PKVM_PTDEV_BAR_REVOKED;
	return 0;
}

static int pkvm_revoke_ptdev_bars_locked(struct pkvm_ptdev *ptdev)
{
	u16 idx;
	int ret;

	if (ptdev->owner == PKVM_PTDEV_OWNER_HYP)
		return 0;
	if (!ptdev->mmio_metadata_valid)
		return -EAGAIN;

	ret = pkvm_prepare_ptdev_bar_resources_locked(ptdev);
	if (ret)
		return ret;

	ptdev->assignment_state = PKVM_PTDEV_ATTACHING;
	for (idx = 0; idx < ptdev->mmio_metadata.nr_ranges; idx++) {
		const struct kvm_protected_vm_ptdev_mmio_range *range =
			&ptdev->mmio_metadata.ranges[idx];
		u64 hpa;

		if (range->kind != KVM_PROTECTED_VM_PTDEV_MMIO_KIND_DIRECT_BAR) {
			ret = -EINVAL;
			goto err_restore;
		}

		ret = pkvm_ptdev_range_hpa_locked(ptdev, range, &hpa);
		if (ret)
			goto err_restore;
		if (ptdev->touched_mmio_range_count >=
		    ARRAY_SIZE(ptdev->touched_mmio_ranges)) {
			ret = -E2BIG;
			goto err_restore;
		}

		ret = pkvm_host_ept_annotate_mmio_owner(hpa, range->size,
							PKVM_ID_PTDEV_MMIO);
		if (ret)
			goto err_restore;

		ret = pkvm_record_ptdev_mmio_range_locked(ptdev, range->bar_index,
							  hpa, range->size);
		if (ret)
			goto err_restore;

		pkvm_dbg("pkvm: ptdev MMIO range revoked bdf=0x%x bar=%u hpa=0x%llx size=0x%llx guest_gpa=0x%llx offset=0x%llx\n",
			 ptdev->bdf, range->bar_index, hpa, range->size,
			 range->guest_gpa, range->bar_offset);
	}

	ptdev->owner = PKVM_PTDEV_OWNER_HYP;
	ptdev->assignment_state = PKVM_PTDEV_HOST_REVOKED;
	return 0;

err_restore:
	pkvm_restore_ptdev_mmio_ranges_locked(ptdev);
	ptdev->owner = PKVM_PTDEV_OWNER_HOST;
	ptdev->assignment_state = PKVM_PTDEV_DETACHED;
	return ret;
}

static int pkvm_restore_ptdev_bars_locked(struct pkvm_vm *vm,
					  struct pkvm_ptdev *ptdev)
{
	int ret;

	ptdev->assignment_state = PKVM_PTDEV_RESTORING;
	pkvm_withdraw_ptdev_mmio_contract_locked(vm, ptdev);

	ret = pkvm_restore_ptdev_mmio_ranges_locked(ptdev);
	if (ret)
		return ret;

	ptdev->owner = PKVM_PTDEV_OWNER_HOST;
	ptdev->assignment_state = PKVM_PTDEV_DETACHED;
	return 0;
}

int pkvm_attach_ptdev(u16 bdf, struct pkvm_vm *vm)
{
	struct pkvm_ptdev *ptdev;
	int vm_handle;
	int ret;

	ret = __pkvm_get_or_create_ptdev(bdf, &ptdev);
	if (ret == -EPERM)
		pkvm_err("%s: reject bdf 0x%x outside boot manifest\n",
			 __func__, bdf);
	if (ret)
		return ret;

	pkvm_spin_lock(&ptdev->lock);

	vm_handle = vm->kvm.arch.pkvm.handle;
	if (cmpxchg(&ptdev->vm_handle, 0, vm_handle) != 0) {
		pkvm_err("%s: ptdev with bdf 0x%x is already attached\n",
			 __func__, bdf);
		pkvm_spin_unlock(&ptdev->lock);
		pkvm_put_ptdev(ptdev);
		return -ENODEV;
	}

	ptdev->assignment_state = PKVM_PTDEV_ATTACHING;

	pkvm_spin_unlock(&ptdev->lock);

	pkvm_vm_link_ptdev(vm, &ptdev->vm_node);

	pkvm_spin_lock(&ptdev->lock);
	ret = pkvm_publish_ptdev_mmio_contract_locked(vm, ptdev);
	pkvm_spin_unlock(&ptdev->lock);
	if (ret) {
		pkvm_detach_ptdev(ptdev, vm);
		return ret;
	}

	return 0;
}

int pkvm_remove_ptdev(u16 bdf, struct pkvm_vm *vm)
{
	struct pkvm_ptdev *ptdev;
	int vm_handle;

	ptdev = pkvm_get_ptdev(bdf);
	if (!ptdev)
		return -ENODEV;

	vm_handle = vm->kvm.arch.pkvm.handle;

	pkvm_spin_lock(&ptdev->lock);
	if (ptdev->vm_handle != vm_handle) {
		pkvm_spin_unlock(&ptdev->lock);
		pkvm_put_ptdev(ptdev);
		return -ENODEV;
	}
	pkvm_spin_unlock(&ptdev->lock);

	pkvm_detach_ptdev(ptdev, vm);
	return 0;
}

void pkvm_vm_destroy_ptdevs(struct pkvm_vm *vm)
{
	struct pkvm_ptdev *ptdev, *tmp;

	pkvm_spin_lock(&vm->lock);
	list_for_each_entry_safe(ptdev, tmp, &vm->ptdev_head, vm_node) {
		if (!atomic_inc_not_zero(&ptdev->refcount)) {
			pkvm_err("pkvm: destroy_ptdevs: ptdev bdf=0x%x refcount already zero\n",
				 ptdev->bdf);
			continue;
		}
		pkvm_spin_unlock(&vm->lock);

		pkvm_spin_lock(&ptdev->lock);
		if (ptdev->vm_handle != vm->kvm.arch.pkvm.handle) {
			pkvm_spin_unlock(&ptdev->lock);
			pkvm_put_ptdev(ptdev);
			pkvm_spin_lock(&vm->lock);
			continue;
		}
		pkvm_spin_unlock(&ptdev->lock);

		pkvm_detach_ptdev(ptdev, vm);
		pkvm_put_ptdev(ptdev);

		pkvm_spin_lock(&vm->lock);
	}
	pkvm_spin_unlock(&vm->lock);
}

static int pkvm_validate_ptdev_mmio_metadata_locked(
	struct pkvm_ptdev *ptdev,
	const struct kvm_ptdev_mmio_metadata *metadata)
{
	u16 i;
	int ret;

	ret = pkvm_prepare_ptdev_bar_resources_locked(ptdev);
	if (ret)
		return ret;

	for (i = 0; i < metadata->nr_ranges; i++) {
		const struct kvm_protected_vm_ptdev_mmio_range *range =
			&metadata->ranges[i];

		if (range->kind != KVM_PROTECTED_VM_PTDEV_MMIO_KIND_DIRECT_BAR)
			return -EINVAL;
		if (!pkvm_ptdev_bar_contains_range_locked(ptdev,
				range->bar_index, range->bar_offset, range->size))
			return -EPERM;
	}

	return 0;
}

static int pkvm_publish_ptdev_mmio_contract_locked(struct pkvm_vm *vm,
						   struct pkvm_ptdev *ptdev)
{
	u16 idx;
	int ret;

	if (!ptdev->mmio_metadata_valid)
		return 0;
	if (ptdev->guest_contract_published)
		return 0;

	ret = pkvm_revoke_ptdev_bars_locked(ptdev);
	if (ret)
		return ret;

	if (!pkvm_ptdev_allows_guest_bar_mapping_locked(ptdev))
		return -EAGAIN;

	pkvm_update_vm_mmio_allowlist(vm, &ptdev->mmio_metadata);
	for (idx = 0; idx < ptdev->touched_mmio_range_count; idx++) {
		struct pkvm_ptdev_mmio_range_state *range =
			&ptdev->touched_mmio_ranges[idx];

		range->progress = PKVM_PTDEV_BAR_CONTRACT_PUBLISHED;
		ptdev->bars[range->bar_index].progress =
			PKVM_PTDEV_BAR_CONTRACT_PUBLISHED;
	}
	ptdev->guest_contract_published = true;
	ptdev->assignment_state = PKVM_PTDEV_GUEST_ASSIGNED;
	return 0;
}

static void pkvm_withdraw_ptdev_mmio_contract_locked(struct pkvm_vm *vm,
						     struct pkvm_ptdev *ptdev)
{
	if (!ptdev->guest_contract_published)
		return;

	pkvm_clear_vm_mmio_allowlist(vm);
	ptdev->guest_contract_published = false;
}

int pkvm_set_ptdev_mmio_metadata(struct pkvm_vm *vm,
				 const struct kvm_ptdev_mmio_metadata *metadata)
{
	struct pkvm_ptdev *ptdev;
	int vm_handle;
	int ret = 0;

	if (!metadata || !metadata->nr_ranges)
		return -EINVAL;

	ptdev = pkvm_get_ptdev(metadata->bdf);
	if (!ptdev)
		return -ENODEV;

	vm_handle = vm->kvm.arch.pkvm.handle;

	pkvm_spin_lock(&ptdev->lock);
	if (ptdev->vm_handle != vm_handle) {
		ret = -ENODEV;
		goto out;
	}

	if (!ptdev->mmio_metadata_valid) {
		ret = pkvm_validate_ptdev_mmio_metadata_locked(ptdev, metadata);
		if (ret)
			goto out;
		ptdev->mmio_metadata = *metadata;
		ptdev->mmio_metadata_valid = true;
		ret = pkvm_publish_ptdev_mmio_contract_locked(vm, ptdev);
		if (ret == -EAGAIN) {
			ret = 0;
		} else if (ret) {
			ptdev->mmio_metadata_valid = false;
			memset(&ptdev->mmio_metadata, 0,
			       sizeof(ptdev->mmio_metadata));
		}
		goto out;
	}

	ret = pkvm_ptdev_mmio_metadata_equal(&ptdev->mmio_metadata, metadata) ?
	      pkvm_publish_ptdev_mmio_contract_locked(vm, ptdev) : -EBUSY;
	if (ret == -EAGAIN) {
		ret = 0;
	} else if (ret && ret != -EBUSY) {
		ptdev->mmio_metadata_valid = false;
		memset(&ptdev->mmio_metadata, 0, sizeof(ptdev->mmio_metadata));
	}
out:
	pkvm_spin_unlock(&ptdev->lock);
	pkvm_put_ptdev(ptdev);
	return ret;
}

int pkvm_get_ptdev_mmio_info(struct pkvm_vm *vm,
			     struct pkvm_guest_mmio_info *info)
{
	if (!vm || !info)
		return -EINVAL;

	pkvm_spin_lock(&vm->lock);
	info->nr_ranges = vm->mmio_allow_nr_ranges;
	info->generation = vm->mmio_allow_generation;
	info->flags = vm->mmio_allow_flags;
	pkvm_spin_unlock(&vm->lock);
	return 0;
}

int pkvm_read_ptdev_mmio_allow_ranges(struct pkvm_vm *vm, u16 start,
				      u16 nr_ranges,
				      struct pkvm_guest_mmio_allow_range *ranges)
{
	int ret = 0;

	if (!vm || !ranges || !nr_ranges)
		return -EINVAL;

	pkvm_spin_lock(&vm->lock);
	if (start >= vm->mmio_allow_nr_ranges ||
	    nr_ranges > vm->mmio_allow_nr_ranges - start) {
		ret = -EINVAL;
		goto out;
	}

	memcpy(ranges, &vm->mmio_allow_ranges[start],
	       nr_ranges * sizeof(ranges[0]));
out:
	pkvm_spin_unlock(&vm->lock);
	return ret;
}

static int pkvm_write_guest_gpa(struct kvm_vcpu *vcpu, gpa_t gpa,
				void *data, unsigned int bytes)
{
	struct pkvm_vm *pkvm_vm = to_pkvm(vcpu->kvm);
	unsigned int remaining = bytes;
	unsigned long offset = 0;
	int ret = 0;

	pkvm_spin_lock(&pkvm_vm->mmu_lock);
	while (remaining > 0) {
		unsigned long hpa = INVALID_PAGE;
		unsigned int len, page_offset;

		page_offset = (unsigned int)(gpa + offset) & ~PAGE_MASK;
		len = min(remaining, (unsigned int)PAGE_SIZE - page_offset);

		pkvm_pgtable_lookup(&pkvm_vm->mmu, gpa + offset, &hpa, NULL, NULL);
		if (hpa == INVALID_PAGE) {
			ret = -EFAULT;
			break;
		}

		memcpy(pkvm_phys_to_virt(hpa), data + offset, len);

		offset += len;
		remaining -= len;
	}
	pkvm_spin_unlock(&pkvm_vm->mmu_lock);

	return ret;
}

int pkvm_handle_ptdev_mmio_info(struct kvm_vcpu *vcpu, gpa_t guest_gpa,
				unsigned long size)
{
	struct pkvm_vm *vm = to_pkvm(vcpu->kvm);
	struct pkvm_guest_mmio_info info = {};
	int ret;

	if (!guest_gpa || size < sizeof(info))
		return -KVM_EINVAL;

	ret = pkvm_get_ptdev_mmio_info(vm, &info);
	if (ret)
		return ret;

	ret = pkvm_write_guest_gpa(vcpu, guest_gpa, &info, sizeof(info));

	return ret ? -KVM_EFAULT : 0;
}

int pkvm_handle_ptdev_mmio_read(struct kvm_vcpu *vcpu, gpa_t guest_gpa,
				u16 nr_ranges, u16 start)
{
	struct pkvm_vm *vm = to_pkvm(vcpu->kvm);
	struct pkvm_guest_mmio_allow_range
		ranges[PKVM_GUEST_MMIO_ALLOW_MAX_RANGES];
	int ret;

	if (!guest_gpa || !nr_ranges || nr_ranges > ARRAY_SIZE(ranges))
		return -KVM_EINVAL;

	ret = pkvm_read_ptdev_mmio_allow_ranges(vm, start, nr_ranges, ranges);
	if (ret)
		return ret;

	ret = pkvm_write_guest_gpa(vcpu, guest_gpa, ranges,
				   nr_ranges * sizeof(ranges[0]));

	return ret ? -KVM_EFAULT : 0;
}
