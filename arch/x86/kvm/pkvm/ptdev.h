/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2022 Intel Corporation. */

#ifndef _PKVM_PTDEV_H_
#define _PKVM_PTDEV_H_

#include <linux/pci_regs.h>

#include "pkvm.h"
#include "pgtable.h"

struct kvm;

#define PKVM_PTDEV_VM_UNBOUND (-1)

enum pkvm_ptdev_owner {
	PKVM_PTDEV_OWNER_HOST,
	PKVM_PTDEV_OWNER_HYP,
};

enum pkvm_ptdev_assignment_state {
	PKVM_PTDEV_DETACHED,
	PKVM_PTDEV_ATTACHING,
	PKVM_PTDEV_HOST_REVOKED,
	PKVM_PTDEV_GUEST_ASSIGNED,
	PKVM_PTDEV_RESTORING,
};

enum pkvm_ptdev_bar_progress {
	PKVM_PTDEV_BAR_HOST_VISIBLE,
	PKVM_PTDEV_BAR_REVOKED,
	PKVM_PTDEV_BAR_CONTRACT_PUBLISHED,
	PKVM_PTDEV_BAR_RESTORING,
};

struct pkvm_ptdev_bar_resource {
	u8 bar_index;
	u64 hpa;
	u64 size;
	enum pkvm_ptdev_bar_progress progress;
};

struct pkvm_ptdev_mmio_range_state {
	u8 bar_index;
	u64 hpa;
	u64 size;
	enum pkvm_ptdev_bar_progress progress;
};

struct pkvm_ptdev {
	atomic_t refcount;
	struct hlist_node hnode;
	u16 bdf;
	/* Guest identity is protected by the owning VM's lock while linked. */
	u16 guest_segment;
	u16 guest_bdf;
	bool guest_pci_id_valid;
	unsigned long index;

	pkvm_spinlock_t lock;

	int vm_handle;
	bool guest_contract_published;
	enum pkvm_ptdev_owner owner;
	enum pkvm_ptdev_assignment_state assignment_state;
	unsigned long managed_bar_mask;
	unsigned long touched_bar_mask;
	struct pkvm_ptdev_bar_resource bars[PCI_STD_NUM_BARS];
	u16 touched_mmio_range_count;
	struct pkvm_ptdev_mmio_range_state
		touched_mmio_ranges[KVM_PROTECTED_VM_PTDEV_MMIO_MAX_RANGES];
	bool mmio_metadata_valid;
	struct kvm_ptdev_mmio_metadata mmio_metadata;
	struct list_head vm_node;
};

struct pkvm_ptdev *pkvm_get_ptdev(u16 bdf);
void pkvm_put_ptdev(struct pkvm_ptdev *ptdev);
void pkvm_detach_ptdev(struct pkvm_ptdev *ptdev, struct pkvm_vm *vm);
int pkvm_attach_ptdev(u16 bdf, struct pkvm_vm *vm);
int pkvm_remove_ptdev(u16 bdf, struct pkvm_vm *vm);
int pkvm_register_ptdev_pci_id(struct pkvm_vm *vm, u64 host_id, u64 guest_id);
void pkvm_vm_destroy_ptdevs(struct pkvm_vm *vm);
int pkvm_set_ptdev_mmio_metadata(struct pkvm_vm *vm,
				 const struct kvm_ptdev_mmio_metadata *metadata);
int pkvm_get_ptdev_mmio_info(struct pkvm_vm *vm,
			     struct pkvm_guest_mmio_info *info);
int pkvm_read_ptdev_mmio_allow_ranges(struct pkvm_vm *vm, u16 start,
				      u16 nr_ranges,
				      struct pkvm_guest_mmio_allow_range *ranges);
int pkvm_handle_ptdev_mmio_info(struct kvm_vcpu *vcpu, gpa_t guest_gpa,
				unsigned long size);
int pkvm_handle_ptdev_mmio_read(struct kvm_vcpu *vcpu, gpa_t guest_gpa,
				u16 nr_ranges, u16 start);
int pkvm_handle_ptdev_pci_list(struct kvm_vcpu *vcpu, gpa_t guest_gpa,
			       u64 max_entries);
bool pkvm_host_hpa_hits_boot_ptdev_bar(u64 hpa, u64 size);
bool pkvm_vm_hpa_hits_attached_boot_ptdev_bar(struct kvm *kvm, u64 hpa, u64 size);
bool pkvm_is_boot_ptdev(u16 bdf);

void pkvm_vm_link_ptdev(struct pkvm_vm *vm, struct list_head *node);
void pkvm_vm_unlink_ptdev(struct pkvm_vm *vm, struct list_head *node);

static inline bool match_ptdev(struct pkvm_ptdev *ptdev, u16 bdf)
{
	return ptdev && (ptdev->bdf == bdf);
}

static inline bool ptdev_attached_to_vm(struct pkvm_ptdev *ptdev)
{
	return READ_ONCE(ptdev->vm_handle) >= 0;
}
#endif
