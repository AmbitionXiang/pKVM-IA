/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PKVM_VMX_EPT_H
#define __PKVM_VMX_EPT_H

#include "pgtable.h"

int pkvm_host_ept_init(struct pkvm_pgtable *pgt, void *pool_base,
		       unsigned long pool_pages);
int pkvm_host_ept_finalize(struct pkvm_pgtable *pgt);
void pkvm_handle_host_ept_violation(struct kvm_vcpu *vcpu);
void pkvm_flush_host_ept(void);

u64 pkvm_host_ept_root(void);
int pkvm_host_ept_level(void);
struct pkvm_pgtable *pkvm_host_ept_get(void);

void pkvm_guest_ept_setup(void);

#ifdef CONFIG_PKVM_INTEL
enum pkvm_host_ept_lookup_kind {
	PKVM_HOST_EPT_LOOKUP_PRESENT,
	PKVM_HOST_EPT_LOOKUP_ANNOTATED,
	PKVM_HOST_EPT_LOOKUP_EMPTY,
};

struct pkvm_host_ept_lookup_result {
	enum pkvm_host_ept_lookup_kind kind;
	unsigned long hpa;
	u64 prot;
	u64 annotation;
	u64 raw_pte;
	enum pkvm_owner_id owner_id;
	int level;
};

int pkvm_host_ept_annotate_mmio_owner(unsigned long hpa, unsigned long size,
				      enum pkvm_owner_id owner_id);
int pkvm_host_ept_restore_mmio_idmap(unsigned long hpa, unsigned long size,
				     u64 prot);
int pkvm_host_ept_unmap(unsigned long vaddr, unsigned long phys,
			unsigned long size);
int pkvm_host_ept_lookup_mmio_annotation_locked(unsigned long vaddr,
						struct pkvm_host_ept_lookup_result *res);
#endif

#endif /* __PKVM_VMX_EPT_H */
