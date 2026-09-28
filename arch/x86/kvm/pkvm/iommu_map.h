/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PKVM_X86_IOMMU_MAP_H
#define __PKVM_X86_IOMMU_MAP_H

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/list.h>

struct pkvm_vm;

#ifdef CONFIG_PKVM_INTEL

#define MAX_HPA_RANGES	256

struct pkvm_hpa_range {
	u64 hpa_start;
	u64 hpa_end;
	struct list_head node;
};

int pkvm_register_hpa_vm(u64 hpa_start, u64 hpa_end, int vm_handle);
int pkvm_lookup_hpa_vm(u64 hpa_start, u64 hpa_end);
void pkvm_destroy_hpa_ranges(struct pkvm_vm *vm);

#else /* !CONFIG_PKVM_INTEL */

static inline int pkvm_register_hpa_vm(u64 hpa_start, u64 hpa_end, int vm_handle)
{
	return -ENODEV;
}
static inline int pkvm_lookup_hpa_vm(u64 hpa_start, u64 hpa_end)
{
	return -ENOENT;
}
static inline void pkvm_destroy_hpa_ranges(struct pkvm_vm *vm) { }

#endif /* CONFIG_PKVM_INTEL */

#endif /* __PKVM_X86_IOMMU_MAP_H */
