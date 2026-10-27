/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PKVM_X86_IOMMU_MAP_H
#define __PKVM_X86_IOMMU_MAP_H

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/err.h>

struct pkvm_vm;

#ifdef CONFIG_PKVM_INTEL

int pkvm_register_hpa_vm(u64 hpa_start, u64 hpa_end, int vm_handle);
/* A nonnegative handle owns a reference: caller must pkvm_put_vm_handle(). */
int pkvm_lookup_hpa_vm(u64 hpa_start, u64 hpa_end);
/* host_mmu_lock must be held; called before returning guest pages to host. */
void pkvm_clear_hpa_backing(u64 start, u64 size, int vm_handle);
void pkvm_destroy_hpa_backing(struct pkvm_vm *vm);

#else /* !CONFIG_PKVM_INTEL */

static inline int pkvm_register_hpa_vm(u64 hpa_start, u64 hpa_end, int vm_handle)
{
	return -ENODEV;
}
static inline int pkvm_lookup_hpa_vm(u64 start, u64 end)
{
	return -ENOENT;
}
static inline void pkvm_clear_hpa_backing(u64 start, u64 size, int handle) { }
static inline void pkvm_destroy_hpa_backing(struct pkvm_vm *vm) { }

#endif /* CONFIG_PKVM_INTEL */

#endif /* __PKVM_X86_IOMMU_MAP_H */
