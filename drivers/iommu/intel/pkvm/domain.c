// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2026 Google. */


#include <linux/hashtable.h>
#include <asm/pkvm_spinlock.h>
#include "pkvm.h"
#include "pkvm/ptdev.h"
#include "pkvm/debug.h"
#include "pkvm/memory.h"
#include "pkvm/vmx/ept.h"
#include "pkvm/iommu_map.h"
#include "../pkvm_iommu.h"
#include "../iommu.h"

/*
 * TODO: Make this a dynamic value.
 */
/* Temporary capacity increase for large-platform boot validation. */
#define MAX_IOMMU_DOMAIN_NUM	512
static DEFINE_HASHTABLE(iommu_domain_hasht, 8);
static DECLARE_BITMAP(iommu_domains_bitmap, MAX_IOMMU_DOMAIN_NUM);
static struct dmar_domain iommu_domains[MAX_IOMMU_DOMAIN_NUM];
static DEFINE_PKVM_SPINLOCK(iommu_domain_lock);
/* Serializes P2P contract collection, mapping and release. */
static DEFINE_PKVM_SPINLOCK(pkvm_p2p_lock);

#ifdef __PKVM_HYP__
static struct pkvm_p2p_contract pkvm_p2p_contracts[MAX_PKVM_VMS];

static bool pkvm_p2p_owner_is_attached(struct pkvm_vm *vm, u16 bdf)
{
	struct pkvm_ptdev *ptdev;

	list_for_each_entry(ptdev, &vm->ptdev_head, vm_node)
		if (ptdev->bdf == bdf && ptdev->vm_handle ==
		    vm->kvm.arch.pkvm.handle)
			return true;

	return false;
}

/* Caller holds vm->lock and domain->cache_lock. */
static int pkvm_p2p_domain_is_used(struct pkvm_vm *vm,
				   struct dmar_domain *domain)
{
	struct cache_tag *tag;
	int used = 0;

	list_for_each_entry(tag, &domain->cache_tags, node) {
		if (tag->type != CACHE_TAG_IOTLB)
			continue;
		if (!pkvm_p2p_owner_is_attached(vm,
					      PCI_DEVID(tag->bus, tag->devfn))) {
			used = -EPERM;
			break;
		}
		used = 1;
	}
	return used;
}

/* Publish membership under the same lock used to validate source bindings. */
static int pkvm_p2p_collect_domain(struct pkvm_p2p_contract *contract,
				   struct dmar_domain *domain)
{
	int ret;

	pkvm_spin_lock(&domain->cache_lock);
	ret = pkvm_p2p_domain_is_used(contract->vm, domain);
	if (ret <= 0 || domain->p2p_contract == contract)
		goto out;
	if (domain->p2p_contract) {
		ret = -EPERM;
		goto out;
	}
	if (contract->domain_count == PKVM_P2P_MAX_DOMAINS) {
		ret = -E2BIG;
		goto out;
	}
	atomic_inc(&domain->refcount);
	contract->domains[contract->domain_count++] = domain;
	domain->p2p_contract = contract;
out:
	pkvm_spin_unlock(&domain->cache_lock);
	return ret;
}

static void pkvm_p2p_release_contract(struct pkvm_p2p_contract *contract)
{
	unsigned int d;

	for (d = 0; d < contract->domain_count; d++) {
		struct dmar_domain *domain = contract->domains[d];

		pkvm_spin_lock(&domain->cache_lock);
		domain->p2p_contract = NULL;
		pkvm_spin_unlock(&domain->cache_lock);
		pkvm_put_iommu_domain(domain);
	}
	memset(contract, 0, sizeof(*contract));
}

static int pkvm_p2p_collect_contract(struct pkvm_vm *vm,
				     struct pkvm_p2p_contract *contract)
{
	struct dmar_domain *domain;
	int i, ret;

	if (vm->mmio_allow_nr_ranges > PKVM_P2P_MAX_RANGES)
		return -E2BIG;

	for (i = 0; i < vm->mmio_allow_nr_ranges; i++) {
		u64 hpa = vm->mmio_allow_hpa[i];
		u64 size = vm->mmio_allow_ranges[i].size;
		u64 gpa = vm->mmio_allow_ranges[i].guest_gpa;
		u16 bdf = vm->mmio_allow_owner_bdf[i];

		if (!size || !PAGE_ALIGNED(gpa) || !PAGE_ALIGNED(hpa) ||
		    !PAGE_ALIGNED(size) || gpa > U64_MAX - size ||
		    hpa > U64_MAX - size ||
		    !pkvm_p2p_owner_is_attached(vm, bdf))
			return -EINVAL;

		contract->ranges[i] = (struct pkvm_p2p_range) {
			.iova = gpa,
			.hpa = hpa,
			.size = size,
			.owner_bdf = bdf,
		};
	}
	contract->range_count = vm->mmio_allow_nr_ranges;

	for (i = 0; i < MAX_IOMMU_DOMAIN_NUM; i++) {
		if (!test_bit(i, iommu_domains_bitmap))
			continue;
		domain = &iommu_domains[i];
		if (domain->vm_handle != vm->kvm.arch.pkvm.handle)
			continue;
		ret = pkvm_p2p_collect_domain(contract, domain);
		if (ret < 0)
			return ret;
	}

	return contract->domain_count ? 0 : -ENODEV;
}

/* Caller holds domain->lock. Only pass ranges prechecked for this transaction. */
static void pkvm_p2p_unmap_bars(struct pkvm_p2p_contract *contract,
				struct dmar_domain *domain, unsigned int ranges)
{
	unsigned int r;

	for (r = 0; r < ranges; r++) {
		struct pkvm_p2p_range *range = &contract->ranges[r];

		domain_unmap(domain, range->iova >> VTD_PAGE_SHIFT,
			     (range->iova + range->size - 1) >> VTD_PAGE_SHIFT,
			     NULL);
	}
}

int pkvm_iommu_map_p2p(int vm_handle)
{
	struct pkvm_vm *vm = pkvm_get_vm(vm_handle);
	struct pkvm_p2p_contract *contract;
	unsigned int d, r;
	int ret;

	if (!vm)
		return -EINVAL;

	/* Match allowlist withdrawal: vm->lock precedes pkvm_p2p_lock. */
	pkvm_spin_lock(&vm->lock);
	pkvm_spin_lock(&pkvm_p2p_lock);
	contract = &pkvm_p2p_contracts[vm_handle];
	if (contract->vm) {
		ret = contract->vm == vm ? 0 : -EPERM;
		goto out_unlock;
	}

	if (!vm->mmio_allow_nr_ranges) {
		ret = -EAGAIN;
		goto out_unlock;
	}
	memset(contract, 0, sizeof(*contract));
	contract->vm = vm;
	pkvm_spin_lock(&iommu_domain_lock);
	ret = pkvm_p2p_collect_contract(vm, contract);
	pkvm_spin_unlock(&iommu_domain_lock);
	if (ret) {
		pkvm_p2p_release_contract(contract);
		goto out_unlock;
	}

	/* Keep each domain locked from precheck through mapping or local rollback. */
	for (d = 0; d < contract->domain_count; d++) {
		struct dmar_domain *domain = contract->domains[d];

		pkvm_spin_lock(&domain->lock);
		for (r = 0; r < contract->range_count; r++) {
			struct pkvm_p2p_range *range = &contract->ranges[r];

			ret = pkvm_domain_range_empty(domain,
					range->iova >> VTD_PAGE_SHIFT,
					range->size >> VTD_PAGE_SHIFT);
			if (ret)
				break;
		}
		if (ret) {
			pkvm_spin_unlock(&domain->lock);
			goto rollback;
		}
		for (r = 0; r < contract->range_count; r++) {
			struct pkvm_p2p_range *range = &contract->ranges[r];

			ret = pkvm_domain_map_peer(domain,
					range->iova >> VTD_PAGE_SHIFT,
					range->hpa >> VTD_PAGE_SHIFT,
					range->size >> VTD_PAGE_SHIFT);
			if (ret) {
				/* Include the range whose map may have partially succeeded. */
				pkvm_p2p_unmap_bars(contract, domain, r + 1);
				break;
			}
		}
		pkvm_spin_unlock(&domain->lock);
		if (ret)
			goto rollback;
	}

	ret = 0;
	vm->p2p_contract = contract;
	goto out_unlock;

rollback:
	/* The current domain was either untouched or rolled back under its lock. */
	while (d) {
		struct dmar_domain *domain = contract->domains[--d];

		pkvm_spin_lock(&domain->lock);
		pkvm_p2p_unmap_bars(contract, domain, contract->range_count);
		pkvm_spin_unlock(&domain->lock);
	}
	pkvm_p2p_release_contract(contract);
out_unlock:
	pkvm_spin_unlock(&pkvm_p2p_lock);
	pkvm_spin_unlock(&vm->lock);
	pkvm_put_vm(vm);
	return ret;
}

void pkvm_iommu_unmap_p2p(struct pkvm_vm *vm)
{
	struct pkvm_p2p_contract *contract;
	unsigned int d;

	pkvm_spin_lock(&pkvm_p2p_lock);
	contract = vm->p2p_contract;
	if (!contract)
		goto out;
	for (d = 0; d < contract->domain_count; d++) {
		struct dmar_domain *domain = contract->domains[d];

		pkvm_spin_lock(&domain->lock);
		pkvm_p2p_unmap_bars(contract, domain, contract->range_count);
		pkvm_spin_unlock(&domain->lock);
	}
	pkvm_p2p_release_contract(contract);
	vm->p2p_contract = NULL;
out:
	pkvm_spin_unlock(&pkvm_p2p_lock);
}

#endif

/*
 * Passthrough domain for implementing passthrough (identity) mode for the host,
 * signified by the default DID (FLPT_DEFAULT_DID). A real passthrough mode
 * (no translation) would allow devices to access all physical memory. So model
 * passthrough mode as a second-stage domain backed by the host EPT instead.
 */
struct dmar_domain pt_domain;

void init_pt_domain(void)
{
	INIT_LIST_HEAD(&pt_domain.cache_tags);
	pkvm_spin_lock_init(&pt_domain.cache_lock);
	pt_domain.qi_batch = &pt_domain._qi_batch;
	pt_domain.pgd = __pkvm_va(pkvm_host_ept_root());
	pt_domain.agaw = level_to_agaw(pkvm_host_ept_level());
}

static struct dmar_domain *__pkvm_get_iommu_domain_locked(void *pgd, bool inc_ref)
{
	struct dmar_domain *domain;

	hash_for_each_possible(iommu_domain_hasht, domain, hnode, (u64)pgd) {
		if (domain->pgd != pgd)
			continue;

		if (inc_ref && WARN_ON_ONCE(!atomic_inc_not_zero(&domain->refcount)))
			return NULL;

		return domain;
	}

	return NULL;
}

static struct dmar_domain *__pkvm_get_iommu_domain(void *pgd)
{
	struct dmar_domain *domain;

	pkvm_spin_lock(&iommu_domain_lock);
	domain = __pkvm_get_iommu_domain_locked(pgd, true);
	pkvm_spin_unlock(&iommu_domain_lock);

	return domain;
}

/*
 * Retrieve the domain without incrementing refcount.
 * This is useful when there is a refcount on the domain which is guaranteed
 * to be >1 (at least one reference).
 */
static struct dmar_domain *__pkvm_get_iommu_domain_noref(void *pgd)
{
	struct dmar_domain *domain;

	pkvm_spin_lock(&iommu_domain_lock);
	domain = __pkvm_get_iommu_domain_locked(pgd, false);
	/*
	 * pgd passed in here is derived from a valid context/pasid entry.
	 * Hence it's a pKVM bug if this pgd can't resolve to a domain.
	 */
	BUG_ON(!domain || atomic_read(&domain->refcount) <= 1);
	pkvm_spin_unlock(&iommu_domain_lock);

	return domain;
}

/*
 * Check the domain properties that affect how an IOMMU walks and caches the
 * domain page tables. A domain may be shared by multiple IOMMUs, but only if
 * each IOMMU is compatible with the properties selected at allocation time.
 */
static bool iommu_domain_compatible(struct intel_iommu *iommu,
				    struct dmar_domain *domain)
{
	int addr_width;

	if (domain->use_first_level) {
		if (!sm_supported(iommu) || !ecap_flts(iommu->ecap))
			return false;
	} else {
		if (sm_supported(iommu) && !ecap_slts(iommu->ecap))
			return false;

		if (cap_caching_mode(iommu->cap) && !domain->iotlb_sync_map)
			return false;
	}

	if (domain->iommu_superpage >
	    iommu_superpage_capability(iommu, domain->use_first_level))
		return false;

	if (domain->iommu_coherency !=
	    iommu_paging_structure_coherency(iommu))
		return false;

	addr_width = agaw_to_width(iommu->agaw);
	if (addr_width > cap_mgaw(iommu->cap))
		addr_width = cap_mgaw(iommu->cap);
	if (domain->gaw > addr_width || domain->agaw > iommu->agaw)
		return false;

	return true;
}

struct dmar_domain *pkvm_get_iommu_domain(void *pgd, u16 did,
					  struct intel_iommu *iommu)
{
	struct dmar_domain *domain;

	if (did == FLPT_DEFAULT_DID)
		return &pt_domain;

	domain = __pkvm_get_iommu_domain(pgd);

	if (domain && !iommu_domain_compatible(iommu, domain)) {
		pkvm_err("%s: domain[pgd:%p] is incompatible with iommu%d\n",
			 __func__, pgd, iommu->seq_id);
		pkvm_put_iommu_domain(domain);
		domain = NULL;
	}

	return domain;
}

struct dmar_domain *pkvm_get_iommu_domain_noref(void *pgd, u16 did)
{
	if (did == FLPT_DEFAULT_DID)
		return &pt_domain;

	return __pkvm_get_iommu_domain_noref(pgd);
}

void pkvm_put_iommu_domain(struct dmar_domain *domain)
{
	if (domain == &pt_domain)
		return;

	WARN_ON_ONCE(atomic_dec_if_positive(&domain->refcount) <= 0);
}

static int refill_domain_memcache(struct dmar_domain *domain,
				  struct pkvm_memcache *host_mc)
{
	struct pkvm_memcache *mc = &domain->mc;
	unsigned long min_pages;

	/*
	 * The host expects pKVM to drain the memcache fully and use it until
	 * the domain is freed, as the host itself doesn't store the memcache
	 * in any persistent data structure. This will not result in the
	 * hypervisor's memcache growing endlessly, since the host only
	 * provides a memcache if the hypervisor's memcache doesn't already
	 * have enough pages.
	 */
	min_pages = mc->count + READ_ONCE(host_mc->count);
	return pkvm_refill_memcache(mc, min_pages, host_mc);
}

static void free_domain_memcache(struct dmar_domain *domain,
				 struct pkvm_memcache *teardown_mc)
{
	struct pkvm_memcache *mc = &domain->mc;

	while (mc->count) {
		void *addr = pop_pkvm_memcache_page(mc, pkvm_phys_to_virt);

		push_pkvm_memcache_page(teardown_mc, addr, pkvm_virt_to_host_gpa);
		pkvm_hyp_donate_host(__pkvm_pa(addr), VTD_PAGE_SIZE, false);
	}
}

int pkvm_free_iommu_domain(u64 pgd_gpa, struct pkvm_memcache *teardown_mc)
{
	void *pgd = pkvm_host_gpa_to_virt(pgd_gpa);
	struct dmar_domain *domain;

	pkvm_spin_lock(&iommu_domain_lock);

	domain = __pkvm_get_iommu_domain_locked(pgd, false);
	if (!domain) {
		pkvm_spin_unlock(&iommu_domain_lock);
		pkvm_err("%s: no domain exist for pgd: %p\n", __func__, pgd);
		return -EINVAL;
	}

	if (atomic_cmpxchg(&domain->refcount, 1, 0) != 1) {
		pkvm_err("%s: domain[pgd:%p] has users, refcount %d\n",
			 __func__, domain->pgd, atomic_read(&domain->refcount));
		pkvm_spin_unlock(&iommu_domain_lock);
		return -EBUSY;
	}

	/*
	 * Remove the domain from the hash list while still holding the lock,
	 * to prevent someone else from getting this domain while freeing it.
	 */
	hash_del(&domain->hnode);

	pkvm_spin_unlock(&iommu_domain_lock);

	/* Unmap any remaining mappings. */
	domain_unmap(domain, 0, DOMAIN_MAX_PFN(domain->gaw), NULL);
	free_domain_memcache(domain, teardown_mc);
	/*
	 * pgd was not allocated through memcache, but its safe to return to
	 * memcache as the teardown mc frees it the same way host driver frees
	 * the pages.
	 */
	push_pkvm_memcache_page(teardown_mc, domain->pgd, pkvm_virt_to_host_gpa);
	pkvm_hyp_donate_host(__pkvm_pa(domain->pgd), VTD_PAGE_SIZE, false);

	pkvm_dbg("%s: freeing domain[pgd: %p], freed pages: %lu\n",
		 __func__, domain->pgd, teardown_mc->count);

	pkvm_spin_lock(&iommu_domain_lock);
	__clear_bit(domain->index, iommu_domains_bitmap);
	memset(domain, 0, sizeof(struct dmar_domain));
	pkvm_spin_unlock(&iommu_domain_lock);

	return 0;
}

struct dmar_domain *pkvm_alloc_iommu_domain(struct alloc_domain_data *data,
					    bool need_iotlb_sync_map)
{
	void *pgd = pkvm_host_gpa_to_virt(data->pgd_gpa);
	struct dmar_domain *domain;
	unsigned long index;

	pkvm_spin_lock(&iommu_domain_lock);
	domain = __pkvm_get_iommu_domain_locked(pgd, false);
	if (unlikely(domain)) {
		pkvm_spin_unlock(&iommu_domain_lock);
		return ERR_PTR(-EEXIST);
	}

	index = find_first_zero_bit(iommu_domains_bitmap, MAX_IOMMU_DOMAIN_NUM);
	if (index < MAX_IOMMU_DOMAIN_NUM) {
		__set_bit(index, iommu_domains_bitmap);
		domain = &iommu_domains[index];
		INIT_LIST_HEAD(&domain->cache_tags);
		domain->pgd = pgd;
		domain->use_first_level = data->use_first_level;
		domain->iommu_superpage = data->iommu_superpage;
		domain->iommu_coherency = data->iommu_coherency;
		domain->iotlb_sync_map = need_iotlb_sync_map;
		domain->agaw = data->agaw;
		domain->gaw = data->gaw;
		domain->max_addr = data->max_addr;
		domain->index = index;
		domain->qi_batch = &domain->_qi_batch;
		domain->vm_handle = PKVM_DOMAIN_UNBOUND; // initialize vm_handle to unbound
		atomic_set(&domain->refcount, 1);
		pkvm_spin_lock_init(&domain->lock);
		pkvm_spin_lock_init(&domain->cache_lock);
		hash_add(iommu_domain_hasht, &domain->hnode, (u64)pgd);
		pkvm_dbg("%s: allocated domain pgd: %p\n", __func__, pgd);
	} else {
		domain = ERR_PTR(-ENOMEM);
	}
	pkvm_spin_unlock(&iommu_domain_lock);

	return domain;
}

static int iommu_domain_map(struct domain_map_data *data)
{
	struct dmar_domain *domain;
	u64 iova, phys, size, end;
	int ret, hpa_vm, owner;

	/* Check for possible overflows that may have security implications */
	if (check_shl_overflow(data->iov_pfn, VTD_PAGE_SHIFT, &iova))
		return -EINVAL;
	if (check_shl_overflow(data->phys_pfn, VTD_PAGE_SHIFT, &phys))
		return -EINVAL;
	if (check_mul_overflow(data->nr_pages, VTD_PAGE_SIZE, &size))
		return -EINVAL;
	if (check_add_overflow(iova, size, &end))
		return -EINVAL;
	if (check_add_overflow(phys, size, &end))
		return -EINVAL;

	domain = __pkvm_get_iommu_domain(pkvm_host_gpa_to_virt(data->pgd_gpa));
	if (!domain) {
		pkvm_err("%s: failed to get the domain [pgd:%llx]\n",
			 __func__, data->pgd_gpa);
		return -EINVAL;
	}

	/* Only a completely unregistered HPA range belongs to the host. */
	hpa_vm = pkvm_lookup_hpa_vm(phys, phys + size);
	if (hpa_vm == -ENOENT)
		owner = PKVM_DOMAIN_HOST;
	else if (hpa_vm >= 0)
		owner = hpa_vm;
	else {
		pkvm_err("%s: invalid HPA range [0x%llx, 0x%llx), err=%d\n",
			 __func__, phys, phys + size, hpa_vm);
		pkvm_put_iommu_domain(domain);
		return -EPERM;
	}

	pkvm_spin_lock(&domain->lock);
	if (domain->vm_handle == PKVM_DOMAIN_UNBOUND)
		domain->vm_handle = owner;
	if (domain->vm_handle != owner) {
		pkvm_err("%s: domain owner=%d, HPA owner=%d\n",
			 __func__, domain->vm_handle, owner);
		ret = -EPERM;
		goto out_unlock;
	}
	if (data->mc.count) {
		ret = refill_domain_memcache(domain, &data->mc);
		if (ret) {
			pkvm_err("%s: failed to refill memcache for domain[pgd: %p] (err=%d)\n",
				 __func__, domain->pgd, ret);
			goto out_unlock;
		}
	}
	if (domain->mc.count < __pkvm_pgtable_max_pages(data->nr_pages)) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	ret = domain_map(domain, data->iov_pfn, data->phys_pfn,
			 data->nr_pages, data->prot, 0);

out_unlock:
	pkvm_spin_unlock(&domain->lock);
	if (hpa_vm >= 0)
		pkvm_put_vm_handle(hpa_vm);
	pkvm_put_iommu_domain(domain);

	return ret;
}

int pkvm_iommu_domain_map(struct domain_map_data *in, struct domain_map_data *out)
{
	int ret = iommu_domain_map(in);

	*out = *in;
	return ret;
}

int pkvm_iommu_domain_unmap(u64 pgd_gpa, u64 start_pfn, u64 last_pfn)
{
	struct dmar_domain *domain;

	domain = __pkvm_get_iommu_domain(pkvm_host_gpa_to_virt(pgd_gpa));
	if (!domain) {
		pkvm_err("%s, failed to get the domain [pgd:%llx]\n",
			 __func__, pgd_gpa);
		return -EINVAL;
	}

	pkvm_spin_lock(&domain->lock);
	domain_unmap(domain, start_pfn, last_pfn, NULL);
	pkvm_spin_unlock(&domain->lock);

	pkvm_put_iommu_domain(domain);

	return 0;
}

int pkvm_iommu_attach_ptdev(u16 bdf, int vm_handle)
{
	struct dmar_domain *domain;
	int i, j;
	int ret = -ENODEV;

	pkvm_spin_lock(&iommu_domain_lock);
	for (i = 0; i < MAX_IOMMU_DOMAIN_NUM; i++) {
		if (!test_bit(i, iommu_domains_bitmap))
			continue;
		domain = &iommu_domains[i];
		for (j = 0; j < domain->pending_count; j++) {
			if (domain->pending_bdfs[j] == bdf) {
				domain->pending_bdfs[j] =
					domain->pending_bdfs[--domain->pending_count];
				if (domain->vm_handle == PKVM_DOMAIN_UNBOUND || domain->vm_handle == PKVM_DOMAIN_HOST) {
					domain->vm_handle = vm_handle;
				} else if (domain->vm_handle != vm_handle) {
					pkvm_err("%s: cross-VM attach! domain->vm_handle=%d vm_handle=%d\n",
						 __func__, domain->vm_handle, vm_handle);
					ret = -EPERM;
					goto out;
				}
				ret = 0;
				goto out;
			}
		}
	}
out:
	pkvm_spin_unlock(&iommu_domain_lock);
	return ret;
}

bool pkvm_iommu_vm_domains_ready(int vm_handle)
{
	struct dmar_domain *domain;
	int i;
	bool ready = true;

	pkvm_spin_lock(&iommu_domain_lock);
	for (i = 0; i < MAX_IOMMU_DOMAIN_NUM; i++) {
		if (!test_bit(i, iommu_domains_bitmap))
			continue;
		domain = &iommu_domains[i];
		if (domain->vm_handle == vm_handle && domain->pending_count > 0) {
			ready = false;
			break;
		}
	}
	pkvm_spin_unlock(&iommu_domain_lock);
	return ready;
}
