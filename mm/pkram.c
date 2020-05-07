// SPDX-License-Identifier: GPL-2.0
#include <linux/crash_dump.h>
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/pfn.h>
#include <linux/pkram.h>
#include <linux/reboot.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/types.h>

#include "internal.h"


/*
 * Represents a reference to a data page saved to PKRAM.
 */
typedef __u64 pkram_entry_t;

#define PKRAM_ENTRY_FLAGS_SHIFT	0x5
#define PKRAM_ENTRY_FLAGS_MASK	0x7f
#define PKRAM_ENTRY_ORDER_MASK	0x1f

/*
 * Keeps references to data pages saved to PKRAM.
 * The structure occupies a memory page.
 */
struct pkram_link {
	__u64	link_pfn;	/* points to the next link of the object */
	__u64	index;		/* mapping index of first pkram_entry_t */

	/*
	 * the array occupies the rest of the link page; if the link is not
	 * full, the rest of the array must be filled with zeros
	 */
	pkram_entry_t entry[0];
};

#define PKRAM_LINK_ENTRIES_MAX \
	((PAGE_SIZE-sizeof(struct pkram_link))/sizeof(pkram_entry_t))

struct pkram_obj {
	__u64	data_pfn;	/* points to the byte data */
	__u64	data_len;	/* byte data size */
	__u64	link_pfn;	/* points to the first link of the object */
	__u64	obj_pfn;	/* points to the next object in the list */
};

/*
 * Preserved memory is divided into nodes that can be saved or loaded
 * independently of each other. The nodes are identified by unique name
 * strings.
 *
 * References to data pages saved to a preserved memory node are kept in a
 * singly-linked list of PKRAM link structures (see above), the node has a
 * pointer to the head of.
 *
 * To facilitate data restore in the new kernel, before reboot all PKRAM nodes
 * are organized into a list singly-linked by pfn's (see pkram_reboot()).
 *
 * The structure occupies a memory page.
 */
struct pkram_node {
	__u32	flags;
	__u64	obj_pfn;	/* points to the first obj of the node */
	__u64	node_pfn;	/* points to the next node in the node list */

	__u8	name[PKRAM_NAME_MAX];
};

#define PKRAM_SAVE		1
#define PKRAM_LOAD		2
#define PKRAM_ACCMODE_MASK	3

/*
 * The PKRAM super block contains data needed to restore the preserved memory
 * structure on boot. The pointer to it (pfn) should be passed via the 'pkram'
 * boot param if one wants to restore preserved data saved by the previously
 * executing kernel. For that purpose the kernel exports the pfn via
 * /sys/kernel/pkram. If none is passed, preserved memory if any will not be
 * preserved and a new clean page will be allocated for the super block.
 *
 * The structure occupies a memory page.
 */
struct pkram_super_block {
	__u64	node_pfn;		/* first element of the node list */
	__u64	pgd_pfn;
};

static unsigned long pkram_sb_pfn __initdata;
static struct pkram_super_block *pkram_sb;

static pgd_t *pkram_pgd;
static DEFINE_SPINLOCK(pkram_pgd_lock);

static int pkram_add_identity_map(struct page *page);
static void pkram_remove_identity_map(struct page *page);
static int pkram_reserve_page_ranges(pgd_t *pgd);

/*
 * For convenience sake PKRAM nodes are kept in an auxiliary doubly-linked list
 * connected through the lru field of the page struct.
 */
static LIST_HEAD(pkram_nodes);			/* linked through page::lru */
static DEFINE_MUTEX(pkram_mutex);		/* serializes open/close */

unsigned long __initdata pkram_reserved_pages;
static bool pkram_reservation_in_progress;

/*
 * For tracking a region of memory that PKRAM is not allowed to use.
 */
struct banned_region {
	unsigned long start, end;		/* pfn, inclusive */
};

#define MAX_NR_BANNED		(32 + MAX_NUMNODES * 2)

static unsigned int nr_banned;			/* number of banned regions */

/* banned regions; arranged in ascending order, do not overlap */
static struct banned_region banned[MAX_NR_BANNED];
/*
 * If a page allocated for PKRAM turns out to belong to a banned region,
 * it is placed on the banned_pages list so subsequent allocation attempts
 * do not encounter it again. The list is shrunk when system memory is low.
 */
static LIST_HEAD(banned_pages);			/* linked through page::lru */
static DEFINE_SPINLOCK(banned_pages_lock);
static unsigned long nr_banned_pages;

/*
 * The PKRAM super block pfn, see above.
 */
static int __init parse_pkram_sb_pfn(char *arg)
{
	return kstrtoul(arg, 16, &pkram_sb_pfn);
}
early_param("pkram", parse_pkram_sb_pfn);

static void * __init pkram_map_meta(unsigned long pfn)
{
	if (pfn >= max_low_pfn)
		return ERR_PTR(-EINVAL);
	return pfn_to_kaddr(pfn);
}

static int __init pkram_reserve_page(unsigned long pfn)
{
	phys_addr_t base, size;
	int err = 0;

	if (pfn >= max_pfn)
		return -EINVAL;

	base = PFN_PHYS(pfn);
	size = PAGE_SIZE;

	if (memblock_is_region_reserved(base, size) ||
	    memblock_reserve(base, size) < 0)
		err = -EBUSY;

	if (!err)
		pkram_reserved_pages++;

	return err;
}

static void __init pkram_unreserve_page(unsigned long pfn)
{
	memblock_free(PFN_PHYS(pfn), PAGE_SIZE);
	pkram_reserved_pages--;
}

/*
 * Reserved pages that belong to preserved memory.
 *
 * This function should be called at boot time as early as possible to prevent
 * preserved memory from being recycled.
 */
void __init pkram_reserve(void)
{
	int err = 0;

	if (!pkram_sb_pfn || is_kdump_kernel())
		return;

	pr_info("PKRAM: Examining preserved memory...\n");
	pkram_reservation_in_progress = true;

	err = pkram_reserve_page(pkram_sb_pfn);
	if (err)
		goto out;
	pkram_sb = pkram_map_meta(pkram_sb_pfn);
	if (IS_ERR(pkram_sb)) {
		pkram_unreserve_page(pkram_sb_pfn);
		err = PTR_ERR(pkram_sb);
		goto out;
	}

	/* An empty pkram_sb is not an error */
	if (!pkram_sb->node_pfn) {
		pkram_unreserve_page(pkram_sb_pfn);
		pkram_sb = NULL;
		goto done;
	}

	err = pkram_reserve_page(pkram_sb->pgd_pfn);
	if (err) {
		pr_warn("PKRAM: pgd_pfn=0x%llx already reserved\n",
			pkram_sb->pgd_pfn);
		pkram_unreserve_page(pkram_sb_pfn);
		goto out;
	}
	pkram_pgd = pfn_to_kaddr(pkram_sb->pgd_pfn);
	err = pkram_reserve_page_ranges(pkram_pgd);
	if (err) {
		pkram_unreserve_page(pkram_sb->pgd_pfn);
		pkram_unreserve_page(pkram_sb_pfn);
		pkram_pgd = NULL;
	}

out:
	pkram_reservation_in_progress = false;

	if (err) {
		pr_err("PKRAM: Reservation failed: %d\n", err);
		WARN_ON(pkram_reserved_pages > 0);
		pkram_sb = NULL;
		return;
	}

done:
	pr_info("PKRAM: %lu pages reserved\n", pkram_reserved_pages);
}

/*
 * Ban pfn range [start..end] (inclusive) from use in PKRAM.
 */
void pkram_ban_region(unsigned long start, unsigned long end)
{
	int i, merged = -1;

	if (pkram_reservation_in_progress)
		return;

	/* first try to merge the region with an existing one */
	for (i = nr_banned - 1; i >= 0 && start <= banned[i].end + 1; i--) {
		if (end + 1 >= banned[i].start) {
			start = min(banned[i].start, start);
			end = max(banned[i].end, end);
			if (merged < 0)
				merged = i;
		} else
			/*
			 * Regions are arranged in ascending order and do not
			 * intersect so the merged region cannot jump over its
			 * predecessors.
			 */
			BUG_ON(merged >= 0);
	}

	i++;

	if (merged >= 0) {
		banned[i].start = start;
		banned[i].end = end;
		/* shift if merged with more than one region */
		memmove(banned + i + 1, banned + merged + 1,
			sizeof(*banned) * (nr_banned - merged - 1));
		nr_banned -= merged - i;
		return;
	}

	/*
	 * The region does not intersect with an existing one;
	 * try to create a new one.
	 */
	if (nr_banned == MAX_NR_BANNED) {
		pr_err("PKRAM: Failed to ban %lu-%lu: "
		       "Too many banned regions\n", start, end);
		return;
	}

	memmove(banned + i + 1, banned + i,
		sizeof(*banned) * (nr_banned - i));
	banned[i].start = start;
	banned[i].end = end;
	nr_banned++;
}

static void pkram_show_banned(void)
{
	int i;
	unsigned long n, total = 0;

	if (is_kdump_kernel())
		return;

	pr_info("PKRAM: banned regions:\n");
	for (i = 0; i < nr_banned; i++) {
		n = banned[i].end - banned[i].start + 1;
		pr_info("%4d: [%08lx - %08lx] %ld pages\n",
			i, banned[i].start, banned[i].end, n);
		total += n;
	}
	pr_info("Total banned: %ld pages in %d regions\n",
		total, nr_banned);
}

/*
 * Returns true if the page may not be used for storing preserved data.
 */
static bool pkram_page_banned(struct page *page)
{
	unsigned long epfn, pfn = page_to_pfn(page);
	int l = 0, r = nr_banned - 1, m;

	epfn = pfn + compound_nr(page) - 1;

	/* do binary search */
	while (l <= r) {
		m = (l + r) / 2;
		if (epfn < banned[m].start)
			r = m - 1;
		else if (pfn > banned[m].end)
			l = m + 1;
		else
			return true;
	}
	return false;
}

static inline struct page *__pkram_alloc_page(gfp_t gfp_mask, bool add_to_map)
{
	struct page *page;
	LIST_HEAD(list);
	unsigned long len = 0;
	int err;

	page = alloc_page(gfp_mask);
	while (page && pkram_page_banned(page)) {
		len++;
		list_add(&page->lru, &list);
		page = alloc_page(gfp_mask);
	}
	if (len > 0) {
		spin_lock(&banned_pages_lock);
		nr_banned_pages += len;
		list_splice(&list, &banned_pages);
		spin_unlock(&banned_pages_lock);
	}

	if (page && add_to_map) {
		err = pkram_add_identity_map(page);
		if (err) {
			__free_page(page);
			page = NULL;
		}
	}

	return page;
}

static inline struct page *pkram_alloc_page(gfp_t gfp_mask)
{
	return __pkram_alloc_page(gfp_mask, true);
}

static inline void pkram_free_page(void *addr)
{
	/*
	 * The page may have the reserved bit set since preserved pages
	 * are reserved early in boot.
	 */
	ClearPageReserved(virt_to_page(addr));
	pkram_remove_identity_map(virt_to_page(addr));
	free_page((unsigned long)addr);
}

static void __banned_pages_shrink(unsigned long nr_to_scan)
{
	struct page *page;

	if (nr_to_scan <= 0)
		return;

	while (nr_banned_pages > 0) {
		BUG_ON(list_empty(&banned_pages));
		page = list_first_entry(&banned_pages, struct page, lru);
		list_del(&page->lru);
		__free_page(page);
		nr_banned_pages--;
		nr_to_scan--;
		if (!nr_to_scan)
			break;
	}
}

static unsigned long
banned_pages_count(struct shrinker *shrink, struct shrink_control *sc)
{
	return nr_banned_pages;
}

static unsigned long
banned_pages_scan(struct shrinker *shrink, struct shrink_control *sc)
{
	int nr_left = nr_banned_pages;

	if (!sc->nr_to_scan || !nr_left)
		return nr_left;

	spin_lock(&banned_pages_lock);
	__banned_pages_shrink(sc->nr_to_scan);
	nr_left = nr_banned_pages;
	spin_unlock(&banned_pages_lock);

	return nr_left;
}

static struct shrinker banned_pages_shrinker = {
	.count_objects = banned_pages_count,
	.scan_objects = banned_pages_scan,
	.seeks = DEFAULT_SEEKS,
};

static inline void pkram_insert_node(struct pkram_node *node)
{
	list_add(&virt_to_page(node)->lru, &pkram_nodes);
}

static inline void pkram_delete_node(struct pkram_node *node)
{
	list_del(&virt_to_page(node)->lru);
}

static struct pkram_node *pkram_find_node(const char *name)
{
	struct page *page;
	struct pkram_node *node;

	list_for_each_entry(page, &pkram_nodes, lru) {
		node = page_address(page);
		if (strcmp(node->name, name) == 0)
			return node;
	}
	return NULL;
}

static void pkram_truncate_link(struct pkram_link *link)
{
	struct page *page;
	pkram_entry_t p;
	int i;

	for (i = 0; i < PKRAM_LINK_ENTRIES_MAX; i++) {
		p = link->entry[i];
		if (!p)
			continue;
		page = pfn_to_page(PHYS_PFN(p));
		/*
		 * The page may have the reserved bit set since preserved pages
		 * are reserved early in boot.
		 */
		ClearPageReserved(page);
		pkram_remove_identity_map(page);
		put_page(page);
	}
}

static void pkram_truncate_obj(struct pkram_obj *obj)
{
	unsigned long link_pfn;
	struct pkram_link *link;

	link_pfn = obj->link_pfn;
	while (link_pfn) {
		link = pfn_to_kaddr(link_pfn);
		pkram_truncate_link(link);
		link_pfn = link->link_pfn;
		pkram_free_page(link);
		cond_resched();
	}
	obj->link_pfn = 0;
}

static void pkram_truncate_node(struct pkram_node *node)
{
	unsigned long obj_pfn;
	struct pkram_obj *obj;

	obj_pfn = node->obj_pfn;
	while (obj_pfn) {
		obj = pfn_to_kaddr(obj_pfn);
		pkram_truncate_obj(obj);
		obj_pfn = obj->obj_pfn;
		pkram_free_page(obj);
		cond_resched();
	}
	node->obj_pfn = 0;
}

/*
 * Free all nodes that are not under operation.
 */
static void pkram_truncate(void)
{
	struct page *page, *tmp;
	struct pkram_node *node;
	LIST_HEAD(dispose);

	mutex_lock(&pkram_mutex);
	list_for_each_entry_safe(page, tmp, &pkram_nodes, lru) {
		node = page_address(page);
		if (!(node->flags & PKRAM_ACCMODE_MASK))
			list_move(&page->lru, &dispose);
	}
	mutex_unlock(&pkram_mutex);

	while (!list_empty(&dispose)) {
		page = list_first_entry(&dispose, struct page, lru);
		list_del(&page->lru);
		node = page_address(page);
		pkram_truncate_node(node);
		pkram_free_page(node);
	}
}

static void pkram_add_link(struct pkram_link *link, struct pkram_obj *obj)
{
	link->link_pfn = obj->link_pfn;
	obj->link_pfn = page_to_pfn(virt_to_page(link));
}

static struct pkram_link *pkram_remove_link(struct pkram_obj *obj)
{
	struct pkram_link *current_link;

	if (!obj->link_pfn)
		return NULL;

	current_link = pfn_to_kaddr(obj->link_pfn);
	obj->link_pfn = current_link->link_pfn;
	current_link->link_pfn = 0;

	return current_link;
}

static void pkram_stream_init(struct pkram_stream *ps,
			     struct pkram_node *node, gfp_t gfp_mask)
{
	memset(ps, 0, sizeof(*ps));
	ps->gfp_mask = gfp_mask;
	ps->node = node;
}

static void pkram_stream_init_obj(struct pkram_stream *ps, struct pkram_obj *obj)
{
	ps->obj = obj;
	ps->link = NULL;
	ps->entry_idx = 0;
	ps->next_index = 0;
}

/**
 * Create a preserved memory node with name @name and initialize stream @ps
 * for saving data to it.
 *
 * @gfp_mask specifies the memory allocation mask to be used when saving data.
 *
 * Error values:
 *	%ENODEV: PKRAM not available
 *	%ENAMETOOLONG: name len >= PKRAM_NAME_MAX
 *	%ENOMEM: insufficient memory available
 *	%EEXIST: node with specified name already exists
 *
 * Returns 0 on success, -errno on failure.
 *
 * After the save has finished, pkram_finish_save() (or pkram_discard_save() in
 * case of failure) is to be called.
 */
int pkram_prepare_save(struct pkram_stream *ps, const char *name, gfp_t gfp_mask)
{
	struct page *page;
	struct pkram_node *node;
	int err = 0;

	if (!pkram_sb)
		return -ENODEV;

	if (strlen(name) >= PKRAM_NAME_MAX)
		return -ENAMETOOLONG;

	page = pkram_alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
		return -ENOMEM;
	node = page_address(page);

	node->flags = PKRAM_SAVE;
	strcpy(node->name, name);

	mutex_lock(&pkram_mutex);
	if (!pkram_find_node(name))
		pkram_insert_node(node);
	else
		err = -EEXIST;
	mutex_unlock(&pkram_mutex);
	if (err) {
		__free_page(page);
		return err;
	}

	pkram_stream_init(ps, node, gfp_mask);
	return 0;
}

/**
 * Create a preserved memory object and initialize stream @ps for saving data
 * to it.
 *
 * Returns 0 on success, -errno on failure.
 *
 * Error values:
 *	%ENOMEM: insufficient memory available
 *
 * After the save has finished, pkram_finish_save_obj() (or pkram_discard_save()
 * in case of failure) is to be called.
 */
int pkram_prepare_save_obj(struct pkram_stream *ps)
{
	struct pkram_node *node = ps->node;
	struct pkram_obj *obj;
	struct page *page;

	BUG_ON((node->flags & PKRAM_ACCMODE_MASK) != PKRAM_SAVE);

	page = pkram_alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
		return -ENOMEM;
	obj = page_address(page);

	if (node->obj_pfn)
		obj->obj_pfn = node->obj_pfn;
	node->obj_pfn = page_to_pfn(page);

	pkram_stream_init_obj(ps, obj);
	return 0;
}

/**
 * Commit the object started with pkram_prepare_save_obj() to preserved memory.
 */
void pkram_finish_save_obj(struct pkram_stream *ps)
{
	struct pkram_node *node = ps->node;

	BUG_ON((node->flags & PKRAM_ACCMODE_MASK) != PKRAM_SAVE);
}

/**
 * Commit the save to preserved memory started with pkram_prepare_save().
 * After the call, the stream may not be used any more.
 */
void pkram_finish_save(struct pkram_stream *ps)
{
	struct pkram_node *node = ps->node;

	BUG_ON((node->flags & PKRAM_ACCMODE_MASK) != PKRAM_SAVE);

	smp_wmb();
	node->flags &= ~PKRAM_ACCMODE_MASK;
}

/**
 * Cancel the save to preserved memory started with pkram_prepare_save() and
 * destroy the corresponding preserved memory node freeing any data already
 * saved to it.
 */
void pkram_discard_save(struct pkram_stream *ps)
{
	struct pkram_node *node = ps->node;

	BUG_ON((node->flags & PKRAM_ACCMODE_MASK) != PKRAM_SAVE);

	mutex_lock(&pkram_mutex);
	pkram_delete_node(node);
	mutex_unlock(&pkram_mutex);

	pkram_truncate_node(node);
	pkram_free_page(node);
}

/**
 * Remove the preserved memory node with name @name and initialize stream @ps
 * for loading data from it.
 *
 * Returns 0 on success, -errno on failure.
 *
 * Error values:
 *	%ENODEV: PKRAM not available
 *	%ENOENT: node with specified name does not exist
 *	%EBUSY: save to required node has not finished yet
 *
 * After the load has finished, pkram_finish_load() is to be called.
 */
int pkram_prepare_load(struct pkram_stream *ps, const char *name)
{
	struct pkram_node *node;
	int err = 0;

	if (!pkram_sb)
		return -ENODEV;

	mutex_lock(&pkram_mutex);
	node = pkram_find_node(name);
	if (!node) {
		err = -ENOENT;
		goto out_unlock;
	}
	if (node->flags & PKRAM_ACCMODE_MASK) {
		err = -EBUSY;
		goto out_unlock;
	}
	pkram_delete_node(node);
out_unlock:
	mutex_unlock(&pkram_mutex);
	if (err)
		return err;

	node->flags |= PKRAM_LOAD;
	pkram_stream_init(ps, node, 0);
	return 0;
}

/**
 * Remove the next preserved memory object from the stream @ps and
 * initialize stream @ps for loading data from it.
 *
 * Returns 0 on success, -errno on failure.
 *
 * Error values:
 *	%ENODATA: Stream @ps has no preserved memory objects
 *
 * After the load has finished, pkram_finish_load_obj() is to be called.
 */
int pkram_prepare_load_obj(struct pkram_stream *ps)
{
	struct pkram_node *node = ps->node;
	struct pkram_obj *obj;

	BUG_ON((node->flags & PKRAM_ACCMODE_MASK) != PKRAM_LOAD);

	if (!node->obj_pfn)
		return -ENODATA;

	obj = pfn_to_kaddr(node->obj_pfn);
	node->obj_pfn = obj->obj_pfn;

	pkram_stream_init_obj(ps, obj);
	return 0;
}

/**
 * Finish the load of a preserved memory object started with
 * pkram_prepare_load_obj() freeing the object and any data that has not
 * been loaded from it.
 */
void pkram_finish_load_obj(struct pkram_stream *ps)
{
	struct pkram_node *node = ps->node;
	struct pkram_obj *obj = ps->obj;
	struct pkram_link *link = ps->link;

	BUG_ON((node->flags & PKRAM_ACCMODE_MASK) != PKRAM_LOAD);

	/*
	 * If link is not null, then loading stopped within a pkram_link
	 * unexpectedly.
	 */
	if (link) {
		unsigned long link_pfn;

		link_pfn = page_to_pfn(virt_to_page(link));
		while (link_pfn) {
			link = pfn_to_kaddr(link_pfn);
			pkram_truncate_link(link);
			link_pfn = link->link_pfn;
			pkram_free_page(link);
			cond_resched();
		}
	}

	if (ps->data_page)
		pkram_free_page(page_address(ps->data_page));

	pkram_truncate_obj(obj);
	pkram_free_page(obj);
}

/**
 * Finish the load from preserved memory started with pkram_prepare_load()
 * freeing the corresponding preserved memory node and any data that has
 * not been loaded from it.
 */
void pkram_finish_load(struct pkram_stream *ps)
{
	struct pkram_node *node = ps->node;

	BUG_ON((node->flags & PKRAM_ACCMODE_MASK) != PKRAM_LOAD);

	if (ps->data_page)
		put_page(ps->data_page);

	pkram_truncate_node(node);
	pkram_free_page(node);
}

/*
 * Insert page to PKRAM node allocating a new PKRAM link if necessary.
 */
static int __pkram_save_page(struct pkram_stream *ps,
			    struct page *page, short flags, unsigned long index)
{
	struct pkram_link *link = ps->link;
	struct pkram_obj *obj = ps->obj;
	pkram_entry_t p;
	int order;

	if (!link || ps->entry_idx >= PKRAM_LINK_ENTRIES_MAX ||
	    index != ps->next_index) {
		struct page *link_page;

		link_page = pkram_alloc_page((ps->gfp_mask & GFP_RECLAIM_MASK) |
					    __GFP_ZERO);
		if (!link_page)
			return -ENOMEM;

		ps->link = link = page_address(link_page);
		pkram_add_link(link, obj);

		ps->entry_idx = 0;

		ps->next_index = link->index = index;
	}

	if (PageTransHuge(page))
		flags |= PKRAM_PAGE_TRANS_HUGE;

	order = compound_order(page);
	ps->next_index += (1 << order);

	get_page(page);
	p = page_to_phys(page);
	p |= order;
	p |= ((flags & PKRAM_ENTRY_FLAGS_MASK) << PKRAM_ENTRY_FLAGS_SHIFT);
	link->entry[ps->entry_idx] = p;
	ps->entry_idx++;

	return 0;
}

static int __pkram_save_page_copy(struct pkram_stream *ps, struct page *page,
				short flags)
{
	int nr_pages = compound_nr(page);
	pgoff_t index = page->index;
	int i, err;

	for (i = 0; i < nr_pages; i++, index++) {
		struct page *p = page + i;
		struct page *new;

		new = pkram_alloc_page(ps->gfp_mask);
		if (!new)
			return -ENOMEM;

		copy_highpage(new, p);
		err = __pkram_save_page(ps, new, flags, index);
		put_page(new);

		if (err)
			return err;
	}

	return 0;
}

/**
 * Save page @page to the preserved memory node and object associated with
 * stream @ps. The stream must have been initialized with pkram_prepare_save()
 * and pkram_prepare_save_obj().
 *
 * @flags specifies supplemental page state to be preserved.
 *
 * Returns 0 on success, -errno on failure.
 *
 * Error values:
 *	%ENOMEM: insufficient amount of memory available
 *
 * Saving a page to preserved memory is simply incrementing its refcount so
 * that it will not get freed after the last user puts it. That means it is
 * safe to use the page as usual after it has been saved.
 */
int pkram_save_page(struct pkram_stream *ps, struct page *page, short flags)
{
	struct pkram_node *node = ps->node;
	int err;

	BUG_ON((node->flags & PKRAM_ACCMODE_MASK) != PKRAM_SAVE);

	/* if page is banned, relocate it */
	if (pkram_page_banned(page))
		return __pkram_save_page_copy(ps, page, flags);

	err = __pkram_save_page(ps, page, flags, page->index);
	if (!err)
		err = pkram_add_identity_map(page);

	return err;
}

/*
 * Extract the next page from preserved memory freeing a PKRAM link if it
 * becomes empty.
 */
static struct page *__pkram_load_page(struct pkram_stream *ps, unsigned long *index, short *flags)
{
	struct pkram_link *link = ps->link;
	struct page *page;
	pkram_entry_t p;
	int i, order;
	short flgs;

	if (!link) {
		link = pkram_remove_link(ps->obj);
		if (!link)
			return NULL;

		ps->link = link;
		ps->entry_idx = 0;
		ps->next_index = link->index;
	}

	BUG_ON(ps->entry_idx >= PKRAM_LINK_ENTRIES_MAX);

	p = link->entry[ps->entry_idx];
	BUG_ON(!p);

	flgs = (p >> PKRAM_ENTRY_FLAGS_SHIFT) & PKRAM_ENTRY_FLAGS_MASK;
	order = p & PKRAM_ENTRY_ORDER_MASK;
	page = pfn_to_page(PHYS_PFN(p));

	for (i = 0; i < (1 << order); i++) {
		struct page *pg = page + i;

		ClearPageReserved(pg);
	}

	if (flgs & PKRAM_PAGE_TRANS_HUGE) {
		prep_compound_page(page, order);
		prep_transhuge_page(page);
	}

	if (flags)
		*flags = flgs;
	if (index)
		*index = ps->next_index;

	ps->next_index += (1 << order);

	/* clear to avoid double free (see pkram_truncate_link()) */
	link->entry[ps->entry_idx] = 0;

	pkram_remove_identity_map(page);

	ps->entry_idx++;
	if (ps->entry_idx >= PKRAM_LINK_ENTRIES_MAX ||
	    !link->entry[ps->entry_idx]) {
		ps->link = NULL;
		pkram_free_page(link);
	}

	return page;
}

/**
 * Load the next page from the preserved memory node and object associated
 * with stream @ps. The stream must have been initialized with
 * pkram_prepare_load() and pkram_prepare_load_obj().
 *
 * If not NULL, @index is initialized with the preserved mapping offset of the
 * page loaded.
 * If not NULL, @flags is initialized with preserved supplemental state of the
 * page loaded.
 *
 * Returns the page loaded or NULL if the node is empty.
 *
 * The page loaded has its refcount incremented.
 */
struct page *pkram_load_page(struct pkram_stream *ps, unsigned long *index, short *flags)
{
	struct pkram_node *node = ps->node;

	BUG_ON((node->flags & PKRAM_ACCMODE_MASK) != PKRAM_LOAD);

	return __pkram_load_page(ps, index, flags);
}

/**
 * Copy @count bytes from @buf to the preserved memory node and object
 * associated with stream @ps. The stream must have been initialized with
 * pkram_prepare_save() and pkram_prepare_save_obj().
 *
 * On success, returns the number of bytes written, which is always equal to
 * @count. On failure, -errno is returned.
 *
 * Error values:
 *    %ENOMEM: insufficient amount of memory available
 */
ssize_t pkram_write(struct pkram_stream *ps, const void *buf, size_t count)
{
	struct pkram_node *node = ps->node;
	struct pkram_obj *obj = ps->obj;
	void *addr;

	BUG_ON((node->flags & PKRAM_ACCMODE_MASK) != PKRAM_SAVE);

	if (!ps->data_page) {
		struct page *page;

		page = pkram_alloc_page((ps->gfp_mask & GFP_RECLAIM_MASK) |
				       __GFP_HIGHMEM | __GFP_ZERO);
		if (!page)
			return -ENOMEM;

		ps->data_page = page;
		ps->data_offset = 0;
		obj->data_pfn = page_to_pfn(page);
	}

	BUG_ON(count > PAGE_SIZE - ps->data_offset);

	addr = kmap_atomic(ps->data_page);
	memcpy(addr + ps->data_offset, buf, count);
	kunmap_atomic(addr);

	obj->data_len += count;
	ps->data_offset += count;

	return count;
}

/**
 * Copy up to @count bytes from the preserved memory node and object
 * associated with stream @ps to @buf. The stream must have been initialized
 * with pkram_prepare_load() and pkram_prepare_load_obj().
 *
 * Returns the number of bytes read, which may be less than @count if the node
 * has fewer bytes available.
 */
size_t pkram_read(struct pkram_stream *ps, void *buf, size_t count)
{
	struct pkram_node *node = ps->node;
	struct pkram_obj *obj = ps->obj;
	size_t copy_count;
	char *addr;

	BUG_ON((node->flags & PKRAM_ACCMODE_MASK) != PKRAM_LOAD);

	if (!count || !obj->data_len)
		return 0;

	if (!ps->data_page) {
		struct page *page;

		page = pfn_to_page(obj->data_pfn);
		if (!page)
			return 0;
		ClearPageReserved(page);

		ps->data_page = page;
		ps->data_offset = 0;
		obj->data_pfn = 0;
	}

	BUG_ON(count > PAGE_SIZE - ps->data_offset);

	copy_count = min_t(size_t, count, PAGE_SIZE - ps->data_offset);
	if (copy_count > obj->data_len)
		copy_count = obj->data_len;

	addr = kmap_atomic(ps->data_page);
	memcpy(buf, addr + ps->data_offset, copy_count);
	kunmap_atomic(addr);

	obj->data_len -= copy_count;
	ps->data_offset += copy_count;

	if (!obj->data_len) {
		pkram_free_page(page_address(ps->data_page));
		ps->data_page = NULL;
	}

	return copy_count;
}

/*
 * Build the list of PKRAM nodes.
 */
static void __pkram_reboot(void)
{
	struct page *page;
	struct pkram_node *node;
	unsigned long node_pfn = 0;
	unsigned long pgd_pfn = 0;

	if (pkram_pgd) {
		pkram_show_banned();
		list_for_each_entry_reverse(page, &pkram_nodes, lru) {
			node = page_address(page);
			if (WARN_ON(node->flags & PKRAM_ACCMODE_MASK))
				continue;
			node->node_pfn = node_pfn;
			node_pfn = page_to_pfn(page);
		}
		pgd_pfn = page_to_pfn(virt_to_page(pkram_pgd));
	}
	/*
	 * Zero out pkram_sb completely since it may have been passed from
	 * the previous boot.
	 */
	memset(pkram_sb, 0, PAGE_SIZE);
	if (node_pfn) {
		pkram_sb->node_pfn = node_pfn;
		pkram_sb->pgd_pfn = pgd_pfn;
	}
}

static int pkram_reboot(struct notifier_block *notifier,
		       unsigned long val, void *v)
{
	if (val != SYS_RESTART)
		return NOTIFY_DONE;
	if (pkram_sb)
		__pkram_reboot();
	return NOTIFY_OK;
}

static struct notifier_block pkram_reboot_notifier = {
	.notifier_call = pkram_reboot,
};

static ssize_t show_pkram_sb_pfn(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	unsigned long pfn = pkram_sb ? PFN_DOWN(__pa(pkram_sb)) : 0;

	return sprintf(buf, "%lx\n", pfn);
}

static ssize_t store_pkram_sb_pfn(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int val;

	if (kstrtoint(buf, 0, &val) || val)
		return -EINVAL;
	pkram_truncate();
	return count;
}

static struct kobj_attribute pkram_sb_pfn_attr =
	__ATTR(pkram, 0644, show_pkram_sb_pfn, store_pkram_sb_pfn);

static struct attribute *pkram_attrs[] = {
	&pkram_sb_pfn_attr.attr,
	NULL,
};

static struct attribute_group pkram_attr_group = {
	.attrs = pkram_attrs,
};

/* returns non-zero on success */
static int __init pkram_init_sb(void)
{
	unsigned long pfn;
	struct pkram_node *node;

	if (!pkram_sb) {
		struct page *page;

		page = __pkram_alloc_page(GFP_KERNEL | __GFP_ZERO, false);
		if (!page) {
			pr_err("PKRAM: Failed to allocate super block\n");
			__banned_pages_shrink(ULONG_MAX);
			return 0;
		}
		pkram_sb = page_address(page);
	}

	/*
	 * Build auxiliary doubly-linked list of nodes connected through
	 * page::lru for convenience sake.
	 */
	pfn = pkram_sb->node_pfn;
	while (pfn) {
		node = pfn_to_kaddr(pfn);
		pkram_insert_node(node);
		pfn = node->node_pfn;
	}
	return 1;
}

static int __init pkram_init(void)
{
	if (!is_kdump_kernel() && pkram_init_sb()) {
		register_reboot_notifier(&pkram_reboot_notifier);
		register_shrinker(&banned_pages_shrinker);
		sysfs_update_group(kernel_kobj, &pkram_attr_group);
	}
	return 0;
}
module_init(pkram_init);

static unsigned long *pkram_alloc_pte_bitmap(void)
{
	return page_address(__pkram_alloc_page(GFP_KERNEL | __GFP_ZERO, false));
}

static void pkram_free_pte_bitmap(void *bitmap)
{
	ClearPageReserved(virt_to_page(bitmap));
	pkram_remove_identity_map(virt_to_page(bitmap));
	free_page((unsigned long)bitmap);
}

#define set_p4d(p4dp, p4d)	WRITE_ONCE(*(p4dp), (p4d))

static int pkram_add_identity_map(struct page *page)
{
	unsigned long orig_paddr, paddr;
	unsigned long *bitmap;
	int result = -ENOMEM;
	unsigned int index;
	struct page *pg;
	LIST_HEAD(list);
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	if (!pkram_pgd) {
		spin_lock(&pkram_pgd_lock);
		if (!pkram_pgd) {
			pg = __pkram_alloc_page(GFP_KERNEL | __GFP_ZERO, false);
			if (!pg)
				goto err;
			pkram_pgd = page_address(pg);
		}
		spin_unlock(&pkram_pgd_lock);
	}

	orig_paddr = paddr = __pa(page_address(page));
again:
	pgd = pkram_pgd;
	pgd += pgd_index(paddr);
	if (pgd_none(*pgd)) {
		spin_lock(&pkram_pgd_lock);
		if (pgd_none(*pgd)) {
			pg = __pkram_alloc_page(GFP_KERNEL|__GFP_ZERO, false);
			if (!pg)
				goto err;
			list_add(&pg->lru, &list);
			p4d = page_address(pg);
			set_pgd(pgd, __pgd(__pa(p4d)));
		}
		spin_unlock(&pkram_pgd_lock);
	}
	p4d = p4d_offset(pgd, paddr);
	if (p4d_none(*p4d)) {
		spin_lock(&pkram_pgd_lock);
		if (p4d_none(*p4d)) {
			pg = __pkram_alloc_page(GFP_KERNEL|__GFP_ZERO, false);
			if (!pg)
				goto err;
			list_add(&pg->lru, &list);
			pud = page_address(pg);
			set_p4d(p4d, __p4d(__pa(pud)));
		}
		spin_unlock(&pkram_pgd_lock);
	}
	pud = pud_offset(p4d, paddr);
	if (pud_none(*pud)) {
		spin_lock(&pkram_pgd_lock);
		if (pud_none(*pud)) {
			pg = __pkram_alloc_page(GFP_KERNEL|__GFP_ZERO, false);
			if (!pg)
				goto err;
			list_add(&pg->lru, &list);
			pmd = page_address(pg);
			set_pud(pud, __pud(__pa(pmd)));
		}
		spin_unlock(&pkram_pgd_lock);
	}
	pmd = pmd_offset(pud, paddr);
	if (pmd_none(*pmd)) {
		spin_lock(&pkram_pgd_lock);
		if (pmd_none(*pmd)) {
			if (PageTransHuge(page)) {
				set_pmd(pmd, pmd_mkhuge(*pmd));
				spin_unlock(&pkram_pgd_lock);
				goto next;
			}
			bitmap = pkram_alloc_pte_bitmap();
			if (!bitmap)
				goto err;
			pg = virt_to_page(bitmap);
			list_add(&pg->lru, &list);
			set_pmd(pmd, __pmd(__pa(bitmap)));
		} else {
			BUG_ON(pmd_large(*pmd));
			bitmap = __va(pmd_val(*pmd));
		}
		spin_unlock(&pkram_pgd_lock);
	} else {
		BUG_ON(pmd_large(*pmd));
		bitmap = __va(pmd_val(*pmd));
	}

	index = pte_index(paddr);
	BUG_ON(test_bit(index, bitmap));
	set_bit(index, bitmap);
	smp_mb__after_atomic();
	if (bitmap_full(bitmap, PTRS_PER_PTE))
		set_pmd(pmd, pmd_mkhuge(*pmd));
next:
	/* Add mappings for any pagetable pages that were allocated */
	if (!list_empty(&list)) {
		page = list_first_entry(&list, struct page, lru);
		list_del_init(&page->lru);
		paddr = __pa(page_address(page));
		goto again;
	}

	return 0;
err:
	spin_unlock(&pkram_pgd_lock);
	while (!list_empty(&list)) {
		pg = list_first_entry(&list, struct page, lru);
		list_del_init(&pg->lru);
	}
	return result;
}

static void pkram_remove_identity_map(struct page *page)
{
	unsigned long *bitmap;
	unsigned long paddr;
	unsigned int index;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	/*
	 * pkram_pgd will be null when freeing metadata pages after a reboot
	 */
	if (!pkram_pgd)
		return;

	paddr = __pa(page_address(page));
	pgd = pkram_pgd;
	pgd += pgd_index(paddr);
	if (pgd_none(*pgd)) {
		WARN_ONCE(1, "PKRAM: %s: no pgd for 0x%lx\n", __func__, paddr);
		return;
	}
	p4d = p4d_offset(pgd, paddr);
	if (p4d_none(*p4d)) {
		WARN_ONCE(1, "PKRAM: %s: no p4d for 0x%lx\n", __func__, paddr);
		return;
	}
	pud = pud_offset(p4d, paddr);
	if (pud_none(*pud)) {
		WARN_ONCE(1, "PKRAM: %s: no pud for 0x%lx\n", __func__, paddr);
		return;
	}
	pmd = pmd_offset(pud, paddr);
	if (pmd_none(*pmd)) {
		WARN_ONCE(1, "PKRAM: %s: no pmd for 0x%lx\n", __func__, paddr);
		return;
	}
	if (PageTransHuge(page)) {
		BUG_ON(!pmd_large(*pmd));
		pmd_clear(pmd);
		return;
	}

	if (pmd_large(*pmd)) {
		spin_lock(&pkram_pgd_lock);
		if (pmd_large(*pmd))
			set_pmd(pmd, __pmd(pte_val(pte_clrhuge(*(pte_t *)pmd))));
		spin_unlock(&pkram_pgd_lock);
	}

	bitmap = __va(pmd_val(*pmd));
	index = pte_index(paddr);
	clear_bit(index, bitmap);
	smp_mb__after_atomic();

	spin_lock(&pkram_pgd_lock);
	if (!pmd_none(*pmd) && bitmap_empty(bitmap, PTRS_PER_PTE)) {
		pmd_clear(pmd);
		spin_unlock(&pkram_pgd_lock);
		pkram_free_pte_bitmap(bitmap);
	} else {
		spin_unlock(&pkram_pgd_lock);
	}
}

static int __init pkram_reserve_range_cb(struct pkram_pg_state *st, unsigned long base, unsigned long size)
{
	if (memblock_is_region_reserved(base, size) ||
	    memblock_reserve(base, size) < 0) {
		pr_warn("PKRAM: reservations exist in [0x%lx,0x%lx]\n", base, base + size - 1);
		/*
		 * Set a lower bound so another walk can undo the earlier,
		 * successful reservations.
		 */
		st->min_addr = base + size;
		st->retval = -EBUSY;
		return 1;
	}

	pkram_reserved_pages += (size >> PAGE_SHIFT);
	return 0;
}

static int __init pkram_unreserve_range_cb(struct pkram_pg_state *st, unsigned long base, unsigned long size)
{
	memblock_free(base, size);
	pkram_reserved_pages -= (size >> PAGE_SHIFT);
	return 0;
}

/*
 * Walk the preserved pages pagetable and reserve each present address range.
 */
static int __init pkram_reserve_page_ranges(pgd_t *pgd)
{
	struct pkram_pg_state st = {
		.range_cb = pkram_reserve_range_cb,
		.max_addr = PHYS_ADDR_MAX,
	};
	int err = 0;

	pkram_walk_pgt_rev(&st, pgd);
	if ((int)st.retval < 0) {
		err = st.retval;
		st.retval = 0;
		st.range_cb = pkram_unreserve_range_cb;
		pkram_walk_pgt_rev(&st, pgd);
	}

	return err;
}

void pkram_free_pgt(void)
{
	if (!pkram_pgd)
		return;

	pkram_free_pgt_walk_pgd(pkram_pgd);

	__free_pages_core(virt_to_page(pkram_pgd), 0);
	pkram_pgd = NULL;
}

static int __init_memblock pkram_memblock_find_cb(struct pkram_pg_state *st, unsigned long base, unsigned long size)
{
	unsigned long end = base + size;
	unsigned long addr;

	if (size < st->min_size)
		return 0;

	addr =  memblock_find_in_range(base, end, st->min_size, PAGE_SIZE);
	if (!addr)
		return 0;

	st->retval = addr;
	return 1;
}

/*
 * It may be necessary to allocate a larger reserved memblock array
 * while populating it with ranges of preserved pages.  To avoid
 * trampling preserved pages that have not yet been added to the
 * memblock reserved list this function implements a wrapper around
 * memblock_find_in_range() that restricts searches to subranges
 * that do not contain preserved pages.
 */
phys_addr_t __init_memblock pkram_memblock_find_in_range(phys_addr_t start,
					phys_addr_t end, phys_addr_t size,
					phys_addr_t align)
{
	struct pkram_pg_state st = {
		.range_cb = pkram_memblock_find_cb,
		.min_addr = start,
		.max_addr = end,
		.min_size = PAGE_ALIGN(size),
		.find_holes = true,
	};

	if (!pkram_reservation_in_progress)
		return memblock_find_in_range(start, end, size, align);

	if (!pkram_pgd) {
		WARN_ONCE(1, "No preserved pages pagetable\n");
		return memblock_find_in_range(start, end, size, align);
	}

	WARN_ONCE(memblock_bottom_up(), "PKRAM: bottom up memblock allocation not yet supported\n");

	pkram_walk_pgt_rev(&st, pkram_pgd);

	return st.retval;
}

static int pkram_has_preserved_pages_cb(struct pkram_pg_state *st, unsigned long base, unsigned long size)
{
	st->retval = 1;
	return 1;
}

/*
 * Check whether the memory range [start, end) contains preserved pages.
 */
int pkram_has_preserved_pages(unsigned long start, unsigned long end)
{
	struct pkram_pg_state st = {
		.range_cb = pkram_has_preserved_pages_cb,
		.min_addr = start,
		.max_addr = end,
	};

	if (!pkram_pgd)
		return 0;

	pkram_walk_pgt_rev(&st, pkram_pgd);

	return st.retval;
}
