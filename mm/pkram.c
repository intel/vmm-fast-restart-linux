// SPDX-License-Identifier: GPL-2.0
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/list.h>
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
};

static unsigned long pkram_sb_pfn __initdata;
static struct pkram_super_block *pkram_sb;

static pgd_t *pkram_pgd;
static DEFINE_SPINLOCK(pkram_pgd_lock);

static int pkram_add_identity_map(struct page *page);
static void pkram_remove_identity_map(struct page *page);

/*
 * For convenience sake PKRAM nodes are kept in an auxiliary doubly-linked list
 * connected through the lru field of the page struct.
 */
static LIST_HEAD(pkram_nodes);			/* linked through page::lru */
static DEFINE_MUTEX(pkram_mutex);		/* serializes open/close */

/*
 * The PKRAM super block pfn, see above.
 */
static int __init parse_pkram_sb_pfn(char *arg)
{
	return kstrtoul(arg, 16, &pkram_sb_pfn);
}
early_param("pkram", parse_pkram_sb_pfn);

static inline struct page *__pkram_alloc_page(gfp_t gfp_mask, bool add_to_map)
{
	struct page *page;
	int err;

	page = alloc_page(gfp_mask);
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
	pkram_remove_identity_map(virt_to_page(addr));
	free_page((unsigned long)addr);
}

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
	int order;
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

	list_for_each_entry_reverse(page, &pkram_nodes, lru) {
		node = page_address(page);
		if (WARN_ON(node->flags & PKRAM_ACCMODE_MASK))
			continue;
		node->node_pfn = node_pfn;
		node_pfn = page_to_pfn(page);
	}
	pkram_sb->node_pfn = node_pfn;
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

static struct kobj_attribute pkram_sb_pfn_attr =
	__ATTR(pkram, 0444, show_pkram_sb_pfn, NULL);

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
	if (pkram_init_sb()) {
		register_reboot_notifier(&pkram_reboot_notifier);
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
