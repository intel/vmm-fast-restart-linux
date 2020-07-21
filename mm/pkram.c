// SPDX-License-Identifier: GPL-2.0
#include <linux/err.h>
#include <linux/gfp.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/pkram.h>
#include <linux/string.h>
#include <linux/types.h>

/*
 * Preserved memory is divided into nodes that can be saved or loaded
 * independently of each other. The nodes are identified by unique name
 * strings.
 *
 * The structure occupies a memory page.
 */
struct pkram_node {
	__u32	flags;

	__u8	name[PKRAM_NAME_MAX];
};

#define PKRAM_SAVE		1
#define PKRAM_LOAD		2
#define PKRAM_ACCMODE_MASK	3

static LIST_HEAD(pkram_nodes);			/* linked through page::lru */
static DEFINE_MUTEX(pkram_mutex);		/* serializes open/close */

static inline struct page *pkram_alloc_page(gfp_t gfp_mask)
{
	return alloc_page(gfp_mask);
}

static inline void pkram_free_page(void *addr)
{
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

static void pkram_stream_init(struct pkram_stream *ps,
			     struct pkram_node *node, gfp_t gfp_mask)
{
	memset(ps, 0, sizeof(*ps));
	ps->gfp_mask = gfp_mask;
	ps->node = node;
}

/**
 * Create a preserved memory node with name @name and initialize stream @ps
 * for saving data to it.
 *
 * @gfp_mask specifies the memory allocation mask to be used when saving data.
 *
 * Error values:
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
 * After the save has finished, pkram_finish_save_obj() (or pkram_discard_save()
 * in case of failure) is to be called.
 */
int pkram_prepare_save_obj(struct pkram_stream *ps)
{
	return -ENOSYS;
}

/**
 * Commit the object started with pkram_prepare_save_obj() to preserved memory.
 */
void pkram_finish_save_obj(struct pkram_stream *ps)
{
	BUG();
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

	pkram_free_page(node);
}

/**
 * Remove the preserved memory node with name @name and initialize stream @ps
 * for loading data from it.
 *
 * Returns 0 on success, -errno on failure.
 *
 * Error values:
 *	%ENOENT: node with specified name does not exist
 *	%EBUSY: save to required node has not finished yet
 *
 * After the load has finished, pkram_finish_load() is to be called.
 */
int pkram_prepare_load(struct pkram_stream *ps, const char *name)
{
	struct pkram_node *node;
	int err = 0;

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
 * After the load has finished, pkram_finish_load_obj() is to be called.
 */
int pkram_prepare_load_obj(struct pkram_stream *ps)
{
	return -ENOSYS;
}

/**
 * Finish the load of a preserved memory object started with
 * pkram_prepare_load_obj() freeing the object and any data that has not
 * been loaded from it.
 */
void pkram_finish_load_obj(struct pkram_stream *ps)
{
	BUG();
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

	pkram_free_page(node);
}

/**
 * Save page @page to the preserved memory node and object associated with
 * stream @ps. The stream must have been initialized with pkram_prepare_save()
 * and pkram_prepare_save_obj().
 *
 * @flags specifies supplemental page state to be preserved.
 *
 * Returns 0 on success, -errno on failure.
 */
int pkram_save_page(struct pkram_stream *ps, struct page *page, short flags)
{
	return -ENOSYS;
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
	return NULL;
}

/**
 * Copy @count bytes from @buf to the preserved memory node and object
 * associated with stream @ps. The stream must have been initialized with
 * pkram_prepare_save() and pkram_prepare_save_obj().
 *
 * On success, returns the number of bytes written, which is always equal to
 * @count. On failure, -errno is returned.
 */
ssize_t pkram_write(struct pkram_stream *ps, const void *buf, size_t count)
{
	return -ENOSYS;
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
	return 0;
}
