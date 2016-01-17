/*
 * fs/f2fs/recovery.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/fs.h>
#include <linux/f2fs_fs.h>
#include "f2fs.h"
#include "node.h"
#include "segment.h"

<<<<<<< HEAD
=======
/*
 * Roll forward recovery scenarios.
 *
 * [Term] F: fsync_mark, D: dentry_mark
 *
 * 1. inode(x) | CP | inode(x) | dnode(F)
 * -> Update the latest inode(x).
 *
 * 2. inode(x) | CP | inode(F) | dnode(F)
 * -> No problem.
 *
 * 3. inode(x) | CP | dnode(F) | inode(x)
 * -> Recover to the latest dnode(F), and drop the last inode(x)
 *
 * 4. inode(x) | CP | dnode(F) | inode(F)
 * -> No problem.
 *
 * 5. CP | inode(x) | dnode(F)
 * -> The inode(DF) was missing. Should drop this dnode(F).
 *
 * 6. CP | inode(DF) | dnode(F)
 * -> No problem.
 *
 * 7. CP | dnode(F) | inode(DF)
 * -> If f2fs_iget fails, then goto next to find inode(DF).
 *
 * 8. CP | dnode(F) | inode(x)
 * -> If f2fs_iget fails, then goto next to find inode(DF).
 *    But it will fail due to no inode(DF).
 */

>>>>>>> cm/cm-13.0
static struct kmem_cache *fsync_entry_slab;

bool space_for_roll_forward(struct f2fs_sb_info *sbi)
{
	if (sbi->last_valid_block_count + sbi->alloc_valid_block_count
			> sbi->user_block_count)
		return false;
	return true;
}

static struct fsync_inode_entry *get_fsync_inode(struct list_head *head,
								nid_t ino)
{
	struct fsync_inode_entry *entry;

	list_for_each_entry(entry, head, list)
		if (entry->inode->i_ino == ino)
			return entry;

	return NULL;
}

<<<<<<< HEAD
static int recover_dentry(struct page *ipage, struct inode *inode)
=======
static int recover_dentry(struct inode *inode, struct page *ipage)
>>>>>>> cm/cm-13.0
{
	struct f2fs_inode *raw_inode = F2FS_INODE(ipage);
	nid_t pino = le32_to_cpu(raw_inode->i_pino);
	struct f2fs_dir_entry *de;
	struct qstr name;
	struct page *page;
	struct inode *dir, *einode;
	int err = 0;

<<<<<<< HEAD
	dir = check_dirty_dir_inode(F2FS_SB(inode->i_sb), pino);
	if (!dir) {
		dir = f2fs_iget(inode->i_sb, pino);
		if (IS_ERR(dir)) {
			err = PTR_ERR(dir);
			goto out;
		}
		set_inode_flag(F2FS_I(dir), FI_DELAY_IPUT);
		add_dirty_dir_inode(dir);
=======
	dir = f2fs_iget(inode->i_sb, pino);
	if (IS_ERR(dir)) {
		err = PTR_ERR(dir);
		goto out;
	}

	if (file_enc_name(inode)) {
		iput(dir);
		return 0;
>>>>>>> cm/cm-13.0
	}

	name.len = le32_to_cpu(raw_inode->i_namelen);
	name.name = raw_inode->i_name;

	if (unlikely(name.len > F2FS_NAME_LEN)) {
		WARN_ON(1);
		err = -ENAMETOOLONG;
<<<<<<< HEAD
		goto out;
=======
		goto out_err;
>>>>>>> cm/cm-13.0
	}
retry:
	de = f2fs_find_entry(dir, &name, &page);
	if (de && inode->i_ino == le32_to_cpu(de->ino))
		goto out_unmap_put;
<<<<<<< HEAD
=======

>>>>>>> cm/cm-13.0
	if (de) {
		einode = f2fs_iget(inode->i_sb, le32_to_cpu(de->ino));
		if (IS_ERR(einode)) {
			WARN_ON(1);
<<<<<<< HEAD
			if (PTR_ERR(einode) == -ENOENT)
				err = -EEXIST;
			goto out_unmap_put;
		}
		err = acquire_orphan_inode(F2FS_SB(inode->i_sb));
=======
			err = PTR_ERR(einode);
			if (err == -ENOENT)
				err = -EEXIST;
			goto out_unmap_put;
		}
		err = acquire_orphan_inode(F2FS_I_SB(inode));
>>>>>>> cm/cm-13.0
		if (err) {
			iput(einode);
			goto out_unmap_put;
		}
<<<<<<< HEAD
		f2fs_delete_entry(de, page, einode);
		iput(einode);
		goto retry;
	}
	err = __f2fs_add_link(dir, &name, inode);
	goto out;

out_unmap_put:
	kunmap(page);
	f2fs_put_page(page, 0);
=======
		f2fs_delete_entry(de, page, dir, einode);
		iput(einode);
		goto retry;
	}
	err = __f2fs_add_link(dir, &name, inode, inode->i_ino, inode->i_mode);
	if (err)
		goto out_err;

	if (is_inode_flag_set(F2FS_I(dir), FI_DELAY_IPUT)) {
		iput(dir);
	} else {
		add_dirty_dir_inode(dir);
		set_inode_flag(F2FS_I(dir), FI_DELAY_IPUT);
	}

	goto out;

out_unmap_put:
	f2fs_dentry_kunmap(dir, page);
	f2fs_put_page(page, 0);
out_err:
	iput(dir);
>>>>>>> cm/cm-13.0
out:
	f2fs_msg(inode->i_sb, KERN_NOTICE,
			"%s: ino = %x, name = %s, dir = %lx, err = %d",
			__func__, ino_of_node(ipage), raw_inode->i_name,
			IS_ERR(dir) ? 0 : dir->i_ino, err);
	return err;
}

<<<<<<< HEAD
static int recover_inode(struct inode *inode, struct page *node_page)
{
	struct f2fs_inode *raw_inode = F2FS_INODE(node_page);

	if (!IS_INODE(node_page))
		return 0;

	inode->i_mode = le16_to_cpu(raw_inode->i_mode);
	i_size_write(inode, le64_to_cpu(raw_inode->i_size));
	inode->i_atime.tv_sec = le64_to_cpu(raw_inode->i_mtime);
	inode->i_ctime.tv_sec = le64_to_cpu(raw_inode->i_ctime);
	inode->i_mtime.tv_sec = le64_to_cpu(raw_inode->i_mtime);
	inode->i_atime.tv_nsec = le32_to_cpu(raw_inode->i_mtime_nsec);
	inode->i_ctime.tv_nsec = le32_to_cpu(raw_inode->i_ctime_nsec);
	inode->i_mtime.tv_nsec = le32_to_cpu(raw_inode->i_mtime_nsec);

	if (is_dent_dnode(node_page))
		return recover_dentry(node_page, inode);

	f2fs_msg(inode->i_sb, KERN_NOTICE, "recover_inode: ino = %x, name = %s",
			ino_of_node(node_page), raw_inode->i_name);
	return 0;
=======
static void recover_inode(struct inode *inode, struct page *page)
{
	struct f2fs_inode *raw = F2FS_INODE(page);
	char *name;

	inode->i_mode = le16_to_cpu(raw->i_mode);
	i_size_write(inode, le64_to_cpu(raw->i_size));
	inode->i_atime.tv_sec = le64_to_cpu(raw->i_mtime);
	inode->i_ctime.tv_sec = le64_to_cpu(raw->i_ctime);
	inode->i_mtime.tv_sec = le64_to_cpu(raw->i_mtime);
	inode->i_atime.tv_nsec = le32_to_cpu(raw->i_mtime_nsec);
	inode->i_ctime.tv_nsec = le32_to_cpu(raw->i_ctime_nsec);
	inode->i_mtime.tv_nsec = le32_to_cpu(raw->i_mtime_nsec);

	if (file_enc_name(inode))
		name = "<encrypted>";
	else
		name = F2FS_INODE(page)->i_name;

	f2fs_msg(inode->i_sb, KERN_NOTICE, "recover_inode: ino = %x, name = %s",
			ino_of_node(page), name);
>>>>>>> cm/cm-13.0
}

static int find_fsync_dnodes(struct f2fs_sb_info *sbi, struct list_head *head)
{
	unsigned long long cp_ver = cur_cp_version(F2FS_CKPT(sbi));
	struct curseg_info *curseg;
<<<<<<< HEAD
	struct page *page;
=======
	struct page *page = NULL;
>>>>>>> cm/cm-13.0
	block_t blkaddr;
	int err = 0;

	/* get node pages in the current segment */
	curseg = CURSEG_I(sbi, CURSEG_WARM_NODE);
	blkaddr = NEXT_FREE_BLKADDR(sbi, curseg);

<<<<<<< HEAD
	/* read node page */
	page = alloc_page(GFP_F2FS_ZERO);
	if (!page)
		return -ENOMEM;
	lock_page(page);
=======
	ra_meta_pages(sbi, blkaddr, 1, META_POR, true);
>>>>>>> cm/cm-13.0

	while (1) {
		struct fsync_inode_entry *entry;

<<<<<<< HEAD
		err = f2fs_submit_page_bio(sbi, page, blkaddr, READ_SYNC);
		if (err)
			return err;

		lock_page(page);
=======
		if (!is_valid_blkaddr(sbi, blkaddr, META_POR))
			return 0;

		page = get_tmp_page(sbi, blkaddr);
>>>>>>> cm/cm-13.0

		if (cp_ver != cpver_of_node(page))
			break;

		if (!is_fsync_dnode(page))
			goto next;

		entry = get_fsync_inode(head, ino_of_node(page));
<<<<<<< HEAD
		if (entry) {
			if (IS_INODE(page) && is_dent_dnode(page))
				set_inode_flag(F2FS_I(entry->inode),
							FI_INC_LINK);
		} else {
=======
		if (!entry) {
>>>>>>> cm/cm-13.0
			if (IS_INODE(page) && is_dent_dnode(page)) {
				err = recover_inode_page(sbi, page);
				if (err)
					break;
			}

			/* add this fsync inode to the list */
<<<<<<< HEAD
			entry = kmem_cache_alloc(fsync_entry_slab, GFP_NOFS);
=======
			entry = kmem_cache_alloc(fsync_entry_slab, GFP_F2FS_ZERO);
>>>>>>> cm/cm-13.0
			if (!entry) {
				err = -ENOMEM;
				break;
			}
<<<<<<< HEAD

=======
			/*
			 * CP | dnode(F) | inode(DF)
			 * For this case, we should not give up now.
			 */
>>>>>>> cm/cm-13.0
			entry->inode = f2fs_iget(sbi->sb, ino_of_node(page));
			if (IS_ERR(entry->inode)) {
				err = PTR_ERR(entry->inode);
				kmem_cache_free(fsync_entry_slab, entry);
<<<<<<< HEAD
=======
				if (err == -ENOENT) {
					err = 0;
					goto next;
				}
>>>>>>> cm/cm-13.0
				break;
			}
			list_add_tail(&entry->list, head);
		}
		entry->blkaddr = blkaddr;

<<<<<<< HEAD
		err = recover_inode(entry->inode, page);
		if (err && err != -ENOENT)
			break;
next:
		/* check next segment */
		blkaddr = next_blkaddr_of_node(page);
	}

	unlock_page(page);
	__free_pages(page, 0);

=======
		if (IS_INODE(page)) {
			entry->last_inode = blkaddr;
			if (is_dent_dnode(page))
				entry->last_dentry = blkaddr;
		}
next:
		/* check next segment */
		blkaddr = next_blkaddr_of_node(page);
		f2fs_put_page(page, 1);

		ra_meta_pages_cond(sbi, blkaddr);
	}
	f2fs_put_page(page, 1);
>>>>>>> cm/cm-13.0
	return err;
}

static void destroy_fsync_dnodes(struct list_head *head)
{
	struct fsync_inode_entry *entry, *tmp;

	list_for_each_entry_safe(entry, tmp, head, list) {
		iput(entry->inode);
		list_del(&entry->list);
		kmem_cache_free(fsync_entry_slab, entry);
	}
}

static int check_index_in_prev_nodes(struct f2fs_sb_info *sbi,
			block_t blkaddr, struct dnode_of_data *dn)
{
	struct seg_entry *sentry;
	unsigned int segno = GET_SEGNO(sbi, blkaddr);
	unsigned short blkoff = GET_BLKOFF_FROM_SEG0(sbi, blkaddr);
	struct f2fs_summary_block *sum_node;
	struct f2fs_summary sum;
	struct page *sum_page, *node_page;
<<<<<<< HEAD
=======
	struct dnode_of_data tdn = *dn;
>>>>>>> cm/cm-13.0
	nid_t ino, nid;
	struct inode *inode;
	unsigned int offset;
	block_t bidx;
	int i;

	sentry = get_seg_entry(sbi, segno);
	if (!f2fs_test_bit(blkoff, sentry->cur_valid_map))
		return 0;

	/* Get the previous summary */
	for (i = CURSEG_WARM_DATA; i <= CURSEG_COLD_DATA; i++) {
		struct curseg_info *curseg = CURSEG_I(sbi, i);
		if (curseg->segno == segno) {
			sum = curseg->sum_blk->entries[blkoff];
			goto got_it;
		}
	}

	sum_page = get_sum_page(sbi, segno);
	sum_node = (struct f2fs_summary_block *)page_address(sum_page);
	sum = sum_node->entries[blkoff];
	f2fs_put_page(sum_page, 1);
got_it:
	/* Use the locked dnode page and inode */
	nid = le32_to_cpu(sum.nid);
	if (dn->inode->i_ino == nid) {
<<<<<<< HEAD
		struct dnode_of_data tdn = *dn;
		tdn.nid = nid;
		tdn.node_page = dn->inode_page;
		tdn.ofs_in_node = le16_to_cpu(sum.ofs_in_node);
		truncate_data_blocks_range(&tdn, 1);
		return 0;
	} else if (dn->nid == nid) {
		struct dnode_of_data tdn = *dn;
		tdn.ofs_in_node = le16_to_cpu(sum.ofs_in_node);
		truncate_data_blocks_range(&tdn, 1);
		return 0;
=======
		tdn.nid = nid;
		if (!dn->inode_page_locked)
			lock_page(dn->inode_page);
		tdn.node_page = dn->inode_page;
		tdn.ofs_in_node = le16_to_cpu(sum.ofs_in_node);
		goto truncate_out;
	} else if (dn->nid == nid) {
		tdn.ofs_in_node = le16_to_cpu(sum.ofs_in_node);
		goto truncate_out;
>>>>>>> cm/cm-13.0
	}

	/* Get the node page */
	node_page = get_node_page(sbi, nid);
	if (IS_ERR(node_page))
		return PTR_ERR(node_page);

	offset = ofs_of_node(node_page);
	ino = ino_of_node(node_page);
	f2fs_put_page(node_page, 1);

<<<<<<< HEAD
	/* Deallocate previous index in the node page */
	inode = f2fs_iget(sbi->sb, ino);
	if (IS_ERR(inode))
		return PTR_ERR(inode);

	bidx = start_bidx_of_node(offset, F2FS_I(inode)) +
					le16_to_cpu(sum.ofs_in_node);

	truncate_hole(inode, bidx, bidx + 1);
	iput(inode);
=======
	if (ino != dn->inode->i_ino) {
		/* Deallocate previous index in the node page */
		inode = f2fs_iget(sbi->sb, ino);
		if (IS_ERR(inode))
			return PTR_ERR(inode);
	} else {
		inode = dn->inode;
	}

	bidx = start_bidx_of_node(offset, F2FS_I(inode)) +
			le16_to_cpu(sum.ofs_in_node);

	/*
	 * if inode page is locked, unlock temporarily, but its reference
	 * count keeps alive.
	 */
	if (ino == dn->inode->i_ino && dn->inode_page_locked)
		unlock_page(dn->inode_page);

	set_new_dnode(&tdn, inode, NULL, NULL, 0);
	if (get_dnode_of_data(&tdn, bidx, LOOKUP_NODE))
		goto out;

	if (tdn.data_blkaddr == blkaddr)
		truncate_data_blocks_range(&tdn, 1);

	f2fs_put_dnode(&tdn);
out:
	if (ino != dn->inode->i_ino)
		iput(inode);
	else if (dn->inode_page_locked)
		lock_page(dn->inode_page);
	return 0;

truncate_out:
	if (datablock_addr(tdn.node_page, tdn.ofs_in_node) == blkaddr)
		truncate_data_blocks_range(&tdn, 1);
	if (dn->inode->i_ino == nid && !dn->inode_page_locked)
		unlock_page(dn->inode_page);
>>>>>>> cm/cm-13.0
	return 0;
}

static int do_recover_data(struct f2fs_sb_info *sbi, struct inode *inode,
					struct page *page, block_t blkaddr)
{
	struct f2fs_inode_info *fi = F2FS_I(inode);
	unsigned int start, end;
	struct dnode_of_data dn;
<<<<<<< HEAD
	struct f2fs_summary sum;
	struct node_info ni;
	int err = 0, recovered = 0;

	if (recover_inline_data(inode, page))
		goto out;

	if (recover_xattr_data(inode, page, blkaddr))
		goto out;

	start = start_bidx_of_node(ofs_of_node(page), fi);
	if (IS_INODE(page))
		end = start + ADDRS_PER_INODE(fi);
	else
		end = start + ADDRS_PER_BLOCK;

	f2fs_lock_op(sbi);
=======
	struct node_info ni;
	int err = 0, recovered = 0;

	/* step 1: recover xattr */
	if (IS_INODE(page)) {
		recover_inline_xattr(inode, page);
	} else if (f2fs_has_xattr_block(ofs_of_node(page))) {
		/*
		 * Deprecated; xattr blocks should be found from cold log.
		 * But, we should remain this for backward compatibility.
		 */
		recover_xattr_data(inode, page, blkaddr);
		goto out;
	}

	/* step 2: recover inline data */
	if (recover_inline_data(inode, page))
		goto out;

	/* step 3: recover data indices */
	start = start_bidx_of_node(ofs_of_node(page), fi);
	end = start + ADDRS_PER_PAGE(page, fi);
>>>>>>> cm/cm-13.0

	set_new_dnode(&dn, inode, NULL, NULL, 0);

	err = get_dnode_of_data(&dn, start, ALLOC_NODE);
<<<<<<< HEAD
	if (err) {
		f2fs_unlock_op(sbi);
		goto out;
	}
=======
	if (err)
		goto out;
>>>>>>> cm/cm-13.0

	f2fs_wait_on_page_writeback(dn.node_page, NODE);

	get_node_info(sbi, dn.nid, &ni);
<<<<<<< HEAD
	f2fs_bug_on(ni.ino != ino_of_node(page));
	f2fs_bug_on(ofs_of_node(dn.node_page) != ofs_of_node(page));

	for (; start < end; start++) {
=======
	f2fs_bug_on(sbi, ni.ino != ino_of_node(page));
	f2fs_bug_on(sbi, ofs_of_node(dn.node_page) != ofs_of_node(page));

	for (; start < end; start++, dn.ofs_in_node++) {
>>>>>>> cm/cm-13.0
		block_t src, dest;

		src = datablock_addr(dn.node_page, dn.ofs_in_node);
		dest = datablock_addr(page, dn.ofs_in_node);

<<<<<<< HEAD
		if (src != dest && dest != NEW_ADDR && dest != NULL_ADDR) {
			if (src == NULL_ADDR) {
				err = reserve_new_block(&dn);
				/* We should not get -ENOSPC */
				f2fs_bug_on(err);
=======
		/* skip recovering if dest is the same as src */
		if (src == dest)
			continue;

		/* dest is invalid, just invalidate src block */
		if (dest == NULL_ADDR) {
			truncate_data_blocks_range(&dn, 1);
			continue;
		}

		/*
		 * dest is reserved block, invalidate src block
		 * and then reserve one new block in dnode page.
		 */
		if (dest == NEW_ADDR) {
			truncate_data_blocks_range(&dn, 1);
			err = reserve_new_block(&dn);
			f2fs_bug_on(sbi, err);
			continue;
		}

		/* dest is valid block, try to recover from src to dest */
		if (is_valid_blkaddr(sbi, dest, META_POR)) {

			if (src == NULL_ADDR) {
				err = reserve_new_block(&dn);
				/* We should not get -ENOSPC */
				f2fs_bug_on(sbi, err);
>>>>>>> cm/cm-13.0
			}

			/* Check the previous node page having this index */
			err = check_index_in_prev_nodes(sbi, dest, &dn);
			if (err)
				goto err;

<<<<<<< HEAD
			set_summary(&sum, dn.nid, dn.ofs_in_node, ni.version);

			/* write dummy data page */
			recover_data_page(sbi, NULL, &sum, src, dest);
			update_extent_cache(dest, &dn);
			recovered++;
		}
		dn.ofs_in_node++;
	}

	/* write node page in place */
	set_summary(&sum, dn.nid, 0, 0);
=======
			/* write dummy data page */
			f2fs_replace_block(sbi, &dn, src, dest,
							ni.version, false);
			recovered++;
		}
	}

>>>>>>> cm/cm-13.0
	if (IS_INODE(dn.node_page))
		sync_inode_page(&dn);

	copy_node_footer(dn.node_page, page);
	fill_node_footer(dn.node_page, dn.nid, ni.ino,
					ofs_of_node(page), false);
	set_page_dirty(dn.node_page);
<<<<<<< HEAD

	recover_node_page(sbi, dn.node_page, &sum, &ni, blkaddr);
err:
	f2fs_put_dnode(&dn);
	f2fs_unlock_op(sbi);
=======
err:
	f2fs_put_dnode(&dn);
>>>>>>> cm/cm-13.0
out:
	f2fs_msg(sbi->sb, KERN_NOTICE,
		"recover_data: ino = %lx, recovered = %d blocks, err = %d",
		inode->i_ino, recovered, err);
	return err;
}

static int recover_data(struct f2fs_sb_info *sbi,
				struct list_head *head, int type)
{
	unsigned long long cp_ver = cur_cp_version(F2FS_CKPT(sbi));
	struct curseg_info *curseg;
<<<<<<< HEAD
	struct page *page;
=======
	struct page *page = NULL;
>>>>>>> cm/cm-13.0
	int err = 0;
	block_t blkaddr;

	/* get node pages in the current segment */
	curseg = CURSEG_I(sbi, type);
	blkaddr = NEXT_FREE_BLKADDR(sbi, curseg);

<<<<<<< HEAD
	/* read node page */
	page = alloc_page(GFP_F2FS_ZERO);
	if (!page)
		return -ENOMEM;

	lock_page(page);

	while (1) {
		struct fsync_inode_entry *entry;

		err = f2fs_submit_page_bio(sbi, page, blkaddr, READ_SYNC);
		if (err)
			return err;

		lock_page(page);

		if (cp_ver != cpver_of_node(page))
			break;
=======
	while (1) {
		struct fsync_inode_entry *entry;

		if (!is_valid_blkaddr(sbi, blkaddr, META_POR))
			break;

		ra_meta_pages_cond(sbi, blkaddr);

		page = get_tmp_page(sbi, blkaddr);

		if (cp_ver != cpver_of_node(page)) {
			f2fs_put_page(page, 1);
			break;
		}
>>>>>>> cm/cm-13.0

		entry = get_fsync_inode(head, ino_of_node(page));
		if (!entry)
			goto next;
<<<<<<< HEAD

		err = do_recover_data(sbi, entry->inode, page, blkaddr);
		if (err)
			break;
=======
		/*
		 * inode(x) | CP | inode(x) | dnode(F)
		 * In this case, we can lose the latest inode(x).
		 * So, call recover_inode for the inode update.
		 */
		if (entry->last_inode == blkaddr)
			recover_inode(entry->inode, page);
		if (entry->last_dentry == blkaddr) {
			err = recover_dentry(entry->inode, page);
			if (err) {
				f2fs_put_page(page, 1);
				break;
			}
		}
		err = do_recover_data(sbi, entry->inode, page, blkaddr);
		if (err) {
			f2fs_put_page(page, 1);
			break;
		}
>>>>>>> cm/cm-13.0

		if (entry->blkaddr == blkaddr) {
			iput(entry->inode);
			list_del(&entry->list);
			kmem_cache_free(fsync_entry_slab, entry);
		}
next:
		/* check next segment */
		blkaddr = next_blkaddr_of_node(page);
<<<<<<< HEAD
	}

	unlock_page(page);
	__free_pages(page, 0);

=======
		f2fs_put_page(page, 1);
	}
>>>>>>> cm/cm-13.0
	if (!err)
		allocate_new_segments(sbi);
	return err;
}

int recover_fsync_data(struct f2fs_sb_info *sbi)
{
<<<<<<< HEAD
	struct list_head inode_list;
=======
	struct curseg_info *curseg = CURSEG_I(sbi, CURSEG_WARM_NODE);
	struct list_head inode_list;
	block_t blkaddr;
>>>>>>> cm/cm-13.0
	int err;
	bool need_writecp = false;

	fsync_entry_slab = f2fs_kmem_cache_create("f2fs_fsync_inode_entry",
			sizeof(struct fsync_inode_entry));
	if (!fsync_entry_slab)
		return -ENOMEM;

	INIT_LIST_HEAD(&inode_list);

<<<<<<< HEAD
	/* step #1: find fsynced inode numbers */
	sbi->por_doing = true;
=======
	/* prevent checkpoint */
	mutex_lock(&sbi->cp_mutex);

	blkaddr = NEXT_FREE_BLKADDR(sbi, curseg);

	/* step #1: find fsynced inode numbers */
>>>>>>> cm/cm-13.0
	err = find_fsync_dnodes(sbi, &inode_list);
	if (err)
		goto out;

	if (list_empty(&inode_list))
		goto out;

	need_writecp = true;

	/* step #2: recover data */
	err = recover_data(sbi, &inode_list, CURSEG_WARM_NODE);
<<<<<<< HEAD
	f2fs_bug_on(!list_empty(&inode_list));
out:
	destroy_fsync_dnodes(&inode_list);
	kmem_cache_destroy(fsync_entry_slab);
	sbi->por_doing = false;
	if (!err && need_writecp)
		write_checkpoint(sbi, false);
=======
	if (!err)
		f2fs_bug_on(sbi, !list_empty(&inode_list));
out:
	destroy_fsync_dnodes(&inode_list);
	kmem_cache_destroy(fsync_entry_slab);

	/* truncate meta pages to be used by the recovery */
	truncate_inode_pages_range(META_MAPPING(sbi),
			(loff_t)MAIN_BLKADDR(sbi) << PAGE_CACHE_SHIFT, -1);

	if (err) {
		truncate_inode_pages(NODE_MAPPING(sbi), 0);
		truncate_inode_pages(META_MAPPING(sbi), 0);
	}

	clear_sbi_flag(sbi, SBI_POR_DOING);
	if (err) {
		bool invalidate = false;

		if (discard_next_dnode(sbi, blkaddr))
			invalidate = true;

		/* Flush all the NAT/SIT pages */
		while (get_pages(sbi, F2FS_DIRTY_META))
			sync_meta_pages(sbi, META, LONG_MAX);

		/* invalidate temporary meta page */
		if (invalidate)
			invalidate_mapping_pages(META_MAPPING(sbi),
							blkaddr, blkaddr);

		set_ckpt_flags(sbi->ckpt, CP_ERROR_FLAG);
		mutex_unlock(&sbi->cp_mutex);
	} else if (need_writecp) {
		struct cp_control cpc = {
			.reason = CP_RECOVERY,
		};
		mutex_unlock(&sbi->cp_mutex);
		write_checkpoint(sbi, &cpc);
	} else {
		mutex_unlock(&sbi->cp_mutex);
	}
>>>>>>> cm/cm-13.0
	return err;
}
