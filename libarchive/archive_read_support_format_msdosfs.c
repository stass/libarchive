/*-
 * Copyright (c) 2026 Stanislav Sedov <stas@deglitch.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * FAT (msdosfs) filesystem image reader for libarchive.
 *
 * Reads FAT12, FAT16, and FAT32 disk images, presenting each file and
 * directory as an archive entry.  On first read_header() the entire
 * directory tree is walked and a sorted list of entries is built; files
 * are then delivered in disk-offset order for efficient forward reading.
 *
 * The FAT table is loaded into memory once during initialization.
 */

#include "archive_platform.h"

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "archive.h"
#include "archive_endian.h"
#include "archive_entry.h"
#include "archive_entry_locale.h"
#include "archive_private.h"
#include "archive_read_private.h"
#include "archive_string.h"

#define DIR_ENTRY_SIZE	32

/* Directory entry attributes. */
#define ATTR_READ_ONLY	0x01
#define ATTR_HIDDEN	0x02
#define ATTR_SYSTEM	0x04
#define ATTR_VOLUME_ID	0x08
#define ATTR_DIRECTORY	0x10
#define ATTR_ARCHIVE	0x20
#define ATTR_LONG_NAME	(ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID)

/* Cluster count thresholds (same as writer). */
#define FAT12_MAX_CLUSTERS	4084
#define FAT16_MAX_CLUSTERS	65524

/* End-of-chain markers. */
#define FAT12_EOC	0xFF8
#define FAT16_EOC	0xFFF8
#define FAT32_EOC	0x0FFFFFF8

/* Maximum directory recursion depth. */
#define MAX_DIR_DEPTH	64

/* Maximum cluster chain length (safety limit). */
#define MAX_CHAIN_LENGTH	(1 << 28)

/* Initial entry array allocation. */
#define INITIAL_ENTRIES	256

/* A single file or directory discovered during directory walk. */
struct msdosfs_file {
	struct archive_string pathname;	/* full path */
	uint64_t	disk_offset;	/* byte offset of first cluster */
	uint32_t	first_cluster;
	uint32_t	size;		/* file size (0 for dirs) */
	uint8_t		attr;		/* FAT attributes */
	time_t		mtime;
	time_t		ctime;
	time_t		atime;
	int		is_dir;
};

/* Main reader state. */
struct msdosfs_read {
	/* BPB-derived geometry. */
	int		fat_type;	/* 12, 16, or 32 */
	uint32_t	sector_size;
	uint32_t	cluster_size;	/* sectors per cluster */
	uint32_t	reserved_sectors;
	uint8_t		num_fats;
	uint32_t	fat_size;	/* sectors per FAT */
	uint32_t	root_entries;	/* FAT12/16 root entry count */
	uint32_t	total_sectors;
	uint32_t	cluster_count;	/* total data clusters */
	uint32_t	root_cluster;	/* FAT32 root cluster */

	/* Computed byte offsets. */
	uint64_t	fat_offset;
	uint64_t	root_dir_offset;	/* FAT12/16 only */
	uint64_t	data_offset;

	/* In-memory FAT table. */
	unsigned char	*fat_table;
	size_t		fat_table_size;

	/* Sorted entry array. */
	struct msdosfs_file *entries;
	int		entry_count;
	int		entry_alloc;
	int		current_entry;

	/* Current file data state. */
	uint64_t	entry_bytes_remaining;
	size_t		entry_bytes_unconsumed;
	int64_t		entry_sparse_offset;

	/* Cluster chain for current file. */
	uint32_t	*chain;
	uint32_t	chain_count;
	uint32_t	chain_index;
	uint32_t	chain_offset_in_cluster; /* bytes consumed in current cluster */

	/* String conversion for LFN (UTF-16LE -> locale). */
	struct archive_string_conv *sconv_utf16le;
};

static int	archive_read_format_msdosfs_bid(struct archive_read *, int);
static int	archive_read_format_msdosfs_options(struct archive_read *,
		    const char *, const char *);
static int	archive_read_format_msdosfs_read_header(struct archive_read *,
		    struct archive_entry *);
static int	archive_read_format_msdosfs_read_data(struct archive_read *,
		    const void **, size_t *, int64_t *);
static int	archive_read_format_msdosfs_read_data_skip(struct archive_read *);
static int	archive_read_format_msdosfs_cleanup(struct archive_read *);

static int	msdosfs_initialize(struct archive_read *);
static int	msdosfs_parse_bpb(struct archive_read *, const unsigned char *);
static int	msdosfs_load_fat(struct archive_read *);
static int	msdosfs_walk_directory(struct archive_read *,
		    uint32_t, uint64_t, uint32_t, const char *, int);
static int	msdosfs_read_dir_data(struct archive_read *,
		    uint32_t, uint64_t, uint32_t,
		    unsigned char **, size_t *);
static int	msdosfs_add_entry(struct archive_read *,
		    const char *, uint32_t, uint32_t,
		    uint8_t, time_t, time_t, time_t, int);
static uint32_t	fat_next_cluster(struct msdosfs_read *, uint32_t);
static int	msdosfs_build_chain(struct archive_read *, uint32_t);
static time_t	msdosfs_decode_datetime(uint16_t, uint16_t);
static unsigned char lfn_checksum(const unsigned char *);
static int	entry_cmp(const void *, const void *);

int
archive_read_support_format_msdosfs(struct archive *_a)
{
	struct archive_read *a = (struct archive_read *)_a;
	struct msdosfs_read *msdos;
	int r;

	archive_check_magic(_a, ARCHIVE_READ_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_read_support_format_msdosfs");

	msdos = (struct msdosfs_read *)calloc(1, sizeof(*msdos));
	if (msdos == NULL) {
		archive_set_error(&a->archive, ENOMEM,
		    "Can't allocate msdosfs data");
		return (ARCHIVE_FATAL);
	}
	msdos->current_entry = -1;

	r = __archive_read_register_format(a, msdos, "msdosfs",
	    archive_read_format_msdosfs_bid,
	    archive_read_format_msdosfs_options,
	    archive_read_format_msdosfs_read_header,
	    archive_read_format_msdosfs_read_data,
	    archive_read_format_msdosfs_read_data_skip,
	    NULL,	/* seek_data */
	    archive_read_format_msdosfs_cleanup,
	    NULL,	/* format_capabilities */
	    NULL);	/* has_encrypted_entries */

	if (r != ARCHIVE_OK) {
		free(msdos);
		return (r);
	}
	return (ARCHIVE_OK);
}

static int
archive_read_format_msdosfs_bid(struct archive_read *a, int best_bid)
{
	const unsigned char *p;
	ssize_t avail;
	uint16_t bytes_per_sec, reserved;
	uint8_t sec_per_clus, num_fats, media;
	uint16_t fat_sz16;
	uint32_t fat_sz32;
	uint16_t tot16;
	uint32_t tot32;
	int bid;

	if (best_bid > 30)
		return (-1);

	p = __archive_read_ahead(a, 512, &avail);
	if (p == NULL || avail < 512)
		return (-1);

	/* Boot sector signature. */
	if (p[510] != 0x55 || p[511] != 0xAA)
		return (-1);

	/* Reject EXFAT and NTFS. */
	if (memcmp(p + 3, "EXFAT   ", 8) == 0)
		return (0);
	if (memcmp(p + 3, "NTFS    ", 8) == 0)
		return (0);

	bid = 0;

	/* Bytes per sector must be a power of 2: 512, 1024, 2048, 4096. */
	bytes_per_sec = archive_le16dec(p + 11);
	if (bytes_per_sec != 512 && bytes_per_sec != 1024 &&
	    bytes_per_sec != 2048 && bytes_per_sec != 4096)
		return (0);
	bid += 8;

	/* Sectors per cluster must be a power of 2 in [1..128]. */
	sec_per_clus = p[13];
	if (sec_per_clus == 0 || (sec_per_clus & (sec_per_clus - 1)) != 0 ||
	    sec_per_clus > 128)
		return (0);
	bid += 4;

	/* Number of FATs: should be 1 or 2. */
	num_fats = p[16];
	if (num_fats < 1 || num_fats > 2)
		return (0);
	bid += 4;

	/* Media descriptor: 0xF0 or >= 0xF8. */
	media = p[21];
	if (media != 0xF0 && media < 0xF8)
		return (0);
	bid += 4;

	/* Reserved sectors >= 1. */
	reserved = archive_le16dec(p + 14);
	if (reserved < 1)
		return (0);
	bid += 2;

	/* FAT size: at least one of fat_sz16 or fat_sz32 must be nonzero. */
	fat_sz16 = archive_le16dec(p + 22);
	fat_sz32 = archive_le32dec(p + 36);
	if (fat_sz16 == 0 && fat_sz32 == 0)
		return (0);
	bid += 4;

	/* Total sectors: at least one must be nonzero. */
	tot16 = archive_le16dec(p + 19);
	tot32 = archive_le32dec(p + 32);
	if (tot16 == 0 && tot32 == 0)
		return (0);
	bid += 4;

	return (bid);
}

static int
archive_read_format_msdosfs_options(struct archive_read *a __LA_UNUSED,
    const char *key __LA_UNUSED, const char *val __LA_UNUSED)
{
	/* No options supported yet. */
	return (ARCHIVE_WARN);
}

static int
archive_read_format_msdosfs_read_header(struct archive_read *a,
    struct archive_entry *entry)
{
	struct msdosfs_read *msdos;
	struct msdosfs_file *file;
	int r;

	msdos = (struct msdosfs_read *)(a->format->data);

	/* Initialize on first call. */
	if (msdos->current_entry == -1) {
		a->archive.archive_format = ARCHIVE_FORMAT_MSDOSFS;
		a->archive.archive_format_name = "MSDOS FAT";

		r = msdosfs_initialize(a);
		if (r != ARCHIVE_OK)
			return (r);
	}

	/* Consume any leftover bytes from previous entry. */
	if (msdos->entry_bytes_unconsumed > 0) {
		__archive_read_consume(a, msdos->entry_bytes_unconsumed);
		msdos->entry_bytes_unconsumed = 0;
	}

	/* Free previous cluster chain. */
	free(msdos->chain);
	msdos->chain = NULL;
	msdos->chain_count = 0;
	msdos->chain_index = 0;
	msdos->chain_offset_in_cluster = 0;

	/* End of entries? */
	if (msdos->current_entry >= msdos->entry_count)
		return (ARCHIVE_EOF);

	file = &msdos->entries[msdos->current_entry++];

	/* Populate archive_entry. */
	archive_entry_set_pathname(entry, file->pathname.s);

	if (file->is_dir) {
		archive_entry_set_filetype(entry, AE_IFDIR);
		if (file->attr & ATTR_READ_ONLY)
			archive_entry_set_mode(entry, AE_IFDIR | 0555);
		else
			archive_entry_set_mode(entry, AE_IFDIR | 0755);
		archive_entry_set_size(entry, 0);
	} else {
		archive_entry_set_filetype(entry, AE_IFREG);
		if (file->attr & ATTR_READ_ONLY)
			archive_entry_set_mode(entry, AE_IFREG | 0444);
		else
			archive_entry_set_mode(entry, AE_IFREG | 0644);
		archive_entry_set_size(entry, file->size);
	}

	archive_entry_set_mtime(entry, file->mtime, 0);
	archive_entry_set_ctime(entry, file->ctime, 0);
	archive_entry_set_atime(entry, file->atime, 0);

	/* Set up data reading state for regular files. */
	msdos->entry_bytes_remaining = file->size;
	msdos->entry_sparse_offset = 0;
	msdos->entry_bytes_unconsumed = 0;

	if (!file->is_dir && file->size > 0 && file->first_cluster >= 2) {
		r = msdosfs_build_chain(a, file->first_cluster);
		if (r != ARCHIVE_OK)
			return (r);
		msdos->chain_index = 0;
		msdos->chain_offset_in_cluster = 0;

		/* Seek to start of first cluster. */
		{
			uint64_t target = msdos->data_offset +
			    (uint64_t)(file->first_cluster - 2) *
			    msdos->cluster_size * msdos->sector_size;
			int64_t sr = __archive_read_seek(a,
			    (int64_t)target, SEEK_SET);
			if (sr < 0) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "Failed to seek to file data");
				return (ARCHIVE_FATAL);
			}
		}
	}

	return (ARCHIVE_OK);
}

static int
archive_read_format_msdosfs_read_data(struct archive_read *a,
    const void **buff, size_t *size, int64_t *offset)
{
	struct msdosfs_read *msdos;
	uint32_t cluster_bytes;
	uint32_t bytes_in_cluster;
	ssize_t bytes_read;
	const void *p;

	msdos = (struct msdosfs_read *)(a->format->data);

	/* Consume previous read. */
	if (msdos->entry_bytes_unconsumed > 0) {
		__archive_read_consume(a, msdos->entry_bytes_unconsumed);
		msdos->entry_bytes_unconsumed = 0;
	}

	if (msdos->entry_bytes_remaining == 0) {
		*buff = NULL;
		*size = 0;
		*offset = msdos->entry_sparse_offset;
		return (ARCHIVE_EOF);
	}

	if (msdos->chain == NULL || msdos->chain_count == 0) {
		*buff = NULL;
		*size = 0;
		*offset = msdos->entry_sparse_offset;
		return (ARCHIVE_EOF);
	}

	cluster_bytes = msdos->cluster_size * msdos->sector_size;

	/* If we've consumed the current cluster, advance to the next. */
	if (msdos->chain_offset_in_cluster >= cluster_bytes) {
		msdos->chain_index++;
		msdos->chain_offset_in_cluster = 0;

		if (msdos->chain_index >= msdos->chain_count) {
			/* Chain exhausted before bytes ran out. */
			msdos->entry_bytes_remaining = 0;
			*buff = NULL;
			*size = 0;
			*offset = msdos->entry_sparse_offset;
			return (ARCHIVE_EOF);
		}

		/* Check if we need to seek (non-contiguous cluster). */
		if (msdos->chain[msdos->chain_index] !=
		    msdos->chain[msdos->chain_index - 1] + 1) {
			uint64_t target = msdos->data_offset +
			    (uint64_t)(msdos->chain[msdos->chain_index] - 2) *
			    cluster_bytes;
			int64_t sr = __archive_read_seek(a,
			    (int64_t)target, SEEK_SET);
			if (sr < 0) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "Failed to seek to cluster");
				return (ARCHIVE_FATAL);
			}
		}
	}

	/* How many bytes left in this cluster? */
	bytes_in_cluster = cluster_bytes - msdos->chain_offset_in_cluster;

	/* Don't read past end of file. */
	if (bytes_in_cluster > msdos->entry_bytes_remaining)
		bytes_in_cluster = (uint32_t)msdos->entry_bytes_remaining;

	/* Read from the archive stream. */
	p = __archive_read_ahead(a, 1, &bytes_read);
	if (p == NULL || bytes_read <= 0) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Truncated FAT image");
		return (ARCHIVE_FATAL);
	}

	if ((uint32_t)bytes_read > bytes_in_cluster)
		bytes_read = (ssize_t)bytes_in_cluster;

	*buff = p;
	*size = (size_t)bytes_read;
	*offset = msdos->entry_sparse_offset;

	msdos->entry_sparse_offset += bytes_read;
	msdos->entry_bytes_remaining -= bytes_read;
	msdos->entry_bytes_unconsumed = (size_t)bytes_read;
	msdos->chain_offset_in_cluster += (uint32_t)bytes_read;

	return (ARCHIVE_OK);
}

static int
archive_read_format_msdosfs_read_data_skip(struct archive_read *a)
{
	struct msdosfs_read *msdos;

	msdos = (struct msdosfs_read *)(a->format->data);

	if (msdos->entry_bytes_unconsumed > 0) {
		__archive_read_consume(a, msdos->entry_bytes_unconsumed);
		msdos->entry_bytes_unconsumed = 0;
	}
	msdos->entry_bytes_remaining = 0;
	return (ARCHIVE_OK);
}

static int
archive_read_format_msdosfs_cleanup(struct archive_read *a)
{
	struct msdosfs_read *msdos;
	int i;

	msdos = (struct msdosfs_read *)(a->format->data);
	if (msdos == NULL)
		return (ARCHIVE_OK);

	free(msdos->fat_table);
	free(msdos->chain);

	if (msdos->entries != NULL) {
		for (i = 0; i < msdos->entry_count; i++)
			archive_string_free(&msdos->entries[i].pathname);
		free(msdos->entries);
	}

	free(msdos);
	a->format->data = NULL;
	return (ARCHIVE_OK);
}

/*
 * Initialization: parse BPB, load FAT, walk directory tree.
 */
static int
msdosfs_initialize(struct archive_read *a)
{
	struct msdosfs_read *msdos;
	const unsigned char *p;
	ssize_t avail;
	int r;

	msdos = (struct msdosfs_read *)(a->format->data);

	/* Read boot sector. */
	p = __archive_read_ahead(a, 512, &avail);
	if (p == NULL || avail < 512) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
		    "Truncated FAT boot sector");
		return (ARCHIVE_FATAL);
	}

	r = msdosfs_parse_bpb(a, p);
	if (r != ARCHIVE_OK)
		return (r);

	/* Load FAT table into memory. */
	r = msdosfs_load_fat(a);
	if (r != ARCHIVE_OK)
		return (r);

	/* Allocate initial entry array. */
	msdos->entries = (struct msdosfs_file *)calloc(INITIAL_ENTRIES,
	    sizeof(struct msdosfs_file));
	if (msdos->entries == NULL) {
		archive_set_error(&a->archive, ENOMEM,
		    "Can't allocate entry array");
		return (ARCHIVE_FATAL);
	}
	msdos->entry_alloc = INITIAL_ENTRIES;
	msdos->entry_count = 0;

	/* Create UTF-16LE converter for LFN. */
	msdos->sconv_utf16le =
	    archive_string_conversion_from_charset(&a->archive,
	    "UTF-16LE", 1);

	/* Walk directory tree starting from root. */
	if (msdos->fat_type == 32) {
		/* FAT32: root is cluster-based. */
		r = msdosfs_walk_directory(a,
		    msdos->root_cluster, 0, 0, "", 0);
	} else {
		/* FAT12/16: root is at fixed offset. */
		r = msdosfs_walk_directory(a,
		    0, msdos->root_dir_offset,
		    msdos->root_entries * DIR_ENTRY_SIZE, "", 0);
	}
	if (r != ARCHIVE_OK)
		return (r);

	/* Sort entries by disk offset for efficient forward reading. */
	if (msdos->entry_count > 0)
		qsort(msdos->entries, msdos->entry_count,
		    sizeof(struct msdosfs_file), entry_cmp);

	msdos->current_entry = 0;
	return (ARCHIVE_OK);
}

/*
 * BPB processing
 */
static int
msdosfs_parse_bpb(struct archive_read *a, const unsigned char *p)
{
	struct msdosfs_read *msdos;
	uint32_t root_dir_sectors, data_sectors;

	msdos = (struct msdosfs_read *)(a->format->data);

	msdos->sector_size = archive_le16dec(p + 11);
	msdos->cluster_size = p[13];
	msdos->reserved_sectors = archive_le16dec(p + 14);
	msdos->num_fats = p[16];
	msdos->root_entries = archive_le16dec(p + 17);

	msdos->total_sectors = archive_le16dec(p + 19);
	if (msdos->total_sectors == 0)
		msdos->total_sectors = archive_le32dec(p + 32);

	msdos->fat_size = archive_le16dec(p + 22);
	if (msdos->fat_size == 0)
		msdos->fat_size = archive_le32dec(p + 36);

	if (msdos->sector_size == 0 || msdos->cluster_size == 0 ||
	    msdos->num_fats == 0 || msdos->fat_size == 0 ||
	    msdos->total_sectors == 0) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
		    "Invalid FAT BPB parameters");
		return (ARCHIVE_FATAL);
	}

	msdos->fat_offset = (uint64_t)msdos->reserved_sectors *
	    msdos->sector_size;

	root_dir_sectors = ((msdos->root_entries * DIR_ENTRY_SIZE) +
	    (msdos->sector_size - 1)) / msdos->sector_size;

	msdos->root_dir_offset = msdos->fat_offset +
	    (uint64_t)msdos->num_fats * msdos->fat_size * msdos->sector_size;

	msdos->data_offset = msdos->root_dir_offset +
	    (uint64_t)root_dir_sectors * msdos->sector_size;

	/* Determine FAT type from cluster count. */
	data_sectors = msdos->total_sectors - msdos->reserved_sectors -
	    (msdos->num_fats * msdos->fat_size) - root_dir_sectors;
	msdos->cluster_count = data_sectors / msdos->cluster_size;

	if (msdos->cluster_count <= FAT12_MAX_CLUSTERS)
		msdos->fat_type = 12;
	else if (msdos->cluster_count <= FAT16_MAX_CLUSTERS)
		msdos->fat_type = 16;
	else
		msdos->fat_type = 32;

	/* FAT32: root cluster from extended BPB. */
	if (msdos->fat_type == 32) {
		msdos->root_cluster = archive_le32dec(p + 44);
		if (msdos->root_cluster < 2) {
			archive_set_error(&a->archive,
			    ARCHIVE_ERRNO_FILE_FORMAT,
			    "Invalid FAT32 root cluster");
			return (ARCHIVE_FATAL);
		}
	}

	return (ARCHIVE_OK);
}

/*
 * Load the FAT table into memory.
 */
static int
msdosfs_load_fat(struct archive_read *a)
{
	struct msdosfs_read *msdos;
	const unsigned char *p;
	ssize_t avail;
	int64_t sr;

	msdos = (struct msdosfs_read *)(a->format->data);

	msdos->fat_table_size = (size_t)msdos->fat_size * msdos->sector_size;

	/* Seek to FAT. */
	sr = __archive_read_seek(a, (int64_t)msdos->fat_offset, SEEK_SET);
	if (sr < 0) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Cannot seek to FAT table; "
		    "msdosfs requires a seekable input");
		return (ARCHIVE_FATAL);
	}

	msdos->fat_table = (unsigned char *)malloc(msdos->fat_table_size);
	if (msdos->fat_table == NULL) {
		archive_set_error(&a->archive, ENOMEM,
		    "Can't allocate FAT table (%zu bytes)",
		    msdos->fat_table_size);
		return (ARCHIVE_FATAL);
	}

	/* Read FAT into memory.  May need multiple reads. */
	{
		size_t remaining = msdos->fat_table_size;
		size_t copied = 0;

		while (remaining > 0) {
			p = __archive_read_ahead(a, 1, &avail);
			if (p == NULL || avail <= 0) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_FILE_FORMAT,
				    "Truncated FAT table");
				return (ARCHIVE_FATAL);
			}
			if ((size_t)avail > remaining)
				avail = (ssize_t)remaining;
			memcpy(msdos->fat_table + copied, p, avail);
			__archive_read_consume(a, avail);
			copied += avail;
			remaining -= avail;
		}
	}

	return (ARCHIVE_OK);
}

/*
 * Get the next cluster in a FAT chain.
 * Returns the next cluster number, or >= FAT32_EOC if end-of-chain.
 */
static uint32_t
fat_next_cluster(struct msdosfs_read *msdos, uint32_t cluster)
{
	uint32_t val;
	uint32_t off;

	if (msdos->fat_type == 12) {
		off = (cluster * 3) / 2;
		if (off + 1 >= msdos->fat_table_size)
			return (FAT32_EOC);
		val = msdos->fat_table[off] |
		    ((uint32_t)msdos->fat_table[off + 1] << 8);
		if (cluster & 1)
			val >>= 4;
		else
			val &= 0xFFF;
		if (val >= FAT12_EOC)
			return (FAT32_EOC);
	} else if (msdos->fat_type == 16) {
		off = cluster * 2;
		if (off + 1 >= msdos->fat_table_size)
			return (FAT32_EOC);
		val = archive_le16dec(msdos->fat_table + off);
		if (val >= FAT16_EOC)
			return (FAT32_EOC);
	} else {
		off = cluster * 4;
		if (off + 3 >= msdos->fat_table_size)
			return (FAT32_EOC);
		val = archive_le32dec(msdos->fat_table + off) & 0x0FFFFFFF;
		if (val >= FAT32_EOC)
			return (FAT32_EOC);
	}

	return (val);
}

static int
msdosfs_build_chain(struct archive_read *a, uint32_t first_cluster)
{
	struct msdosfs_read *msdos;
	uint32_t cluster;
	uint32_t count;
	uint32_t alloc;
	uint32_t *chain;

	msdos = (struct msdosfs_read *)(a->format->data);

	/* Free previous chain. */
	free(msdos->chain);
	msdos->chain = NULL;
	msdos->chain_count = 0;

	alloc = 64;
	chain = (uint32_t *)malloc(alloc * sizeof(uint32_t));
	if (chain == NULL) {
		archive_set_error(&a->archive, ENOMEM,
		    "Can't allocate cluster chain");
		return (ARCHIVE_FATAL);
	}

	cluster = first_cluster;
	count = 0;

	while (cluster >= 2 && cluster < FAT32_EOC) {
		if (count >= MAX_CHAIN_LENGTH) {
			archive_set_error(&a->archive,
			    ARCHIVE_ERRNO_FILE_FORMAT,
			    "FAT cluster chain too long (possible loop)");
			free(chain);
			return (ARCHIVE_FATAL);
		}
		if (count >= alloc) {
			uint32_t newalloc = alloc * 2;
			uint32_t *newchain;
			newchain = (uint32_t *)realloc(chain,
			    newalloc * sizeof(uint32_t));
			if (newchain == NULL) {
				archive_set_error(&a->archive, ENOMEM,
				    "Can't grow cluster chain");
				free(chain);
				return (ARCHIVE_FATAL);
			}
			chain = newchain;
			alloc = newalloc;
		}
		chain[count++] = cluster;
		cluster = fat_next_cluster(msdos, cluster);
	}

	msdos->chain = chain;
	msdos->chain_count = count;
	return (ARCHIVE_OK);
}

/*
 * Decode DOS date/time to time_t.
 */
static time_t
msdosfs_decode_datetime(uint16_t dos_date, uint16_t dos_time)
{
	struct tm t;

	if (dos_date == 0 && dos_time == 0)
		return (0);

	memset(&t, 0, sizeof(t));
	t.tm_sec = (dos_time & 0x1F) * 2;
	t.tm_min = (dos_time >> 5) & 0x3F;
	t.tm_hour = (dos_time >> 11) & 0x1F;
	t.tm_mday = dos_date & 0x1F;
	t.tm_mon = ((dos_date >> 5) & 0x0F) - 1;
	t.tm_year = ((dos_date >> 9) & 0x7F) + 80;
	t.tm_isdst = -1;

	if (t.tm_mday < 1)
		t.tm_mday = 1;
	if (t.tm_mon < 0)
		t.tm_mon = 0;

	return (mktime(&t));
}

static unsigned char
lfn_checksum(const unsigned char *shortname)
{
	unsigned char sum;
	int i;

	sum = 0;
	for (i = 0; i < 11; i++)
		sum = (unsigned char)((sum >> 1) +
		    ((sum & 1) ? 0x80 : 0) + shortname[i]);
	return (sum);
}

static int
msdosfs_read_dir_data(struct archive_read *a,
    uint32_t first_cluster, uint64_t fixed_offset, uint32_t fixed_size,
    unsigned char **out_buf, size_t *out_size)
{
	struct msdosfs_read *msdos;
	const unsigned char *p;
	ssize_t avail;

	msdos = (struct msdosfs_read *)(a->format->data);

	if (first_cluster == 0) {
		/* Fixed root directory (FAT12/16). */
		unsigned char *buf;
		size_t remaining;
		size_t copied;

		if (fixed_size == 0) {
			*out_buf = NULL;
			*out_size = 0;
			return (ARCHIVE_OK);
		}

		buf = (unsigned char *)malloc(fixed_size);
		if (buf == NULL) {
			archive_set_error(&a->archive, ENOMEM,
			    "Can't allocate root directory buffer");
			return (ARCHIVE_FATAL);
		}

		if (__archive_read_seek(a, (int64_t)fixed_offset,
		    SEEK_SET) < 0) {
			free(buf);
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Cannot seek to root directory");
			return (ARCHIVE_FATAL);
		}

		remaining = fixed_size;
		copied = 0;
		while (remaining > 0) {
			p = __archive_read_ahead(a, 1, &avail);
			if (p == NULL || avail <= 0) {
				free(buf);
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_FILE_FORMAT,
				    "Truncated root directory");
				return (ARCHIVE_FATAL);
			}
			if ((size_t)avail > remaining)
				avail = (ssize_t)remaining;
			memcpy(buf + copied, p, avail);
			__archive_read_consume(a, avail);
			copied += avail;
			remaining -= avail;
		}

		*out_buf = buf;
		*out_size = fixed_size;
		return (ARCHIVE_OK);
	} else {
		/* Cluster-based directory. */
		uint32_t cluster;
		uint32_t cluster_bytes;
		unsigned char *buf;
		size_t buf_size;
		size_t buf_alloc;
		uint32_t chain_len;

		cluster_bytes = msdos->cluster_size * msdos->sector_size;
		buf_alloc = cluster_bytes * 4;
		buf = (unsigned char *)malloc(buf_alloc);
		if (buf == NULL) {
			archive_set_error(&a->archive, ENOMEM,
			    "Can't allocate directory buffer");
			return (ARCHIVE_FATAL);
		}
		buf_size = 0;
		chain_len = 0;

		cluster = first_cluster;
		while (cluster >= 2 && cluster < FAT32_EOC) {
			uint64_t offset;
			size_t remaining;
			size_t copied;

			if (chain_len++ > MAX_CHAIN_LENGTH) {
				free(buf);
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_FILE_FORMAT,
				    "Directory cluster chain too long");
				return (ARCHIVE_FATAL);
			}

			/* Grow buffer if needed. */
			if (buf_size + cluster_bytes > buf_alloc) {
				size_t new_alloc = buf_alloc * 2;
				unsigned char *newbuf;
				newbuf = (unsigned char *)realloc(buf,
				    new_alloc);
				if (newbuf == NULL) {
					free(buf);
					archive_set_error(&a->archive,
					    ENOMEM,
					    "Can't grow directory buffer");
					return (ARCHIVE_FATAL);
				}
				buf = newbuf;
				buf_alloc = new_alloc;
			}

			offset = msdos->data_offset +
			    (uint64_t)(cluster - 2) * cluster_bytes;

			if (__archive_read_seek(a, (int64_t)offset,
			    SEEK_SET) < 0) {
				free(buf);
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "Cannot seek to directory cluster");
				return (ARCHIVE_FATAL);
			}

			remaining = cluster_bytes;
			copied = 0;
			while (remaining > 0) {
				p = __archive_read_ahead(a, 1, &avail);
				if (p == NULL || avail <= 0) {
					free(buf);
					archive_set_error(&a->archive,
					    ARCHIVE_ERRNO_FILE_FORMAT,
					    "Truncated directory data");
					return (ARCHIVE_FATAL);
				}
				if ((size_t)avail > remaining)
					avail = (ssize_t)remaining;
				memcpy(buf + buf_size + copied, p, avail);
				__archive_read_consume(a, avail);
				copied += avail;
				remaining -= avail;
			}
			buf_size += cluster_bytes;

			cluster = fat_next_cluster(msdos, cluster);
		}

		*out_buf = buf;
		*out_size = buf_size;
		return (ARCHIVE_OK);
	}
}

static int
msdosfs_add_entry(struct archive_read *a,
    const char *pathname, uint32_t first_cluster, uint32_t size,
    uint8_t attr, time_t mtime, time_t ctime, time_t atime, int is_dir)
{
	struct msdosfs_read *msdos;
	struct msdosfs_file *file;

	msdos = (struct msdosfs_read *)(a->format->data);

	/* Grow array if needed. */
	if (msdos->entry_count >= msdos->entry_alloc) {
		int new_alloc = msdos->entry_alloc * 2;
		struct msdosfs_file *new_entries;
		new_entries = (struct msdosfs_file *)realloc(
		    msdos->entries,
		    new_alloc * sizeof(struct msdosfs_file));
		if (new_entries == NULL) {
			archive_set_error(&a->archive, ENOMEM,
			    "Can't grow entry array");
			return (ARCHIVE_FATAL);
		}
		msdos->entries = new_entries;
		msdos->entry_alloc = new_alloc;
	}

	file = &msdos->entries[msdos->entry_count++];
	memset(file, 0, sizeof(*file));

	archive_string_init(&file->pathname);
	archive_strcpy(&file->pathname, pathname);

	file->first_cluster = first_cluster;
	file->size = size;
	file->attr = attr;
	file->mtime = mtime;
	file->ctime = ctime;
	file->atime = atime;
	file->is_dir = is_dir;

	/* Compute disk offset for sorting. */
	if (first_cluster >= 2) {
		file->disk_offset = msdos->data_offset +
		    (uint64_t)(first_cluster - 2) *
		    msdos->cluster_size * msdos->sector_size;
	} else {
		/* Entries without clusters (empty files, root) sort first. */
		file->disk_offset = 0;
	}

	return (ARCHIVE_OK);
}

static int
msdosfs_walk_directory(struct archive_read *a,
    uint32_t first_cluster, uint64_t fixed_offset, uint32_t fixed_size,
    const char *parent_path, int depth)
{
	struct msdosfs_read *msdos;
	unsigned char *dirbuf;
	size_t dirsize;
	size_t nentries;
	size_t i;
	int r;

	/* LFN accumulation state. */
	uint8_t lfn_buf[255 * 2]; /* max 255 UTF-16 code units */
	int lfn_chars;	/* total UTF-16 chars accumulated */
	unsigned char lfn_checksum_val;
	int lfn_active;

	msdos = (struct msdosfs_read *)(a->format->data);

	if (depth > MAX_DIR_DEPTH) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_FILE_FORMAT,
		    "Directory nesting too deep");
		return (ARCHIVE_WARN);
	}

	r = msdosfs_read_dir_data(a, first_cluster, fixed_offset,
	    fixed_size, &dirbuf, &dirsize);
	if (r != ARCHIVE_OK)
		return (r);
	if (dirbuf == NULL || dirsize == 0)
		return (ARCHIVE_OK);

	nentries = dirsize / DIR_ENTRY_SIZE;
	lfn_active = 0;
	lfn_chars = 0;
	lfn_checksum_val = 0;
	memset(lfn_buf, 0, sizeof(lfn_buf));

	for (i = 0; i < nentries; i++) {
		const unsigned char *ent = dirbuf + i * DIR_ENTRY_SIZE;
		uint8_t attr;
		uint8_t ordinal;

		/* End of directory. */
		if (ent[0] == 0x00)
			break;

		/* Deleted entry. */
		if (ent[0] == 0xE5) {
			lfn_active = 0;
			continue;
		}

		attr = ent[11];

		/* LFN entry. */
		if (attr == ATTR_LONG_NAME) {
			int seq, j;

			ordinal = ent[0];

			/* Start of a new LFN sequence? */
			if (ordinal & 0x40) {
				lfn_active = 1;
				lfn_chars = (ordinal & 0x3F) * 13;
				lfn_checksum_val = ent[13];
				if (lfn_chars > 255)
					lfn_chars = 255;
				memset(lfn_buf, 0xFF, sizeof(lfn_buf));
			} else if (!lfn_active || ent[13] != lfn_checksum_val) {
				lfn_active = 0;
				continue;
			}

			seq = (ordinal & 0x3F) - 1;
			if (seq < 0 || seq * 13 >= 255) {
				lfn_active = 0;
				continue;
			}

			/* Extract 13 UTF-16LE code units. */
			for (j = 0; j < 13; j++) {
				int idx = seq * 13 + j;
				int lfn_off;
				uint16_t ch;

				if (idx >= 255)
					break;

				if (j < 5)
					lfn_off = 1 + j * 2;
				else if (j < 11)
					lfn_off = 14 + (j - 5) * 2;
				else
					lfn_off = 28 + (j - 11) * 2;

				ch = ent[lfn_off] |
				    ((uint16_t)ent[lfn_off + 1] << 8);

				lfn_buf[idx * 2] =
				    (uint8_t)(ch & 0xFF);
				lfn_buf[idx * 2 + 1] =
				    (uint8_t)(ch >> 8);
			}
			continue;
		}

		/* Skip volume label entries. */
		if (attr & ATTR_VOLUME_ID) {
			lfn_active = 0;
			continue;
		}

		/* This is a short directory entry. */
		{
			char name_buf[256];
			struct archive_string full_path;
			uint32_t cluster_lo, cluster_hi, file_cluster;
			uint32_t file_size;
			uint16_t crt_time, crt_date, acc_date;
			uint16_t wrt_time, wrt_date;
			time_t mtime, ctime, atime;
			int is_dir;

			/* Skip "." and ".." entries. */
			if (ent[0] == '.' && (ent[1] == ' ' || ent[1] == '.')) {
				lfn_active = 0;
				continue;
			}

			is_dir = (attr & ATTR_DIRECTORY) != 0;

			/* Extract cluster number. */
			cluster_lo = archive_le16dec(ent + 26);
			cluster_hi = (msdos->fat_type == 32) ?
			    archive_le16dec(ent + 20) : 0;
			file_cluster = (cluster_hi << 16) | cluster_lo;

			/* File size. */
			file_size = archive_le32dec(ent + 28);

			/* Timestamps. */
			crt_time = archive_le16dec(ent + 14);
			crt_date = archive_le16dec(ent + 16);
			acc_date = archive_le16dec(ent + 18);
			wrt_time = archive_le16dec(ent + 22);
			wrt_date = archive_le16dec(ent + 24);

			mtime = msdosfs_decode_datetime(wrt_date, wrt_time);
			ctime = msdosfs_decode_datetime(crt_date, crt_time);
			atime = msdosfs_decode_datetime(acc_date, 0);

			/*
			 * Build the entry name.  Always extract the
			 * 8.3 short name first, then try to replace
			 * it with the long filename if available.
			 */
			{
				char base[9], ext[4];
				int bi, ei;

				/* Extract base name (8 chars, trim spaces). */
				memcpy(base, ent, 8);
				base[8] = '\0';
				for (bi = 7; bi >= 0 && base[bi] == ' '; bi--)
					base[bi] = '\0';

				/* Extract extension (3 chars, trim spaces). */
				memcpy(ext, ent + 8, 3);
				ext[3] = '\0';
				for (ei = 2; ei >= 0 && ext[ei] == ' '; ei--)
					ext[ei] = '\0';

				/* Convert to lowercase for readability. */
				for (bi = 0; base[bi]; bi++) {
					if (base[bi] >= 'A' && base[bi] <= 'Z')
						base[bi] += 32;
				}
				for (ei = 0; ext[ei]; ei++) {
					if (ext[ei] >= 'A' && ext[ei] <= 'Z')
						ext[ei] += 32;
				}

				if (ext[0] != '\0')
					snprintf(name_buf, sizeof(name_buf),
					    "%s.%s", base, ext);
				else
					snprintf(name_buf, sizeof(name_buf),
					    "%s", base);
			}

			/* Override with LFN if valid. */
			if (lfn_active &&
			    lfn_checksum(ent) == lfn_checksum_val &&
			    msdos->sconv_utf16le != NULL) {
				struct archive_string lfn_str;
				size_t lfn_bytes;
				int ci;

				lfn_bytes = 0;
				for (ci = 0; ci < lfn_chars; ci++) {
					uint16_t ch = lfn_buf[ci * 2] |
					    ((uint16_t)lfn_buf[ci * 2 + 1] << 8);
					if (ch == 0x0000 || ch == 0xFFFF)
						break;
					lfn_bytes = (ci + 1) * 2;
				}

				archive_string_init(&lfn_str);
				if (lfn_bytes > 0 &&
				    archive_strncpy_l(&lfn_str,
				    (const char *)lfn_buf, lfn_bytes,
				    msdos->sconv_utf16le) == 0 &&
				    lfn_str.length > 0) {
					snprintf(name_buf, sizeof(name_buf),
					    "%s", lfn_str.s);
				}
				archive_string_free(&lfn_str);
			}

			/* Build full path. */
			archive_string_init(&full_path);
			if (parent_path[0] != '\0') {
				archive_strcpy(&full_path, parent_path);
			}
			archive_strcat(&full_path, name_buf);
			if (is_dir)
				archive_strappend_char(&full_path, '/');

			/* Add entry. */
			r = msdosfs_add_entry(a, full_path.s,
			    file_cluster, is_dir ? 0 : file_size,
			    attr, mtime, ctime, atime, is_dir);

			/* Recurse into subdirectories. */
			if (r == ARCHIVE_OK && is_dir &&
			    file_cluster >= 2) {
				r = msdosfs_walk_directory(a,
				    file_cluster, 0, 0,
				    full_path.s, depth + 1);
			}

			archive_string_free(&full_path);

			if (r != ARCHIVE_OK && r != ARCHIVE_WARN) {
				free(dirbuf);
				return (r);
			}

			lfn_active = 0;
		}
	}

	free(dirbuf);
	return (ARCHIVE_OK);
}

/*
 * sort entries by disk offset, then by path
 */
static int
entry_cmp(const void *a, const void *b)
{
	const struct msdosfs_file *fa = (const struct msdosfs_file *)a;
	const struct msdosfs_file *fb = (const struct msdosfs_file *)b;

	if (fa->disk_offset < fb->disk_offset)
		return (-1);
	if (fa->disk_offset > fb->disk_offset)
		return (1);
	return (strcmp(fa->pathname.s, fb->pathname.s));
}
