/*-
 * Copyright (c) 2024 Stanislav Sedov
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

#include "archive_platform.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#include <stdio.h>
#include <stdarg.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <time.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

#include <assert.h>

#include "archive.h"
#include "archive_endian.h"
#include "archive_entry.h"
#include "archive_entry_locale.h"
#include "archive_private.h"
#include "archive_rb.h"
#include "archive_write_private.h"

/*
 * Options
 */
struct msdosfs_option {
	unsigned int sectorsize;
	unsigned int clustersize;
	unsigned int reserved_cnt;
	unsigned int fat_cnt;
	unsigned int fat_sec_cnt;
	unsigned int total_size;
	unsigned int volume_id;
};

struct msdosfs_entry;

struct msdosfs_chain {
	struct msdosfs_entry *first;
	struct msdosfs_entry **last;
};

/*
 * The Data only for a directory file.
 */
struct dir_info {
	struct archive_rb_tree rbtree;
	struct msdosfs_chain children;
	struct msdosfs_entry *chnext;
	int virtual;
};

typedef struct msdosfs_entry {
	struct archive_rb_node rbnode;
	struct msdosfs_entry *next;
	struct msdosfs_entry *parent;
	struct dir_info *dir_info;

	struct archive_string parentdir;
	struct archive_string basename;
	struct archive_string pathname;
	struct archive_string symlink;
	struct archive_string uname;
	struct archive_string gname;
	struct archive_string fflags_text;
	
	uint32_t parent_cluster;  /* Cluster number of parent directory */
	uint8_t short_name[11];   /* 8.3 format name */
	uint8_t lfn_entries;      /* Number of LFN entries needed */
	unsigned int nlink;
	mode_t filetype;
	mode_t mode;
	int64_t size;
	int64_t uid;
	int64_t gid;
	time_t mtime;
	long mtime_nsec;
	unsigned long fflags_set;
	unsigned long fflags_clear;
	dev_t rdevmajor;
	dev_t rdevminor;
	dev_t devmajor;
	dev_t devminor;
	int64_t ino;
	uint32_t nclusters;
	uint32_t cluster;
} msdosfs_entry_t;

#define	OEM_NAME_MAX	10
#define	VOLUME_LABEL_MAX	10

#define MAX_FILE_SIZE	(ARCHIVE_LITERAL_LL(1) << 32)	/* 4Gb */

typedef struct msdosfs_ctx {
	struct msdosfs_option	opt;
	struct archive_string	oem_name;
	struct archive_string	volume_label;
	unsigned int sector_size;
	uint64_t bytes_remaining;
	msdosfs_entry_t *cur_entry;
	uint32_t cluster_size;
	uint32_t next_free_cluster;
	uint32_t free_cluster_count;

	struct msdosfs_entry *root;
	struct msdosfs_entry *cur_dirent;
	struct archive_string cur_dirstr;
	struct msdosfs_chain file_list;
	uint32_t	filecount;

	int			 temp_fd;
	ssize_t			temp_size;

#define wb_buffmax()	(512 * 32)
#define wb_remaining(a)	(((struct msdosfs_ctx *)(a)->format_data)->wbuff_remaining)
#define wb_offset(a)	(((struct msdosfs_ctx *)(a)->format_data)->wbuff_offset \
		+ wb_buffmax() - wb_remaining(a))
	unsigned char		 wbuff[512 * 32];
	size_t			 wbuff_remaining;
	enum {
		WB_TO_STREAM,
		WB_TO_TEMP
	} 			 wbuff_type;
	int64_t			 wbuff_offset;
	int64_t			 wbuff_written;
	int64_t			 wbuff_tail;
} msdosfs_ctx_t;

static int	msdosfs_options(struct archive_write *,
		    const char *, const char *);
static int	msdosfs_write_header(struct archive_write *,
		    struct archive_entry *);
static ssize_t	msdosfs_write_data(struct archive_write *,
		    const void *, size_t);
static int	msdosfs_finish_entry(struct archive_write *);
static int	msdosfs_close(struct archive_write *);
static int	msdosfs_free(struct archive_write *);
static int msdosfs_entry_cmp_node(const struct archive_rb_node *,
	const struct archive_rb_node *);
static int msdosfs_entry_cmp_key(const struct archive_rb_node *, const void *);
static int msdosfs_entry_setup_filenames(struct archive_write *,
	msdosfs_entry_t *, struct archive_entry *);
static int msdosfs_entry_setup_filenames(struct archive_write *,
	msdosfs_entry_t *, struct archive_entry *);
static int msdosfs_entry_tree_add(struct archive_write *, struct msdosfs_entry **);
static int msdosfs_entry_new(struct archive_write *a, struct archive_entry *entry,
    msdosfs_entry_t **m_entry);
static void msdosfs_entry_free(msdosfs_entry_t *me);
static int msdosfs_entry_exchange_same_entry(struct archive_write *a, struct msdosfs_entry *np,
    struct msdosfs_entry *file);
static void msdosfs_entry_register_init(msdosfs_ctx_t *ctx);
static int write_to_temp(struct archive_write *a, const void *buff, size_t s);

static inline unsigned char *
wb_buffptr(struct archive_write *a)
{
	struct msdosfs_ctx *ctx = (struct msdosfs_ctx *)a->format_data;

	return (&(ctx->wbuff[sizeof(ctx->wbuff)
		- ctx->wbuff_remaining]));
}

static int
wb_write_out(struct archive_write *a)
{
	struct msdosfs_ctx *ctx = (struct msdosfs_ctx *)a->format_data;
	size_t wsize, nw;
	int r;

	wsize = sizeof(ctx->wbuff) - ctx->wbuff_remaining;
	nw = wsize % 512;
	if (ctx->wbuff_type == WB_TO_STREAM)
		r = __archive_write_output(a, ctx->wbuff, wsize - nw);
	else
		r = write_to_temp(a, ctx->wbuff, wsize - nw);
	/* Increase the offset. */
	ctx->wbuff_offset += wsize - nw;
	if (ctx->wbuff_offset > ctx->wbuff_written)
		ctx->wbuff_written = ctx->wbuff_offset;
	ctx->wbuff_remaining = sizeof(ctx->wbuff);
	if (nw) {
		ctx->wbuff_remaining -= nw;
		memmove(ctx->wbuff, ctx->wbuff + wsize - nw, nw);
	}
	return (r);
}

static int
wb_consume(struct archive_write *a, size_t size)
{
	struct msdosfs_ctx *ctx = (struct msdosfs_ctx *)a->format_data;

	if (size > ctx->wbuff_remaining ||
	    ctx->wbuff_remaining == 0) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Internal Programming error: iso9660:wb_consume()"
		    " size=%jd, wbuff_remaining=%jd",
		    (intmax_t)size, (intmax_t)ctx->wbuff_remaining);
		return (ARCHIVE_FATAL);
	}
	ctx->wbuff_remaining -= size;
	if (ctx->wbuff_remaining < 512)
		return (wb_write_out(a));
	return (ARCHIVE_OK);
}

static int
write_null(struct archive_write *a, size_t size)
{
	size_t remaining;
	unsigned char *p, *old;
	int r;

	remaining = wb_remaining(a);
	p = wb_buffptr(a);
	if (size <= remaining) {
		memset(p, 0, size);
		return (wb_consume(a, size));
	}
	memset(p, 0, remaining);
	r = wb_consume(a, remaining);
	if (r != ARCHIVE_OK)
		return (r);
	size -= remaining;
	old = p;
	p = wb_buffptr(a);
	memset(p, 0, old - p);
	remaining = wb_remaining(a);
	while (size) {
		size_t wsize = size;

		if (wsize > remaining)
			wsize = remaining;
		r = wb_consume(a, wsize);
		if (r != ARCHIVE_OK)
			return (r);
		size -= wsize;
	}
	return (ARCHIVE_OK);
}

int
archive_write_set_format_msdosfs(struct archive *_a)
{
	struct archive_write *a = (struct archive_write *)_a;
	msdosfs_ctx_t *ctx;

	archive_check_magic(_a, ARCHIVE_WRITE_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_write_set_format_msdosfs");

	/* If another format was already registered, unregister it. */
	if (a->format_free != NULL)
		(a->format_free)(a);

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		archive_set_error(&a->archive, ENOMEM,
		    "Can't allocate msdosfs ctx");
		return (ARCHIVE_FATAL);
	}
	ctx->cur_entry = NULL;
	ctx->temp_fd = -1;
	archive_string_init(&(ctx->oem_name));
	archive_string_init(&(ctx->volume_label));
	msdosfs_entry_register_init(ctx);
	ctx->wbuff_remaining = 512 * 32;
	ctx->wbuff_type = WB_TO_TEMP;

	ctx->sector_size = 512;
	ctx->cluster_size = 16*512;

	a->format_data = ctx;
	a->format_name = "msdosfs";
	a->format_options = msdosfs_options;
	a->format_write_header = msdosfs_write_header;
	a->format_write_data = msdosfs_write_data;
	a->format_finish_entry = msdosfs_finish_entry;
	a->format_close = msdosfs_close;
	a->format_free = msdosfs_free;
	a->archive.archive_format = ARCHIVE_FORMAT_MSDOSFS;
	a->archive.archive_format_name = "MSDOSFS";

	return (ARCHIVE_OK);
}

static int
get_str_opt(struct archive_write *a, struct archive_string *s,
    size_t maxsize, const char *key, const char *value)
{

	if (strlen(value) > maxsize) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Value is longer than %zu characters "
		    "for option ``%s''", maxsize, key);
		return (ARCHIVE_FATAL);
	}
	archive_strcpy(s, value);
	return (ARCHIVE_OK);
}

static int
get_num_opt(struct archive_write *a, int *num, int high, int low,
    const char *key, const char *value)
{
	const char *p = value;
	int data = 0;
	int neg = 0;

	if (p == NULL) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Invalid value(empty) for option ``%s''", key);
		return (ARCHIVE_FATAL);
	}
	if (*p == '-') {
		neg = 1;
		p++;
	}
	while (*p) {
		if (*p >= '0' && *p <= '9')
			data = data * 10 + *p - '0';
		else {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Invalid value for option ``%s''", key);
			return (ARCHIVE_FATAL);
		}
		if (data > high) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Invalid value(over %d) for "
			    "option ``%s''", high, key);
			return (ARCHIVE_FATAL);
		}
		if (data < low) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Invalid value(under %d) for "
			    "option ``%s''", low, key);
			return (ARCHIVE_FATAL);
		}
		p++;
	}
	if (neg)
		data *= -1;
	*num = data;

	return (ARCHIVE_OK);
}

static uint16_t fat_date(time_t t) {
	struct tm *tm = localtime(&t);
	return ((tm->tm_year - 80) << 9) |
		((tm->tm_mon + 1) << 5) |
		tm->tm_mday;
}

static uint16_t fat_time(time_t t) {
	struct tm *tm = localtime(&t);
	return (tm->tm_hour << 11) |
		(tm->tm_min << 5) |
		(tm->tm_sec / 2);
}

static int generate_short_name(struct msdosfs_entry *entry, struct msdosfs_entry *parent) {
	char base[9], ext[4];
	int i, j;
	const char *src = entry->basename.s;
	int collision = 0;
	
	/* Initialize with spaces */
	memset(base, ' ', 8);
	memset(ext, ' ', 3);
	base[8] = ext[3] = '\0';

	/* Split into base and extension */
	for (i = 0, j = 0; src[i] && i < 8 && src[i] != '.'; i++)
		base[j++] = toupper(src[i]);
	
	if (src[i] == '.') {
		i++;
		for (j = 0; src[i] && j < 3; i++, j++)
			ext[j] = toupper(src[i]);
	}

	/* Handle collisions by adding ~N */
	while (collision < 999999) {
		char tmp[9];
		struct msdosfs_entry *existing;
		
		if (collision > 0)
			snprintf(tmp, sizeof(tmp), "%.6s~%d", base, collision);
		else
			strncpy(tmp, base, 8);

		/* Check if name exists in parent */
		existing = msdosfs_entry_find_child(parent, tmp);
		if (!existing) {
			/* Found unique name */
			memcpy(entry->short_name, tmp, 8);
			memcpy(entry->short_name + 8, ext, 3);
			return ARCHIVE_OK;
		}
		collision++;
	}
	
	return ARCHIVE_WARN;
}

static int generate_lfn_entries(struct msdosfs_entry *entry) {
	size_t len = strlen(entry->basename.s);
	entry->lfn_entries = (len + 12) / 13;
	return ARCHIVE_OK;
}

static int
msdosfs_options(struct archive_write *a, const char *key, const char *value)
{
	msdosfs_ctx_t *ctx;
	const char *p;
	int r;

	ctx = a->format_data;
	assert(ctx != NULL);

	if (strcmp(key, "cluster-size") == 0) {
		int size;
		r = get_num_opt(a, &size, 512, 65536, key, value);
		if (r == ARCHIVE_OK)
			ctx->cluster_size = size;
		return r;
	}
	if (strcmp(key, "volume-label") == 0) {
		return get_str_opt(a, &ctx->volume_label, 11, key, value);
	}
	if (strcmp(key, "oem-name") == 0) {
	if (strcmp(key, "sector-size") == 0) {
		int num = 0;
		r = get_num_opt(a, &num, 0xffff, 1, key, value);
//		iso9660->opt.boot_load_size = r == ARCHIVE_OK;
		if (r != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		ctx->sector_size = (uint16_t)num;
		return (ARCHIVE_OK);
	}

	/*
	 * Note: the "warn" return is just to inform the options
	 * supervisor that we didn't handle it.  It will generate
	 * a suitable error if no one used this option.
	 */
	return (ARCHIVE_WARN);

invalid_value:
	archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
	    "Invalid value for option ``%s''", key);
	return (ARCHIVE_FAILED);
}

static int
msdosfs_entry_cmp_node(const struct archive_rb_node *n1,
    const struct archive_rb_node *n2)
{
	const msdosfs_entry_t *e1 = (const msdosfs_entry_t *)n1;
	const msdosfs_entry_t *e2 = (const msdosfs_entry_t *)n2;

	return (strcmp(e2->basename.s, e1->basename.s));
}

static int
msdosfs_entry_cmp_key(const struct archive_rb_node *n, const void *key)
{
	const msdosfs_entry_t *e = (const msdosfs_entry_t *)n;

	return (strcmp((const char *)key, e->basename.s));
}

static void
msdosfs_entry_register_add(msdosfs_ctx_t *ctx, struct msdosfs_entry *file)
{
        file->next = NULL;
        *ctx->file_list.last = file;
        ctx->file_list.last = &(file->next);
	ctx->filecount++;
}

static void
msdosfs_entry_register_init(msdosfs_ctx_t *ctx)
{
	ctx->file_list.first = NULL;
	ctx->file_list.last = &(ctx->file_list.first);
}

static void
msdosfs_entry_register_free(msdosfs_ctx_t *ctx)
{
	struct msdosfs_entry *file, *file_next;

	file = ctx->file_list.first;
	while (file != NULL) {
		file_next = file->next;
		msdosfs_entry_free(file);
		file = file_next;
	}
}

static int
msdosfs_entry_add_child_tail(struct msdosfs_entry *parent,
    struct msdosfs_entry *child)
{
	child->dir_info->chnext = NULL;
	*parent->dir_info->children.last = child;
	parent->dir_info->children.last = &(child->dir_info->chnext);
	return (1);
}

/*
 * Find a entry from a parent entry with the name.
 */
static struct msdosfs_entry *
msdosfs_entry_find_child(struct msdosfs_entry *parent, const char *child_name)
{
	struct msdosfs_entry *np;

	if (parent == NULL)
		return (NULL);
	np = (struct msdosfs_entry *)__archive_rb_tree_find_node(
	    &(parent->dir_info->rbtree), child_name);
	return (np);
}

static int
get_path_component(char *name, size_t n, const char *fn)
{
	char *p;
	size_t l;

	p = strchr(fn, '/');
	if (p == NULL) {
		if ((l = strlen(fn)) == 0)
			return (0);
	} else
		l = p - fn;
	if (l > n -1)
		return (-1);
	memcpy(name, fn, l);
	name[l] = '\0';

	return ((int)l);
}

#if defined(_WIN32) || defined(__CYGWIN__)
static int
cleanup_backslash_1(char *p)
{
	int mb, dos;

	mb = dos = 0;
	while (*p) {
		if (*(unsigned char *)p > 127)
			mb = 1;
		if (*p == '\\') {
			/* If we have not met any multi-byte characters,
			 * we can replace '\' with '/'. */
			if (!mb)
				*p = '/';
			dos = 1;
		}
		p++;
	}
	if (!mb || !dos)
		return (0);
	return (-1);
}

static void
cleanup_backslash_2(wchar_t *p)
{

	/* Convert a path-separator from '\' to  '/' */
	while (*p != L'\0') {
		if (*p == L'\\')
			*p = L'/';
		p++;
	}
}
#endif

/*
 * Generate a parent directory name and a base name from a pathname.
 */
static int
msdosfs_entry_setup_filenames(struct archive_write *a, msdosfs_entry_t *file,
    struct archive_entry *entry)
{
	const char *pathname;
	char *p, *dirname, *slash;
	size_t len;
	int ret = ARCHIVE_OK;

	archive_strcpy(&file->pathname, archive_entry_pathname(entry));
#if defined(_WIN32) || defined(__CYGWIN__)
	/*
	 * Convert a path-separator from '\' to  '/'
	 */
	if (cleanup_backslash_1(file->pathname.s) != 0) {
		const wchar_t *wp = archive_entry_pathname_w(entry);
		struct archive_wstring ws;

		if (wp != NULL) {
			int r;
			archive_string_init(&ws);
			archive_wstrcpy(&ws, wp);
			cleanup_backslash_2(ws.s);
			archive_string_empty(&(file->pathname));
			r = archive_string_append_from_wcs(&(file->pathname),
			    ws.s, ws.length);
			archive_wstring_free(&ws);
			if (r < 0 && errno == ENOMEM) {
				archive_set_error(&a->archive, ENOMEM,
				    "Can't allocate memory");
				return (ARCHIVE_FATAL);
			}
		}
	}
#else
	(void)a; /* UNUSED */
#endif
	pathname =  file->pathname.s;
	if (strcmp(pathname, ".") == 0) {
		archive_strcpy(&file->basename, ".");
		return (ARCHIVE_OK);
	}

	archive_strcpy(&(file->parentdir), pathname);

	len = file->parentdir.length;
	p = dirname = file->parentdir.s;

	/*
	 * Remove leading '/' and '../' elements
	 */
	while (*p) {
		if (p[0] == '/') {
			p++;
			len--;
		} else if (p[0] != '.')
			break;
		else if (p[1] == '.' && p[2] == '/') {
			p += 3;
			len -= 3;
		} else
			break;
	}
	if (p != dirname) {
		memmove(dirname, p, len+1);
		p = dirname;
	}
	/*
	 * Remove "/","/." and "/.." elements from tail.
	 */
	while (len > 0) {
		size_t ll = len;

		if (len > 0 && p[len-1] == '/') {
			p[len-1] = '\0';
			len--;
		}
		if (len > 1 && p[len-2] == '/' && p[len-1] == '.') {
			p[len-2] = '\0';
			len -= 2;
		}
		if (len > 2 && p[len-3] == '/' && p[len-2] == '.' &&
		    p[len-1] == '.') {
			p[len-3] = '\0';
			len -= 3;
		}
		if (ll == len)
			break;
	}
	while (*p) {
		if (p[0] == '/') {
			if (p[1] == '/')
				/* Convert '//' --> '/' */
				memmove(p, p+1, strlen(p+1) + 1);
			else if (p[1] == '.' && p[2] == '/')
				/* Convert '/./' --> '/' */
				memmove(p, p+2, strlen(p+2) + 1);
			else if (p[1] == '.' && p[2] == '.' && p[3] == '/') {
				/* Convert 'dir/dir1/../dir2/'
				 *     --> 'dir/dir2/'
				 */
				char *rp = p -1;
				while (rp >= dirname) {
					if (*rp == '/')
						break;
					--rp;
				}
				if (rp > dirname) {
					strcpy(rp, p+3);
					p = rp;
				} else {
					strcpy(dirname, p+4);
					p = dirname;
				}
			} else
				p++;
		} else
			p++;
	}
	p = dirname;
	len = strlen(p);

	/*
	 * Add "./" prefix.
	 * NOTE: If the pathname does not have a path separator, we have
	 * to add "./" to the head of the pathname because msdosfs reader
	 * will suppose that it is v1(a.k.a classic) mtree format and
	 * change the directory unexpectedly and so it will make a wrong
	 * path.
	 */
	if (strcmp(p, ".") != 0 && strncmp(p, "./", 2) != 0) {
		struct archive_string as;
		archive_string_init(&as);
		archive_strcpy(&as, "./");
		archive_strncat(&as, p, len);
		archive_string_empty(&file->parentdir);
		archive_string_concat(&file->parentdir, &as);
		archive_string_free(&as);
		p = file->parentdir.s;
		len = archive_strlen(&file->parentdir);
	}

	/*
	 * Find out the position which points the last position of
	 * path separator('/').
	 */
	slash = NULL;
	for (; *p != '\0'; p++) {
		if (*p == '/')
			slash = p;
	}
	if (slash == NULL) {
		/* The pathname doesn't have a parent directory. */
		file->parentdir.length = len;
		archive_string_copy(&(file->basename), &(file->parentdir));
		archive_string_empty(&(file->parentdir));
		*file->parentdir.s = '\0';
		return (ret);
	}

	/* Make a basename from file->parentdir.s and slash */
	*slash  = '\0';
	file->parentdir.length = slash - file->parentdir.s;
	archive_strcpy(&(file->basename),  slash + 1);
	return (ret);
}

static int
msdosfs_entry_create_virtual_dir(struct archive_write *a, const char *pathname,
    msdosfs_entry_t **m_entry)
{
	struct archive_entry *entry;
	msdosfs_entry_t *file;
	int r;

	entry = archive_entry_new();
	if (entry == NULL) {
		*m_entry = NULL;
		archive_set_error(&a->archive, ENOMEM,
		    "Can't allocate memory");
		return (ARCHIVE_FATAL);
	}
	archive_entry_copy_pathname(entry, pathname);
	archive_entry_set_mode(entry, AE_IFDIR | 0755);
	archive_entry_set_mtime(entry, time(NULL), 0);

	r = msdosfs_entry_new(a, entry, &file);
	archive_entry_free(entry);
	if (r < ARCHIVE_WARN) {
		*m_entry = NULL;
		archive_set_error(&a->archive, ENOMEM,
		    "Can't allocate memory");
		return (ARCHIVE_FATAL);
	}

	file->dir_info->virtual = 1;

	*m_entry = file;
	return (ARCHIVE_OK);
}

/*
 * Add a new entry into the tree.
 */
static int
msdosfs_entry_tree_add(struct archive_write *a, struct msdosfs_entry **filep)
{
#if defined(_WIN32) && !defined(__CYGWIN__)
	char name[_MAX_FNAME];/* Included null terminator size. */
#elif defined(NAME_MAX) && NAME_MAX >= 255
	char name[NAME_MAX+1];
#else
	char name[256];
#endif
	msdosfs_ctx_t *ctx = (msdosfs_ctx_t *)a->format_data;
	struct msdosfs_entry *dent, *file, *np;
	const char *fn, *p;
	int l, r;


	file = *filep;
	if (file->parentdir.length == 0 && file->basename.length == 1 &&
	    file->basename.s[0] == '.') {
		file->parent = file;
		if (ctx->root != NULL) {
			np = ctx->root;
			goto same_entry;
		}
		ctx->root = file;
		msdosfs_entry_register_add(ctx, file);
		return (ARCHIVE_OK);
	}

	if (file->parentdir.length == 0) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Internal programming error "
		    "in generating canonical name for %s",
		    file->pathname.s);
		return (ARCHIVE_FAILED);
	}

	fn = p = file->parentdir.s;

	/*
	 * If the path of the parent directory of `file' entry is
	 * the same as the path of `cur_dirent', add `file' entry to
	 * `cur_dirent'.
	 */
	if (archive_strlen(&(ctx->cur_dirstr))
	      == archive_strlen(&(file->parentdir)) &&
	    strcmp(ctx->cur_dirstr.s, fn) == 0) {
		if (!__archive_rb_tree_insert_node(
		    &(ctx->cur_dirent->dir_info->rbtree),
		    (struct archive_rb_node *)file)) {
			/* There is the same name in the tree. */
			np = (struct msdosfs_entry *)__archive_rb_tree_find_node(
			    &(ctx->cur_dirent->dir_info->rbtree),
			    file->basename.s);
			goto same_entry;
		}
		file->parent = ctx->cur_dirent;
		msdosfs_entry_register_add(ctx, file);
		return (ARCHIVE_OK);
	}

	dent = ctx->root;
	for (;;) {
		l = get_path_component(name, sizeof(name), fn);
		if (l == 0) {
			np = NULL;
			break;
		}
		if (l < 0) {
			archive_set_error(&a->archive,
			    ARCHIVE_ERRNO_MISC,
			    "A name buffer is too small");
			return (ARCHIVE_FATAL);
		}
		if (l == 1 && name[0] == '.' && dent != NULL &&
		    dent == ctx->root) {
			fn += l;
			if (fn[0] == '/')
				fn++;
			continue;
		}

		np = msdosfs_entry_find_child(dent, name);
		if (np == NULL || fn[0] == '\0')
			break;

		/* Find next sub directory. */
		if (!np->dir_info) {
			/* NOT Directory! */
			archive_set_error(&a->archive,
			    ARCHIVE_ERRNO_MISC,
			    "`%s' is not directory, we cannot insert `%s' ",
			    np->pathname.s, file->pathname.s);
			return (ARCHIVE_FAILED);
		}
		fn += l;
		if (fn[0] == '/')
			fn++;
		dent = np;
	}
	if (np == NULL) {
		/*
		 * Create virtual parent directories.
		 */
		while (fn[0] != '\0') {
			struct msdosfs_entry *vp;
			struct archive_string as;

			archive_string_init(&as);
			archive_strncat(&as, p, fn - p + l);
			if (as.s[as.length-1] == '/') {
				as.s[as.length-1] = '\0';
				as.length--;
			}
			r = msdosfs_entry_create_virtual_dir(a, as.s, &vp);
			archive_string_free(&as);
			if (r < ARCHIVE_WARN)
				return (r);

			if (strcmp(vp->pathname.s, ".") == 0) {
				vp->parent = vp;
				ctx->root = vp;
			} else {
				__archive_rb_tree_insert_node(
				    &(dent->dir_info->rbtree),
				    (struct archive_rb_node *)vp);
				vp->parent = dent;
			}
			msdosfs_entry_register_add(ctx, vp);
			np = vp;

			fn += l;
			if (fn[0] == '/')
				fn++;
			l = get_path_component(name, sizeof(name), fn);
			if (l < 0) {
				archive_string_free(&as);
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "A name buffer is too small");
				return (ARCHIVE_FATAL);
			}
			dent = np;
		}

		/* Found out the parent directory where `file' can be
		 * inserted. */
		ctx->cur_dirent = dent;
		archive_string_empty(&(ctx->cur_dirstr));
		archive_string_ensure(&(ctx->cur_dirstr),
		    archive_strlen(&(dent->parentdir)) +
		    archive_strlen(&(dent->basename)) + 2);
		if (archive_strlen(&(dent->parentdir)) +
		    archive_strlen(&(dent->basename)) == 0)
			ctx->cur_dirstr.s[0] = 0;
		else {
			if (archive_strlen(&(dent->parentdir)) > 0) {
				archive_string_copy(&(ctx->cur_dirstr),
				    &(dent->parentdir));
				archive_strappend_char(
				    &(ctx->cur_dirstr), '/');
			}
			archive_string_concat(&(ctx->cur_dirstr),
			    &(dent->basename));
		}

		if (!__archive_rb_tree_insert_node(
		    &(dent->dir_info->rbtree),
		    (struct archive_rb_node *)file)) {
			np = (struct msdosfs_entry *)__archive_rb_tree_find_node(
			    &(dent->dir_info->rbtree), file->basename.s);
			goto same_entry;
		}
		file->parent = dent;
		msdosfs_entry_register_add(ctx, file);
		return (ARCHIVE_OK);
	}

same_entry:
	/*
	 * We have already has the entry the filename of which is
	 * the same.
	 */
	r = msdosfs_entry_exchange_same_entry(a, np, file);
	if (r < ARCHIVE_WARN)
		return (r);
	if (np->dir_info)
		np->dir_info->virtual = 0;
	*filep = np;
	msdosfs_entry_free(file);
	return (ARCHIVE_WARN);
}

static int
msdosfs_entry_exchange_same_entry(struct archive_write *a, struct msdosfs_entry *np,
    struct msdosfs_entry *file)
{

	if ((np->mode & AE_IFMT) != (file->mode & AE_IFMT)) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Found duplicate entries `%s' and its file type is "
		    "different",
		    np->pathname.s);
		return (ARCHIVE_FAILED);
	}

	/* Update the existent mtree entry's attributes by the new one's. */
	archive_string_empty(&np->symlink);
	archive_string_concat(&np->symlink, &file->symlink);
	archive_string_empty(&np->uname);
	archive_string_concat(&np->uname, &file->uname);
	archive_string_empty(&np->gname);
	archive_string_concat(&np->gname, &file->gname);
	archive_string_empty(&np->fflags_text);
	archive_string_concat(&np->fflags_text, &file->fflags_text);
	np->nlink = file->nlink;
	np->filetype = file->filetype;
	np->mode = file->mode;
	np->size = file->size;
	np->uid = file->uid;
	np->gid = file->gid;
	np->fflags_set = file->fflags_set;
	np->fflags_clear = file->fflags_clear;
	np->mtime = file->mtime;
	np->mtime_nsec = file->mtime_nsec;
	np->rdevmajor = file->rdevmajor;
	np->rdevminor = file->rdevminor;
	np->devmajor = file->devmajor;
	np->devminor = file->devminor;
	np->ino = file->ino;

	return (ARCHIVE_WARN);
}

static int
msdosfs_entry_new(struct archive_write *a, struct archive_entry *entry,
    msdosfs_entry_t **m_entry)
{
	msdosfs_entry_t *me;
	const char *s;
	int r;
	static const struct archive_rb_tree_ops rb_ops = {
		msdosfs_entry_cmp_node, msdosfs_entry_cmp_key
	};

	me = calloc(1, sizeof(*me));
	if (me == NULL) {
		archive_set_error(&a->archive, ENOMEM,
		    "Can't allocate memory for a msdosfs entry");
		*m_entry = NULL;
		return (ARCHIVE_FATAL);
	}

	r = msdosfs_entry_setup_filenames(a, me, entry);
	if (r < ARCHIVE_WARN) {
		msdosfs_entry_free(me);
		*m_entry = NULL;
		return (r);
	}

	if ((s = archive_entry_symlink(entry)) != NULL)
		archive_strcpy(&me->symlink, s);
	me->nlink = archive_entry_nlink(entry);
	me->filetype = archive_entry_filetype(entry);
	me->mode = archive_entry_mode(entry) & 07777;
	me->uid = archive_entry_uid(entry);
	me->gid = archive_entry_gid(entry);
	if ((s = archive_entry_uname(entry)) != NULL)
		archive_strcpy(&me->uname, s);
	if ((s = archive_entry_gname(entry)) != NULL)
		archive_strcpy(&me->gname, s);
	if ((s = archive_entry_fflags_text(entry)) != NULL)
		archive_strcpy(&me->fflags_text, s);
	archive_entry_fflags(entry, &me->fflags_set, &me->fflags_clear);
	me->mtime = archive_entry_mtime(entry);
	me->mtime_nsec = archive_entry_mtime_nsec(entry);
	me->rdevmajor = archive_entry_rdevmajor(entry);
	me->rdevminor = archive_entry_rdevminor(entry);
	me->devmajor = archive_entry_devmajor(entry);
	me->devminor = archive_entry_devminor(entry);
	me->ino = archive_entry_ino(entry);
	me->size = archive_entry_size(entry);
	if (me->filetype == AE_IFDIR) {
		me->dir_info = calloc(1, sizeof(*me->dir_info));
		if (me->dir_info == NULL) {
			msdosfs_entry_free(me);
			archive_set_error(&a->archive, ENOMEM,
			    "Can't allocate memory for a msdosfs entry");
			*m_entry = NULL;
			return (ARCHIVE_FATAL);
		}
		__archive_rb_tree_init(&me->dir_info->rbtree, &rb_ops);
		me->dir_info->children.first = NULL;
		me->dir_info->children.last = &(me->dir_info->children.first);
		me->dir_info->chnext = NULL;
	}

	*m_entry = me;
	return (ARCHIVE_OK);
}

static void
msdosfs_entry_free(msdosfs_entry_t *me)
{
	archive_string_free(&me->parentdir);
	archive_string_free(&me->basename);
	archive_string_free(&me->pathname);
	archive_string_free(&me->symlink);
	archive_string_free(&me->uname);
	archive_string_free(&me->gname);
	archive_string_free(&me->fflags_text);
	free(me->dir_info);
	free(me);
}

static int
msdosfs_write_header(struct archive_write *a, struct archive_entry *entry)
{
	msdosfs_ctx_t *ctx;
	msdosfs_entry_t *file;
	int ret;

	ctx = a->format_data;

	if (archive_entry_filetype(entry) == AE_IFLNK) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Ignoring symlink file.");
		ctx->cur_entry = NULL;
		return (ARCHIVE_WARN);
	}

	if (archive_entry_filetype(entry) == AE_IFREG &&
	    archive_entry_size(entry) > MAX_FILE_SIZE) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "File is too large (exceeds %lld bytes). ", MAX_FILE_SIZE);
		ctx->cur_entry = NULL;
		return (ARCHIVE_WARN);
	}

	ctx->bytes_remaining = archive_entry_size(entry);

	ret = msdosfs_entry_new(a, entry, &file);
	if (ret < ARCHIVE_WARN)
		return (ret);
	ret = msdosfs_entry_tree_add(a, &file);
	if (ret < ARCHIVE_WARN) {
		msdosfs_entry_free(file);
		return (ret);
	}
	ctx->cur_entry = file;

	if (ctx->temp_fd < 0) {
		ctx->temp_fd = __archive_mktemp(NULL);
		if (ctx->temp_fd < 0) {
			archive_set_error(&a->archive, errno,
			    "Could not create temporary file");
			return (ARCHIVE_FATAL);
		}
	}

	return (ret);
}

static int
write_to_temp(struct archive_write *a, const void *buff, size_t s)
{
	msdosfs_ctx_t *ctx = a->format_data;
	ssize_t written;
	const unsigned char *b;

	b = (const unsigned char *)buff;
	while (s) {
		written = write(ctx->temp_fd, b, s);
		if (written < 0) {
			archive_set_error(&a->archive, errno,
			    "Can't write to temporary file");
			return (ARCHIVE_FATAL);
		}
		s -= written;
		b += written;
		ctx->temp_size += written;
	}
	return (ARCHIVE_OK);
}

static int
wb_write_to_temp(struct archive_write *a, const void *buff, size_t s)
{
	const char *xp = buff;
	size_t xs = s;

	/*
	 * If a written data size is big enough to use system-call
	 * and there is no waiting data, this calls write_to_temp() in
	 * order to reduce a extra memory copy.
	 */
	if (wb_remaining(a) == wb_buffmax() && s > (1024 * 16)) {
		msdosfs_ctx_t *ctx = (msdosfs_ctx_t *)a->format_data;
		xs = s % 512;
		ctx->wbuff_offset += s - xs;
		if (write_to_temp(a, buff, s - xs) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		if (xs == 0)
			return (ARCHIVE_OK);
		xp += s - xs;
	}

	while (xs) {
		size_t size = xs;
		if (size > wb_remaining(a))
			size = wb_remaining(a);
		memcpy(wb_buffptr(a), xp, size);
		if (wb_consume(a, size) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		xs -= size;
		xp += size;
	}
	return (ARCHIVE_OK);
}

static ssize_t
write_msdosfs_data(struct archive_write *a, const void *buff, size_t s)
{
	msdosfs_ctx_t *ctx = a->format_data;

	if (ctx->temp_fd < 0) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Couldn't create temporary file");
		return (ARCHIVE_FATAL);
	}

	if (wb_write_to_temp(a, buff, s) != ARCHIVE_OK) {
		return (ARCHIVE_FATAL);
	}

	return (s);
}

static ssize_t
msdosfs_write_data(struct archive_write *a, const void *buff, size_t s)
{
	struct msdosfs_ctx *ctx = a->format_data;
	ssize_t r;

	if (ctx->cur_entry == NULL)
		return (0);
	if (ctx->cur_entry->filetype != AE_IFREG)
		return (0);
	if (s > ctx->bytes_remaining) {	// XXX: why?
		s = (size_t)ctx->bytes_remaining;
		printf("\nResetting bytes remaining\n");
	}
	if (s == 0)
		return (0);

	r = write_msdosfs_data(a, buff, s);
	if (r > 0)
		ctx->bytes_remaining -= r;
	return (r);
}

static int
msdosfs_finish_entry(struct archive_write *a)
{
	msdosfs_ctx_t *ctx = a->format_data;
	int ret;

	if (ctx->cur_entry == NULL)
		return (ARCHIVE_OK);
	if ((ctx->cur_entry->filetype) != AE_IFREG)
		return (ARCHIVE_OK);

	/* If there are unwritten data, write null data instead. */
	while (ctx->bytes_remaining > 0) {
		size_t s;

		s = (ctx->bytes_remaining > a->null_length)?
		    a->null_length: (size_t)ctx->bytes_remaining;
		if (write_msdosfs_data(a, a->nulls, s) < 0)
			return (ARCHIVE_FATAL);
		ctx->bytes_remaining -= s;
	}

	/* Write padding. */
	ctx->cur_entry->nclusters = ctx->cur_entry->size / ctx->cluster_size;
	uint32_t rem = ctx->cur_entry->size - (ctx->cur_entry->nclusters * ctx->cluster_size);
	if (rem != 0) {
		ret = write_null(a, ctx->cluster_size - rem);
		ctx->cur_entry->nclusters += 1;
	} else {
		ret = ARCHIVE_OK;
	}

	return (ret);
}

struct bpb {
	uint16_t bpbBytesPerSec;		/* bytes per sector */
	uint8_t bpbSecPerClus;		/* sectors per cluster */
	uint16_t bpbRsvdSecCnt;		/* reserved sectors */
	uint8_t bpbNumFATs;			/* number of FATs */
	uint16_t bpbRootEntCnt;		/* root directory entries */
	uint16_t bpbTotSec16;		/* total sectors */
	uint8_t bpbMedia;			/* media descriptor */
	uint16_t bpbFATSz16;		/* sectors per FAT */
	uint16_t bpbSecPerTrk;		/* sectors per track */
	uint16_t bpbNumHeads;		/* drive heads */
	uint32_t bpbHiddSecs;		/* hidden sectors */
	uint32_t bpbTotSec32;		/* big total sectors */
} __attribute__ ((packed));

struct bpb_fat32 {
	uint32_t bpbFATSz32;		/* big sectors per FAT */
	uint16_t bpbExtFlags;		/* FAT control flags */
	uint16_t bpbFSVer;		/* file system version */
	uint32_t bpbRootClus;		/* root directory start cluster */
	uint16_t bpbFSInfo;		/* file system info sector */
	uint16_t bpbBkBootSec;		/* backup boot sector */
	uint8_t bpbReserved[12];		/* reserved */
} __packed;

struct bs1 {
	uint8_t bsJmpBoot[3];			/* bootstrap entry point */
	uint8_t bsOEMName[8];		/* OEM name and version */
} __attribute__ ((packed));

struct bs2 {
	uint8_t bsDrvNum;		/* drive number */
	uint8_t bsReserved1;		/* reserved */
	uint8_t bsBootSig;		/* extended boot signature */
	uint32_t bsVolID;		/* volume ID number */
	uint8_t bsVolLab[11];		/* volume label */
	uint8_t bsFileSysType[8];		/* file system type */
} __attribute__ ((packed));

struct fat32_hdr {
	struct bs1 bs1;
	struct bpb bpb;
	struct bpb_fat32 bpb_fat32;
	struct bs2 bs2;
} __attribute__ ((packed));

static int
write_bpb(struct archive_write *a)
{
	struct fat32_hdr hdr;
	
	int reserved_cnt = 32;
	int sec_size = 512;
	int numfats = 2;
	int bpbMedia = 0xf8;
	int fatsz = 600;
	int sec_per_clus = 16;
	uint32_t total_secs = ((uint32_t)fatsz * sec_size / 4 - 2) * sec_per_clus + fatsz * numfats + reserved_cnt;
	int bkp_sector = 6;

	hdr.bs1.bsJmpBoot[0] = 0xeb;
	hdr.bs1.bsJmpBoot[1] = 0xff;
	hdr.bs1.bsJmpBoot[2] = 0x90;
	strncpy((char *)&hdr.bs1.bsOEMName, "BSD4.4  ", 8);

	archive_le16enc(&hdr.bpb.bpbBytesPerSec, sec_size);
	hdr.bpb.bpbSecPerClus = sec_per_clus;
	archive_le16enc(&hdr.bpb.bpbRsvdSecCnt, reserved_cnt);
	hdr.bpb.bpbNumFATs = numfats;
	archive_le16enc(&hdr.bpb.bpbRootEntCnt, 0);	// Should be 0 for FAT32
	archive_le16enc(&hdr.bpb.bpbTotSec16, 0);
	hdr.bpb.bpbMedia = bpbMedia;
	archive_le16enc(&hdr.bpb.bpbFATSz16, 0);
	archive_le16enc(&hdr.bpb.bpbSecPerTrk, 16);
	archive_le16enc(&hdr.bpb.bpbNumHeads, 2);
	archive_le32enc(&hdr.bpb.bpbHiddSecs, 0);
	archive_le32enc(&hdr.bpb.bpbTotSec32, total_secs);

	archive_le32enc(&hdr.bpb_fat32.bpbFATSz32, fatsz);
	archive_le16enc(&hdr.bpb_fat32.bpbExtFlags, 0);
	archive_le16enc(&hdr.bpb_fat32.bpbFSVer, 0);
	archive_le32enc(&hdr.bpb_fat32.bpbRootClus, 2);
	archive_le16enc(&hdr.bpb_fat32.bpbFSInfo, 1);
	archive_le16enc(&hdr.bpb_fat32.bpbBkBootSec, bkp_sector);
	bzero(&hdr.bpb_fat32.bpbReserved, sizeof(hdr.bpb_fat32.bpbReserved));

	hdr.bs2.bsDrvNum = 1;
	hdr.bs2.bsReserved1 = 0;
	hdr.bs2.bsBootSig = 0x29;
	archive_le32enc(&hdr.bs2.bsVolID, 0xdeadbeef);
	strncpy((char *)&hdr.bs2.bsVolLab, "FreeBSD vol", 11);
	strncpy((char *)&hdr.bs2.bsFileSysType, "FAT32   ", 8);

	char sig[2] = {0x55, 0xaa};

	__archive_write_output(a, &hdr, sizeof(hdr));
	__archive_write_nulls(a, 512 - sizeof(hdr) - sizeof(sig));
	__archive_write_output(a, sig, sizeof(sig));
	if (sec_size > 512)
		__archive_write_nulls(a, sec_size - 512);

	/* Write FSInfo */
	uint32_t fsinfo_sig1, fsinfo_sig2, fsinfo_sig3;
	uint32_t fsinfo_free, fsinfo_nxtfree;
	archive_le32enc(&fsinfo_sig1, 0x41615252);
	archive_le32enc(&fsinfo_sig2, 0x61417272);
	archive_le32enc(&fsinfo_sig3, 0xaa550000);
	archive_le32enc(&fsinfo_free, 0xffffffff);
	archive_le32enc(&fsinfo_nxtfree, 0xffffffff);
	__archive_write_output(a, &fsinfo_sig1, sizeof(fsinfo_sig1));
	__archive_write_nulls(a, 480);
	__archive_write_output(a, &fsinfo_sig2, sizeof(fsinfo_sig2));
	__archive_write_output(a, &fsinfo_free, sizeof(fsinfo_free));
	__archive_write_output(a, &fsinfo_nxtfree, sizeof(fsinfo_nxtfree));
	__archive_write_nulls(a, 12);
	__archive_write_output(a, &fsinfo_sig3, sizeof(fsinfo_sig2));
	if (sec_size > 512)
		__archive_write_nulls(a, sec_size - 512);
	return (ARCHIVE_OK);
}

static void print_tree(struct archive_rb_tree *root);

static int flcnt = 0;

static int
msdosfs_close(struct archive_write *a)
{
	msdosfs_ctx_t *ctx;
	
	int reserved_cnt = 32;
	int sec_size = 512;
	int bkp_sector = 6;
	int numfats = 2;
	int bpbMedia = 0xf8;
	int fatsz = 600;
	int sec_per_clus = 16;
	uint32_t total_secs = ((uint32_t)fatsz * sec_size / 4 - 2) * sec_per_clus + fatsz * numfats + reserved_cnt;
	int ret;

	ctx = a->format_data;
	assert(ctx != NULL);

	/*
	 * Write remaining data out to the temporary file.
	 */
	if (wb_remaining(a) > 0) {
		ret = wb_write_out(a);
		if (ret < 0)
			return (ret);
	}

	(void)write_bpb(a);
	__archive_write_nulls(a, sec_size * (bkp_sector - 2));
	(void)write_bpb(a); /* Backup */

	if (reserved_cnt > 2)
		__archive_write_nulls(a, sec_size * (reserved_cnt - (2 + bkp_sector)));

	/* Write FATs */
	for (int i = 0; i < numfats; i++) {
		uint32_t fat0;
		uint32_t fat1;
		uint32_t endcls;
		uint32_t fatbytes;

		archive_le32enc(&fat0, 0xffffff00 | bpbMedia);
		archive_le32enc(&fat1, 0xffffffff);
		fatbytes = fatsz * sec_size;

		archive_le32enc(&endcls, 0x0fffffff);

		__archive_write_output(a, &fat0, sizeof(fat0));
		__archive_write_output(a, &fat1, sizeof(fat1));

		uint32_t clusters = 2;
		int dirclusters = (ctx->filecount * 32 + ctx->cluster_size - 1)/ ctx->cluster_size;

		printf("Dirclusters = %d\n", dirclusters);
		while (dirclusters > 1) {
			uint32_t ce;
			archive_le32enc(&ce, clusters + 1);
			__archive_write_output(a, &ce, sizeof(ce));
			dirclusters --;
			clusters++;
		}
		__archive_write_output(a, &endcls, sizeof(endcls)); /* end of root cluster */
		clusters++;

		struct msdosfs_entry *file;

		file = ctx->file_list.first;
		while (file != NULL) {
			printf("FP %s nclusers = %d:", file->pathname.s, file->nclusters);
			uint32_t fnclusters = file->nclusters;

			if (fnclusters > 0) {
				file->cluster = clusters;
				while (fnclusters > 1) {
					uint32_t ce;
					archive_le32enc(&ce, clusters + 1);
					__archive_write_output(a, &ce, sizeof(ce));
					printf(" 0x%x", clusters);
					clusters++;
					fnclusters--;
				}
				__archive_write_output(a, &endcls, sizeof(endcls)); /* last cluster */
				printf(" 0x%x", clusters);
				clusters += 1;
			}
			file = file->next;
			printf("\n");
		}

		if ((fatbytes - sizeof(fat0) * clusters) > 0)
			__archive_write_nulls(a, fatbytes - sizeof(fat0) * clusters);
	}

	/*
	 * Root directory.
	 */
	struct msdosfs_entry *file;
	file = ctx->file_list.first;
	while (file != NULL) {
		char name[12];
		uint8_t attr;
		uint32_t z = 0;
		uint16_t clstw;
		
		snprintf(name, 12, "FL%-6dTXT", flcnt++);
		printf("DIRE %s\n", name);
		__archive_write_output(a, name, 11);
		if (file->filetype != AE_IFDIR) {
			attr = 0x0;
		} else {
			attr = 0x1;
		}
		__archive_write_output(a, &attr, 1);
		__archive_write_output(a, &z, 1);
		__archive_write_output(a, &z, 1);
		__archive_write_output(a, &z, 2);
		__archive_write_output(a, &z, 2);
		__archive_write_output(a, &z, 2);
		archive_le16enc(&clstw, file->cluster >> 16);
		__archive_write_output(a, &clstw, 2);
		__archive_write_output(a, &z, 2);
		__archive_write_output(a, &z, 2);
		archive_le16enc(&clstw, file->cluster & 0xffff);
		__archive_write_output(a, &clstw, 2);
		if (file->filetype != AE_IFDIR) {
			archive_le32enc(&z, file->size);
		else
			z = 0;
		__archive_write_output(a, &z, 4);
		file = file->next;
	}
	__archive_write_nulls(a, ctx->cluster_size - ((32 * ctx->filecount) % ctx->cluster_size));

	if (lseek(ctx->temp_fd, 0, SEEK_SET) != 0) {
		archive_set_error(&a->archive, errno,
		    "Can't seek file");
		return (ARCHIVE_FATAL);
	}

	uint32_t written = 0;
	printf("TEMP size is %ld\n", ctx->temp_size);
	while (ctx->temp_size > 0) {
		size_t rsize;
		ssize_t rs;
		char buf[1024];

		rsize = sizeof(buf);
		if (rsize > ctx->temp_size)
			rsize = (size_t)ctx->temp_size;
		rs = read(ctx->temp_fd, buf, rsize);
		if (rs <= 0) {
			archive_set_error(&a->archive, errno,
			    "Can't read temporary file(%jd)", (intmax_t)rs);
			return (ARCHIVE_FATAL);
		}
		ctx->temp_size -= rs;
		__archive_write_output(a, buf, rs);
		written += rs;
	}

	/* rest of the disk */
	if (((total_secs - fatsz * numfats - reserved_cnt) * sec_size - written) != 0)
		__archive_write_nulls(a, (total_secs - fatsz * numfats - reserved_cnt) * sec_size - written);

	print_tree(&ctx->root->dir_info->rbtree);

	return (ARCHIVE_OK);
}

static void
print_tree(struct archive_rb_tree *root)
{
	struct archive_rb_node *rn;

	ARCHIVE_RB_TREE_FOREACH(rn, root) {
		struct msdosfs_entry *e = (struct msdosfs_entry *)rn;

		printf("FP %s\n", e->pathname.s);
		if (e->filetype == AE_IFDIR) {
			print_tree(&e->dir_info->rbtree);
		}
	}
}

static int
msdosfs_free(struct archive_write *a)
{
	msdosfs_ctx_t *ctx;

	ctx = a->format_data;

	assert(ctx != NULL);

	/* Close the temporary file. */
	if (ctx->temp_fd >= 0)
		close(ctx->temp_fd);

	archive_string_free(&(ctx->oem_name));
	archive_string_free(&(ctx->volume_label));

	msdosfs_entry_register_free(ctx);

	free(ctx);
	a->format_data = NULL;

	return (ARCHIVE_OK);
}
