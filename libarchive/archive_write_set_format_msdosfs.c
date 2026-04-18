/*-
 * Copyright (c) 2024-2026 Stanislav Sedov <stas@deglitch.com>
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

/*-
 * archive_write_set_format_msdosfs.c
 *
 * msdosfs (FAT) format writer for libarchive implementing
 * two-pass creation:
 *
 *   Pass 1 = Collect file data in temp file.
 *   Pass 2 = Build a minimal FAT geometry & cluster assignments,
 *            then write the entire FAT disk image to libarchive’s
 *            final output stream.
 *
 */

#include "archive_platform.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "archive.h"
#include "archive_entry.h"
#include "archive_endian.h"
#include "archive_private.h"
#include "archive_string.h"
#include "archive_write_private.h"

/* Debug macros -- uncomment to enable verbose debug output to stderr. */
/* #define MSDOSFS_DEBUG */
#ifdef MSDOSFS_DEBUG
#define DEBUG_PRINT(fmt, ...)  fprintf(stderr, "MSDOSFS: " fmt "\n", ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...)
#endif

/* 512-byte sectors. */
#define SECTOR_SIZE 512

/* FAT12 limit ~4084 clusters; FAT16 limit ~65524. */
#define FAT12_MAX_CLUSTERS  4084
#define FAT16_MIN_CLUSTERS  4085
#define FAT16_MAX_CLUSTERS  65524
#define FAT32_MIN_CLUSTERS  65525
/* 32-bit FAT uses up to ~2^28 clusters, but we rarely get that big. */

/* The first 2 cluster entries in the FAT are reserved. */
#define FAT_RESERVED_ENTRIES 2

/* 32-byte directory entries. */
#define DIR_ENTRY_SIZE 32

/* Directory entry attributes. */
#define ATTR_READ_ONLY  0x01
#define ATTR_HIDDEN     0x02
#define ATTR_SYSTEM     0x04
#define ATTR_VOLUME_ID  0x08
#define ATTR_DIRECTORY  0x10
#define ATTR_ARCHIVE    0x20
#define ATTR_LONG_NAME  (ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID)

/* FSInfo sector signature offsets and values (FAT32). */
#define FSINFO_SIG1_OFF     0
#define FSINFO_SIG1_VAL     0x41615252
#define FSINFO_SIG2_OFF     484
#define FSINFO_SIG2_VAL     0x61417272
#define FSINFO_FREE_OFF     488
#define FSINFO_NEXT_OFF     492
#define FSINFO_TRAIL_OFF    508
#define FSINFO_TRAIL_VAL    0xAA550000

/* Default CHS geometry for BPB. */
#define BPB_SEC_PER_TRK     63
#define BPB_NUM_HEADS       255

/* A single file or directory in this FAT image. */
struct fat_file {
    struct fat_file *next;

    /* The original libarchive entry (for time, perms, etc.). */
    struct archive_entry *entry;

    /* Basic info. */
    uint32_t size;             /* file size in bytes */
    int      is_dir;
    int      is_root;          /* True if it's the root directory (for FAT12/16 or FAT32). */

    /* Internal references. */
    struct fat_file *parent;   /* directory that contains us, or NULL if top-level (FAT12/16 root). */
    struct fat_file *children; /* child linked list for subdirectories. */
    struct fat_file *sibling;  /* next sibling. */

    /* FAT cluster assignment. */
    uint32_t first_cluster;
    uint32_t cluster_count;

    /* Name strings. */
    char    *long_name;        /* full path component or fallback. */
    uint8_t *utf16name;        /* long_name converted to UTF-16LE. */
    size_t   utf16name_len;    /* byte length of utf16name. */

    /* Where file data is stored in the temp file (for files). */
    off_t    content_offset;

    /* Additional fields could go here if needed. */
    char short_name[12];  /* 8.3 short name, null-terminated */
};

/* For detecting short-name collisions, we keep a hash of used names per directory. */
#define SHORTNAME_HASH_SIZE 256
struct shortname_entry {
    char name[12];  /* "8.3" short name, plus a terminating NUL or padding. */
    struct fat_file *parent_dir;
    struct shortname_entry *next;
};
struct shortname_hash {
    struct shortname_entry *buckets[SHORTNAME_HASH_SIZE];
};

/* Main context structure for this writer. */
struct msdosfs {
    /* Options / user selections: */
    int  fat_type;             /* 12, 16, 32, or 0 for 'auto' */
    char volume_label[12];     /* 11 chars + NUL */
    uint32_t volume_id;        /* volume serial number */
    int  volume_id_set;        /* non-zero if user explicitly set volume_id */
    int  cluster_size_override;/* 0 = auto, else sectors per cluster */
    /* Computed geometry: */
    uint32_t volume_size;      /* total sectors in the volume */
    uint32_t reserved_sectors;
    uint32_t fat_size;         /* in sectors */
    uint32_t root_entries;     /* # of 32-byte dir entries in FAT12/16 root */
    uint32_t root_size;        /* # of sectors in the root dir region */
    uint32_t cluster_size;     /* sectors per cluster */
    uint32_t cluster_count;    /* total usable clusters */
    uint32_t fat_offset;       /* sector offset of first FAT */
    uint32_t root_offset;      /* sector offset of FAT12/16 root directory */
    uint32_t data_offset;      /* sector offset of first data cluster */

    /* Linked list of all files (including directories). */
    struct fat_file *files;

    /* During pass #1, which file are we currently writing data to? */
    struct fat_file *current_file;
    size_t bytes_remaining;

    /* Temp file descriptor to hold the actual file data. */
    int temp_fd;

    /* For short-name collision detection: */
    struct shortname_hash used_shortnames;

    /* For a FAT32 root directory node, if needed. (is_root=1 + is_dir=1) */
    struct fat_file *fat32_root;

    /* String converter for UTF-8 to UTF-16LE (for LFN entries). */
    struct archive_string_conv *sconv_to_utf16;
    struct archive_string utf16buf;
};

/* The mandatory format callbacks: */
static int  archive_write_msdosfs_options(struct archive_write *a, const char *key, const char *val);
static int  archive_write_msdosfs_header(struct archive_write *a, struct archive_entry *entry);
static ssize_t archive_write_msdosfs_data(struct archive_write *a, const void *buff, size_t s);
static int  archive_write_msdosfs_finish_entry(struct archive_write *a);
static int  archive_write_msdosfs_close(struct archive_write *a);
static int  archive_write_msdosfs_free(struct archive_write *a);

/* Helpers for pass #2 (geometry, cluster assignment, output, etc.): */
static int  msdosfs_compute_geometry(struct archive_write *a);
static int  msdosfs_assign_clusters(struct archive_write *a);
static int  msdosfs_write_disk_image(struct archive_write *a);

/* Sub-steps for msdosfs_write_disk_image(): */
static int  write_boot_sector(struct archive_write *a);
static int  write_fat_tables(struct archive_write *a);
static int  write_fat12_16_root_dir(struct archive_write *a);
static int  write_data_clusters(struct archive_write *a);

/* Directory-entry build helpers: */
static void write_one_dir_entry(unsigned char *buf, const char shortnm[12],
                                const struct fat_file *f, int fat_type);
static void write_longname_entries(unsigned char *buf, const uint8_t *u16name,
                                   size_t u16len, const char shortnm[12]);

/* Directory and short-name utilities: */
static struct fat_file* find_or_create_dir(struct archive_write *a,
                                           struct msdosfs *msdos,
                                           struct fat_file *parent,
                                           const char *dirname);
static void add_child_to_parent(struct fat_file *parent, struct fat_file *child);

/* Short name logic + collisions. */
static void init_shortname_hash(struct shortname_hash *hash);
static unsigned int shortname_hash_key(const char *name, struct fat_file *parent_dir);
static int  shortname_exists(struct msdosfs *msdos, const char *name, struct fat_file *parent_dir);
static int  add_shortname(struct msdosfs *msdos, const char *name, struct fat_file *parent_dir);
static int  ensure_unique_short_name(struct archive_write *a, struct msdosfs *msdos,
                                     char short_name[12], struct fat_file *parent_dir);
static void make_short_name(const char *long_name, char short_name[12]);
static int  convert_name_to_utf16(struct archive_write *a, struct msdosfs *msdos,
                                  struct fat_file *f);

#ifdef MSDOSFS_DEBUG
static void
debug_dump_directory_buffer(const unsigned char *dirbuf, size_t total_bytes)
{
    size_t entry_count = total_bytes / 32;
    size_t i;

    fprintf(stderr, "\n[DIR DEBUG] Dumping %zu bytes of directory data:\n",
        total_bytes);

    for (i = 0; i < entry_count; i++) {
        const unsigned char *ent = dirbuf + i * 32;
        unsigned char attr;
        int b;

        if (ent[0] == 0x00) {
            fprintf(stderr,
                "  Entry #%zu @%zu: END OF DIR (0x00)\n", i, i * 32);
            break;
        }
        if (ent[0] == 0xE5) {
            fprintf(stderr,
                "  Entry #%zu @%zu: FREE (0xE5)\n", i, i * 32);
            continue;
        }

        attr = ent[11];
        if (attr == 0x0F) {
            fprintf(stderr,
                "  Entry #%zu @%zu: LFN (ord=0x%02X, chksum=0x%02X)\n",
                i, i * 32, ent[0], ent[13]);
        } else {
            unsigned int cluster_lo = ent[26] | (ent[27] << 8);
            unsigned int size = ent[28] | (ent[29] << 8) |
                (ent[30] << 16) | (ent[31] << 24);
            fprintf(stderr,
                "  Entry #%zu @%zu: SHORT [%.11s] attr=0x%02X "
                "cluster=%u size=%u\n",
                i, i * 32, (const char *)ent, attr, cluster_lo, size);
        }
        fprintf(stderr, "     Raw hex:");
        for (b = 0; b < 32; b++) {
            if (b % 8 == 0) fprintf(stderr, "\n     ");
            fprintf(stderr, " %02X", ent[b]);
        }
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "[DIR DEBUG] End of dump.\n\n");
}
#else
static void
debug_dump_directory_buffer(const unsigned char *dirbuf, size_t total_bytes)
{
    (void)dirbuf;
    (void)total_bytes;
}
#endif

/*
 * Public entry point: set the format to msdosfs (FAT).
 */
int
archive_write_set_format_msdosfs(struct archive *_a)
{
    struct archive_write *a = (struct archive_write *)_a;
    struct msdosfs *msdos;

    archive_check_magic(&a->archive, ARCHIVE_WRITE_MAGIC,
        ARCHIVE_STATE_NEW, "archive_write_set_format_msdosfs");

    msdos = (struct msdosfs *)calloc(1, sizeof(*msdos));
    if (!msdos) {
        archive_set_error(&a->archive, ENOMEM, "Cannot allocate msdosfs data");
        return (ARCHIVE_FATAL);
    }
    a->format_data = msdos;

    /* By default, let fat_type=0 => auto-detect (12/16/32) once we see total size. */
    msdos->fat_type = 0;

    /* Default volume label and ID. */
    memcpy(msdos->volume_label, "NO NAME    ", 11);
    msdos->volume_label[11] = '\0';
    msdos->volume_id = 0;
    msdos->volume_id_set = 0;
    msdos->cluster_size_override = 0;

    /* For FAT12/16, a default root_entries. We'll recalculate it later. */
    msdos->root_entries = 512; 

    /* Create the temp file (to store file data in pass #1). */
    msdos->temp_fd = __archive_mktemp(NULL);
    if (msdos->temp_fd < 0) {
        free(msdos);
        archive_set_error(&a->archive, errno, "Could not create temp file");
        return (ARCHIVE_FATAL);
    }

    /* Initialize short-name collision hash. */
    init_shortname_hash(&msdos->used_shortnames);

    /* Set up callbacks. */
    a->format_name           = "msdosfs";
    a->format_options        = archive_write_msdosfs_options;
    a->format_write_header   = archive_write_msdosfs_header;
    a->format_write_data     = archive_write_msdosfs_data;
    a->format_finish_entry   = archive_write_msdosfs_finish_entry;
    a->format_close          = archive_write_msdosfs_close;
    a->format_free           = archive_write_msdosfs_free;

    a->archive.archive_format = ARCHIVE_FORMAT_MSDOSFS;
    a->archive.archive_format_name = "MSDOSFS";

    return (ARCHIVE_OK);
}

/*
 * Implement user-specified options (e.g. "fat_type=12|16|32").
 */
static int
archive_write_msdosfs_options(struct archive_write *a, const char *key, const char *val)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;

    if (strcmp(key, "fat_type") == 0) {
        int t = atoi(val);
        if (t != 12 && t != 16 && t != 32) {
            archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
                "Invalid FAT type %d (must be 12, 16, or 32)", t);
            return (ARCHIVE_FATAL);
        }
        msdos->fat_type = t;
        return (ARCHIVE_OK);
    }
    if (strcmp(key, "volume_label") == 0 || strcmp(key, "volume-label") == 0) {
        size_t len, i;
        if (val == NULL)
            val = "";
        len = strlen(val);
        if (len > 11)
            len = 11;
        memset(msdos->volume_label, ' ', 11);
        msdos->volume_label[11] = '\0';
        for (i = 0; i < len; i++) {
            unsigned char c = (unsigned char)val[i];
            if (c >= 'a' && c <= 'z')
                c -= 32;
            msdos->volume_label[i] = c;
        }
        return (ARCHIVE_OK);
    }
    if (strcmp(key, "volume_id") == 0 || strcmp(key, "volume-id") == 0) {
        char *end;
        unsigned long id;
        if (val == NULL || *val == '\0') {
            archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
                "volume_id requires a value");
            return (ARCHIVE_FATAL);
        }
        id = strtoul(val, &end, 0);
        if (*end != '\0') {
            archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
                "Invalid volume_id: %s", val);
            return (ARCHIVE_FATAL);
        }
        msdos->volume_id = (uint32_t)id;
        msdos->volume_id_set = 1;
        return (ARCHIVE_OK);
    }
    if (strcmp(key, "cluster_size") == 0 || strcmp(key, "cluster-size") == 0) {
        int cs = atoi(val);
        if (cs < 1 || cs > 128 || (cs & (cs - 1)) != 0) {
            archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
                "cluster_size must be a power of 2 between 1 and 128");
            return (ARCHIVE_FATAL);
        }
        msdos->cluster_size_override = cs;
        return (ARCHIVE_OK);
    }

    /* If unrecognized, return warning. */
    return (ARCHIVE_WARN);
}

/*
 * Pass 1: archive_write_header => new file/dir is about to be written.
 * We create a new fat_file, parse its path into parent dirs, etc.
 * For directories, no data is written. For files, we remember content_offset
 * in the temp file.
 */
static int
archive_write_msdosfs_header(struct archive_write *a, struct archive_entry *entry)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    const char *pathname = archive_entry_pathname(entry);
    if (!pathname) pathname = "";

    DEBUG_PRINT("HEADER: %s", pathname);

    /* Allocate a new fat_file object. */
    struct fat_file *file = (struct fat_file *)calloc(1, sizeof(*file));
    if (!file) {
        archive_set_error(&a->archive, ENOMEM, "Cannot allocate fat_file");
        return ARCHIVE_FATAL;
    }
    file->entry   = archive_entry_clone(entry);
    file->is_dir  = (archive_entry_filetype(entry) == AE_IFDIR);

    /* FAT max file size is 4GB - 1. */
    if (!file->is_dir && archive_entry_size(entry) > (int64_t)UINT32_MAX) {
        archive_entry_free(file->entry);
        free(file);
        archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
            "File too large for FAT filesystem (max 4GB)");
        return (ARCHIVE_FAILED);
    }
    file->size = (uint32_t)archive_entry_size(entry);

    /* For FAT32, we keep a single special root node if needed. Create it once. */
    if (msdos->fat_type == 32 && msdos->fat32_root == NULL) {
        /* Create the FAT32 root directory node. */
        struct fat_file *root = (struct fat_file *)calloc(1, sizeof(*root));
        if (!root) {
            archive_entry_free(file->entry);
            free(file);
            archive_set_error(&a->archive, ENOMEM, "Cannot allocate FAT32 root dir");
            return (ARCHIVE_FATAL);
        }
        root->is_dir   = 1;
        root->is_root  = 1;
        root->long_name = strdup("FAT32_ROOT");
        root->next     = msdos->files;
        msdos->files   = root;
        msdos->fat32_root = root;
    }

    /* Duplicate the path for splitting. */
    char *dup_path = strdup(pathname);
    if (!dup_path) {
        archive_entry_free(file->entry);
        free(file);
        archive_set_error(&a->archive, ENOMEM, "strdup failed");
        return (ARCHIVE_FATAL);
    }

    /* Starting parent depends on if we have FAT32 root or not. */
    struct fat_file *parent_dir = NULL;
    if (msdos->fat_type == 32 && msdos->fat32_root) {
        parent_dir = msdos->fat32_root;
    }

    /* Split path by '/' to find or create each intermediate directory. */
    char *token, *brk;
    token = strtok_r(dup_path, "/", &brk);
    char *last_component = NULL;

    while (token) {
        char *next = strtok_r(NULL, "/", &brk);
        if (next) {
            /* This 'token' is an intermediate directory. */
            parent_dir = find_or_create_dir(a, msdos, parent_dir, token);
            if (parent_dir == NULL) {
                archive_entry_free(file->entry);
                free(file);
                free(dup_path);
                archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
                    "Failed to create intermediate directory");
                return (ARCHIVE_FATAL);
            }
        } else {
            /* This is the final component. */
            last_component = token;
        }
        token = next;
    }
    if (!last_component) last_component = dup_path;

    /* Save the final name as file->long_name. */
    if (last_component && last_component[0] != '\0')
        file->long_name = strdup(last_component);
    if (!file->long_name || file->long_name[0] == '\0') {
        if (file->long_name) free(file->long_name);
        file->long_name = strdup("NONAME");
    }

    free(dup_path);

    /* Generate and ensure unique short name. */
    make_short_name(file->long_name, file->short_name);
    if (ensure_unique_short_name(a, msdos, file->short_name, parent_dir) != 0) {
        archive_entry_free(file->entry);
        free(file->long_name);
        free(file);
        return (ARCHIVE_FATAL);
    }

    /* Convert name to UTF-16LE for LFN entries. */
    if (convert_name_to_utf16(a, msdos, file) != ARCHIVE_OK) {
        archive_entry_free(file->entry);
        free(file->long_name);
        free(file);
        return (ARCHIVE_FATAL);
    }

    /* Set up parent, link into parent's child list. */
    file->parent = parent_dir;
    if (parent_dir) {
        add_child_to_parent(parent_dir, file);
    }

    /* Insert into global msdos->files list. */
    file->next = msdos->files;
    msdos->files = file;

    if (!file->is_dir) {
        msdos->current_file = file;
        msdos->bytes_remaining = file->size;
        /* Seek to end of temp file to record where data starts. */
        off_t off = lseek(msdos->temp_fd, 0, SEEK_END);
        file->content_offset = off;
    }

    return ARCHIVE_OK;
}

/*
 * Pass 1: archive_write_data => write a data block for the *current_file*.
 * Simply write this block to the temp file.
 */
static ssize_t
archive_write_msdosfs_data(struct archive_write *a, const void *buff, size_t s)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    if (!msdos->current_file || msdos->current_file->is_dir) {
        /* No file is currently receiving data, or it's a dir. */
        return 0;
    }
    if (s > msdos->bytes_remaining) {
        s = msdos->bytes_remaining;
    }
    if (s == 0) {
        return 0;
    }
    ssize_t w = write(msdos->temp_fd, buff, s);
    if (w < 0) {
        archive_set_error(&a->archive, errno, "Write to temp file failed");
        return (ssize_t)ARCHIVE_FATAL;
    }
    msdos->bytes_remaining -= (size_t)w;
    return w;
}

/*
 * Pass 1: archive_write_finish_entry => finalize this entry.
 * Pad the file with zeros as needed.
 */
static int
archive_write_msdosfs_finish_entry(struct archive_write *a)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    if (msdos->current_file && msdos->bytes_remaining > 0) {
        char zero[8192];
        memset(zero, 0, sizeof(zero));
        while (msdos->bytes_remaining > 0) {
            size_t to_write = msdos->bytes_remaining;
            if (to_write > sizeof(zero)) {
                to_write = sizeof(zero);
            }
            if (write(msdos->temp_fd, zero, to_write) != (ssize_t)to_write) {
                archive_set_error(&a->archive, errno, "Zero-padding temp file failed");
                return ARCHIVE_FATAL;
            }
            msdos->bytes_remaining -= to_write;
        }
    }
    msdos->current_file = NULL;
    return ARCHIVE_OK;
}

/*
 * Pass 2: compute the minimal FAT geometry, assign clusters, and do a single
 * streaming write of the complete FAT filesystem structure to the archive.
 */
static int
archive_write_msdosfs_close(struct archive_write *a)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;

    /* 1) Compute minimal geometry to hold all directories & files. */
    int r = msdosfs_compute_geometry(a);
    if (r != ARCHIVE_OK) {
        return r;
    }

    DEBUG_PRINT("FAT type: %d, cluster_size=%u, volume_size=%u, fat_size=%u",
        msdos->fat_type, msdos->cluster_size,
        msdos->volume_size, msdos->fat_size);

    /* 2) Assign clusters to each file/directory. */
    r = msdosfs_assign_clusters(a);
    if (r != ARCHIVE_OK) {
        return r;
    }

    DEBUG_PRINT("Cluster assignment complete");

    /* 3) Stream out the final disk image directly to libarchive. */
    r = msdosfs_write_disk_image(a);
    if (r != ARCHIVE_OK) {
        return r;
    }

    /* Cleanup: close temp file, etc. */
    close(msdos->temp_fd);
    msdos->temp_fd = -1;
    return ARCHIVE_OK;
}

static int
archive_write_msdosfs_free(struct archive_write *a)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    if (msdos) {
        /* Free the shortname hash. */
        for (int i = 0; i < SHORTNAME_HASH_SIZE; i++) {
            struct shortname_entry *p = msdos->used_shortnames.buckets[i];
            while (p) {
                struct shortname_entry *nx = p->next;
                free(p);
                p = nx;
            }
        }
        /* Free the file list. */
        struct fat_file *f = msdos->files;
        while (f) {
            struct fat_file *nx = f->next;
            if (f->entry) archive_entry_free(f->entry);
            free(f->long_name);
            free(f->utf16name);
            free(f);
            f = nx;
        }
        archive_string_free(&msdos->utf16buf);
        free(msdos);
        a->format_data = NULL;
    }
    return ARCHIVE_OK;
}

/* ======================= PASS 2: Compute Geometry ======================= */

static void compute_directory_sizes(struct msdosfs *msdos);
static uint32_t count_needed_dir_entries(struct fat_file *dir);
static int try_fat_geometry(struct archive_write *a, int fat_type,
                            uint32_t *out_cluster_size);

/*
 * msdosfs_compute_geometry():
 *
 *  - Figures out whether to use FAT12, FAT16, or FAT32,
 *  - Picks a suitable cluster size (1..128 sectors/cluster),
 *  - Computes a volume size that fits all files + directories,
 *  - Stores the result into msdos->volume_size, msdos->fat_size, etc.
 *
 * This function tries:
 *    1) If msdos->fat_type is nonzero, we attempt that type only.
 *    2) If msdos->fat_type==0, we do "auto" => try FAT12, then 16, then 32.
 * For each type, we run an iterative approach that picks a cluster size
 * and tries to converge on a stable FAT layout.  If we fail for that type,
 * we move on to the next (unless the user forced a specific type).
 * 
 * We also handle the top-level root directory entry count for FAT12/16,
 * enlarging msdos->root_entries if needed to hold top-level items. 
 * For FAT32, root_entries = 0, root_size=0, because root is in data.
 * 
 * On success: returns ARCHIVE_OK; geometry fields are set.
 * On failure: returns ARCHIVE_FATAL with an error message in a->archive.
 */
static int
msdosfs_compute_geometry(struct archive_write *a)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;

    /* 
     * 1) First figure out how many directory entries are required, 
     *    so we know how big the root dir (for FAT12/16) must be, 
     *    and how big subdirs must be.
     */
    compute_directory_sizes(msdos);

    /*
     * If the user specified fat_type=12/16/32, we only try that.
     * Otherwise we try 12 -> 16 -> 32 in ascending order.
     */
    int types_to_try[3];
    int nt=0;
    if (msdos->fat_type == 0) {
        types_to_try[0] = 12;
        types_to_try[1] = 16;
        types_to_try[2] = 32;
        nt = 3;
    } else {
        types_to_try[0] = msdos->fat_type;
        nt = 1;
    }

    /* For each type we attempt, we see if we can find a cluster size that works. */
    for (int i = 0; i < nt; i++) {
        int ft = types_to_try[i];
        /*
         * try_fat_geometry() is a helper that tries cluster sizes from small to bigger
         * and, if it converges on a stable geometry, sets msdos->fat_type=ft, etc. 
         */
        uint32_t chosen_cluster_size = 0;
        int r = try_fat_geometry(a, ft, &chosen_cluster_size);
        if (r == ARCHIVE_OK) {
            /* success => store final type: */
            msdos->fat_type = ft;
            msdos->cluster_size = chosen_cluster_size;
            return ARCHIVE_OK;
        }
        /* If we fail, we continue to next type, unless that was forced by the user. */
        if (nt==1) {
            /* user forced this type => fatal error. */
            return ARCHIVE_FATAL;
        }
    }

    /* If we get here, we tried all feasible types => fail. */
    archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
                      "Could not find a suitable FAT geometry for all data");
    return ARCHIVE_FATAL;
}

/*
 * try_fat_geometry() => for a given fat_type = (12|16|32), tries 
 * cluster_size = 1,2,4,8,16,... up to some max, and attempts to converge 
 * on a stable geometry that fits all files & directories. 
 * 
 * If successful, sets msdos->... fields and returns ARCHIVE_OK. 
 * If not, returns ARCHIVE_FATAL, leaving geometry untouched.
 */
static int
try_fat_geometry(struct archive_write *a, int fat_type, uint32_t *out_cluster_size)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;

    /* We'll try these cluster sizes in turn: */
    static const uint32_t cluster_candidates[] = {1,2,4,8,16,32,64,128};
    int n_candidates = (int)(sizeof(cluster_candidates)/sizeof(cluster_candidates[0]));

    /* Precompute how many top-level items we might need in the root if FAT12/16. */
    if (fat_type==12 || fat_type==16) {
        /* Count how many top-level files/dirs are parent==NULL. */
        int count_top = 0;
        for (struct fat_file *f = msdos->files; f; f = f->next) {
            if (!f->is_root && f->parent == NULL) {
                count_top += count_needed_dir_entries(f);
            }
        }
        /* If that’s bigger than msdos->root_entries, enlarge it a bit. */
        if (count_top > (int)msdos->root_entries) {
            msdos->root_entries = (uint32_t)(count_top + 16);
        }
    } else {
        /* FAT32 => root_entries=0, root_size=0 (the root is in data). */
        msdos->root_entries = 0;
        msdos->root_size    = 0;
    }

    /* Now we attempt each cluster size in ascending order.
     * If the user specified a cluster_size_override, try only that. */
    for (int j=0; j<n_candidates; j++) {
        uint32_t csize = cluster_candidates[j];
        if (msdos->cluster_size_override > 0) {
            csize = (uint32_t)msdos->cluster_size_override;
            j = n_candidates; /* exit after this iteration */
        }

        /* Set up initial fields: */
        msdos->fat_type = fat_type;
        msdos->cluster_size = csize;

        if (fat_type == 32) {
            msdos->reserved_sectors = 32;
        } else {
            msdos->reserved_sectors = 1;
        }

        /* For FAT12/16 => root dir # of entries => root_size in sectors. */
        if (fat_type == 32) {
            msdos->root_size = 0;
        } else {
            msdos->root_size =
               (msdos->root_entries * DIR_ENTRY_SIZE + SECTOR_SIZE-1)/SECTOR_SIZE;
        }

        /* We do an iterative approach to fix up the FAT size. 
         * The challenge here is that the FAT size depends on cluster_count, which depends on 
         * volume_size - (reserved+2*fat_size+root_size)/cluster_size. 
         */
        uint32_t try_fat_size = 1; 
        uint32_t old_fat_size = 0;
        int attempts = 50; /* limit to avoid infinite loop in worst case. */

        while (attempts-- > 0) {

            /* 
             * We'll compute:
             *   data_offset = reserved_sectors + 2*fats + root_size
             *   data_sectors = volume_size - data_offset
             *   cluster_count = data_sectors / cluster_size
             *   then we see how many FAT entries => cluster_count+2 => 
             *   => how many bytes => => how many sectors => new_fat_size
             * If new_fat_size != try_fat_size, we update and loop again.
             */

             /* Count clusters needed per-file (each file/dir gets its
              * own cluster chain, so a 1-byte file still uses 1 cluster). */
            uint64_t cbytes = (uint64_t)csize * SECTOR_SIZE;
            uint64_t needed_clusters_for_files = 0;
            uint64_t needed_clusters_for_dirs = 0;
            for (struct fat_file *f = msdos->files; f; f = f->next) {
                if (f->is_dir) {
                    /* FAT12/16 root (is_root) does not consume clusters. */
                    if (!(f->is_root && (fat_type == 12 || fat_type == 16))
                        && f->size > 0)
                        needed_clusters_for_dirs +=
                            (f->size + cbytes - 1) / cbytes;
                } else {
                    if (f->size > 0)
                        needed_clusters_for_files +=
                            (f->size + cbytes - 1) / cbytes;
                }
            }
            uint64_t approx_clusters = needed_clusters_for_files + needed_clusters_for_dirs + 120;

            /* Enforce minimum cluster counts per FAT type so that
             * external tools (which determine FAT type by cluster
             * count, per the MS spec) agree with our format. */
            if (fat_type == 16 && approx_clusters < FAT16_MIN_CLUSTERS)
                approx_clusters = FAT16_MIN_CLUSTERS;
            if (fat_type == 32 && approx_clusters < FAT32_MIN_CLUSTERS)
                approx_clusters = FAT32_MIN_CLUSTERS;

            /* Let's pick volume_size initially as big enough for that many clusters 
             * plus overhead. We'll do a guess for the FAT. We'll override with try_fat_size. 
             */
            /* We'll do the formula:
             * volume_size = reserved_sectors + 2*fat_size + root_size + (approx_clusters * cluster_size)
             */
            uint64_t guess_volume = (uint64_t)msdos->reserved_sectors
                                  + 2ULL * try_fat_size
                                  + msdos->root_size
                                  + approx_clusters * csize;
            if (guess_volume > 0xFFFFFFFFU) {
                /* We exceed 32-bit sector count => can't do this approach. 
                 * (FAT in practice uses up to 2^32 - 1 sectors for FAT32. 
                 * We'll just fail if it’s bigger than 0xFFFFFFFF.)
                 */
                break; /* go to next cluster size. */
            }
            msdos->volume_size = (uint32_t)guess_volume;

            /* Now compute data_offset: */
            msdos->fat_offset  = msdos->reserved_sectors;
            msdos->root_offset = msdos->fat_offset + 2*try_fat_size;
            if (fat_type == 32) {
                msdos->data_offset = msdos->root_offset; /* root in data area */
            } else {
                msdos->data_offset = msdos->root_offset + msdos->root_size;
            }

            /* data_sectors = volume_size - data_offset, if that’s < 0 => fail. */
            if (msdos->data_offset >= msdos->volume_size) {
                /* means not enough data area. skip. */
                break;
            }
            uint32_t data_sectors = msdos->volume_size - msdos->data_offset;
            msdos->cluster_count = data_sectors / csize; /* how many clusters can fit? */

            /* Check cluster count limit for FAT12 or FAT16. 
             *  - FAT12 => <4084
             *  - FAT16 => <65524
             */
            if (fat_type==12 && msdos->cluster_count >= FAT12_MAX_CLUSTERS) {
                /* too big for FAT12 => break => next cluster size. */
                break;
            }
            if (fat_type==16 && msdos->cluster_count >= FAT16_MAX_CLUSTERS) {
                /* too big for FAT16 => break => next cluster size. */
                break;
            }

            /* Now compute how many FAT entries: cluster_count + 2 reserved. */
            uint32_t fat_entries = msdos->cluster_count + FAT_RESERVED_ENTRIES;

            /* Bytes needed for the FAT: */
            uint64_t fat_bytes = 0;
            if (fat_type==12) {
                fat_bytes = ((uint64_t)fat_entries *3 +1)/2; /* each cluster=12 bits => 1.5 bytes */
            } else if (fat_type==16) {
                fat_bytes = (uint64_t)fat_entries * 2;
            } else {
                fat_bytes = (uint64_t)fat_entries * 4;
            }
            uint32_t new_fat_size = (uint32_t)((fat_bytes + SECTOR_SIZE-1)/SECTOR_SIZE);

            if (new_fat_size == try_fat_size) {
                /* converged => let's see if cluster_count is large enough for all files + overhead. 
                 * We'll finalize msdos->fat_size and do a quick check if we truly can hold everything.
                 */
                msdos->fat_size = try_fat_size;

                /* 
                 * Quick final check: we can do a more thorough check in assign_clusters.
                 * But let's at least see if cluster_count=0 or obviously too small. 
                 */
                if (msdos->cluster_count < 1 && fat_type==32) {
                    /* We need at least 1 cluster for the FAT32 root. */
                    break;
                }
                /* We appear stable => success. */
                *out_cluster_size = csize;
                return ARCHIVE_OK;
            }

            /* Otherwise update try_fat_size and repeat. */
            if (new_fat_size == old_fat_size) {
                /* no progress => break. */
                break;
            }
            old_fat_size = try_fat_size;
            try_fat_size = new_fat_size;
        } /* end while attempts>0 */
    } /* end for j=0..n_candidates */

    /* If we get here => we couldn’t converge for that fat_type, fail. */
    return ARCHIVE_FATAL;
}

/*
 * compute_directory_sizes():
 *   For each directory in msdos->files, compute how many bytes are needed
 *   to store its directory entries (including LFN if used).  We place
 *   that into 'f->size' for the directory.  For the FAT12/16 root directory,
 *   we do not store anything in 'f->size' if f->is_root.
 *
 *   This is needed so we know how many clusters a subdirectory might require,
 *   and how large the root directory region might need to be (for FAT12/16).
 *
 *   Implementation details:
 *     - Each directory needs 2 entries for "." and "..".
 *     - Each child file/dir might need 1 short entry + LFN entries.
 *     - Then f->size = num_entries * 32.
 * 
 * Note that for the FAT12/16 root directory, we do NOT set f->size; instead
 * it’s limited by msdos->root_entries.  Only subdirectories get cluster-based
 * storage.
 */
static void
compute_directory_sizes(struct msdosfs *msdos)
{
    /* For each directory, count how many child dir-entries are needed. */
    for (struct fat_file *dir = msdos->files; dir; dir = dir->next) {
        if (!dir->is_dir) {
            continue;
        }
        if (dir->is_root && (msdos->fat_type==12 || msdos->fat_type==16)) {
            /* The FAT12/16 root directory is a fixed region, so skip. */
            continue;
        }

        /* Count children => 2 (for "." and "..") plus sum of each child’s needed entries. */
        uint32_t needed = 2; 
        /* For FAT32 root, we do the same approach, because FAT32 root is cluster-based. */
        for (struct fat_file *f = msdos->files; f; f=f->next) {
            if (f->parent == dir && f != dir) {
                needed += count_needed_dir_entries(f);
            }
        }
        /* Each entry is 32 bytes => total.  If a directory is empty, 
         * we still want at least 2 entries for "." and "..".
         */
        dir->size = needed * DIR_ENTRY_SIZE;
    }
}

/*
 * count_needed_dir_entries(f): 
 *   returns how many 32-byte directory entries are needed for this file
 *   or directory, including short+LFN.  Typically 1 short entry if the
 *   short name == long_name, otherwise add the LFN count.
 * 
 *   If f is a directory, we do not add the 2 extra for "." and ".." here,
 *   that is handled by the parent’s calculation. 
 */
static uint32_t
count_needed_dir_entries(struct fat_file *f)
{
    /* 1 short entry.  If long_name differs from the short name,
     * add LFN entries based on the UTF-16 character count.
     * Each LFN entry holds 13 UTF-16 code units.
     */
    if (!f->long_name)
        return (1);
    /* If the long name matches the short name, no LFN needed. */
    if (strcmp(f->long_name, f->short_name) == 0)
        return (1);
    /* Use UTF-16 code unit count (2 bytes each) for LFN calculation. */
    if (f->utf16name != NULL && f->utf16name_len > 0) {
        size_t u16chars = f->utf16name_len / 2;
        uint32_t lfn_count = (uint32_t)((u16chars + 12) / 13);
        return (1 + lfn_count);
    }
    /* Fallback: use byte length (correct for ASCII). */
    {
        size_t len = strlen(f->long_name);
        uint32_t lfn_count = (uint32_t)((len + 12) / 13);
        return (1 + lfn_count);
    }
}

/*
 * msdosfs_assign_clusters():
 *
 *  - For FAT12/16, the “root directory” is a fixed region, so it gets
 *    no clusters.
 *  - For FAT32, the root directory is allocated clusters just like
 *    a normal subdirectory, with at least 1 cluster if non-empty.
 *  - For subdirectories (non-root), we allocate enough clusters to hold
 *    f->size bytes.  If size>0 but the computed # of clusters is 0, 
 *    we force at least 1.
 *  - For files, if size>0, allocate enough clusters.  Zero-length => 0.
 *  - If we ever run out of cluster_count, we fail with “Not enough clusters for file”.
 */
static int
msdosfs_assign_clusters(struct archive_write *a)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    uint32_t total_clusters = msdos->cluster_count;  /* total in data area */
    uint32_t cluster_size_bytes = msdos->cluster_size * SECTOR_SIZE;

    /* We start assigning from cluster #2 up to cluster #2 + total_clusters -1. */
    uint32_t next_cluster = FAT_RESERVED_ENTRIES;
    uint32_t last_cluster = FAT_RESERVED_ENTRIES + total_clusters - 1;

    /* If FAT32 => root directory is cluster-based.  If f->size>0, allocate. 
     * We find the single f->is_root item if msdos->fat32_root is non-null. 
     */
    if (msdos->fat_type == 32) {
        struct fat_file *root_dir = msdos->fat32_root;
        if (!root_dir) {
            /* FAT32 was auto-detected; create the root node now
             * and re-parent all top-level files under it. */
            root_dir = (struct fat_file *)calloc(1, sizeof(*root_dir));
            if (!root_dir) {
                archive_set_error(&a->archive, ENOMEM,
                    "Cannot allocate FAT32 root dir");
                return ARCHIVE_FATAL;
            }
            root_dir->is_dir  = 1;
            root_dir->is_root = 1;
            root_dir->long_name = strdup("FAT32_ROOT");
            root_dir->next = msdos->files;
            msdos->files = root_dir;
            msdos->fat32_root = root_dir;

            /* Re-parent top-level files under the new root. */
            for (struct fat_file *f = msdos->files; f; f = f->next) {
                if (f != root_dir && !f->is_root && f->parent == NULL) {
                    f->parent = root_dir;
                    add_child_to_parent(root_dir, f);
                }
            }

            /* Recompute directory sizes with the new root. */
            compute_directory_sizes(msdos);
        }
        if (root_dir) {
            /* compute how many clusters are needed. */
            uint64_t s = root_dir->size;
            uint32_t needed = (uint32_t)((s + cluster_size_bytes -1)/cluster_size_bytes);
            if (needed==0) {
                needed=1;
            }

            if (needed>0) {
                if (next_cluster + needed -1 > last_cluster) {
                    archive_set_error(&a->archive, ENOSPC, 
                                      "Not enough clusters for FAT32 root");
                    return ARCHIVE_FATAL;
                }
                root_dir->first_cluster = next_cluster;
                root_dir->cluster_count = needed;
                next_cluster += needed;
            } else {
                root_dir->first_cluster = 0;
                root_dir->cluster_count = 0;
            }
        }
    }

    /* Now assign clusters to everything else. */
    for (struct fat_file *f = msdos->files; f; f = f->next) {
        /* If this is the FAT32 root, we already assigned above. */
        if (msdos->fat_type==32 && f->is_root) {
            continue;
        }

        /* If this is the FAT12/16 root => no clusters. */
        if (f->is_root && (msdos->fat_type==12 || msdos->fat_type==16)) {
            f->first_cluster = 0;
            f->cluster_count = 0;
            continue;
        }

        DEBUG_PRINT("Trying to assign clusters for '%s'(size=%u)\n",
                        f->long_name ? f->long_name : "null", f->size);
        if (f->is_dir) {
            /* subdirectory => need enough clusters for f->size. 
             * if f->size>0 => #clusters = (f->size+(cluster_size_bytes-1))/cluster_size_bytes.
             * if zero => we typically do 0 or 1 cluster. Let’s do 1 if it’s not the root. 
             */
            uint64_t dir_bytes = (f->size==0 ? 0 : (uint64_t)f->size);
            uint32_t needed = (uint32_t)((dir_bytes + cluster_size_bytes-1)/cluster_size_bytes);
            if (dir_bytes>0 && needed==0) {
                needed=1;
            }
            if (needed>0) {
                if (next_cluster + needed -1 > last_cluster) {
                    archive_set_error(&a->archive, ENOSPC, 
                                      "Not enough clusters for subdirectory");
                    return ARCHIVE_FATAL;
                }
                f->first_cluster = next_cluster;
                f->cluster_count = needed;
                next_cluster += needed;
            } else {
                /* empty => zero clusters. */
                f->first_cluster=0;
                f->cluster_count=0;
            }
        } else {
            /* a regular file */
            if (f->size == 0) {
                f->first_cluster=0;
                f->cluster_count=0;
            } else {
                uint64_t file_bytes = f->size;
                uint32_t needed = (uint32_t)((file_bytes + cluster_size_bytes -1)/cluster_size_bytes);
                if (next_cluster + needed -1 > last_cluster) {
                    DEBUG_PRINT("Unable to assign '%s' clusters %u..%u (count=%u)\n",
                        f->long_name ? f->long_name : "(null)",
                        next_cluster, next_cluster + needed, needed);
                    archive_set_error(&a->archive, ENOSPC, 
                                      "Not enough clusters for file");
                    return ARCHIVE_FATAL;
                }
                f->first_cluster = next_cluster;
                f->cluster_count = needed;
                next_cluster += needed;
            }
        }
                    DEBUG_PRINT("Assigning '%s' clusters %u..%u (count=%u)\n",
                        f->long_name ? f->long_name : "(null)",
                        f->first_cluster, f->first_cluster + f->cluster_count, f->cluster_count);
    }

    /* If we get here => success. */
    return ARCHIVE_OK;
}

/* ======================= PASS 2: Write Disk Image ======================= */

/*
 * Produce the entire FAT volume by writing each piece in order:
 *   1) Boot sector (and FSInfo, backup BS if FAT32)
 *   2) FAT #1, FAT #2
 *   3) Root directory region (only for FAT12/16)
 *   4) Data area: cluster by cluster
 *      - If cluster belongs to a subdir, build that subdir in memory, output it
 *      - If cluster belongs to a file, read from temp file
 *      - If cluster is free (not assigned), output zeros
 */
static int
msdosfs_write_disk_image(struct archive_write *a)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    int r;

    /* 1) Write the boot sector (and possibly FSInfo + backup BS). */
    r = write_boot_sector(a);
    if (r != ARCHIVE_OK) return r;

    /* 2) Build and write the two FAT copies in memory. */
    r = write_fat_tables(a);
    if (r != ARCHIVE_OK) return r;

    /* 3) If FAT12/16, write the root directory region directly. */
    if (msdos->fat_type != 32) {
        r = write_fat12_16_root_dir(a);
        if (r != ARCHIVE_OK) return r;
    }

    /* 4) Now write the data area cluster by cluster. */
    r = write_data_clusters(a);
    if (r != ARCHIVE_OK) return r;

    return ARCHIVE_OK;
}

/* ------------------- 1) Boot Sector & FSInfo  ------------------- */

/* Minimal helper for building boot sector in memory. */
/* Standard DOS 8‐byte jump + OEM, then a BPB. We unify for FAT12/16/32. */
struct bpb_common {
    uint8_t  jmp[3];      /* 0xEB, +2 bytes, e.g. 0xEB 0x58 0x90 */
    uint8_t  oem[8];      /* e.g. "MSWIN4.1" */
    /* BIOS Parameter Block (BPB) fields: */
    uint16_t bytes_per_sec;
    uint8_t  sec_per_clus;
    uint16_t rsvd_sec_cnt;
    uint8_t  num_fats;
    uint16_t root_ent_cnt;
    uint16_t tot_sec16;
    uint8_t  media;
    uint16_t fat_sz16;
    uint16_t sec_per_trk;
    uint16_t num_heads;
    uint32_t hid_sec;
    uint32_t tot_sec32;
} __attribute__ ((packed));
struct bpb_fat32 {
    uint32_t fat_sz32;
    uint16_t ext_flags;
    uint16_t fs_ver;
    uint32_t root_clus;
    uint16_t fs_info;
    uint16_t bk_boot_sec;
    uint8_t  reserved[12];
} __attribute__ ((packed));
struct bs_ext {
    uint8_t  drv_num;
    uint8_t  reserved1;
    uint8_t  boot_sig;
    uint32_t vol_id;
    uint8_t  vol_lab[11];
    uint8_t  fil_sys_type[8];
} __attribute__ ((packed));

static int
write_boot_sector(struct archive_write *a)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    unsigned char sector[SECTOR_SIZE];
    uint32_t vol_id;
    struct bpb_common *bpb;

    /* Generate volume ID if not explicitly set. */
    if (msdos->volume_id_set)
        vol_id = msdos->volume_id;
    else
        vol_id = (uint32_t)time(NULL);

    memset(sector, 0, SECTOR_SIZE);
    bpb = (struct bpb_common *)sector;
    bpb->jmp[0] = 0xEB;  /* short jmp */
    bpb->jmp[1] = 0x3C;
    bpb->jmp[2] = 0x90;
    memcpy(bpb->oem, "MSWIN4.1", 8);

    archive_le16enc(&bpb->bytes_per_sec, SECTOR_SIZE);
    bpb->sec_per_clus = (uint8_t)msdos->cluster_size;
    archive_le16enc(&bpb->rsvd_sec_cnt, (uint16_t)msdos->reserved_sectors);
    bpb->num_fats = 2;

    if (msdos->fat_type == 32 || msdos->volume_size >= 65536) {
        archive_le16enc(&bpb->tot_sec16, 0);
        archive_le32enc(&bpb->tot_sec32, msdos->volume_size);
    } else {
        archive_le16enc(&bpb->tot_sec16, (uint16_t)msdos->volume_size);
        archive_le32enc(&bpb->tot_sec32, 0);
    }
    bpb->media = 0xF8; /* fixed disk */
    archive_le16enc(&bpb->sec_per_trk, BPB_SEC_PER_TRK);
    archive_le16enc(&bpb->num_heads, BPB_NUM_HEADS);
    archive_le32enc(&bpb->hid_sec, 0);

    /* For FAT12/16, store fat_sz16 in bpb; for FAT32, store in bpb_fat32. */
    if (msdos->fat_type == 32) {
        archive_le16enc(&bpb->fat_sz16, 0);

        /* The FAT32 extensions come after the common BPB. */
        struct bpb_fat32 *bpb32 = (struct bpb_fat32 *)(sector + 36);
        archive_le32enc(&bpb32->fat_sz32, msdos->fat_size);
        archive_le16enc(&bpb32->ext_flags, 0);
        archive_le16enc(&bpb32->fs_ver, 0);
        archive_le32enc(&bpb32->root_clus, 2);
        archive_le16enc(&bpb32->fs_info, 1);
        archive_le16enc(&bpb32->bk_boot_sec, 6);
        memset(&bpb32->reserved[0], 0, 12);

        /* Then the DOS 3.31 boot sector extension near offset 0x5A. */
        struct bs_ext *bsx = (struct bs_ext *)(sector + 64);
        bsx->drv_num = 0x80;
        bsx->reserved1 = 0;
        bsx->boot_sig = 0x29;
        archive_le32enc(&bsx->vol_id, vol_id);
        memcpy(bsx->vol_lab, msdos->volume_label, 11);
        memcpy(bsx->fil_sys_type, "FAT32   ", 8);
    } else {
    	archive_le16enc(&bpb->root_ent_cnt, (uint16_t)msdos->root_entries);
        archive_le16enc(&bpb->fat_sz16, (uint16_t)msdos->fat_size);
        /* The DOS extension for FAT12/16 is at offset 36. */
        struct bs_ext *bsx = (struct bs_ext *)(sector + 36);
        bsx->drv_num = 0x80;
        bsx->reserved1 = 0;
        bsx->boot_sig = 0x29;
        archive_le32enc(&bsx->vol_id, vol_id);
        memcpy(bsx->vol_lab, msdos->volume_label, 11);
        if (msdos->fat_type == 16)
            memcpy(bsx->fil_sys_type, "FAT16   ", 8);
        else
            memcpy(bsx->fil_sys_type, "FAT12   ", 8);
    }

    /* Signature */
    sector[510] = 0x55;
    sector[511] = 0xAA;

    /* Write out the boot sector. */
    int r = __archive_write_output(a, sector, SECTOR_SIZE);
    if (r != ARCHIVE_OK) {
        return r;
    }

    /* If FAT32 => FSInfo (sector #1), Backup Boot Sector (#6). */
    if (msdos->fat_type == 32) {
        /* FSInfo sector. */
        unsigned char fsinfo[SECTOR_SIZE];
        memset(fsinfo, 0, SECTOR_SIZE);
        archive_le32enc(fsinfo + FSINFO_SIG1_OFF, FSINFO_SIG1_VAL);
        archive_le32enc(fsinfo + FSINFO_SIG2_OFF, FSINFO_SIG2_VAL);

        /* Compute total allocated clusters. */
        uint32_t used_clusters = 0;
        uint32_t last_allocated = 2; /* Default: FAT32 root cluster */
        struct fat_file *f;

        for (f = msdos->files; f; f = f->next) {
            used_clusters += f->cluster_count;
            if (f->cluster_count > 0) {
                uint32_t end_cluster = f->first_cluster + f->cluster_count - 1;
                if (end_cluster > last_allocated)
                    last_allocated = end_cluster;
            }
        }

        /* Compute free clusters. */
        uint32_t data_clusters = msdos->cluster_count;
        uint32_t free_clusters = (data_clusters > used_clusters) ?
            (data_clusters - used_clusters) : 0;

        archive_le32enc(fsinfo + FSINFO_FREE_OFF, free_clusters);
        archive_le32enc(fsinfo + FSINFO_NEXT_OFF, last_allocated);
        archive_le32enc(fsinfo + FSINFO_TRAIL_OFF, FSINFO_TRAIL_VAL);
        r = __archive_write_output(a, fsinfo, SECTOR_SIZE);
        if (r != ARCHIVE_OK) return r;

        /* Sectors #2..#5 => normally zero. We need reserved_sectors=32, so we have space. */
        unsigned char zeros[SECTOR_SIZE];
        memset(zeros, 0, SECTOR_SIZE);
        for (int i = 2; i < 6; i++) {
            r = __archive_write_output(a, zeros, SECTOR_SIZE);
            if (r != ARCHIVE_OK) return r;
        }
        /* Sector #6 => backup boot sector (copy of main). */
        r = __archive_write_output(a, sector, SECTOR_SIZE);
        if (r != ARCHIVE_OK) return r;

        /* Then #7.. up to rsvd_sec_cnt-1 => zero. */
        for (int i = 7; i < (int)msdos->reserved_sectors; i++) {
            r = __archive_write_output(a, zeros, SECTOR_SIZE);
            if (r != ARCHIVE_OK) return r;
        }
    } else {
        /* For FAT12/16, typically only 1 reserved sector => we've already written it. */
        /* If reserved_sectors>1, we just fill them with zero except the first. */
        unsigned char zeros[SECTOR_SIZE];
        memset(zeros, 0, SECTOR_SIZE);
        for (int i=1; i<(int)msdos->reserved_sectors; i++) {
            r = __archive_write_output(a, zeros, SECTOR_SIZE);
            if (r != ARCHIVE_OK) return r;
        }
    }
    return ARCHIVE_OK;
}

/* ------------------- 2) Write the FATs in memory ------------------- */

/* Helper for 12-bit packing. */
static void
fat12_set_entry(unsigned char *fat, uint32_t cluster, uint16_t value)
{
    uint32_t index = (cluster * 3) / 2;
    if ((cluster & 1) == 0) {
        fat[index]   = (unsigned char)(value & 0xFF);
        fat[index+1] = (unsigned char)((fat[index+1] & 0xF0) | ((value >> 8) & 0x0F));
    } else {
        fat[index]   = (unsigned char)((fat[index] & 0x0F) | ((value << 4) & 0xF0));
        fat[index+1] = (unsigned char)((value >> 4) & 0xFF);
    }
}

/*
 * Build a single FAT copy in memory, then write it out. We'll do 2 copies.
 * Mark cluster 0 => media descriptor, cluster 1 => 0xFFF... EOC, etc.
 * Then link up each file/dir's cluster chain. 
 *
 * By the time we reach here, msdos->first_cluster/cluster_count are assigned
 * for each item. 
 */
static int
write_fat_tables(struct archive_write *a)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;

    size_t fat_bytes = (size_t)msdos->fat_size * SECTOR_SIZE;
    unsigned char *fat = (unsigned char *)calloc(1, fat_bytes);
    if (!fat) {
        archive_set_error(&a->archive, ENOMEM, "No memory for FAT table");
        return ARCHIVE_FATAL;
    }

    /* Initialize first 2 entries. */
    if (msdos->fat_type == 12) {
        /* cluster=0 => 0xFF8, cluster=1 => 0xFFF. */
        fat12_set_entry(fat, 0, 0xFF8);
        fat12_set_entry(fat, 1, 0xFFF);
    } else if (msdos->fat_type == 16) {
        archive_le16enc(fat + 0, 0xFFF8);
        archive_le16enc(fat + 2, 0xFFFF);
    } else {
        /* FAT32 => first = 0x0FFFFFF8, second= 0x0FFFFFFF. */
        archive_le32enc(fat + 0, 0x0FFFFFF8);
        archive_le32enc(fat + 4, 0x0FFFFFFF);
    }

    /* For each file/dir chain, link the clusters. We'll do them in ascending order. */
    /* We can just do a pass over all fat_file's that have cluster_count>0. Then
     * for cluster_count N, link cluster[k] -> cluster[k+1]. The last => EOC. 
     */
    struct fat_file *f;
    for (f = msdos->files; f; f = f->next) {
        if (f->cluster_count == 0) {
            continue;
        }
        uint32_t start = f->first_cluster;
        uint32_t end   = start + f->cluster_count - 1;

                DEBUG_PRINT("FAT linking '%s' chain from %u..%u\n",
                    f->long_name ? f->long_name : "(null)", start, end);

        for (uint32_t c = start; c <= end; c++) {
            uint32_t nextval = 0;
            if (c < end) {
                nextval = c + 1;
            } else {
                /* final => EOC */
                if (msdos->fat_type == 12) {
                    nextval = 0xFFF;
                } else if (msdos->fat_type == 16) {
                    nextval = 0xFFFF;
                } else {
                    nextval = 0x0FFFFFFF;
                }
            }
            if (c > (msdos->cluster_count + 1)) {
                free(fat);
                archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
                    "Cluster %u exceeds valid range (max %u)",
                    c, msdos->cluster_count + 1);
                return (ARCHIVE_FATAL);
            }
            if (msdos->fat_type == 12) {
                fat12_set_entry(fat, c, (uint16_t)nextval);
            } else if (msdos->fat_type == 16) {
                archive_le16enc(fat + (c*2), (uint16_t)nextval);
            } else {
                archive_le32enc(fat + (c*4), nextval);
            }
        }
    }

    /* Now write out this FAT buffer twice. */
    for (int copy=0; copy < 2; copy++) {
        int r = __archive_write_output(a, fat, fat_bytes);
        if (r != ARCHIVE_OK) {
            free(fat);
            return r;
        }
    }
    free(fat);
    return ARCHIVE_OK;
}

/* ------------------- 3) FAT12/16 Root Directory ------------------- */

/*
 * For FAT12/16, the root dir is in a fixed region of size root_size sectors.
 * We gather all top-level items whose parent==NULL, build the directory entries
 * (including LFN if needed), then zero-fill the rest.
 */
static int
write_fat12_16_root_dir(struct archive_write *a)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    uint32_t root_dir_sectors = msdos->root_size;
    if (root_dir_sectors == 0) {
        return ARCHIVE_OK; /* nothing to write */
    }
    size_t root_dir_bytes = (size_t)root_dir_sectors * SECTOR_SIZE;
    unsigned char *buf = (unsigned char *)calloc(1, root_dir_bytes);
    if (!buf) {
        archive_set_error(&a->archive, ENOMEM, "No memory for root directory");
        return ARCHIVE_FATAL;
    }
    /* Build the entries from all top-level items (parent==NULL). */
    size_t offset = 0;
    struct fat_file *f;
    for (f = msdos->files; f; f = f->next) {
        if (f->parent == NULL && !f->is_root) {
            /* If the long name differs, write LFN. */
            if (f->long_name && strcmp(f->long_name, f->short_name) != 0
                && f->utf16name != NULL) {
                int u16chars = (int)(f->utf16name_len / 2);
                int lfn_count = (u16chars + 12) / 13;
                size_t lfn_bytes = (size_t)lfn_count * DIR_ENTRY_SIZE;
                if (offset + lfn_bytes + DIR_ENTRY_SIZE > root_dir_bytes) {
                    free(buf);
                    archive_set_error(&a->archive, ENOSPC, "Root directory overflow");
                    return (ARCHIVE_FATAL);
                }
                write_longname_entries(buf + offset,
                    f->utf16name, f->utf16name_len, f->short_name);
                offset += lfn_bytes;
            }
            /* Then the final 32-byte short entry. */
            if (offset + DIR_ENTRY_SIZE > root_dir_bytes) {
                free(buf);
                archive_set_error(&a->archive, ENOSPC, "Root directory overflow");
                return ARCHIVE_FATAL;
            }
            write_one_dir_entry(buf + offset, f->short_name, f, msdos->fat_type);
            offset += DIR_ENTRY_SIZE;
        }
    }
    /* Now write out 'buf' to the archive. */
    debug_dump_directory_buffer(buf, root_dir_bytes);
    int r = __archive_write_output(a, buf, root_dir_bytes);
    free(buf);
    return r;
}

/* ------------------- 4) Data Area (subdirectories + file data) ------------------- */

/*
 * For the data area, we have clusters from #2.. up to #2 + cluster_count -1.
 * We'll do a single linear pass over all clusters. For each cluster N:
 *
 *  - If belongs to a directory (f->is_dir) => build that directory block in memory, write it.
 *  - If belongs to a file => read from temp_fd at file->content_offset + cluster_index * cluster_bytes
 *  - Else => zero cluster.
 *
 * We'll track ownership via a small array we build below. For subdirs, we
 * build the actual directory entries (including '.' and '..') in memory.
 */
struct cluster_info {
    struct fat_file *owner;   /* file/dir that owns this cluster (if any) */
    uint32_t index_in_file;   /* which cluster index in that file/dir? 0,1,2,... */
};

static int
write_data_clusters(struct archive_write *a)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    uint32_t total_clusters = msdos->cluster_count;
    size_t cluster_bytes = (size_t)msdos->cluster_size * SECTOR_SIZE;

    /* Build an array that tells us who owns each cluster. */
    struct cluster_info *map =
        (struct cluster_info*)calloc(total_clusters+2, sizeof(*map));
    if (!map) {
        archive_set_error(&a->archive, ENOMEM, "No memory for cluster info map");
        return ARCHIVE_FATAL;
    }
    /* Fill map: For each file/dir that has cluster_count>0, 
     * for c in [first_cluster.. first_cluster+count-1], map[c].owner = that f,
     * and map[c].index_in_file = i. 
     */
    struct fat_file *f;
    for (f = msdos->files; f; f = f->next) {
        if (f->cluster_count == 0) {
            continue;
        }
        uint32_t start = f->first_cluster;
        uint32_t end   = start + f->cluster_count - 1;
        uint32_t idx   = 0;
        for (uint32_t c = start; c <= end; c++) {
            map[c].owner = f;
            map[c].index_in_file = idx++;
        }
    }

    /* Now do a single pass from cluster=2..(1+total_clusters). Write each cluster. */
    unsigned char *tempbuf = (unsigned char *)malloc(cluster_bytes);
    if (!tempbuf) {
        free(map);
        archive_set_error(&a->archive, ENOMEM, "No memory for cluster buffer");
        return ARCHIVE_FATAL;
    }

    /* Cache for directory data: avoid rebuilding for every cluster
     * of a multi-cluster directory.  Clusters for each directory are
     * contiguous, so we build once and reuse. */
    struct fat_file *cached_dir_owner = NULL;
    unsigned char *cached_dirbuf = NULL;
    size_t cached_dir_size = 0;

    for (uint32_t c = FAT_RESERVED_ENTRIES; c < FAT_RESERVED_ENTRIES + total_clusters; c++) {
        struct cluster_info *ci = &map[c];
        if (!ci->owner) {
            /* Unused cluster => write zero. */
            memset(tempbuf, 0, cluster_bytes);
        } else {
            struct fat_file *owner = ci->owner;
            if (owner->is_dir) {
                memset(tempbuf, 0, cluster_bytes);

                /* Build directory data once per directory, cache it. */
                if (owner != cached_dir_owner) {
                    free(cached_dirbuf);
                    cached_dir_size = owner->size;
                    if (cached_dir_size == 0)
                        cached_dir_size = DIR_ENTRY_SIZE * 2;
                    cached_dirbuf = (unsigned char*)calloc(1, cached_dir_size);
                    if (!cached_dirbuf) {
                        free(tempbuf);
                        free(map);
                        archive_set_error(&a->archive, ENOMEM,
                            "No memory for subdir build");
                        return ARCHIVE_FATAL;
                    }
                    cached_dir_owner = owner;

                    size_t off = 0;

                    /* "." entry. */
                    {
                        char dotname[11] = ".          ";
                        write_one_dir_entry(cached_dirbuf + off, dotname,
                            owner, msdos->fat_type);
                        off += DIR_ENTRY_SIZE;
                    }
                    /* ".." entry. */
                    {
                        char dotdot[11] = "..         ";
                        struct fat_file dummy_parent = {0};
                        struct fat_file *p = owner->parent;
                        if (msdos->fat_type == 32 && p && p->is_root) {
                            dummy_parent.is_dir = 1;
                            dummy_parent.first_cluster = 0;
                            write_one_dir_entry(cached_dirbuf + off, dotdot,
                                &dummy_parent, msdos->fat_type);
                        } else if (!p && (msdos->fat_type == 12 ||
                            msdos->fat_type == 16)) {
                            dummy_parent.is_dir = 1;
                            dummy_parent.first_cluster = 0;
                            write_one_dir_entry(cached_dirbuf + off, dotdot,
                                &dummy_parent, msdos->fat_type);
                        } else if (p) {
                            write_one_dir_entry(cached_dirbuf + off, dotdot,
                                p, msdos->fat_type);
                        } else {
                            dummy_parent.is_dir = 1;
                            dummy_parent.first_cluster = 0;
                            write_one_dir_entry(cached_dirbuf + off, dotdot,
                                &dummy_parent, msdos->fat_type);
                        }
                        off += DIR_ENTRY_SIZE;
                    }
                    /* Child entries. */
                    {
                        struct fat_file *ch = owner->children;
                        while (ch) {
                            if (ch->long_name &&
                                strcmp(ch->long_name, ch->short_name) != 0
                                && ch->utf16name != NULL) {
                                int u16c = (int)(ch->utf16name_len / 2);
                                int lfn_count = (u16c + 12) / 13;
                                size_t lfn_bytes =
                                    (size_t)lfn_count * DIR_ENTRY_SIZE;
                                if (off + lfn_bytes + DIR_ENTRY_SIZE >
                                    cached_dir_size) {
                                    free(cached_dirbuf);
                                    free(tempbuf);
                                    free(map);
                                    archive_set_error(&a->archive,
                                        ARCHIVE_ERRNO_MISC,
                                        "Subdirectory entries exceed "
                                        "allocated space");
                                    return (ARCHIVE_FATAL);
                                }
                                write_longname_entries(
                                    cached_dirbuf + off,
                                    ch->utf16name, ch->utf16name_len,
                                    ch->short_name);
                                off += lfn_bytes;
                            }
                            if (off + DIR_ENTRY_SIZE > cached_dir_size) {
                                free(cached_dirbuf);
                                free(tempbuf);
                                free(map);
                                archive_set_error(&a->archive,
                                    ARCHIVE_ERRNO_MISC,
                                    "Subdirectory entries exceed "
                                    "allocated space");
                                return (ARCHIVE_FATAL);
                            }
                            write_one_dir_entry(cached_dirbuf + off,
                                ch->short_name, ch, msdos->fat_type);
                            off += DIR_ENTRY_SIZE;
                            ch = ch->sibling;
                        }
                    }
                    debug_dump_directory_buffer(cached_dirbuf, cached_dir_size);
                }

                /* Copy out the slice for this cluster. */
                size_t cluster_offset =
                    (size_t)ci->index_in_file * cluster_bytes;
                if (cluster_offset < cached_dir_size) {
                    size_t to_copy = cached_dir_size - cluster_offset;
                    if (to_copy > cluster_bytes)
                        to_copy = cluster_bytes;
                    memcpy(tempbuf, cached_dirbuf + cluster_offset, to_copy);
                }

            } else {
                /* It's a file. We read from the temp file. */
                uint32_t idx = ci->index_in_file; /* cluster index in the file. */
                off_t read_off = (off_t)(owner->content_offset + (off_t)idx*(off_t)cluster_bytes);
                /* We read up to cluster_bytes or until the file ends. (But if assigned cluster_count 
                 * exactly matches the file size, it should fill the entire cluster except possibly the last. 
                 */
                memset(tempbuf, 0, cluster_bytes);
                size_t to_read = cluster_bytes;
                /*
                 * Read up to cluster_bytes.  If the file was smaller,
                 * we zero-padded in the temp file during pass #1.
                 */
                if (lseek(msdos->temp_fd, read_off, SEEK_SET) < 0) {
                    free(cached_dirbuf);
                    free(tempbuf);
                    free(map);
                    archive_set_error(&a->archive, errno, "lseek failed reading file data");
                    return ARCHIVE_FATAL;
                }
                size_t got = 0;
                while (got < to_read) {
                    ssize_t rd = read(msdos->temp_fd, tempbuf + got, to_read - got);
                    if (rd < 0) {
                        free(cached_dirbuf);
                        free(tempbuf);
                        free(map);
                        archive_set_error(&a->archive, errno, "Error reading temp file data");
                        return ARCHIVE_FATAL;
                    }
                    if (rd == 0) {
                        /* EOF => fill remainder with zero. */
                        break;
                    }
                    got += (size_t)rd;
                }
            }
        }
        /* Write cluster data out. */
        int ret = __archive_write_output(a, tempbuf, cluster_bytes);
        if (ret != ARCHIVE_OK) {
            free(cached_dirbuf);
            free(tempbuf);
            free(map);
            return ret;
        }
    }

    free(cached_dirbuf);
    free(tempbuf);
    free(map);
    return ARCHIVE_OK;
}

/* -------------------- Directory Entry Builders -------------------- */

/* Write a single 32-byte dir entry (short 8.3 name).  */
static void
write_one_dir_entry(unsigned char *buf, const char shortnm[12],
                    const struct fat_file *f, int fat_type)
{
    memset(buf, 0, DIR_ENTRY_SIZE);
    memcpy(buf, shortnm, 11);

    /* Attributes. */
    buf[11] = (unsigned char)(f->is_dir ? ATTR_DIRECTORY : ATTR_ARCHIVE);

    /* Timestamps: clamp to 1980-01-01 minimum for DOS date encoding. */
    time_t mtime = 0;
    if (f->entry) {
        mtime = archive_entry_mtime(f->entry);
    }
    struct tm t;
    if (!localtime_r(&mtime, &t) || t.tm_year < 80) {
        memset(&t, 0, sizeof(t));
        t.tm_year = 80; /* 1980 */
        t.tm_mon  = 0;
        t.tm_mday = 1;
    }
    uint16_t dos_time = (uint16_t)((t.tm_hour << 11) | (t.tm_min << 5) | (t.tm_sec / 2));
    uint16_t dos_date = (uint16_t)(((t.tm_year - 80) << 9) | ((t.tm_mon + 1) << 5) | t.tm_mday);

    archive_le16enc(buf + 14, dos_time); /* crt time */
    archive_le16enc(buf + 16, dos_date); /* crt date */
    archive_le16enc(buf + 18, dos_date); /* lst access date */
    archive_le16enc(buf + 22, dos_time); /* wtime */
    archive_le16enc(buf + 24, dos_date); /* wdate */

    /* For FAT32, high word of cluster in bytes [20..21]. */
    if (fat_type == 32) {
        archive_le16enc(buf + 20, (uint16_t)(f->first_cluster >> 16));
    }
    /* Low word of cluster in bytes [26..27]. */
    archive_le16enc(buf + 26, (uint16_t)(f->first_cluster & 0xFFFF));

    /* File size if not dir. */
    if (!f->is_dir) {
        archive_le32enc(buf + 28, f->size);
    }
}

/*
 * Write the required LFN entries just before the final short entry.
 * u16name is the filename in UTF-16LE, u16len is its byte length.
 */
static void
write_longname_entries(unsigned char *dirbuf, const uint8_t *u16name,
                       size_t u16len, const char shortnm[12])
{
    int u16chars = (int)(u16len / 2);
    int entries_needed = (u16chars + 12) / 13;
    int i, j, chunk_idx, ordinal;
    unsigned char checksum;
    int pos;

    /* Compute the standard FAT LFN checksum from the short 8.3 name. */
    checksum = 0;
    for (i = 0; i < 11; i++) {
        checksum = (unsigned char)((checksum >> 1) +
            ((checksum & 1) ? 0x80 : 0) + shortnm[i]);
    }

    /*
     * Copy in 13-char chunks from front to back of u16name,
     * but physically place them in descending order in the directory.
     */
    pos = 0;

    for (chunk_idx = 0; chunk_idx < entries_needed; chunk_idx++) {
        size_t entry_offset;
        unsigned char *lfn_ent;
        int lfn_off;

        ordinal = chunk_idx + 1;
        if (ordinal == entries_needed)
            ordinal |= 0x40;

        entry_offset = (size_t)(entries_needed - 1 - chunk_idx) * 32;
        lfn_ent = dirbuf + entry_offset;

        memset(lfn_ent, 0, 32);
        lfn_ent[0] = (unsigned char)ordinal;
        lfn_ent[11] = 0x0F;
        lfn_ent[13] = checksum;

        /* Copy up to 13 UTF-16LE code units. */
        for (j = 0; j < 13; j++) {
            uint16_t ch;
            int namepos = pos + j;

            if (namepos < u16chars) {
                /* Read a UTF-16LE code unit. */
                ch = (uint16_t)(u16name[namepos * 2]) |
                     ((uint16_t)(u16name[namepos * 2 + 1]) << 8);
            } else if (namepos == u16chars) {
                ch = 0; /* NUL terminator */
            } else {
                ch = 0xFFFF; /* Unused slot */
            }

            /*
             * LFN entry layout for 13 UTF-16 chars:
             *   j=0..4   -> bytes [1..10]
             *   j=5..10  -> bytes [14..25]
             *   j=11..12 -> bytes [28..31]
             */
            if (j < 5)
                lfn_off = 1 + j * 2;
            else if (j < 11)
                lfn_off = 14 + (j - 5) * 2;
            else
                lfn_off = 28 + (j - 11) * 2;

            lfn_ent[lfn_off]     = (unsigned char)(ch & 0xFF);
            lfn_ent[lfn_off + 1] = (unsigned char)(ch >> 8);
        }

        pos += 13;
    }
}


/* ---------------- UTF-16LE Name Conversion ---------------- */

/*
 * Convert a fat_file's long_name to UTF-16LE and store the result
 * in f->utf16name / f->utf16name_len.  Creates the string converter
 * lazily on first call.
 */
static int
convert_name_to_utf16(struct archive_write *a, struct msdosfs *msdos,
                      struct fat_file *f)
{
    if (f->long_name == NULL)
        return (ARCHIVE_OK);

    /* Lazy-init the UTF-16LE converter. */
    if (msdos->sconv_to_utf16 == NULL) {
        msdos->sconv_to_utf16 = archive_string_conversion_to_charset(
            &a->archive, "UTF-16LE", 1);
        if (msdos->sconv_to_utf16 == NULL)
            return (ARCHIVE_FATAL);
    }

    /* Convert long_name to UTF-16LE using a reusable buffer. */
    msdos->utf16buf.length = 0;
    if (archive_strncpy_l(&msdos->utf16buf, f->long_name,
        strlen(f->long_name), msdos->sconv_to_utf16) != 0) {
        if (errno == ENOMEM) {
            archive_set_error(&a->archive, ENOMEM,
                "Cannot allocate memory for UTF-16LE name");
            return (ARCHIVE_FATAL);
        }
        archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
            "Filename cannot be converted to UTF-16LE");
        return (ARCHIVE_WARN);
    }

    /* Copy the converted result into the fat_file. */
    f->utf16name_len = msdos->utf16buf.length;
    f->utf16name = (uint8_t *)malloc(f->utf16name_len);
    if (f->utf16name == NULL) {
        archive_set_error(&a->archive, ENOMEM,
            "Cannot allocate UTF-16LE name buffer");
        return (ARCHIVE_FATAL);
    }
    memcpy(f->utf16name, msdos->utf16buf.s, f->utf16name_len);
    return (ARCHIVE_OK);
}

/* ---------------- Directory-Tree Helpers ---------------- */

static struct fat_file*
find_or_create_dir(struct archive_write *a, struct msdosfs *msdos,
    struct fat_file *parent, const char *dirname)
{
    /* Look for an existing child dir with that name. */
    struct fat_file *f;
    for (f = msdos->files; f; f = f->next) {
        if (f->is_dir && f->long_name && strcmp(f->long_name, dirname)==0) {
            if (f->parent == parent) {
                return f;
            }
        }
    }
    /* Not found => create a new directory object. */
    f = (struct fat_file*)calloc(1, sizeof(*f));
    if (!f) return NULL;
    f->is_dir = 1;
    f->long_name = strdup(dirname);
    f->parent = parent;

    /* Generate a valid 8.3 short name. */
    make_short_name(f->long_name, f->short_name);
    if (ensure_unique_short_name(a, msdos, f->short_name, parent) != 0) {
        free(f->long_name);
        free(f);
        return (NULL);
    }

    /* Convert to UTF-16LE for LFN entries. */
    if (convert_name_to_utf16(a, msdos, f) != ARCHIVE_OK) {
        free(f->long_name);
        free(f);
        return (NULL);
    }

    /* Insert into global list. */
    f->next = msdos->files;
    msdos->files = f;
    /* Link into parent's child list. */
    add_child_to_parent(parent, f);
    return (f);
}

static void
add_child_to_parent(struct fat_file *parent, struct fat_file *child)
{
    if (!parent || !child) return;
    if (!parent->children) {
        parent->children = child;
    } else {
        struct fat_file *s = parent->children;
        while (s->sibling) {
            s = s->sibling;
        }
        s->sibling = child;
    }
}

/* ---------------- Short-Name Collision Checking ---------------- */

static void
init_shortname_hash(struct shortname_hash *hash)
{
    memset(hash->buckets, 0, sizeof(hash->buckets));
}

static unsigned int
shortname_hash_key(const char *name, struct fat_file *parent_dir)
{
    unsigned int h = (unsigned int)(uintptr_t)parent_dir;
    for (int i=0; i<11; i++) {
        h = h*31 + (unsigned char)name[i];
    }
    return h % SHORTNAME_HASH_SIZE;
}

static int
shortname_exists(struct msdosfs *msdos, const char *name, struct fat_file *parent_dir)
{
    unsigned int k = shortname_hash_key(name, parent_dir);
    struct shortname_entry *e = msdos->used_shortnames.buckets[k];
    while (e) {
        if (e->parent_dir == parent_dir && memcmp(e->name, name, 11)==0) {
            return 1;
        }
        e = e->next;
    }
    return 0;
}

static int
add_shortname(struct msdosfs *msdos, const char *name, struct fat_file *parent_dir)
{
    unsigned int k = shortname_hash_key(name, parent_dir);
    struct shortname_entry *e = (struct shortname_entry*)calloc(1, sizeof(*e));
    if (e == NULL)
        return (-1);
    memcpy(e->name, name, 11);
    e->name[11] = 0;
    e->parent_dir = parent_dir;
    e->next = msdos->used_shortnames.buckets[k];
    msdos->used_shortnames.buckets[k] = e;
    return (0);
}

/* If there's a collision, we try base~N until we find a free name. */
static int
build_colliding_short_name(const char *base, const char *ext, int num, char *out)
{
    /* base is up to 8 chars (possibly with spaces). We'll find the real length (stopping at space). */
    int base_len = 0;
    while (base_len < 8 && base[base_len] != ' ') {
        base_len++;
    }
    /* Convert num to string => "~1", "~2", etc. We'll see how many digits. */
    char suffix[12];
    snprintf(suffix, sizeof(suffix), "~%d", num);

    int suffix_len = (int)strlen(suffix);
    if (base_len + suffix_len > 8) {
        /* Not possible. We might try chopping. If it’s still too big, we fail. */
        base_len = 8 - suffix_len;
        if (base_len <= 0) {
            return -1;
        }
    }
    /* Construct new base. */
    char newbase[9];
    memcpy(newbase, base, base_len);
    memcpy(newbase+base_len, suffix, suffix_len);
    int total_base_len = base_len + suffix_len;
    while (total_base_len < 8) {
        newbase[total_base_len++] = ' ';
    }
    newbase[8] = 0;

    /* Now out => newbase + ext. */
    memcpy(out, newbase, 8);
    memcpy(out+8, ext, 3);
    out[11] = 0;
    return 0;
}

static int
ensure_unique_short_name(struct archive_write *a, struct msdosfs *msdos,
                         char short_name[12], struct fat_file *parent_dir)
{
    if (!shortname_exists(msdos, short_name, parent_dir)) {
        if (add_shortname(msdos, short_name, parent_dir) != 0) {
            archive_set_error(&a->archive, ENOMEM,
                "Cannot allocate short-name entry");
            return (ARCHIVE_FATAL);
        }
        return (0);
    }
    /* There's a collision. We'll try suffix ~1..~999999. */
    char base[9], ext[4];
    memcpy(base, short_name, 8);
    base[8] = 0;
    memcpy(ext, short_name+8, 3);
    ext[3] = 0;

    for (int i=1; i<1000000; i++) {
        char candidate[12];
        if (build_colliding_short_name(base, ext, i, candidate) != 0) {
            archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
                              "Too many short-name collisions");
            return (ARCHIVE_FATAL);
        }
        if (!shortname_exists(msdos, candidate, parent_dir)) {
            memcpy(short_name, candidate, 12);
            if (add_shortname(msdos, candidate, parent_dir) != 0) {
                archive_set_error(&a->archive, ENOMEM,
                    "Cannot allocate short-name entry");
                return (ARCHIVE_FATAL);
            }
            return (0);
        }
    }
    archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
                      "Excessive short-name collisions");
    return (ARCHIVE_FATAL);
}

/* Generate an 8.3 name from the long name. */
static void
make_short_name(const char *long_name, char short_name[12])
{
    /* We'll parse out up to 8 chars for base, up to 3 for extension. 
     * skipping '.' except to find extension, converting to uppercase, etc. 
     */
    memset(short_name, ' ', 11);
    short_name[11] = 0;

    if (!long_name || !*long_name) {
        memcpy(short_name, "NONAME  ", 8);
        return;
    }

    /* Find last '.' if present => extension. */
    const char *dot = strrchr(long_name, '.');
    int base_len = 0, ext_len=0;
    /* Fill base from the start until dot or slash. */
    for (const char *p = long_name; *p && p != dot && base_len<8; p++) {
        if (*p == '.' || *p==' ') continue;
        unsigned char c = (unsigned char)*p;
        if (c >= 'a' && c <= 'z') c -= 32;
        if ((c >= 'A' && c <= 'Z') || (c>='0' && c<='9') ||
            strchr("$%'-_@~!(){}^#&", c)) {
            short_name[base_len++] = c;
        } else {
            short_name[base_len++] = '_';
        }
    }
    /* Now extension from dot+1 if dot found. */
    if (dot) {
        for (const char *p = dot+1; *p && ext_len<3; p++) {
            if (*p==' ' || *p=='.') continue;
            unsigned char c = (unsigned char)*p;
            if (c>='a' && c<='z') c-=32;
            if ((c>='A' && c<='Z') || (c>='0' && c<='9') ||
                strchr("$%'-_@~!(){}^#&", c)) {
                short_name[8+ext_len] = c;
                ext_len++;
            } else {
                short_name[8+ext_len] = '_';
                ext_len++;
            }
        }
    }
}

/* -------------------------------------------------------------------- */

#ifdef MSDOSFS_DEBUG
static void
debug_print_files(struct archive_write *a)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    int count = 0;
    fprintf(stderr, "MSDOSFS: --- File List ---\n");
    for (struct fat_file *f = msdos->files; f; f = f->next) {
        count++;
        fprintf(stderr,
                "  [%d] %s (dir=%d root=%d size=%u parent=%p first_cluster=%u cluster_count=%u)\n",
                count,
                f->long_name ? f->long_name : "(no name)",
                f->is_dir,
                f->is_root,
                f->size,
                (void*)f->parent,
                f->first_cluster,
                f->cluster_count);
    }
    fprintf(stderr, "Total: %d\n", count);
    fprintf(stderr, "FAT type: %d, cluster_size=%u, volume_size=%u, fat_size=%u\n",
            msdos->fat_type, msdos->cluster_size,
            msdos->volume_size, msdos->fat_size);
    fprintf(stderr, "-------------------------\n");
}
#endif
