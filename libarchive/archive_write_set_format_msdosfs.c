/*-
 * archive_write_set_format_msdosfs.c
 *
 * Revised "msdosfs" (FAT) format writer for libarchive that:
 *   1) Creates a real FAT32 root directory in cluster #2,
 *   2) Allows multiple clusters for the FAT32 root if needed,
 *   3) Correctly writes file entries into that root,
 *   4) Preserves working behavior for FAT12/16 with a fixed-size root region,
 *   5) Avoids bit-twiddling issues in FAT12,
 *   6) Actually writes the final disk image into the archive (not empty).
 *
 * NOTE:
 *   - Uses multi-level subdirectories by splitting the path and recursively creating them.
 *   - This patch also fixes deeper subdirectories not being written (missing files).
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
#include "archive_endian.h"
#include "archive_entry.h"
#include "archive_private.h"
#include "archive_write_private.h"

/* Debug macros */
#define MSDOSFS_DEBUG
#ifdef MSDOSFS_DEBUG
#define DEBUG_PRINT(fmt, ...) fprintf(stderr, "MSDOSFS: " fmt "\n", ##__VA_ARGS__)
#define DEBUG_FILES(msdos) debug_print_files(msdos)
#else
#define DEBUG_PRINT(fmt, ...)
#define DEBUG_FILES(msdos)
#endif

/* 512-byte sectors. */
#define SECTOR_SIZE 512

/* FAT12 limit ~4084 clusters; FAT16 limit ~65524. */
#define FAT12_MAX_CLUSTERS 4084
#define FAT16_MAX_CLUSTERS 65524

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

/* ------------------------- DATA STRUCTURES ------------------------- */

/* A single file or directory in this FAT image. */
struct fat_file {
    struct fat_file *next;
    struct archive_entry *entry;
    uint32_t first_cluster;
    uint32_t cluster_count;
    uint32_t size;
    char *name;
    char *long_name;
    int is_dir;
    int is_root;               /* For FAT12/16 fixed root or FAT32 cluster #2 root */
    off_t content_offset;      /* Where the file’s data is buffered in temp_fd */

    struct fat_file *parent;   /* The directory that contains us, NULL or root pointer. */
    struct fat_file *children; /* Not heavily used here, but can be expanded. */
    struct fat_file *sibling;
};

/* Hash table for tracking used short names to ensure uniqueness. */
#define SHORTNAME_HASH_SIZE 256

struct shortname_entry {
    char name[12];
    struct fat_file *parent_dir; /* Directory context for this short name */
    struct shortname_entry *next;
};

struct shortname_hash {
    struct shortname_entry *buckets[SHORTNAME_HASH_SIZE];
};

/* Our main writer state. */
struct msdosfs {
    int fat_type;
    uint32_t volume_size;
    uint32_t cluster_size;
    uint32_t reserved_sectors;
    uint32_t fat_size;
    uint32_t root_entries;
    uint32_t root_size;
    uint32_t cluster_count;
    uint32_t fat_offset;
    uint32_t root_offset;
    uint32_t data_offset;

    struct fat_file *files;
    struct fat_file *current_file;
    int bytes_remaining;

    int temp_fd;

    unsigned char *write_buffer;
    size_t write_buffer_size;
    size_t write_buffer_pos;

    struct shortname_hash used_shortnames;

    // FIX: Keep a dedicated pointer for the FAT32 root directory object
    struct fat_file *fat32_root;
};

/* Boot sector structures (unchanged) */
struct bs1 {
    uint8_t bsJmpBoot[3];
    uint8_t bsOEMName[8];
} __attribute__ ((packed));

struct bpb {
    uint16_t bpbBytesPerSec;
    uint8_t bpbSecPerClus;
    uint16_t bpbRsvdSecCnt;
    uint8_t bpbNumFATs;
    uint16_t bpbRootEntCnt;
    uint16_t bpbTotSec16;
    uint8_t bpbMedia;
    uint16_t bpbFATSz16;
    uint16_t bpbSecPerTrk;
    uint16_t bpbNumHeads;
    uint32_t bpbHiddSecs;
    uint32_t bpbTotSec32;
} __attribute__ ((packed));

struct bpb_fat32 {
    uint32_t bpbFATSz32;
    uint16_t bpbExtFlags;
    uint16_t bpbFSVer;
    uint32_t bpbRootClus;
    uint16_t bpbFSInfo;
    uint16_t bpbBkBootSec;
    uint8_t bpbReserved[12];
} __attribute__ ((packed));

struct bs2 {
    uint8_t bsDrvNum;
    uint8_t bsReserved1;
    uint8_t bsBootSig;
    uint32_t bsVolID;
    uint8_t bsVolLab[11];
    uint8_t bsFileSysType[8];
} __attribute__ ((packed));

struct fat32_hdr {
    struct bs1 bs1;
    struct bpb bpb;
    struct bpb_fat32 bpb_fat32;
    struct bs2 bs2;
} __attribute__ ((packed));

/* ------------------- FORWARD DECLARATIONS ------------------- */

static int  archive_write_msdosfs_options(struct archive_write *a, const char *key, const char *val);
static int  archive_write_msdosfs_header(struct archive_write *a, struct archive_entry *entry);
static ssize_t archive_write_msdosfs_data(struct archive_write *a, const void *buff, size_t s);
static int  archive_write_msdosfs_finish_entry(struct archive_write *a);
static int  archive_write_msdosfs_close(struct archive_write *a);
static int  archive_write_msdosfs_free(struct archive_write *a);

static int  init_volume_geometry(struct archive_write *a, uint64_t volume_bytes);
static uint32_t compute_fat_size(struct msdosfs *msdos);

static int assign_subdir_sizes(struct msdosfs *msdos);

static void set_fat12_entry(unsigned char *fat, uint32_t cluster, uint16_t value);

static int write_boot_sector(struct archive_write *a);
static int write_fats(struct archive_write *a);
static int write_root_dir(struct archive_write *a);

static int write_subdirectories_recursively(struct archive_write *a, struct fat_file *parent);
static int write_directory(struct archive_write *a, struct fat_file *dir,
                           struct fat_file **dir_entries, int num_entries);
static int write_cluster_chain(struct archive_write *a, struct fat_file *file);

static void make_short_name(const char *long_name, char *short_name);
static int  build_colliding_short_name(const char *base, const char *ext, int num, char *short_name);
static int  write_dir_entry(int fat_type, unsigned char *buffer, const char *name, struct fat_file *file);
static int  write_long_name_entries(unsigned char *buffer, const char *long_name, const char *short_name);
static int  count_dir_entries_for_file(struct fat_file *f);
static unsigned int shortname_hash(const char *name, struct fat_file *parent_dir);
static int  shortname_exists(struct msdosfs *msdos, const char *name, struct fat_file *parent_dir);
static void add_shortname(struct msdosfs *msdos, const char *name, struct fat_file *parent_dir);
static int fix_volume_geometry(struct archive_write *a);

static struct fat_file* find_or_create_dir(struct msdosfs *msdos,
                                           struct fat_file *parent,
                                           const char *dirname);
static void add_child_to_parent(struct fat_file *parent, struct fat_file *child);

static int ensure_unique_short_name(struct archive_write *a, struct msdosfs *msdos, char short_name[12], struct fat_file *parent_dir);
static void init_shortname_hash(struct shortname_hash *hash);

#ifdef MSDOSFS_DEBUG
static void debug_print_files(struct msdosfs *msdos) {
    int count = 0;
    fprintf(stderr, "MSDOSFS: ---- File List ----\n");
    struct fat_file *f;
    for (f = msdos->files; f; f = f->next) {
        count++;
        fprintf(stderr, "MSDOSFS: [%d] %s (is_dir=%d, parent=%p, first_cluster=%u)\n",
                count,
                f->long_name ? f->long_name : "(no name)",
                f->is_dir,
                (void*)f->parent,
                f->first_cluster);
    }
    fprintf(stderr, "MSDOSFS: Total files: %d\n", count);
    fprintf(stderr, "MSDOSFS: ------------------\n");
}
#endif

/* ------------------- PUBLIC ENTRY POINT ------------------- */

int
archive_write_set_format_msdosfs(struct archive *_a)
{
    struct archive_write *a = (struct archive_write *)_a;
    struct msdosfs *msdos;

    archive_check_magic(&a->archive, ARCHIVE_WRITE_MAGIC,
        ARCHIVE_STATE_NEW, "archive_write_set_format_msdosfs");

    msdos = calloc(1, sizeof(*msdos));
    if (!msdos) {
        archive_set_error(&a->archive, ENOMEM, "Can't allocate msdosfs data");
        return (ARCHIVE_FATAL);
    }
    a->format_data = msdos;

    // FIX: Initialize msdos->fat32_root to NULL
    msdos->fat32_root = NULL;

    /* Default volume size = ~100MB. */
    {
        int r = init_volume_geometry(a, 100ULL * 1024ULL * 1024ULL);
        if (r != ARCHIVE_OK) {
            free(msdos);
            return r;
        }
    }

    /* Alloc an I/O buffer. */
    msdos->write_buffer_size = 32768;
    msdos->write_buffer = malloc(msdos->write_buffer_size);
    if (!msdos->write_buffer) {
        free(msdos);
        archive_set_error(&a->archive, ENOMEM, "Can't allocate write buffer");
        return (ARCHIVE_FATAL);
    }

    /* Create temp file. */
    msdos->temp_fd = __archive_mktemp(NULL);
    if (msdos->temp_fd < 0) {
        free(msdos->write_buffer);
        free(msdos);
        archive_set_error(&a->archive, errno, "Could not create temp file");
        return (ARCHIVE_FATAL);
    }

    /* Hook up callbacks. */
    a->format_name           = "msdosfs";
    a->format_options        = archive_write_msdosfs_options;
    a->format_write_header   = archive_write_msdosfs_header;
    a->format_write_data     = archive_write_msdosfs_data;
    a->format_finish_entry   = archive_write_msdosfs_finish_entry;
    a->format_close          = archive_write_msdosfs_close;
    a->format_free           = archive_write_msdosfs_free;

    init_shortname_hash(&msdos->used_shortnames);

    return (ARCHIVE_OK);
}

static int
archive_write_msdosfs_options(struct archive_write *a, const char *key, const char *value)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;

    if (strcmp(key, "fat_type") == 0) {
        int t = atoi(value);
        if (t != 12 && t != 16 && t != 32) {
            archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
                "Invalid FAT type %d (must be 12, 16, or 32)", t);
            return (ARCHIVE_FATAL);
        }
        msdos->fat_type = t;
        return(fix_volume_geometry(a));
    }

    return (ARCHIVE_WARN);
}

/* ------------------- HEADER / DATA / FINISH_ENTRY ------------------- */

static int
archive_write_msdosfs_header(struct archive_write *a, struct archive_entry *entry)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    DEBUG_PRINT("Processing header for %s", archive_entry_pathname(entry));

    // Allocate a new fat_file for this entry
    struct fat_file *file = calloc(1, sizeof(*file));
    if (!file) {
        archive_set_error(&a->archive, ENOMEM, "Can't allocate fat_file");
        return (ARCHIVE_FATAL);
    }
    file->entry   = archive_entry_clone(entry);
    file->size    = (uint32_t)archive_entry_size(entry);
    file->is_dir  = (archive_entry_filetype(entry) == AE_IFDIR);

    // ------------------------------------------------------------------
    // FIX #1: For FAT32, always create (or retrieve) the official root_dir
    //         if we haven't done so yet. We'll store it in msdos->fat32_root.
    // ------------------------------------------------------------------
    if (msdos->fat_type == 32) {
        if (msdos->fat32_root == NULL) {
            // Create the root_dir object exactly once
            msdos->fat32_root = calloc(1, sizeof(*msdos->fat32_root));
            if (!msdos->fat32_root) {
                archive_set_error(&a->archive, ENOMEM,
                                  "Failed to create FAT32 root directory object");
                free(file);
                return (ARCHIVE_FATAL);
            }
            msdos->fat32_root->is_dir  = 1;
            msdos->fat32_root->is_root = 1;
            msdos->fat32_root->long_name = strdup("FAT32_ROOT"); // optional name

            // Insert at head of 'files' list
            msdos->fat32_root->next = msdos->files;
            msdos->files   = msdos->fat32_root;
        }
    }
    // ------------------------------------------------------------------

    // -------------------------------------
    // STEP 2: Get the incoming pathname (fallback to empty if missing)
    // -------------------------------------
    const char *pathname = archive_entry_pathname(entry);
    if (!pathname)
        pathname = "";

    // We'll split it on '/'.
    char *pathdup = strdup(pathname);
    if (!pathdup) {
        archive_set_error(&a->archive, ENOMEM, "strdup failed");
        free(file);
        return (ARCHIVE_FATAL);
    }

    // The directory that will contain this item
    //  - For FAT12/16 => top‐level means parent_dir=NULL
    //  - For FAT32 => top‐level means parent_dir=msdos->fat32_root
    struct fat_file *parent_dir = NULL;
    if (msdos->fat_type == 32) {
        parent_dir = msdos->fat32_root;
    }

    // -------------------------------------
    // STEP 3: Split the path into components
    // -------------------------------------
    char *token, *brkt;
    token = strtok_r(pathdup, "/", &brkt);
    char *last_component = NULL;

    while (token) {
        char *next = strtok_r(NULL, "/", &brkt);
        if (next) {
            // Intermediate directory name
            parent_dir = find_or_create_dir(msdos, parent_dir, token);
            if (!parent_dir) {
                archive_set_error(&a->archive, ENOMEM,
                                  "Failed to create directory for '%s'", token);
                free(pathdup);
                free(file);
                return (ARCHIVE_FATAL);
            }
        } else {
            // The final token => last component is the actual file/dir name
            last_component = token;
        }
        token = next;
    }

    if (!last_component) {
        last_component = pathdup;  // fallback
    }

    // -------------------------------------
    // STEP 4: Fill in `file->long_name` and `file->parent`
    // -------------------------------------
    file->long_name = strdup(last_component ? last_component : "");
    if (!file->long_name || file->long_name[0] == '\0') {
        // Fallback if empty
        if (file->long_name) free(file->long_name);
        file->long_name = strdup("NONAME");
    }
    file->parent = parent_dir;
    if (parent_dir) {
        add_child_to_parent(parent_dir, file);
    }

    free(pathdup);

    // -------------------------------------
    // STEP 5: Insert new file at head of msdos->files
    // -------------------------------------
    file->next   = msdos->files;
    msdos->files = file;

    DEBUG_PRINT("Added file: %s (is_dir=%d, parent=%p)",
                file->long_name, file->is_dir, (void *)file->parent);

    // -------------------------------------
    // STEP 6: If it’s not a directory, set up for data writes
    // -------------------------------------
    if (!file->is_dir) {
        msdos->current_file    = file;
        msdos->bytes_remaining = file->size;
        file->content_offset   = lseek(msdos->temp_fd, 0, SEEK_END);
    }
    return (ARCHIVE_OK);
}

static ssize_t
archive_write_msdosfs_data(struct archive_write *a, const void *buff, size_t s)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    if (!msdos->current_file || s == 0) {
        return 0;
    }
    if ((size_t)msdos->bytes_remaining < s) {
        s = (size_t)msdos->bytes_remaining;
    }
    if (write(msdos->temp_fd, buff, s) != (ssize_t)s) {
        archive_set_error(&a->archive, errno, "Write to temp file failed");
        return (ARCHIVE_FATAL);
    }
    msdos->bytes_remaining -= (int)s;
    return (ssize_t)s;
}

static int
archive_write_msdosfs_finish_entry(struct archive_write *a)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    if (msdos->current_file && msdos->bytes_remaining > 0) {
        char zero[SECTOR_SIZE];
        memset(zero, 0, sizeof(zero));
        while (msdos->bytes_remaining > 0) {
            size_t to_write = (msdos->bytes_remaining > (int)sizeof(zero))
                              ? sizeof(zero) : (size_t)msdos->bytes_remaining;
            if (write(msdos->temp_fd, zero, to_write) != (ssize_t)to_write) {
                archive_set_error(&a->archive, errno, "Zero‐padding temp file failed");
                return (ARCHIVE_FATAL);
            }
            msdos->bytes_remaining -= (int)to_write;
        }
    }
    msdos->current_file = NULL;
    return (ARCHIVE_OK);
}

static int
fix_volume_geometry(struct archive_write *a)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    int r;
    while (1) {
        r = init_volume_geometry(a, (uint64_t)msdos->volume_size * SECTOR_SIZE);
        if (r != ARCHIVE_OK)
            return r;

        uint32_t root_dir_sectors =
           (msdos->root_entries * DIR_ENTRY_SIZE + SECTOR_SIZE - 1) / SECTOR_SIZE;
        if (root_dir_sectors == msdos->root_size) {
            break;
        }
        // Expand volume
        msdos->volume_size += (1024 * 1024) / SECTOR_SIZE;
    }
    return 0;
}

/*
 * The big close:
 *  1) Possibly adjust geometry for FAT12/16 if we need more root dir entries
 *  2) For FAT32, use the single root_dir we created earlier
 *  3) Write boot sector
 *  4) Write FATs
 *  5) Write root directory + subdirectories
 *  6) Write each file's cluster data
 *  7) Copy entire disk image to final archive
 */
static int
archive_write_msdosfs_close(struct archive_write *a)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    int r;

    DEBUG_PRINT("Closing archive");
    DEBUG_FILES(msdos);

    // For FAT12/16, possibly expand root if needed
    if (msdos->fat_type == 12 || msdos->fat_type == 16) {
        int needed_entries = 0;
        struct fat_file *f;
        for (f = msdos->files; f; f = f->next) {
            if (!f->is_root) {
                needed_entries += count_dir_entries_for_file(f);
            }
        }
        if (needed_entries > (int)msdos->root_entries) {
            msdos->root_entries = (uint32_t)(needed_entries + 16);
            r = fix_volume_geometry(a);
            if (r != ARCHIVE_OK) {
                return r;
            }
        }
    }

    // --------------------------------------------------------------------
    // FIX #2: For FAT32, *do not* create a new root_dir. Use msdos->fat32_root.
    //         Then we compute its size. This ensures only one root_dir pointer.
    // --------------------------------------------------------------------
    if (msdos->fat_type == 32) {
        struct fat_file *root_dir = msdos->fat32_root;
    DEBUG_PRINT("FAT32 close: Checking root_dir pointer: %p", (void*)root_dir);
    if (root_dir) {
        DEBUG_PRINT("FAT32 root_dir->first_cluster=%u, size=%u, is_root=%d",
                    root_dir->first_cluster,
                    root_dir->size,
                    root_dir->is_root);
    } else {
        DEBUG_PRINT("No fat32_root found (will create one?)");
    }

        if (!root_dir) {
            // If we somehow never created it, do so now
            root_dir = calloc(1, sizeof(*root_dir));
            root_dir->is_dir  = 1;
            root_dir->is_root = 1;
            root_dir->long_name = strdup("FAT32_ROOT");
            root_dir->next = msdos->files;
            msdos->files = root_dir;
            msdos->fat32_root = root_dir;
        }

        int num_entries = 2; /* "." and ".." */
        {
            struct fat_file *f;
            for (f = msdos->files; f; f = f->next) {
                if (f == root_dir) continue;
                // top-level items => f->parent == root_dir
                if (f->parent == root_dir) {
                    num_entries += count_dir_entries_for_file(f);
                }
            }
        }
        size_t dir_bytes_needed = (size_t)num_entries * DIR_ENTRY_SIZE;
        root_dir->size = (uint32_t)dir_bytes_needed;

        DEBUG_PRINT("FAT32 root_dir after size calculation => cluster=%u size=%u",
                    root_dir->first_cluster,
                    root_dir->size);

        int count_top_level = 0;
        struct fat_file *f;
        for (f = msdos->files; f; f = f->next) {
            if (f->parent == root_dir) {
                count_top_level++;
                DEBUG_PRINT("  top-level item under root: %s (dir=%d, cluster=%u)",
                            (f->long_name ? f->long_name : "(null)"),
                            f->is_dir,
                            f->first_cluster);
            }
        }
        DEBUG_PRINT("Found %d top-level items for root_dir", count_top_level);
    }

    assign_subdir_sizes(msdos);

    /* 1) Boot sector. */
    r = write_boot_sector(a);
    if (r != ARCHIVE_OK) return r;

    /* 2) FATs. */
    r = write_fats(a);
    if (r != ARCHIVE_OK) return r;

    /* 3) Root directory (and subdirs). */
    r = write_root_dir(a);
    if (r != ARCHIVE_OK) return r;

    /* 4) Write file data. */
    {
        struct fat_file *f;
        for (f = msdos->files; f; f = f->next) {
            r = write_cluster_chain(a, f);
            if (r != ARCHIVE_OK) return r;
        }
    }

    /* 5) Copy entire disk image out. */
    {
        unsigned char *buf = msdos->write_buffer;
        size_t disk_size = (size_t)msdos->volume_size * SECTOR_SIZE;

        if (lseek(msdos->temp_fd, 0, SEEK_SET) < 0) {
            archive_set_error(&a->archive, errno, "Seek failed rewinding temp file");
            return (ARCHIVE_FATAL);
        }
        while (disk_size > 0) {
            size_t to_read = (disk_size < msdos->write_buffer_size)
                           ? disk_size : msdos->write_buffer_size;

            ssize_t rd = read(msdos->temp_fd, buf, to_read);
            if (rd < 0) {
                archive_set_error(&a->archive, errno, "Read from temp file failed");
                return (ARCHIVE_FATAL);
            }
            if (rd == 0) {
                /* If short read, pad with zeros. */
                memset(buf, 0, to_read);
                rd = (ssize_t)to_read;
            }
            r = __archive_write_output(a, buf, rd);
            if (r != ARCHIVE_OK) {
                return r;
            }
            disk_size -= (size_t)rd;
        }
    }

    free(msdos->write_buffer);
    close(msdos->temp_fd);
    return (ARCHIVE_OK);
}

static int
archive_write_msdosfs_free(struct archive_write *a)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    if (msdos) {
        {
            /* Free the shortname hash table */
            for (int i = 0; i < SHORTNAME_HASH_SIZE; i++) {
                struct shortname_entry *p = msdos->used_shortnames.buckets[i];
                while (p) {
                    struct shortname_entry *nx = p->next;
                    free(p);
                    p = nx;
                }
            }
        }
        {
            struct fat_file *f = msdos->files;
            while (f) {
                struct fat_file *nx = f->next;
                if (f->entry) archive_entry_free(f->entry);
                free(f->name);
                free(f->long_name);
                free(f);
                f = nx;
            }
        }
        free(msdos);
        a->format_data = NULL;
    }
    return (ARCHIVE_OK);
}

/* ------------------- VOLUME GEOMETRY ------------------- */

static uint32_t
compute_fat_size(struct msdosfs *msdos)
{
    uint32_t root_dir_sectors = 0;
    if (msdos->fat_type != 32) {
        root_dir_sectors =
          (msdos->root_entries * DIR_ENTRY_SIZE + SECTOR_SIZE - 1) / SECTOR_SIZE;
    }
    uint32_t data_sectors = msdos->volume_size
                          - msdos->reserved_sectors
                          - (2 * msdos->fat_size)
                          - root_dir_sectors;

    uint32_t total_clusters = data_sectors / msdos->cluster_size;
    uint32_t fat_entries = total_clusters + FAT_RESERVED_ENTRIES;

    uint32_t fat_bytes;
    if (msdos->fat_type == 12) {
        fat_bytes = (fat_entries * 3 + 1) / 2;
    } else if (msdos->fat_type == 16) {
        fat_bytes = fat_entries * 2;
    } else {
        fat_bytes = fat_entries * 4;
    }
    return (fat_bytes + SECTOR_SIZE - 1) / SECTOR_SIZE;
}

static int
init_volume_geometry(struct archive_write *a, uint64_t volume_bytes)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    uint32_t total_sectors = (uint32_t)((volume_bytes + SECTOR_SIZE - 1)/SECTOR_SIZE);

    if (msdos->fat_type == 0) {
        if (total_sectors < (FAT12_MAX_CLUSTERS+2)*1)
            msdos->fat_type = 12;
        else if (total_sectors < (FAT16_MAX_CLUSTERS+2)*8)
            msdos->fat_type = 16;
        else
            msdos->fat_type = 32;
    }
    msdos->volume_size = total_sectors;

    if (msdos->fat_type == 32) {
        msdos->reserved_sectors = 32;
        msdos->root_entries = 0;
        if (total_sectors < 532480)
            msdos->cluster_size = 1;
        else if (total_sectors < 16777216)
            msdos->cluster_size = 8;
        else if (total_sectors < 33554432)
            msdos->cluster_size = 16;
        else if (total_sectors < 67108864)
            msdos->cluster_size = 32;
        else
            msdos->cluster_size = 64;
    } else {
        msdos->reserved_sectors = 1;
        if (msdos->root_entries == 0)
            msdos->root_entries = 512;
        if (total_sectors < 32680)
            msdos->cluster_size = 2;
        else if (total_sectors < 262144)
            msdos->cluster_size = 4;
        else if (total_sectors < 524288)
            msdos->cluster_size = 8;
        else
            msdos->cluster_size = 16;
    }

    msdos->fat_size = 1;
    {
        int attempts = 16;
        while (attempts-- > 0) {
            uint32_t root_dir_sectors = 0;
            if (msdos->fat_type != 32) {
                root_dir_sectors =
                  (msdos->root_entries*DIR_ENTRY_SIZE + SECTOR_SIZE -1)/SECTOR_SIZE;
            }
            msdos->fat_offset = msdos->reserved_sectors;
            msdos->root_offset = msdos->fat_offset + 2*msdos->fat_size;
            if (msdos->fat_type == 32) {
                msdos->root_size = 0;
                msdos->data_offset = msdos->root_offset;
            } else {
                msdos->root_size = root_dir_sectors;
                msdos->data_offset = msdos->root_offset + msdos->root_size;
            }
            {
                uint32_t data_sectors = msdos->volume_size - msdos->data_offset;
                msdos->cluster_count = data_sectors / msdos->cluster_size;
            }
            if ((msdos->fat_type==12 && msdos->cluster_count>=FAT12_MAX_CLUSTERS) ||
                (msdos->fat_type==16 && msdos->cluster_count>=FAT16_MAX_CLUSTERS)) {
                archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
                    "Too many clusters for FAT%d", msdos->fat_type);
                return (ARCHIVE_FATAL);
            }

            uint32_t new_fat_size = compute_fat_size(msdos);
            if (new_fat_size == msdos->fat_size) {
                break;
            }
            msdos->fat_size = new_fat_size;
        }
    }

    {
        uint32_t root_dir_sectors = 0;
        if (msdos->fat_type != 32) {
            root_dir_sectors =
              (msdos->root_entries * DIR_ENTRY_SIZE + SECTOR_SIZE -1)/SECTOR_SIZE;
        }
        msdos->fat_offset = msdos->reserved_sectors;
        msdos->root_offset = msdos->fat_offset + 2*msdos->fat_size;
        if (msdos->fat_type==32) {
            msdos->root_size=0;
            msdos->data_offset = msdos->root_offset;
        } else {
            msdos->root_size = root_dir_sectors;
            msdos->data_offset = msdos->root_offset + msdos->root_size;
        }
        {
            uint32_t data_sectors = msdos->volume_size - msdos->data_offset;
            msdos->cluster_count = data_sectors / msdos->cluster_size;
        }
        if ((msdos->fat_type==12 && msdos->cluster_count>=FAT12_MAX_CLUSTERS) ||
            (msdos->fat_type==16 && msdos->cluster_count>=FAT16_MAX_CLUSTERS)) {
            archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
                "Too many clusters for FAT%d", msdos->fat_type);
            return (ARCHIVE_FATAL);
        }
    }
    return (ARCHIVE_OK);
}

/* ------------------- BOOT SECTOR / FSINFO ------------------- */

static int
write_boot_sector(struct archive_write *a)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    unsigned char boot[SECTOR_SIZE];
    memset(boot, 0, SECTOR_SIZE);

    struct fat32_hdr *hdr = (struct fat32_hdr *)boot;

    hdr->bs1.bsJmpBoot[0] = 0xEB;
    hdr->bs1.bsJmpBoot[1] = 0x3C;
    hdr->bs1.bsJmpBoot[2] = 0x90;
    memcpy(hdr->bs1.bsOEMName, "MSWIN4.1", 8);

    archive_le16enc(&hdr->bpb.bpbBytesPerSec, SECTOR_SIZE);
    hdr->bpb.bpbSecPerClus = msdos->cluster_size;
    archive_le16enc(&hdr->bpb.bpbRsvdSecCnt, msdos->reserved_sectors);
    hdr->bpb.bpbNumFATs = 2;
    archive_le16enc(&hdr->bpb.bpbRootEntCnt, msdos->root_entries);

    if (msdos->volume_size < 65536) {
        archive_le16enc(&hdr->bpb.bpbTotSec16, (uint16_t)msdos->volume_size);
        archive_le32enc(&hdr->bpb.bpbTotSec32, 0);
    } else {
        archive_le16enc(&hdr->bpb.bpbTotSec16, 0);
        archive_le32enc(&hdr->bpb.bpbTotSec32, msdos->volume_size);
    }

    hdr->bpb.bpbMedia = 0xF8;
    archive_le16enc(&hdr->bpb.bpbSecPerTrk, 63);
    archive_le16enc(&hdr->bpb.bpbNumHeads, 255);
    archive_le32enc(&hdr->bpb.bpbHiddSecs, 0);

    if (msdos->fat_type != 32) {
        archive_le16enc(&hdr->bpb.bpbFATSz16, msdos->fat_size);
    } else {
        archive_le16enc(&hdr->bpb.bpbFATSz16, 0);

        archive_le32enc(&hdr->bpb_fat32.bpbFATSz32, msdos->fat_size);
        archive_le16enc(&hdr->bpb_fat32.bpbExtFlags, 0);
        archive_le16enc(&hdr->bpb_fat32.bpbFSVer, 0);
        archive_le32enc(&hdr->bpb_fat32.bpbRootClus, 2);
        archive_le16enc(&hdr->bpb_fat32.bpbFSInfo, 1);
        archive_le16enc(&hdr->bpb_fat32.bpbBkBootSec, 6);
        memset(hdr->bpb_fat32.bpbReserved, 0, 12);
    }

    {
        struct bs2 *bs2;
        if (msdos->fat_type == 32) {
            bs2 = (struct bs2 *)(boot + 90);
        } else {
            bs2 = (struct bs2 *)(boot + 36);
        }
        bs2->bsDrvNum = 0x80;
        bs2->bsReserved1 = 0;
        bs2->bsBootSig = 0x29;
        archive_le32enc(&bs2->bsVolID, 0x12345678);
        memcpy(bs2->bsVolLab, "NO NAME    ", 11);
        if (msdos->fat_type == 32) {
            memcpy(bs2->bsFileSysType, "FAT32   ", 8);
        } else if (msdos->fat_type == 16) {
            memcpy(bs2->bsFileSysType, "FAT16   ", 8);
        } else {
            memcpy(bs2->bsFileSysType, "FAT12   ", 8);
        }
    }

    boot[510] = 0x55;
    boot[511] = 0xAA;

    if (lseek(msdos->temp_fd, 0, SEEK_SET) < 0) {
        archive_set_error(&a->archive, errno, "Seek to offset 0 for boot sector failed");
        return (ARCHIVE_FATAL);
    }
    if (write(msdos->temp_fd, boot, SECTOR_SIZE) != SECTOR_SIZE) {
        archive_set_error(&a->archive, errno, "Boot sector write failed");
        return (ARCHIVE_FATAL);
    }

    if (msdos->fat_type == 32) {
        if (lseek(msdos->temp_fd, 6 * SECTOR_SIZE, SEEK_SET) < 0 ||
            write(msdos->temp_fd, boot, SECTOR_SIZE) != SECTOR_SIZE) {
            archive_set_error(&a->archive, errno, "Backup boot sector write failed");
            return (ARCHIVE_FATAL);
        }

        unsigned char fsinfo[SECTOR_SIZE];
        memset(fsinfo, 0, SECTOR_SIZE);
        archive_le32enc(fsinfo + 0, 0x41615252);
        archive_le32enc(fsinfo + 484, 0x61417272);
        archive_le32enc(fsinfo + 488, msdos->cluster_count - 1);
        archive_le32enc(fsinfo + 492, 2);
        archive_le32enc(fsinfo + 508, 0xAA550000);

        if (lseek(msdos->temp_fd, SECTOR_SIZE, SEEK_SET) < 0 ||
            write(msdos->temp_fd, fsinfo, SECTOR_SIZE) != SECTOR_SIZE) {
            archive_set_error(&a->archive, errno, "FSInfo write failed");
            return (ARCHIVE_FATAL);
        }
    }

    return (ARCHIVE_OK);
}

/* ------------------- FAT12 BIT TWIDDLING ------------------- */
static void
set_fat12_entry(unsigned char *fat, uint32_t cluster, uint16_t value)
{
    uint32_t index = (cluster * 3)/2;
    if ((cluster & 1) == 0) {
        fat[index]   = (unsigned char)(value & 0xFF);
        fat[index+1] = (unsigned char)((fat[index+1] & 0xF0)|((value >> 8) & 0x0F));
    } else {
        fat[index]   = (unsigned char)((fat[index] & 0x0F)|((value << 4) & 0xF0));
        fat[index+1] = (unsigned char)((value >> 4) & 0xFF);
    }
}

/* ------------------- WRITE FAT(s) ------------------- */

static int
write_fats(struct archive_write *a)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    size_t fat_size_bytes = (size_t)msdos->fat_size * SECTOR_SIZE;

    unsigned char *fat = calloc(1, fat_size_bytes);
    if (!fat) {
        archive_set_error(&a->archive, ENOMEM, "No memory for FAT buffer");
        return (ARCHIVE_FATAL);
    }
    uint32_t fat_entries = msdos->cluster_count + FAT_RESERVED_ENTRIES;

    if (msdos->fat_type == 12) {
        set_fat12_entry(fat, 0, 0xFF8);
        set_fat12_entry(fat, 1, 0xFFF);
    } else if (msdos->fat_type == 16) {
        archive_le16enc(fat + 0, 0xFFF8);
        archive_le16enc(fat + 2, 0xFFFF);
    } else {
        archive_le32enc(fat + 0, 0x0FFFFFF8);
        archive_le32enc(fat + 4, 0x0FFFFFFF);
    }

    {
        uint32_t cluster = FAT_RESERVED_ENTRIES;
        struct fat_file *f;
        for (f = msdos->files; f; f = f->next) {
            if (f->is_root && msdos->fat_type != 32) {
                continue;
            }
            if (f->is_dir) {
                uint32_t dir_size = (f->size==0) ? (DIR_ENTRY_SIZE*2) : f->size;
                uint64_t bpc = (uint64_t)msdos->cluster_size*SECTOR_SIZE;
                uint32_t needed = (uint32_t)((dir_size+bpc-1)/bpc);
                if (needed == 0) needed = 1;

                if (f->is_root && msdos->fat_type == 32) {
                    f->first_cluster = 2;
                    if (needed == 1) {
                        if (msdos->fat_type == 12) {
                            set_fat12_entry(fat, 2, 0xFFF);
                        } else if (msdos->fat_type == 16) {
                            archive_le16enc(fat + 2*2, 0xFFFF);
                        } else {
                            archive_le32enc(fat + 2*4, 0x0FFFFFFF);
                        }
                        if (cluster<3) cluster=3;
                    } else {
                        uint32_t c=2;
                        f->first_cluster=c;
                        f->cluster_count=needed;
                        for (uint32_t i=0; i<needed-1; i++) {
                            uint32_t next = c+1;
                            if (msdos->fat_type == 12) {
                                set_fat12_entry(fat, c, (uint16_t)next);
                            } else if (msdos->fat_type == 16) {
                                archive_le16enc(fat + c*2, (uint16_t)next);
                            } else {
                                archive_le32enc(fat + c*4, next);
                            }
                            c++;
                            if (c>=fat_entries) {
                                free(fat);
                                archive_set_error(&a->archive, ENOSPC, "FAT32 root too large");
                                return (ARCHIVE_FATAL);
                            }
                        }
                        if (msdos->fat_type == 12) {
                            set_fat12_entry(fat, c, 0xFFF);
                        } else if (msdos->fat_type == 16) {
                            archive_le16enc(fat + c*2, 0xFFFF);
                        } else {
                            archive_le32enc(fat + c*4, 0x0FFFFFFF);
                        }
                        if ((c+1)>cluster) {
                            cluster=c+1;
                        }
                    }
                } else {
                    if (cluster+needed-1 >= fat_entries) {
                        free(fat);
                        archive_set_error(&a->archive, ENOSPC, "No space for directory");
                        return (ARCHIVE_FATAL);
                    }
                    f->first_cluster = cluster;
                    f->cluster_count = needed;
                    uint32_t c = cluster;
                    for (uint32_t i=0; i<(needed-1); i++) {
                        uint32_t next = c+1;
                        if (msdos->fat_type == 12) {
                            set_fat12_entry(fat, c, (uint16_t)next);
                        } else if (msdos->fat_type == 16) {
                            archive_le16enc(fat + c*2, (uint16_t)next);
                        } else {
                            archive_le32enc(fat + c*4, next);
                        }
                        c++;
                    }
                    if (msdos->fat_type == 12) {
                        set_fat12_entry(fat, c, 0xFFF);
                    } else if (msdos->fat_type == 16) {
                        archive_le16enc(fat + c*2, 0xFFFF);
                    } else {
                        archive_le32enc(fat + c*4, 0x0FFFFFFF);
                    }
                    cluster += needed;
                }
            }
            else {
                if (f->size==0) {
                    f->first_cluster=0;
                    f->cluster_count=0;
                    continue;
                }
                uint64_t bpc = (uint64_t)msdos->cluster_size*SECTOR_SIZE;
                uint32_t needed = (uint32_t)((f->size + bpc-1)/bpc);
                if (cluster+needed-1 >= fat_entries) {
                    free(fat);
                    archive_set_error(&a->archive, ENOSPC, "No space for file '%s'",
                        f->entry ? archive_entry_pathname(f->entry) : "(?)");
                    return (ARCHIVE_FATAL);
                }
                f->first_cluster = cluster;
                f->cluster_count = needed;
                uint32_t c=cluster;
                for (uint32_t i=0; i<needed-1; i++) {
                    uint32_t next = c+1;
                    if (msdos->fat_type == 12) {
                        set_fat12_entry(fat, c, (uint16_t)next);
                    } else if (msdos->fat_type == 16) {
                        archive_le16enc(fat + c*2, (uint16_t)next);
                    } else {
                        archive_le32enc(fat + c*4, next);
                    }
                    c++;
                }
                if (msdos->fat_type == 12) {
                    set_fat12_entry(fat, c, 0xFFF);
                } else if (msdos->fat_type == 16) {
                    archive_le16enc(fat + c*2, 0xFFFF);
                } else {
                    archive_le32enc(fat + c*4, 0x0FFFFFFF);
                }
                cluster += needed;
            }
        }
    }

    for (int copy=0; copy<2; copy++) {
        off_t fat_off = (off_t)(msdos->fat_offset + copy*msdos->fat_size)*SECTOR_SIZE;
        if (lseek(msdos->temp_fd, fat_off, SEEK_SET)<0 ||
            write(msdos->temp_fd, fat, fat_size_bytes) != (ssize_t)fat_size_bytes) {
            free(fat);
            archive_set_error(&a->archive, errno, "FAT write failed");
            return (ARCHIVE_FATAL);
        }
    }

    free(fat);
    return (ARCHIVE_OK);
}

/* ------------------- WRITE ROOT DIRECTORY ------------------- */

static int
write_root_dir(struct archive_write *a)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    DEBUG_PRINT("Writing root directory");
    DEBUG_FILES(msdos);

    int total_files = 0;
    {
        struct fat_file *f;
        for (f = msdos->files; f; f = f->next) {
            total_files++;
        }
    }
    DEBUG_PRINT("Total files in list: %d", total_files);

    if (msdos->fat_type==32) {
        /* FAT32 => root is just a normal directory chain. */
        struct fat_file *root_dir = NULL;
        {
            struct fat_file *f;
            for (f = msdos->files; f; f=f->next) {
                if (f->is_dir && f->is_root) {
                    root_dir=f;
                    break;
                }
            }
        }
        if (!root_dir) {
            return ARCHIVE_OK; // no root_dir => no files
        }
        DEBUG_PRINT("write_root_dir(FAT32): Found root_dir=%p (cluster=%u, size=%u)",
            (void*)root_dir,
            root_dir->first_cluster,
            root_dir->size);
        /* Gather top-level items for root_dir. */
        int num_entries=0;
        {
            int estimate=2;
            struct fat_file *f;
            for (f=msdos->files; f; f=f->next) {
                if (f==root_dir) continue;
                if (f->parent == root_dir) {
                    estimate += count_dir_entries_for_file(f);
                }
            }
            struct fat_file **list = calloc((size_t)estimate, sizeof(*list));
            if (!list) {
                archive_set_error(&a->archive, ENOMEM, "No mem for root dir list");
                return (ARCHIVE_FATAL);
            }
            list[num_entries++] = root_dir; // "." entry
            list[num_entries++] = NULL;     // ".." entry
            {
                struct fat_file *ff;
                for (ff=msdos->files; ff; ff=ff->next) {
                    if (ff==root_dir) continue;
                    if (ff->parent == root_dir) {
                        list[num_entries++] = ff;
                    }
                }
            }
            DEBUG_PRINT("write_root_dir(FAT32): Building array of top-level items ...");
            DEBUG_PRINT("  will write %d items (including . and ..)", num_entries);
            {
                int r = write_directory(a, root_dir, list, num_entries);
                free(list);
                if (r!=ARCHIVE_OK) return r;
            }
        }
        // Now recursively write subdirectories from root_dir downward.
        {
            int r2 = write_subdirectories_recursively(a, root_dir);
            if (r2 != ARCHIVE_OK)
                return r2;
        }
        return ARCHIVE_OK;
    } else {
        /* FAT12/16 => fixed root region. */
        size_t root_dir_bytes = (size_t)msdos->root_entries*DIR_ENTRY_SIZE;
        unsigned char *buf = calloc(1, root_dir_bytes);
        if (!buf) {
            archive_set_error(&a->archive, ENOMEM, "No mem for FAT12/16 root dir");
            return (ARCHIVE_FATAL);
        }
        size_t offset=0;
        int root_file_count = 0;

        DEBUG_PRINT("Writing FAT12/16 root directory entries");
        {
            struct fat_file *f;
            for (f=msdos->files; f; f=f->next) {
                /* Only top-level items => parent==NULL in FAT12/16. */
                if (f->parent != NULL) {
                    continue;
                }
                root_file_count++;
                char short_name[12];
                make_short_name(f->long_name ? f->long_name : "", short_name);
                DEBUG_PRINT("Processing root file: %s", f->long_name ? f->long_name : "(no name)");
                int error = ensure_unique_short_name(a, msdos, short_name, NULL);
                if (error != 0) {
                    free(buf);
                    return (ARCHIVE_FATAL);
                }

                if (strcmp(f->long_name ? f->long_name : "", short_name)!=0) {
                    int lfn_size = write_long_name_entries(buf+offset, f->long_name, short_name);
                    offset += lfn_size;
                    if (offset+DIR_ENTRY_SIZE>root_dir_bytes) {
                        free(buf);
                        archive_set_error(&a->archive, ENOSPC, "Root dir overflow (LFN)");
                        return (ARCHIVE_FATAL);
                    }
                }
                if (offset+DIR_ENTRY_SIZE>root_dir_bytes) {
                    free(buf);
                    archive_set_error(&a->archive, ENOSPC, "Root dir overflow");
                    return (ARCHIVE_FATAL);
                }
                offset += write_dir_entry(msdos->fat_type, buf+offset, short_name, f);
            }
        }
        DEBUG_PRINT("Added %d files to root directory", root_file_count);

        off_t root_off = (off_t)(msdos->root_offset)*SECTOR_SIZE;
        if (lseek(msdos->temp_fd, root_off, SEEK_SET)<0 ||
            write(msdos->temp_fd, buf, root_dir_bytes) != (ssize_t)root_dir_bytes) {
            free(buf);
            archive_set_error(&a->archive, errno, "FAT12/16 root write failed");
            return (ARCHIVE_FATAL);
        }
        free(buf);

        // Also do a recursive subdirectory write for top-level subdirs.
        {
            int r2 = write_subdirectories_recursively(a, NULL);
            if (r2 != ARCHIVE_OK)
                return r2;
        }

        return (ARCHIVE_OK);
    }
}

static int
write_subdirectories_recursively(struct archive_write *a, struct fat_file *parent)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    int r;
    int dir_count = 0;

    DEBUG_PRINT("Writing subdirectories recursively (parent=%p)", (void*)parent);
    /* Find all directories that have parent == `parent`. */
    struct fat_file *dir;
    for (dir = msdos->files; dir; dir=dir->next) {
        if (!dir->is_dir || dir->is_root)
            continue;
        if (dir->parent == parent) {
            dir_count++;
            DEBUG_PRINT("Found directory to process: %s (parent=%p)",
                       dir->long_name ? dir->long_name : "(no name)",
                       (void*)parent);
            /*
             * Gather all children of 'dir'.
             */
            int num_entries = 2; /* "." + ".." */
            {
                struct fat_file *c;
                for (c = msdos->files; c; c=c->next) {
                    if (c->parent == dir) {
                        num_entries += count_dir_entries_for_file(c);
                    }
                }
            }
            struct fat_file **sublist = calloc((size_t)(num_entries+5), sizeof(*sublist));
            if (!sublist) {
                archive_set_error(&a->archive, ENOMEM, "No mem for subdir list");
                return (ARCHIVE_FATAL);
            }
            int idx=0;
            sublist[idx++] = dir;    /* "." */
            sublist[idx++] = parent; /* ".." (the real parent) */

            struct fat_file *c;
            for (c=msdos->files; c; c=c->next) {
                if (c->parent == dir) {
                    sublist[idx++] = c;
                }
            }
            r = write_directory(a, dir, sublist, idx);
            free(sublist);
            if (r != ARCHIVE_OK)
                return r;

            // Recurse
            r = write_subdirectories_recursively(a, dir);
            if (r != ARCHIVE_OK)
                return r;
        }
    }
    DEBUG_PRINT("Processed %d directories with parent %p", dir_count, (void*)parent);
    return ARCHIVE_OK;
}

static int
write_directory(struct archive_write *a, struct fat_file *dir,
                struct fat_file **dir_entries, int num_entries)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
DEBUG_PRINT("write_directory: dir=%p (name='%s'), num_entries=%d, first_cluster=%u, size=%u",
            (void*)dir,
            dir->long_name ? dir->long_name : "(null)",
            num_entries,
            dir->first_cluster,
            dir->size);
    if (dir->cluster_count==0) {
        return ARCHIVE_OK;
    }
    size_t total_entries=2; // "." + ".."
    {
        int i;
        for (i=0; i<num_entries; i++) {
            if (dir_entries[i]==dir || dir_entries[i]==NULL) {
                continue;
            }
            total_entries += count_dir_entries_for_file(dir_entries[i]);
        }
    }
    size_t dir_size_bytes = (size_t)dir->size;
    {
        size_t needed_bytes = total_entries*DIR_ENTRY_SIZE;
        if (needed_bytes>dir_size_bytes) {
            dir_size_bytes = needed_bytes;
        }
    }

    unsigned char *buf = calloc(1, dir_size_bytes);
    if (!buf) {
        archive_set_error(&a->archive, ENOMEM, "No mem for directory data");
        return (ARCHIVE_FATAL);
    }
    {
        size_t offset=0;
        {
            // '.' entry
            char dot[11] = ".          ";
            offset += write_dir_entry(msdos->fat_type, buf+offset, dot, dir);
        }
        {
            // '..' entry
            char dotdot[11] = "..         ";
            struct fat_file *parent_dir = dir_entries[1];
            if (parent_dir) {
                offset += write_dir_entry(msdos->fat_type, buf+offset, dotdot, parent_dir);
            } else {
                struct fat_file dummy;
                memset(&dummy, 0, sizeof(dummy));
                dummy.is_dir=1;
                offset += write_dir_entry(msdos->fat_type, buf+offset, dotdot, &dummy);
            }
        }
        {
            int i;
            for (i=0; i<num_entries; i++) {
                struct fat_file *f=dir_entries[i];
                if (!f || f==dir) continue;


                char short_name[12];
                make_short_name(f->long_name ? f->long_name : "", short_name);
                int error = ensure_unique_short_name(a, msdos, short_name, dir);
                if (error != 0) {
                    free(buf);
                    return (ARCHIVE_FATAL);
                }

                if (f->long_name && f->long_name[0] != '\0') {
                    if (strcmp(f->long_name, short_name)!=0) {
                        offset += write_long_name_entries(buf+offset, f->long_name, short_name);
                    }
                }
DEBUG_PRINT("  writing subdir/file: '%s' => short_name='%s', is_dir=%d, cluster=%u",
            f->long_name ? f->long_name : "(null)",
            short_name,
            f->is_dir,
            f->first_cluster);
                offset += write_dir_entry(msdos->fat_type, buf+offset, short_name, f);
            }
        }
    }

    {
        size_t cluster_bytes = (size_t)msdos->cluster_size*SECTOR_SIZE;
        size_t bytes_left=dir_size_bytes;
        uint32_t cluster = dir->first_cluster;
        unsigned char *p=buf;

        while (bytes_left>0) {
            size_t chunk = (bytes_left<cluster_bytes)? bytes_left: cluster_bytes;
            off_t cluster_off = (off_t)(msdos->data_offset
                + (cluster - FAT_RESERVED_ENTRIES)*msdos->cluster_size) * SECTOR_SIZE;
            if (lseek(msdos->temp_fd, cluster_off, SEEK_SET)<0 ||
                write(msdos->temp_fd, p, chunk)!=(ssize_t)chunk) {
                free(buf);
                archive_set_error(&a->archive, errno, "Directory cluster write failed");
                return (ARCHIVE_FATAL);
            }
            // zero-pad if chunk < cluster_bytes
            if (chunk<cluster_bytes) {
                char zero[SECTOR_SIZE];
                memset(zero, 0, sizeof(zero));
                size_t pad = cluster_bytes - chunk;
                while (pad>0) {
                    size_t w = (pad<sizeof(zero))? pad: sizeof(zero);
                    if (write(msdos->temp_fd, zero, w)!=(ssize_t)w) {
                        free(buf);
                        archive_set_error(&a->archive, errno, "Zero pad fail");
                        return (ARCHIVE_FATAL);
                    }
                    pad-=w;
                }
            }
            p += chunk;
            bytes_left -= chunk;
            cluster++;
        }
    }

    free(buf);
    return (ARCHIVE_OK);
}

static int
write_cluster_chain(struct archive_write *a, struct fat_file *file)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    if (file->is_dir) {
        return ARCHIVE_OK;
    }
    if (file->cluster_count==0) {
        return ARCHIVE_OK;
    }
    size_t bytes_left = file->size;
    size_t cluster_bytes = (size_t)msdos->cluster_size*SECTOR_SIZE;
    off_t read_off = file->content_offset;
    uint32_t cluster = file->first_cluster;

    unsigned char *buf = malloc(cluster_bytes);
    if (!buf) {
        archive_set_error(&a->archive, ENOMEM, "No mem for cluster data");
        return (ARCHIVE_FATAL);
    }
    while (bytes_left>0) {
        size_t chunk = (bytes_left<cluster_bytes)? bytes_left: cluster_bytes;
        if (lseek(msdos->temp_fd, read_off, SEEK_SET)<0) {
            free(buf);
            archive_set_error(&a->archive, errno, "Seek fail reading file data");
            return (ARCHIVE_FATAL);
        }
        {
            size_t got=0;
            while (got<chunk) {
                ssize_t rd = read(msdos->temp_fd, buf+got, chunk-got);
                if (rd<0) {
                    free(buf);
                    archive_set_error(&a->archive, errno, "Read fail from temp file");
                    return (ARCHIVE_FATAL);
                }
                if (rd==0) {
                    memset(buf+got, 0, chunk-got);
                    got=chunk;
                    break;
                }
                got += (size_t)rd;
            }
            if (got<cluster_bytes) {
                memset(buf+got, 0, cluster_bytes-got);
            }
        }
        {
            off_t cluster_off = (off_t)(msdos->data_offset
               + (cluster - FAT_RESERVED_ENTRIES)*msdos->cluster_size) * SECTOR_SIZE;
            if (lseek(msdos->temp_fd, cluster_off, SEEK_SET)<0 ||
                write(msdos->temp_fd, buf, cluster_bytes)!=(ssize_t)cluster_bytes) {
                free(buf);
                archive_set_error(&a->archive, errno, "Write fail cluster data");
                return (ARCHIVE_FATAL);
            }
        }
        bytes_left -= chunk;
        read_off   += (off_t)chunk;
        cluster++;
    }
    free(buf);
    return (ARCHIVE_OK);
}

/* ------------------- NAME + LFN UTILS ------------------- */

static void
make_short_name(const char *long_name, char *short_name)
{
    int i, j=0;
    const char *ext = strrchr(long_name, '.');
    char base[9], extension[4];
    memset(base, ' ', 8);
    memset(extension, ' ', 3);
    base[8] = '\0';
    extension[3] = '\0';

    DEBUG_PRINT("  Creating short name for: '%s'", long_name);

    /* Handle empty names */
    if (!long_name || !*long_name) {
        memcpy(short_name, "NONAME  ", 8);
        memcpy(short_name+8, "   ", 3);
        short_name[11] = '\0';
        DEBUG_PRINT("  Empty name, using default: '%s'", short_name);
        return;
    }

    /* Process extension first */
    j = 0;
    if (ext) {
        ext++; /* Skip the dot */
        for (i = 0; ext[i] && j < 3; i++) {
            char c = ext[i];
            if (c >= 'a' && c <= 'z') c -= 32; /* Uppercase */
            if (c == ' ' || c == '.') continue;
            if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                strchr("$%'-_@~!(){}^#&", c)) {
                extension[j++] = c;
            } else {
                extension[j++] = '_';
            }
        }
    }

    /* Process base name */
    j = 0;
    for (i = 0; long_name[i] && (&long_name[i] != ext) && j < 8; i++) {
        char c = long_name[i];
        if (c >= 'a' && c <= 'z') c -= 32; /* Uppercase */
        if (c == ' ' || c == '.') continue;
        if ((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            strchr("$%'-_@~!(){}^#&", c)) {
            base[j++] = c;
        } else {
            base[j++] = '_';
        }
    }
    if (j == 0) {
        base[0] = 'X';
    }

    memcpy(short_name, base, 8);
    memcpy(short_name+8, extension, 3);
    short_name[11] = '\0';

    DEBUG_PRINT("  Created short name: '%s'", short_name);
}

static int
build_colliding_short_name(const char *base, const char *ext, int num, char *short_name)
{
    char new_base[9];
    int base_len = 0;

    while (base_len < 8 && base[base_len] != ' ') {
        base_len++;
    }
    int num_digits = 1;
    int temp_num = num;
    while (temp_num >= 10) {
        num_digits++;
        temp_num /= 10;
    }
    int max_base_chars = 8 - (num_digits + 1);
    if (max_base_chars < 1) {
        return -1;
    }
    if (base_len > max_base_chars) {
        base_len = max_base_chars;
    }
    memcpy(new_base, base, base_len);
    new_base[base_len] = '~';
    sprintf(new_base + base_len + 1, "%d", num);

    memset(short_name, ' ', 11);
    {
        int new_base_len = (int)strlen(new_base);
        if (new_base_len > 8) new_base_len = 8;
        memcpy(short_name, new_base, (size_t)new_base_len);
    }
    memcpy(short_name+8, ext, 3);
    short_name[11] = '\0';

    return 0;
}

static int
write_dir_entry(int fat_type, unsigned char *buffer, const char *name, struct fat_file *file)
{
    time_t mtime;
    struct tm tm_buf, *tm_ptr=NULL;
    if (file->entry) {
        mtime = archive_entry_mtime(file->entry);
        tm_ptr = localtime_r(&mtime, &tm_buf);
    }
    if (!tm_ptr) {
        memset(&tm_buf,0,sizeof(tm_buf));
        tm_buf.tm_year=80;
        tm_buf.tm_mon=0;
        tm_buf.tm_mday=1;
    }
    uint16_t dos_time = ((uint16_t)tm_buf.tm_hour<<11)
                      | ((uint16_t)tm_buf.tm_min<<5)
                      | ((uint16_t)(tm_buf.tm_sec/2));
    uint16_t dos_date = ((uint16_t)(tm_buf.tm_year-80)<<9)
                      | ((uint16_t)(tm_buf.tm_mon+1)<<5)
                      | ((uint16_t)tm_buf.tm_mday);

    memcpy(buffer, name, 11);
    buffer[11] = (unsigned char)(file->is_dir ? ATTR_DIRECTORY : ATTR_ARCHIVE);
    buffer[12] = 0;
    buffer[13] = 0;
    archive_le16enc(buffer+14, dos_time);
    archive_le16enc(buffer+16, dos_date);
    archive_le16enc(buffer+18, dos_date);
    archive_le16enc(buffer+22, dos_time);
    archive_le16enc(buffer+24, dos_date);

    if (fat_type == 32) {
        archive_le16enc(buffer + 20, (uint16_t)(file->first_cluster >> 16));
    }
    archive_le16enc(buffer+26, (uint16_t)(file->first_cluster & 0xFFFF));
    if (file->is_dir) {
        archive_le32enc(buffer+28, 0);
    } else {
        archive_le32enc(buffer+28, file->size);
    }
    return DIR_ENTRY_SIZE;
}

static int
write_long_name_entries(unsigned char *buffer, const char *long_name,
                        const char *short_name)
{
    int name_len = (int)strlen(long_name);
    int entries_needed = (name_len+12)/13;
    int total_bytes = entries_needed*DIR_ENTRY_SIZE;

    unsigned char checksum=0;
    {
        int i;
        for (i=0; i<11; i++) {
            checksum = (unsigned char)(((checksum &1)?0x80:0)+(checksum>>1)+(unsigned char)short_name[i]);
        }
    }

    {
        int i, pos=0;
        for (i=entries_needed-1; i>=0; i--) {
            unsigned char *ent = buffer + i*DIR_ENTRY_SIZE;
            int ordinal = (entries_needed - i);
            if (ordinal==entries_needed) {
                ordinal |= 0x40;
            }
            memset(ent, 0xFF, DIR_ENTRY_SIZE);
            ent[0] = (unsigned char)ordinal;
            ent[11] = ATTR_LONG_NAME;
            ent[12] = 0;
            ent[13] = checksum;
            archive_le16enc(ent+26, 0);

            int j;
            for (j=0; j<13; j++) {
                int name_pos = pos+j;
                uint16_t ch=0xFFFF;
                if (name_pos<name_len) {
                    ch = (unsigned char)long_name[name_pos];
                } else if (name_pos==name_len) {
                    ch=0;
                }
                if (j<5) {
                    archive_le16enc(ent+1+ j*2, ch);
                } else if (j<11) {
                    archive_le16enc(ent+14+(j-5)*2, ch);
                } else {
                    archive_le16enc(ent+28+(j-11)*2, ch);
                }
            }
            pos += 13;
        }
    }
    return total_bytes;
}

static int
count_dir_entries_for_file(struct fat_file *f)
{
    if (!f->long_name || !*f->long_name) {
        return 1;
    }
    {
        char short_name[12];
        make_short_name(f->long_name, short_name);
        if (strcmp(f->long_name, short_name)==0) {
            return 1;
        } else {
            int name_len = (int)strlen(f->long_name);
            int lfn_count = (name_len+12)/13;
            return 1 + lfn_count;
        }
    }
}

static struct fat_file*
find_or_create_dir(struct msdosfs *msdos, struct fat_file *parent, const char *dirname)
{
    DEBUG_PRINT("Finding or creating directory: %s (parent=%p)", dirname, (void*)parent);
    struct fat_file *f;
    for (f = msdos->files; f; f=f->next) {
        if (f->is_dir && f->long_name && strcmp(f->long_name, dirname)==0) {
            if (f->parent == parent) {
                DEBUG_PRINT("  Found existing directory: %s", dirname);
                return f;
            }
        }
    }

    f = calloc(1, sizeof(*f));
    if (!f) return NULL;
    f->is_dir = 1;
    f->long_name = strdup(dirname);
    f->parent = parent;
    f->next = msdos->files;
    msdos->files = f;

    DEBUG_PRINT("  Created new directory: %s (parent=%p)", dirname, (void*)parent);

    /* Add this directory to its parent's children list */
    if (parent) {
        add_child_to_parent(parent, f);
    }

    return f;
}

static void
add_child_to_parent(struct fat_file *parent, struct fat_file *child)
{
    if (!parent || !child)
        return;
    if (parent->children == NULL) {
        parent->children = child;
    } else {
        struct fat_file *sibling = parent->children;
        while (sibling->sibling != NULL) {
            sibling = sibling->sibling;
        }
        sibling->sibling = child;
    }
}

static int
assign_subdir_sizes(struct msdosfs *msdos)
{
    struct fat_file *f;
    for (f = msdos->files; f; f = f->next) {
        if (f->is_dir && !f->is_root) {
            int needed_entries = 2; // '.' + '..'
            struct fat_file *c;
            for (c = f->children; c; c = c->sibling) {
                needed_entries += count_dir_entries_for_file(c);
            }
            f->size = needed_entries * DIR_ENTRY_SIZE;
        }
    }
    return ARCHIVE_OK;
}

static void
init_shortname_hash(struct shortname_hash *hash)
{
    memset(hash->buckets, 0, sizeof(hash->buckets));
}

static unsigned int
shortname_hash(const char *name, struct fat_file *parent_dir)
{
    unsigned int hash = 0;
    uintptr_t ptr_val = (uintptr_t)parent_dir;
    hash = (unsigned int)(ptr_val ^ (ptr_val >> 16));
    for (int i = 0; i < 11; i++) {
        hash = hash * 31 + (unsigned char)name[i];
    }
    return hash % SHORTNAME_HASH_SIZE;
}

static int
shortname_exists(struct msdosfs *msdos, const char *name, struct fat_file *parent_dir)
{
    unsigned int hash_val = shortname_hash(name, parent_dir);
    struct shortname_entry *p = msdos->used_shortnames.buckets[hash_val];

    while (p) {
        if (p->parent_dir == parent_dir && memcmp(p->name, name, 11) == 0) {
            return 1;
        }
        p = p->next;
    }
    return 0;
}

static void
add_shortname(struct msdosfs *msdos, const char *name, struct fat_file *parent_dir)
{
    unsigned int hash_val = shortname_hash(name, parent_dir);
    struct shortname_entry *p = malloc(sizeof(*p));
    if (!p) {
        DEBUG_PRINT("  ERROR: Failed to allocate memory for short name: '%s'", name);
        return;
    }
    memset(p, 0, sizeof(*p));
    memcpy(p->name, name, 11);
    p->name[11] = '\0';
    p->parent_dir = parent_dir;
    p->next = msdos->used_shortnames.buckets[hash_val];
    msdos->used_shortnames.buckets[hash_val] = p;
    DEBUG_PRINT("  Added short name to hash: '%s' (parent=%p, bucket=%u)",
                name, (void*)parent_dir, hash_val);
}

static int
ensure_unique_short_name(struct archive_write *a, struct msdosfs *msdos, char short_name[12], struct fat_file *parent_dir)
{
    DEBUG_PRINT("Ensuring unique short name for: '%s' (parent=%p)", short_name, (void*)parent_dir);

    if (!shortname_exists(msdos, short_name, parent_dir)) {
        add_shortname(msdos, short_name, parent_dir);
        return 0;
    }
    char base[9], ext[4];
    memcpy(base, short_name, 8);
    base[8] = '\0';
    memcpy(ext, short_name+8, 3);
    ext[3] = '\0';
    DEBUG_PRINT("  Name collision - base: '%s', ext: '%s'", base, ext);

    for (int i = 1; i <= 999999; i++) {
        char temp[12];
        if (build_colliding_short_name(base, ext, i, temp) != 0) {
            archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
                "Failed to build collision-resolving short name");
            return (ARCHIVE_FATAL);
        }
        DEBUG_PRINT("  Trying collision name: '%s'", temp);
        if (!shortname_exists(msdos, temp, parent_dir)) {
            memcpy(short_name, temp, 12);
            add_shortname(msdos, temp, parent_dir);
            DEBUG_PRINT("  Using unique short name: '%s'", short_name);
            return 0;
        }
        if (i == 999999) {
            archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
                "Too many short name collisions (999999 attempts)");
            DEBUG_PRINT("  ERROR: Too many short name collisions!");
            return (ARCHIVE_FATAL);
        }
    }
    archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
        "Unexpected error in short name collision resolution");
    return (ARCHIVE_FATAL);
}
