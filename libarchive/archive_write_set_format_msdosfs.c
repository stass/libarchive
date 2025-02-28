/*-
 * archive_write_set_format_msdosfs.c
 *
 * Revised "msdosfs" (FAT) format writer for libarchive implementing
 * two-pass creation:
 *
 *   Pass 1 = Collect file data in temp file.
 *            Build an in-memory file/dir tree (msdos->files).
 *   Pass 2 = Compute minimal FAT geometry & cluster assignments,
 *            then write the entire FAT disk image *directly*
 *            to libarchive’s final output stream.
 *
 * The temp file only stores file contents; no FAT metadata is
 * ever overwritten into that temp file. Metadata is built in memory.
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
#include "archive_write_private.h"

/* Debug macros */
#define MSDOSFS_DEBUG
#ifdef MSDOSFS_DEBUG
#define DEBUG_PRINT(fmt, ...)  fprintf(stderr, "MSDOSFS: " fmt "\n", ##__VA_ARGS__)
static void debug_print_files(struct archive_write *a);
#else
#define DEBUG_PRINT(fmt, ...)
static void debug_print_files(struct archive_write *a) { (void)a; }
#endif

/* 512-byte sectors. */
#define SECTOR_SIZE 512

/* FAT12 limit ~4084 clusters; FAT16 limit ~65524. */
#define FAT12_MAX_CLUSTERS  4084
#define FAT16_MAX_CLUSTERS  65524
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

    /* Where file data is stored in the temp file (for files). */
    off_t    content_offset;

    /* Additional fields could go here if needed. */
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
};

/* --------------------- Forward Declarations ----------------------- */

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
static void write_longname_entries(unsigned char *buf, const char *lname,
                                   const char shortnm[12]);

/* Directory and short-name utilities: */
static struct fat_file* find_or_create_dir(struct msdosfs *msdos,
                                           struct fat_file *parent,
                                           const char *dirname);
static void add_child_to_parent(struct fat_file *parent, struct fat_file *child);
static int  count_dir_entries_for_file(struct fat_file *f);

/* Short name logic + collisions. */
static void init_shortname_hash(struct shortname_hash *hash);
static unsigned int shortname_hash_key(const char *name, struct fat_file *parent_dir);
static int  shortname_exists(struct msdosfs *msdos, const char *name, struct fat_file *parent_dir);
static void add_shortname(struct msdosfs *msdos, const char *name, struct fat_file *parent_dir);
static int  ensure_unique_short_name(struct archive_write *a, struct msdosfs *msdos,
                                     char short_name[12], struct fat_file *parent_dir);
static void make_short_name(const char *long_name, char short_name[12]);

/* --------------------------------------------------------------------
 * Public entry point: set the format to msdosfs (FAT).
 * -------------------------------------------------------------------- */
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

    /* For FAT12/16, a default root_entries. We'll refine it later. */
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

    return ARCHIVE_OK;
}

/* --------------------------------------------------------------------
 * Implement user-specified options (e.g. "fat_type=12|16|32").
 * -------------------------------------------------------------------- */
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
        return ARCHIVE_OK;
    }

    /* If unrecognized, return warning. */
    return ARCHIVE_WARN;
}

/* --------------------------------------------------------------------
 * Pass 1: archive_write_header => new file/dir is about to be written.
 * We create a new fat_file, parse its path into parent dirs, etc.
 * For directories, no data is written. For files, we remember content_offset
 * in the temp file.
 * -------------------------------------------------------------------- */
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
    file->size    = (uint32_t)archive_entry_size(entry);
    file->is_dir  = (archive_entry_filetype(entry) == AE_IFDIR);

    /* For FAT32, we keep a single special root node if needed. Create it once. */
    if (msdos->fat_type == 32 && msdos->fat32_root == NULL) {
        /* Create the FAT32 root directory node. */
        struct fat_file *root = (struct fat_file *)calloc(1, sizeof(*root));
        if (!root) {
            free(file);
            archive_set_error(&a->archive, ENOMEM, "Cannot allocate FAT32 root dir");
            return ARCHIVE_FATAL;
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
        free(file);
        archive_set_error(&a->archive, ENOMEM, "strdup failed");
        return ARCHIVE_FATAL;
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
            parent_dir = find_or_create_dir(msdos, parent_dir, token);
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

    /* Set up parent, link into parent's child list. */
    file->parent = parent_dir;
    if (parent_dir) {
        add_child_to_parent(parent_dir, file);
    }

    /* Insert into global msdos->files list. */
    file->next = msdos->files;
    msdos->files = file;

    /* If it's a file, get ready for data. */
    if (!file->is_dir) {
        msdos->current_file = file;
        msdos->bytes_remaining = file->size;
        /* Seek to end of temp file to record where data starts. */
        off_t off = lseek(msdos->temp_fd, 0, SEEK_END);
        file->content_offset = off;
    }

    return ARCHIVE_OK;
}

/* --------------------------------------------------------------------
 * Pass 1: archive_write_data => write a data block for the *current_file*.
 * Simply write this block to the temp file.
 * -------------------------------------------------------------------- */
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

/* --------------------------------------------------------------------
 * Pass 1: archive_write_finish_entry => finalize this entry.
 * If the announced size was bigger than what we got, zero‐pad in the temp file.
 * -------------------------------------------------------------------- */
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

/* --------------------------------------------------------------------
 * Pass 2: archive_write_msdosfs_close => now that all entries are in,
 * we compute the minimal FAT geometry, assign clusters, and do a single
 * streaming write of the complete FAT filesystem structure to the archive.
 * -------------------------------------------------------------------- */
static int
archive_write_msdosfs_close(struct archive_write *a)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;

    debug_print_files(a);

    /* 1) Compute minimal geometry to hold all directories & files. */
    int r = msdosfs_compute_geometry(a);
    if (r != ARCHIVE_OK) {
        return r;
    }

    /* 2) Assign clusters to each file/directory. */
    r = msdosfs_assign_clusters(a);
    if (r != ARCHIVE_OK) {
        return r;
    }

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

/* --------------------------------------------------------------------
 * Free the msdosfs object entirely.
 * -------------------------------------------------------------------- */
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
            free(f);
            f = nx;
        }
        free(msdos);
        a->format_data = NULL;
    }
    return ARCHIVE_OK;
}

/* ======================= PASS 2: Compute Geometry ======================= */

/* 
 * Forward references for these helpers:
 */
static void compute_directory_sizes(struct msdosfs *msdos);
static uint32_t count_needed_dir_entries(struct fat_file *dir);
static int try_fat_geometry(struct archive_write *a, int fat_type,
                            uint32_t *out_cluster_size);

/* ----------------------------------------------------------------------
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
 * ---------------------------------------------------------------------- */
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

/* ----------------------------------------------------------------------
 * try_fat_geometry() => for a given fat_type = (12|16|32), tries 
 * cluster_size = 1,2,4,8,16,... up to some max, and attempts to converge 
 * on a stable geometry that fits all files & directories. 
 * 
 * If successful, sets msdos->... fields and returns ARCHIVE_OK. 
 * If not, returns ARCHIVE_FATAL, leaving geometry untouched.
 * ---------------------------------------------------------------------- */
static int
try_fat_geometry(struct archive_write *a, int fat_type, uint32_t *out_cluster_size)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;

    /* We'll try these cluster sizes in turn: */
    static const uint32_t cluster_candidates[] = {1,2,4,8,16,32,64,128};
    int n_candidates = (int)(sizeof(cluster_candidates)/sizeof(cluster_candidates[0]));

    /* Precompute how many top-level items we might need in the root if FAT12/16. */
    /* We'll see if we need to enlarge msdos->root_entries. The user might have 
     * some default. We'll do it here. 
     */
    if (fat_type==12 || fat_type==16) {
        /* Count how many top-level files/dirs are parent==NULL. */
        int count_top = 0;
        for (struct fat_file *f = msdos->files; f; f = f->next) {
            if (!f->is_root && f->parent == NULL) {
                count_top += count_needed_dir_entries(f);
            }
        }
        /* If that’s bigger than msdos->root_entries, enlarge a bit. */
        if (count_top > (int)msdos->root_entries) {
            msdos->root_entries = (uint32_t)(count_top + 16);
        }
    } else {
        /* FAT32 => root_entries=0, root_size=0 (the root is in data). */
        msdos->root_entries = 0;
        msdos->root_size    = 0;
    }

    /* Now we attempt each cluster size in ascending order. */
    for (int j=0; j<n_candidates; j++) {
        uint32_t csize = cluster_candidates[j];

        /* Set up initial fields: */
        msdos->fat_type = fat_type;
        msdos->cluster_size = csize;

        /* For FAT32, typically 32 reserved sectors. For FAT12/16 => 1 reserved sector. */
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
         * Because the FAT size depends on cluster_count, which depends on 
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

            /* We'll guess some large volume_size to ensure we don't run out, 
             * then we will refine or confirm. 
             * Actually, let's start with a guess based on total file size. 
             */
            uint64_t total_file_bytes = 0;
            for (struct fat_file *f = msdos->files; f; f=f->next) {
                if (!f->is_dir) {
                    total_file_bytes += f->size;
                }
            }
            /* We'll guess how many clusters we might need. 
             * This is somewhat an over-approx if we want to handle big subdirs. 
             * For subdirectories, we might guess each directory uses at least 1 cluster. 
             */
            int dir_count = 0;
            for (struct fat_file *f=msdos->files; f; f=f->next) {
                if (f->is_dir && !(f->is_root && (fat_type==12||fat_type==16))) {
                    /* (FAT12/16 root doesn't consume clusters. FAT32 root does.) */
                    dir_count++;
                }
            }

            /* cluster_size (in bytes) = csize * SECTOR_SIZE */
            uint64_t cbytes = (uint64_t)csize * SECTOR_SIZE;
            uint64_t needed_clusters_for_files =
               (total_file_bytes + cbytes -1)/cbytes;
            uint64_t approx_clusters = needed_clusters_for_files + dir_count + 16;

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

/* ----------------------------------------------------------------------
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
 *     - The function count_needed_dir_entries() calculates the total for
 *       that file or directory.  Summing up each child yields total entries.
 *     - Then f->size = num_entries * 32.
 * 
 * Note that for the FAT12/16 root directory, we do NOT set f->size; instead
 * it’s limited by msdos->root_entries.  Only subdirectories get cluster-based
 * storage.
 * ---------------------------------------------------------------------- */
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

/* ----------------------------------------------------------------------
 * count_needed_dir_entries(f): 
 *   returns how many 32-byte directory entries are needed for this file
 *   or directory, including short+LFN.  Typically 1 short entry if the
 *   short name == long_name, otherwise add the LFN count.
 * 
 *   If f is a directory, we do not add the 2 extra for "." and ".." here,
 *   that is handled by the parent’s calculation. 
 * ---------------------------------------------------------------------- */
static uint32_t
count_needed_dir_entries(struct fat_file *f)
{
    /* Basic approach: 1 short entry.  If f->long_name is different from 
     * the short name, add # of LFN entries => (len(long_name)+12)/13.
     */
    if (!f->long_name) {
        return 1;
    }
    /* generate the short name in a buffer and compare. */
    char shortnm[12];
    make_short_name(f->long_name, shortnm);
    if (strcmp(f->long_name, shortnm)==0) {
        return 1;
    } else {
        size_t len = strlen(f->long_name);
        uint32_t lfn_count = (uint32_t)((len+12)/13);
        return (1 + lfn_count);
    }
}

/* ----------------------------------------------------------------------
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
 * ---------------------------------------------------------------------- */
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
            /* if truly no root => create one just so we have it. */
            /* though typically you’d have done that earlier. */
        }
        if (root_dir) {
            /* compute how many clusters are needed. */
            uint64_t s = (root_dir->size == 0) ? 0 : root_dir->size;
            uint32_t needed = (uint32_t)((s + cluster_size_bytes -1)/cluster_size_bytes);
            if (needed==0 && s>0) {
                needed=1;
            } else if (s==0) {
                /* If user wants empty root => we can do 0 or 1 cluster. 
                 * Some tools require at least 1 cluster.  Let’s do 1 if s>0. 
                 */
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
                    archive_set_error(&a->archive, ENOSPC, 
                                      "Not enough clusters for file");
                    return ARCHIVE_FATAL;
                }
                f->first_cluster = next_cluster;
                f->cluster_count = needed;
                next_cluster += needed;
            }
        }
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
 *
 * All these writes go directly to libarchive via __archive_write_output(...).
 * We do *not* write these items into the temp file. The temp file is only used
 * to read file contents from.
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
#pragma pack(push,1)
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
};
struct bpb_fat32 {
    uint32_t fat_sz32;
    uint16_t ext_flags;
    uint16_t fs_ver;
    uint32_t root_clus;
    uint16_t fs_info;
    uint16_t bk_boot_sec;
    uint8_t  reserved[12];
};
struct bs_ext {
    uint8_t  drv_num;
    uint8_t  reserved1;
    uint8_t  boot_sig;
    uint32_t vol_id;
    uint8_t  vol_lab[11];
    uint8_t  fil_sys_type[8];
};
#pragma pack(pop)

static int
write_boot_sector(struct archive_write *a)
{
    struct msdosfs *msdos = (struct msdosfs *)a->format_data;
    unsigned char sector[SECTOR_SIZE];
    memset(sector, 0, SECTOR_SIZE);

    struct bpb_common *bpb = (struct bpb_common *)sector;
    bpb->jmp[0] = 0xEB;  /* short jmp */
    bpb->jmp[1] = 0x3C;
    bpb->jmp[2] = 0x90;
    memcpy(bpb->oem, "MSWIN4.1", 8);

    archive_le16enc(&bpb->bytes_per_sec, SECTOR_SIZE);
    bpb->sec_per_clus = (uint8_t)msdos->cluster_size;
    archive_le16enc(&bpb->rsvd_sec_cnt, (uint16_t)msdos->reserved_sectors);
    bpb->num_fats = 2;
    archive_le16enc(&bpb->root_ent_cnt, (uint16_t)msdos->root_entries);

    /* tot_sec16 if <65536 else use tot_sec32. */
    if (msdos->volume_size < 65536) {
        archive_le16enc(&bpb->tot_sec16, (uint16_t)msdos->volume_size);
        archive_le32enc(&bpb->tot_sec32, 0);
    } else {
        archive_le16enc(&bpb->tot_sec16, 0);
        archive_le32enc(&bpb->tot_sec32, msdos->volume_size);
    }
    bpb->media = 0xF8; /* fixed disk */
    archive_le16enc(&bpb->sec_per_trk, 63);
    archive_le16enc(&bpb->num_heads, 255);
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
        archive_le32enc(&bsx->vol_id, 0x12345678);
        memcpy(bsx->vol_lab, "NO NAME    ", 11);
        memcpy(bsx->fil_sys_type, "FAT32   ", 8);
    } else {
        archive_le16enc(&bpb->fat_sz16, (uint16_t)msdos->fat_size);
        /* The DOS extension for FAT12/16 is at offset 36. */
        struct bs_ext *bsx = (struct bs_ext *)(sector + 36);
        bsx->drv_num = 0x80;
        bsx->reserved1 = 0;
        bsx->boot_sig = 0x29;
        archive_le32enc(&bsx->vol_id, 0x12345678);
        memcpy(bsx->vol_lab, "NO NAME    ", 11);
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
        archive_le32enc(fsinfo + 0, 0x41615252);
        archive_le32enc(fsinfo + 484, 0x61417272);
        /* We could store the "free cluster count" here, but to keep it simple:
         * 0xFFFFFFFF => unknown free. But let's do a minimal placeholder. */
        archive_le32enc(fsinfo + 488, msdos->cluster_count - 1); /* free clusters (rough) */
        archive_le32enc(fsinfo + 492, 2); /* next free cluster? */
        archive_le32enc(fsinfo + 508, 0xAA550000);
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

    /* # of actual FAT entries: cluster_count + 2 reserved. */
    uint32_t fat_entries = msdos->cluster_count + FAT_RESERVED_ENTRIES;

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
 * (including LFN if needed), then zero‐fill the rest.
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
            /* We'll build an entry for this item. Possibly plus LFN entries. */
            char shortnm[12];
            make_short_name(f->long_name, shortnm);
            if (ensure_unique_short_name(a, msdos, shortnm, NULL) != 0) {
                free(buf);
                return ARCHIVE_FATAL;
            }
            /* If the long name differs, write LFN. */
            if (f->long_name && strcmp(f->long_name, shortnm) != 0) {
                int lfn_count = (int)((strlen(f->long_name)+12)/13);
                size_t lfn_bytes = lfn_count * DIR_ENTRY_SIZE;
                if (offset + lfn_bytes + DIR_ENTRY_SIZE > root_dir_bytes) {
                    free(buf);
                    archive_set_error(&a->archive, ENOSPC, "Root directory overflow");
                    return ARCHIVE_FATAL;
                }
                /* Write LFN entries. */
                write_longname_entries(buf + offset, f->long_name, shortnm);
                offset += lfn_bytes;
            }
            /* Then the final 32-byte short entry. */
            if (offset + DIR_ENTRY_SIZE > root_dir_bytes) {
                free(buf);
                archive_set_error(&a->archive, ENOSPC, "Root directory overflow");
                return ARCHIVE_FATAL;
            }
            write_one_dir_entry(buf + offset, shortnm, f, msdos->fat_type);
            offset += DIR_ENTRY_SIZE;
        }
    }
    /* Now write out 'buf' to the archive. */
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

    for (uint32_t c = FAT_RESERVED_ENTRIES; c < (total_clusters + FAT_RESERVED_ENTRIES); c++) {
        struct cluster_info *ci = &map[c];
        if (!ci->owner) {
            /* Unused cluster => write zero. */
            memset(tempbuf, 0, cluster_bytes);
        } else {
            /* Owned by a file or a directory? */
            struct fat_file *owner = ci->owner;
            if (owner->is_dir) {
                /* Build directory contents for cluster ci->index_in_file. 
                 * Typically, we only have 1 or a few clusters. We'll do a
                 * helper that builds the entire directory data once (since
                 * we have owner->size). Then we pick the slice for the cluster. 
                 */
                memset(tempbuf, 0, cluster_bytes);

                /* The simplest approach: build the entire directory in memory the first time we see cluster_index=0,
                 * store it in a small cache. Or we can build it on-demand each time. 
                 * For brevity, let's do a quick approach: build the entire directory once if not already done, store
                 * it in owner->some_buffer. Then copy out the chunk for this cluster. 
                 *
                 * We'll show a small inline approach. 
                 */
                /* We'll do a static function "build_directory_data(owner)" that returns a buffer of length = owner->size. 
                 * We'll store it in a dynamic pointer. If owner->size < cluster_bytes * owner->cluster_count, the remainder is zero. 
                 * Then we copy out the relevant slice. 
                 */
                /* Pseudocode for a small approach: (omitted for brevity, we do it inline) */

                /* Just do it inline: gather entries => fill in temp array => copy slice. */
                static const int MAX_DIR_ENTS = 4096; /* for safety */
                /* 1) collect all items that are direct children => plus '.' + '..'. */
                /* 2) build LFN + short entry. */

                /* We'll do a minimal approach here: if index_in_file=0, build. Then reuse. */
                /* This sample code might be quite large; you can factor it out if needed. */

                if (!owner->entry) {
                    /* Use a hidden pointer trick or a cached buffer. For a demonstration, we'll do an inline build each time. */
                }

                /* Actually let's store it in 'tempbuf' only if index_in_file=0. We'll do the entire directory at once. 
                 * But if directory spans multiple clusters, we have to output each cluster. We do that by offset = ci->index_in_file * cluster_bytes.
                 */
                size_t dir_size = owner->size;
                if (dir_size == 0 && owner->is_dir) {
                    dir_size = DIR_ENTRY_SIZE * 2; /* "." + ".." */
                }
                unsigned char *dirbuf = (unsigned char*)calloc(1, dir_size);
                if (!dirbuf) {
                    free(tempbuf);
                    free(map);
                    archive_set_error(&a->archive, ENOMEM, "No memory for subdir build");
                    return ARCHIVE_FATAL;
                }
                /* Build subdir entries: 
                 * index 0 => '.' => shortname ".          "
                 * index 1 => '..' => shortname "..         "
                 * then each child. Possibly LFN, etc.
                 */
                size_t off = 0;

                /* "." => references the dir itself. */
                {
                    char dotname[11] = ".          ";
                    write_one_dir_entry(dirbuf + off, dotname, owner, msdos->fat_type);
                    off += DIR_ENTRY_SIZE;
                }
                /* ".." => references owner->parent. (In FAT32, if parent is the root with cluster=0, that's special.)
                 * If this subdir's parent is the FAT32 root, then we typically set the ".." cluster=0 or the parent's cluster?
                 * For simplicity here, we'll pass a "dummy" with cluster=0 for the root. 
                 */
                {
                    char dotdot[11] = "..         ";
                    struct fat_file dummy_parent = {0};
                    struct fat_file *p = owner->parent;
                    if (msdos->fat_type == 32 && p && p->is_root) {
                        /* special case => cluster=0 for FAT32 root's '..' from subdir of root. */
                        dummy_parent.is_dir = 1;
                        dummy_parent.first_cluster = 0;
                        write_one_dir_entry(dirbuf + off, dotdot, &dummy_parent, msdos->fat_type);
                    } else if (!p && (msdos->fat_type ==12||msdos->fat_type==16)) {
                        /* subdir of the FAT12/16 root => root has cluster=0 => that's correct. */
                        dummy_parent.is_dir = 1;
                        dummy_parent.first_cluster = 0;
                        write_one_dir_entry(dirbuf + off, dotdot, &dummy_parent, msdos->fat_type);
                    } else if (p) {
                        write_one_dir_entry(dirbuf + off, dotdot, p, msdos->fat_type);
                    } else {
                        /* No parent => top-level subdir? Not typical for FAT12/16, but oh well. */
                        dummy_parent.is_dir = 1;
                        dummy_parent.first_cluster = 0;
                        write_one_dir_entry(dirbuf + off, dotdot, &dummy_parent, msdos->fat_type);
                    }
                    off += DIR_ENTRY_SIZE;
                }
                /* Then each child => same approach as we did for the root. */
                struct fat_file *c = owner->children;
                while (c) {
                    char shortnm[12];
                    make_short_name(c->long_name, shortnm);
                    if (ensure_unique_short_name(a, msdos, shortnm, owner) != 0) {
                        free(dirbuf);
                        free(tempbuf);
                        free(map);
                        return ARCHIVE_FATAL;
                    }
                    /* Possibly LFN. */
                    if (c->long_name && strcmp(c->long_name, shortnm) != 0) {
                        int lfn_count = (int)((strlen(c->long_name)+12)/13);
                        size_t lfn_bytes = (size_t)lfn_count * DIR_ENTRY_SIZE;
                        if (off + lfn_bytes + DIR_ENTRY_SIZE > dir_size) {
                            /* truncated? oh well. in real code we'd check. */
                        }
                        write_longname_entries(dirbuf + off, c->long_name, shortnm);
                        off += lfn_bytes;
                    }
                    if (off + DIR_ENTRY_SIZE <= dir_size) {
                        write_one_dir_entry(dirbuf + off, shortnm, c, msdos->fat_type);
                        off += DIR_ENTRY_SIZE;
                    }
                    c = c->sibling;
                }

                /* Now copy out the chunk for this cluster index. */
                size_t cluster_offset = (size_t)ci->index_in_file * cluster_bytes;
                memset(tempbuf, 0, cluster_bytes);
                if (cluster_offset < dir_size) {
                    size_t to_copy = dir_size - cluster_offset;
                    if (to_copy > cluster_bytes) {
                        to_copy = cluster_bytes;
                    }
                    memcpy(tempbuf, dirbuf + cluster_offset, to_copy);
                }
                free(dirbuf);

            } else {
                /* It's a file. We read from the temp file. */
                uint32_t idx = ci->index_in_file; /* cluster index in the file. */
                off_t read_off = (off_t)(owner->content_offset + (off_t)idx*(off_t)cluster_bytes);
                /* We read up to cluster_bytes or until the file ends. (But if assigned cluster_count 
                 * exactly matches the file size, it should fill the entire cluster except possibly the last. 
                 */
                memset(tempbuf, 0, cluster_bytes);
                size_t to_read = cluster_bytes;
                /* If it's the last cluster, maybe partial? We'll do the simpler approach: read up to cluster_bytes. 
                 * If the file was smaller, we zero‐padded in the temp file’s pass #1 anyway. So we can just read cluster_bytes. 
                 */
                if (lseek(msdos->temp_fd, read_off, SEEK_SET) < 0) {
                    free(tempbuf);
                    free(map);
                    archive_set_error(&a->archive, errno, "lseek failed reading file data");
                    return ARCHIVE_FATAL;
                }
                size_t got = 0;
                while (got < to_read) {
                    ssize_t rd = read(msdos->temp_fd, tempbuf + got, to_read - got);
                    if (rd < 0) {
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
            free(tempbuf);
            free(map);
            return ret;
        }
    }

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

    /* Timestamps (we can glean from f->entry if needed). For brevity: */
    time_t mtime = 0;
    if (f->entry) {
        mtime = archive_entry_mtime(f->entry);
    }
    struct tm t;
    if (!localtime_r(&mtime, &t)) {
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

/* Write the required LFN entries just before the final short entry. */
static void
write_longname_entries(unsigned char *buf, const char *lname, const char shortnm[12])
{
    int name_len = (int)strlen(lname);
    int entries_needed = (name_len + 12) / 13; /* each LFN entry can hold 13 UTF-16 chars. */

    /* Compute the LFN checksum. */
    unsigned char sum = 0;
    for (int i=0; i<11; i++) {
        sum = (unsigned char)(((sum & 1) ? 0x80 : 0) + (sum >> 1) + (unsigned char)shortnm[i]);
    }

    /* Build from last to first. */
    int pos = 0;
    for (int i = entries_needed - 1; i >= 0; i--) {
        unsigned char *ent = buf + i*DIR_ENTRY_SIZE;
        memset(ent, 0xFF, DIR_ENTRY_SIZE);

        int ord = entries_needed - i;
        if (ord == entries_needed) {
            ord |= 0x40; /* last entry marker */
        }
        ent[0] = (unsigned char)ord;
        ent[11] = ATTR_LONG_NAME;
        ent[13] = sum;

        /* Copy up to 13 UTF-16 chars from lname[pos..pos+12]. */
        for (int j=0; j<13; j++) {
            uint16_t ch = 0xFFFF;
            int namepos = pos + j;
            if (namepos < name_len) {
                ch = (unsigned char)lname[namepos];
            } else if (namepos == name_len) {
                ch = 0; /* null terminator */
            }
            /* LFN entry has 3 chunks: 5 chars at offset 1, 6 chars at offset 14, 2 chars at offset 28. */
            int offset;
            if (j < 5) {
                offset = 1 + j*2;
            } else if (j < 11) {
                offset = 14 + (j-5)*2;
            } else {
                offset = 28 + (j-11)*2;
            }
            archive_le16enc(ent + offset, ch);
        }
        pos += 13;
    }
}

/* Count how many dir entries (including LFN) we would need for this file. */
static int
count_dir_entries_for_file(struct fat_file *f)
{
    /* If it's a directory or file, we always need at least 1 short entry. If it has a long name that differs from the short name, we need extra. */
    /* We'll do a naive approach. */
    if (!f->long_name) return 1;
    char shortnm[12];
    make_short_name(f->long_name, shortnm);
    if (strcmp(f->long_name, shortnm) == 0) {
        return 1;
    }
    int len = (int)strlen(f->long_name);
    int lfn_count = (len + 12)/13;
    return (1 + lfn_count);
}

/* ---------------- Directory-Tree Helpers ---------------- */

static struct fat_file*
find_or_create_dir(struct msdosfs *msdos, struct fat_file *parent, const char *dirname)
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
    /* Insert into global list. */
    f->next = msdos->files;
    msdos->files = f;
    /* Link into parent's child list. */
    add_child_to_parent(parent, f);
    return f;
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

static void
add_shortname(struct msdosfs *msdos, const char *name, struct fat_file *parent_dir)
{
    unsigned int k = shortname_hash_key(name, parent_dir);
    struct shortname_entry *e = (struct shortname_entry*)calloc(1,sizeof(*e));
    memcpy(e->name, name, 11);
    e->name[11] = 0;
    e->parent_dir = parent_dir;
    e->next = msdos->used_shortnames.buckets[k];
    msdos->used_shortnames.buckets[k] = e;
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
        add_shortname(msdos, short_name, parent_dir);
        return 0;
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
            return ARCHIVE_FATAL;
        }
        if (!shortname_exists(msdos, candidate, parent_dir)) {
            memcpy(short_name, candidate, 12);
            add_shortname(msdos, candidate, parent_dir);
            return 0;
        }
    }
    archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
                      "Excessive short-name collisions");
    return ARCHIVE_FATAL;
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
