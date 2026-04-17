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
#include "test.h"

/* ================================================================
 * Byte-level helpers for verifying FAT image structure.
 * ================================================================ */

/* Read a little-endian 16-bit value. */
static uint16_t
le16(const unsigned char *p)
{
	return (uint16_t)(p[0] | (p[1] << 8));
}

/* Read a little-endian 32-bit value. */
static uint32_t
le32(const unsigned char *p)
{
	return (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}

/* Check boot sector signature at offset 510. */
static int
verify_boot_signature(const unsigned char *img, size_t img_size)
{
	if (img_size < 512)
		return 0;
	return (img[510] == 0x55 && img[511] == 0xAA);
}

/* Search the root directory region (FAT12/16) for a short-name entry.
 * Returns pointer to the 32-byte entry or NULL. */
static const unsigned char *
find_root_dir_entry(const unsigned char *img, size_t img_size,
    const char *short_name_11)
{
	uint16_t reserved = le16(img + 14);
	uint8_t num_fats = img[16];
	uint16_t root_entries = le16(img + 17);
	uint16_t fat_size16 = le16(img + 22);

	uint32_t root_offset = (reserved + num_fats * fat_size16) * 512;
	uint32_t root_bytes = root_entries * 32;

	if (root_offset + root_bytes > img_size)
		return NULL;

	for (uint32_t i = 0; i < root_entries; i++) {
		const unsigned char *ent = img + root_offset + i * 32;
		if (ent[0] == 0x00)
			break;		/* end of directory */
		if (ent[0] == 0xE5)
			continue;	/* deleted */
		if (ent[11] == 0x0F)
			continue;	/* LFN entry */
		if (memcmp(ent, short_name_11, 11) == 0)
			return ent;
	}
	return NULL;
}

/* ================================================================
 * Helper: check if mtools is available.
 * ================================================================ */
static int
canMtools(void)
{
	static int tested = 0, value = 0;
	if (!tested) {
		tested = 1;
		if (systemf("mdir --version "
		    ">/dev/null 2>/dev/null") == 0)
			value = 1;
	}
	return (value);
}

/* ================================================================
 * Helper: create a FAT image in memory, write it to a file,
 * and return the image buffer.
 * ================================================================ */

/* Create FAT image helper.  Caller must free() the returned buffer.
 * Returns NULL on failure.  *out_used receives the image size. */
static char *
create_fat_image(size_t buffsize, const char *fat_type,
    void (*populate)(struct archive *a), size_t *out_used)
{
	struct archive *a;
	char *buff;

	buff = malloc(buffsize);
	if (buff == NULL)
		return (NULL);

	assert((a = archive_write_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_msdosfs(a));
	if (fat_type != NULL)
		assertEqualIntA(a, ARCHIVE_OK,
		    archive_write_set_format_option(a, "msdosfs",
		    "fat_type", fat_type));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_add_filter_none(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_open_memory(a, buff, buffsize, out_used));

	if (populate != NULL)
		populate(a);

	assertEqualIntA(a, ARCHIVE_OK, archive_write_close(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_write_free(a));
	return (buff);
}

/* Write image buffer to a file. Returns 0 on success. */
static int
write_image_file(const char *path, const char *buff, size_t used)
{
	FILE *f;

	f = fopen(path, "wb");
	if (f == NULL)
		return (-1);
	if (fwrite(buff, 1, used, f) != used) {
		fclose(f);
		return (-1);
	}
	fclose(f);
	return (0);
}

/* ================================================================
 * Helper: write an archive entry for a file with data.
 * ================================================================ */
static void
write_file_entry(struct archive *a, const char *pathname,
    const char *data, size_t datalen, time_t mtime)
{
	struct archive_entry *ae;

	assert((ae = archive_entry_new()) != NULL);
	archive_entry_set_mtime(ae, mtime, 0);
	archive_entry_copy_pathname(ae, pathname);
	archive_entry_set_mode(ae, AE_IFREG | 0644);
	archive_entry_set_size(ae, (int64_t)datalen);
	assertEqualIntA(a, ARCHIVE_OK, archive_write_header(a, ae));
	archive_entry_free(ae);
	if (datalen > 0)
		assertEqualIntA(a, (int)datalen,
		    (int)archive_write_data(a, data, datalen));
}

/* Helper: write an archive entry for a directory. */
static void
write_dir_entry(struct archive *a, const char *pathname, time_t mtime)
{
	struct archive_entry *ae;

	assert((ae = archive_entry_new()) != NULL);
	archive_entry_set_mtime(ae, mtime, 0);
	archive_entry_copy_pathname(ae, pathname);
	archive_entry_set_mode(ae, S_IFDIR | 0755);
	assertEqualIntA(a, ARCHIVE_OK, archive_write_header(a, ae));
	archive_entry_free(ae);
}


/* ================================================================
 * Byte-level tests (existing).
 * ================================================================ */

static void populate_basic(struct archive *a)
{
	write_file_entry(a, "hello.txt", "Hello, FAT!", 11, 1);
}

/*
 * Test: basic FAT16 image with a single file.
 */
DEFINE_TEST(test_write_format_msdosfs_basic)
{
	size_t used;
	char *buff;

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_basic, &used);
	assert(buff != NULL);

	/* Verify the image. */
	assert(used > 512);
	assert(verify_boot_signature((const unsigned char *)buff, used));

	/* Check BPB: bytes per sector == 512. */
	assertEqualInt(512, le16((const unsigned char *)buff + 11));

	/* Check media descriptor == 0xF8. */
	assertEqualInt(0xF8, (unsigned char)buff[21]);

	/* Find the file in the root directory. */
	{
		const unsigned char *ent;
		ent = find_root_dir_entry((const unsigned char *)buff, used,
		    "HELLO   TXT");
		assert(ent != NULL);
		if (ent != NULL) {
			/* Check file size in directory entry. */
			assertEqualInt(11, (int)le32(ent + 28));
			/* Check ATTR_ARCHIVE is set. */
			assertEqualInt(0x20, ent[11]);
		}
	}

	free(buff);
}

static void populate_directory(struct archive *a)
{
	write_dir_entry(a, "subdir", 1);
	write_file_entry(a, "subdir/inner.txt", "abcde", 5, 2);
}

/*
 * Test: directory creation and nested files.
 */
DEFINE_TEST(test_write_format_msdosfs_directory)
{
	size_t used;
	char *buff;

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_directory, &used);
	assert(buff != NULL);

	assert(used > 512);
	assert(verify_boot_signature((const unsigned char *)buff, used));

	/* Find the directory in root. */
	{
		const unsigned char *ent;
		ent = find_root_dir_entry((const unsigned char *)buff, used,
		    "SUBDIR     ");
		assert(ent != NULL);
		if (ent != NULL) {
			/* Should have ATTR_DIRECTORY. */
			assertEqualInt(0x10, ent[11]);
			/* Directory size should be 0 in dir entry. */
			assertEqualInt(0, (int)le32(ent + 28));
			/* Should have a non-zero cluster. */
			assert(le16(ent + 26) != 0);
		}
	}

	free(buff);
}

static void populate_multiple(struct archive *a)
{
	int i;

	for (i = 0; i < 10; i++) {
		char name[32];
		char data[64];
		int datalen;

		snprintf(name, sizeof(name), "file%d.txt", i);
		datalen = snprintf(data, sizeof(data),
		    "Content of file %d", i);
		write_file_entry(a, name, data, (size_t)datalen, 1000000 + i);
	}
}

/*
 * Test: multiple files.
 */
DEFINE_TEST(test_write_format_msdosfs_multiple_files)
{
	size_t used;
	char *buff;

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_multiple, &used);
	assert(buff != NULL);

	assert(used > 512);
	assert(verify_boot_signature((const unsigned char *)buff, used));

	/* Verify all 10 files exist in the root directory. */
	{
		const unsigned char *img = (const unsigned char *)buff;
		int i;
		for (i = 0; i < 10; i++) {
			char sname[12];
			snprintf(sname, sizeof(sname), "FILE%d   TXT", i);
			assert(find_root_dir_entry(img, used, sname) != NULL);
		}
	}

	free(buff);
}

static void populate_fat32(struct archive *a)
{
	write_file_entry(a, "test.dat", "data", 4, 1);
}

/*
 * Test: FAT32 with explicit option.
 */
DEFINE_TEST(test_write_format_msdosfs_fat32)
{
	size_t buffsize = 64 * 1024 * 1024;  /* 64 MB for FAT32 */
	size_t used;
	char *buff;

	buff = create_fat_image(buffsize, "32", populate_fat32, &used);
	if (buff == NULL) {
		skipping("Unable to allocate 64MB for FAT32 test");
		return;
	}

	assert(used > 512);
	assert(verify_boot_signature((const unsigned char *)buff, used));

	{
		const unsigned char *img = (const unsigned char *)buff;

		/* FAT32: root_entries (offset 17) should be 0. */
		assertEqualInt(0, le16(img + 17));

		/* FAT32: fat_size16 (offset 22) should be 0. */
		assertEqualInt(0, le16(img + 22));

		/* FAT32: fat_size32 at BPB offset 36 should be non-zero. */
		assert(le32(img + 36) > 0);

		/* FSInfo at sector 1: signature 0x41615252. */
		assertEqualInt(0x41615252, (int)le32(img + 512 + 0));
		assertEqualInt(0x61417272, (int)le32(img + 512 + 484));

		/* Backup boot sector at sector 6: should match sector 0. */
		failure("Backup boot sector should match primary");
		assertEqualMem(img, img + 6 * 512, 512);
	}

	free(buff);
}

/*
 * Test: empty archive produces a valid FAT image.
 */
DEFINE_TEST(test_write_format_msdosfs_empty)
{
	size_t used;
	char *buff;

	buff = create_fat_image(4 * 1024 * 1024, "16", NULL, &used);
	assert(buff != NULL);

	/* Should still produce a valid FAT image. */
	assert(used > 512);
	assert(verify_boot_signature((const unsigned char *)buff, used));
	assertEqualInt(512, le16((const unsigned char *)buff + 11));

	free(buff);
}

static void populate_longname(struct archive *a)
{
	write_file_entry(a, "this_is_a_very_long_filename.txt", "abc", 3, 1);
}

/*
 * Test: long filename triggers LFN entries.
 */
DEFINE_TEST(test_write_format_msdosfs_longname)
{
	size_t used;
	char *buff;

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_longname, &used);
	assert(buff != NULL);

	assert(used > 512);
	assert(verify_boot_signature((const unsigned char *)buff, used));

	/* The root directory should contain LFN entries (attr=0x0F)
	 * before the short entry. */
	{
		const unsigned char *img = (const unsigned char *)buff;
		uint16_t reserved = le16(img + 14);
		uint8_t num_fats = img[16];
		uint16_t fat_size16 = le16(img + 22);
		uint16_t root_entries = le16(img + 17);

		uint32_t root_offset =
		    (reserved + num_fats * fat_size16) * 512;
		int found_lfn = 0;

		for (uint32_t i = 0; i < root_entries; i++) {
			const unsigned char *ent =
			    img + root_offset + i * 32;
			if (ent[0] == 0x00)
				break;
			if (ent[11] == 0x0F) {
				found_lfn = 1;
				break;
			}
		}
		assertEqualInt(1, found_lfn);
	}

	free(buff);
}


/* ================================================================
 * mtools-based tests.
 *
 * These write a FAT image to a temp file and use mdir/mtype to
 * verify that external tools can read the filesystem correctly.
 * Skipped if mtools is not installed.
 * ================================================================ */

/*
 * Test: mtools can list and read a single file on FAT16.
 */
static void populate_mtools_basic(struct archive *a)
{
	write_file_entry(a, "readme.txt", "Hello mtools!", 13,
	    1136073600);  /* 2006-01-01 */
}

DEFINE_TEST(test_write_format_msdosfs_mtools_basic)
{
	size_t used;
	char *buff;

	if (!canMtools()) {
		skipping("mtools not available");
		return;
	}

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_mtools_basic, &used);
	assert(buff != NULL);
	assertEqualInt(0, write_image_file("fat16.img", buff, used));
	free(buff);

	/* mdir should list the file. */
	assertEqualInt(0,
	    systemf("mdir -i fat16.img :: > mdir.out 2>&1"));
	assertEqualInt(0,
	    systemf("grep README mdir.out > /dev/null"));

	/* mtype should extract the contents. */
	assertEqualInt(0,
	    systemf("mtype -i fat16.img ::readme.txt > mtype.out 2>&1"));
	assertTextFileContents("Hello mtools!", "mtype.out");
}

/*
 * Test: mtools can navigate a directory tree on FAT16.
 */
static void populate_mtools_dirs(struct archive *a)
{
	write_dir_entry(a, "docs", 1136073600);
	write_file_entry(a, "docs/notes.txt", "some notes here\n", 16,
	    1136073600);
	write_dir_entry(a, "docs/sub", 1136073600);
	write_file_entry(a, "docs/sub/deep.txt", "deep file", 9,
	    1136073600);
	write_file_entry(a, "top.txt", "top level", 9, 1136073600);
}

DEFINE_TEST(test_write_format_msdosfs_mtools_dirs)
{
	size_t used;
	char *buff;

	if (!canMtools()) {
		skipping("mtools not available");
		return;
	}

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_mtools_dirs, &used);
	assert(buff != NULL);
	assertEqualInt(0, write_image_file("fat_dirs.img", buff, used));
	free(buff);

	/* Root should have DOCS directory and top.txt. */
	assertEqualInt(0,
	    systemf("mdir -i fat_dirs.img :: > root.out 2>&1"));
	assertEqualInt(0,
	    systemf("grep DOCS root.out > /dev/null"));
	assertEqualInt(0,
	    systemf("grep TOP root.out > /dev/null"));

	/* DOCS subdirectory should have notes.txt and sub/. */
	assertEqualInt(0,
	    systemf("mdir -i fat_dirs.img ::docs > docs.out 2>&1"));
	assertEqualInt(0,
	    systemf("grep NOTES docs.out > /dev/null"));
	assertEqualInt(0,
	    systemf("grep SUB docs.out > /dev/null"));

	/* Read file contents. */
	assertEqualInt(0,
	    systemf("mtype -i fat_dirs.img ::docs/notes.txt "
	    "> notes.out 2>&1"));
	assertTextFileContents("some notes here\n", "notes.out");

	/* Deep nested file. */
	assertEqualInt(0,
	    systemf("mtype -i fat_dirs.img ::docs/sub/deep.txt "
	    "> deep.out 2>&1"));
	assertTextFileContents("deep file", "deep.out");

	/* Top-level file. */
	assertEqualInt(0,
	    systemf("mtype -i fat_dirs.img ::top.txt "
	    "> top.out 2>&1"));
	assertTextFileContents("top level", "top.out");
}

/*
 * Test: mtools can read a FAT32 image.
 */
static void populate_mtools_fat32(struct archive *a)
{
	write_dir_entry(a, "mydir", 1136073600);
	write_file_entry(a, "mydir/data.bin", "FAT32 data here!", 16,
	    1136073600);
	write_file_entry(a, "root.txt", "root file", 9, 1136073600);
}

DEFINE_TEST(test_write_format_msdosfs_mtools_fat32)
{
	size_t buffsize = 64 * 1024 * 1024;
	size_t used;
	char *buff;

	if (!canMtools()) {
		skipping("mtools not available");
		return;
	}

	buff = create_fat_image(buffsize, "32",
	    populate_mtools_fat32, &used);
	if (buff == NULL) {
		skipping("Unable to allocate 64MB for FAT32 mtools test");
		return;
	}
	assertEqualInt(0, write_image_file("fat32.img", buff, used));
	free(buff);

	/* minfo should report FAT32 characteristics. */
	assertEqualInt(0,
	    systemf("minfo -i fat32.img :: > minfo.out 2>&1"));

	/* Root should list mydir and root.txt. */
	assertEqualInt(0,
	    systemf("mdir -i fat32.img :: > root32.out 2>&1"));
	assertEqualInt(0,
	    systemf("grep MYDIR root32.out > /dev/null"));
	assertEqualInt(0,
	    systemf("grep ROOT root32.out > /dev/null"));

	/* Read nested file. */
	assertEqualInt(0,
	    systemf("mtype -i fat32.img ::mydir/data.bin "
	    "> data32.out 2>&1"));
	assertTextFileContents("FAT32 data here!", "data32.out");
}

/*
 * Test: mtools can read LFN (long filenames) on FAT16.
 */
static void populate_mtools_lfn(struct archive *a)
{
	write_file_entry(a, "a_very_long_filename_for_fat.txt",
	    "LFN content", 11, 1136073600);
	write_file_entry(a, "short.txt",
	    "8.3 content", 11, 1136073600);
	write_file_entry(a,
	    "another_extremely_long_name_that_exceeds_eight_chars.dat",
	    "more LFN", 8, 1136073600);
}

DEFINE_TEST(test_write_format_msdosfs_mtools_lfn)
{
	size_t used;
	char *buff;

	if (!canMtools()) {
		skipping("mtools not available");
		return;
	}

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_mtools_lfn, &used);
	assert(buff != NULL);
	assertEqualInt(0, write_image_file("fat_lfn.img", buff, used));
	free(buff);

	/* mdir should show the long filenames. */
	assertEqualInt(0,
	    systemf("mdir -i fat_lfn.img :: > lfn.out 2>&1"));

	/* Read by long name. */
	assertEqualInt(0,
	    systemf("mtype -i fat_lfn.img "
	    "::a_very_long_filename_for_fat.txt > lfn1.out 2>&1"));
	assertTextFileContents("LFN content", "lfn1.out");

	assertEqualInt(0,
	    systemf("mtype -i fat_lfn.img ::short.txt "
	    "> lfn2.out 2>&1"));
	assertTextFileContents("8.3 content", "lfn2.out");

	assertEqualInt(0,
	    systemf("mtype -i fat_lfn.img "
	    "::another_extremely_long_name_that_exceeds_eight_chars.dat "
	    "> lfn3.out 2>&1"));
	assertTextFileContents("more LFN", "lfn3.out");
}

/*
 * Test: implicit directory creation via path components.
 * When a file path like "a/b/c.txt" is written without explicit
 * directory entries, the intermediate directories must be created
 * automatically with valid short names.
 */
static void populate_mtools_implicit_dirs(struct archive *a)
{
	write_file_entry(a, "alpha/beta/gamma.txt",
	    "deep content", 12, 1136073600);
	write_file_entry(a, "alpha/top.txt",
	    "in alpha", 8, 1136073600);
}

DEFINE_TEST(test_write_format_msdosfs_mtools_implicit_dirs)
{
	size_t used;
	char *buff;

	if (!canMtools()) {
		skipping("mtools not available");
		return;
	}

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_mtools_implicit_dirs, &used);
	assert(buff != NULL);
	assertEqualInt(0,
	    write_image_file("fat_implicit.img", buff, used));
	free(buff);

	/* Root should have alpha directory. */
	assertEqualInt(0,
	    systemf("mdir -i fat_implicit.img :: > imp_root.out 2>&1"));
	assertEqualInt(0,
	    systemf("grep ALPHA imp_root.out > /dev/null"));

	/* alpha should have beta dir and top.txt. */
	assertEqualInt(0,
	    systemf("mdir -i fat_implicit.img ::alpha "
	    "> imp_alpha.out 2>&1"));
	assertEqualInt(0,
	    systemf("grep BETA imp_alpha.out > /dev/null"));
	assertEqualInt(0,
	    systemf("grep TOP imp_alpha.out > /dev/null"));

	/* Read the deeply nested file. */
	assertEqualInt(0,
	    systemf("mtype -i fat_implicit.img "
	    "::alpha/beta/gamma.txt > imp_deep.out 2>&1"));
	assertTextFileContents("deep content", "imp_deep.out");
}

/*
 * Test: multiple files with identical 8.3 prefixes get unique
 * short names via ~N collision avoidance.
 */
static void populate_mtools_collisions(struct archive *a)
{
	write_file_entry(a, "longfilename1.txt",
	    "file 1", 6, 1136073600);
	write_file_entry(a, "longfilename2.txt",
	    "file 2", 6, 1136073600);
	write_file_entry(a, "longfilename3.txt",
	    "file 3", 6, 1136073600);
	write_file_entry(a, "longfilename4.txt",
	    "file 4", 6, 1136073600);
}

DEFINE_TEST(test_write_format_msdosfs_mtools_collisions)
{
	size_t used;
	char *buff;

	if (!canMtools()) {
		skipping("mtools not available");
		return;
	}

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_mtools_collisions, &used);
	assert(buff != NULL);
	assertEqualInt(0,
	    write_image_file("fat_coll.img", buff, used));
	free(buff);

	/* All four files should be readable by their long names. */
	assertEqualInt(0,
	    systemf("mtype -i fat_coll.img ::longfilename1.txt "
	    "> coll1.out 2>&1"));
	assertTextFileContents("file 1", "coll1.out");

	assertEqualInt(0,
	    systemf("mtype -i fat_coll.img ::longfilename2.txt "
	    "> coll2.out 2>&1"));
	assertTextFileContents("file 2", "coll2.out");

	assertEqualInt(0,
	    systemf("mtype -i fat_coll.img ::longfilename3.txt "
	    "> coll3.out 2>&1"));
	assertTextFileContents("file 3", "coll3.out");

	assertEqualInt(0,
	    systemf("mtype -i fat_coll.img ::longfilename4.txt "
	    "> coll4.out 2>&1"));
	assertTextFileContents("file 4", "coll4.out");
}

/*
 * Test: large file spanning multiple clusters.
 */
static void populate_mtools_large(struct archive *a)
{
	/* 16KB of known-pattern data. */
	char data[16384];
	int i;

	for (i = 0; i < (int)sizeof(data); i++)
		data[i] = (char)('A' + (i % 26));
	write_file_entry(a, "bigfile.bin", data, sizeof(data),
	    1136073600);
}

DEFINE_TEST(test_write_format_msdosfs_mtools_large_file)
{
	size_t used;
	char *buff;

	if (!canMtools()) {
		skipping("mtools not available");
		return;
	}

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_mtools_large, &used);
	assert(buff != NULL);
	assertEqualInt(0, write_image_file("fat_large.img", buff, used));
	free(buff);

	/* mcopy to extract the file. */
	assertEqualInt(0,
	    systemf("mcopy -i fat_large.img ::bigfile.bin "
	    "bigfile.extracted 2>&1"));

	/* Verify the extracted file size. */
	assertFileSize("bigfile.extracted", 16384);

	/* Verify the content pattern. */
	{
		FILE *f;
		char readbuf[16384];
		size_t nread;
		int j, ok = 1;

		f = fopen("bigfile.extracted", "rb");
		assert(f != NULL);
		if (f != NULL) {
			nread = fread(readbuf, 1, sizeof(readbuf), f);
			fclose(f);
			assertEqualInt(16384, (int)nread);
			for (j = 0; j < (int)nread && ok; j++) {
				if (readbuf[j] != (char)('A' + (j % 26)))
					ok = 0;
			}
			assertEqualInt(1, ok);
		}
	}
}

/*
 * Test: empty FAT16 image is recognized by mtools.
 */
DEFINE_TEST(test_write_format_msdosfs_mtools_empty)
{
	size_t used;
	char *buff;

	if (!canMtools()) {
		skipping("mtools not available");
		return;
	}

	buff = create_fat_image(4 * 1024 * 1024, "16", NULL, &used);
	assert(buff != NULL);
	assertEqualInt(0, write_image_file("fat_empty.img", buff, used));
	free(buff);

	/* mdir should succeed (empty root). */
	assertEqualInt(0,
	    systemf("mdir -i fat_empty.img :: > empty.out 2>&1"));

	/* minfo should succeed. */
	assertEqualInt(0,
	    systemf("minfo -i fat_empty.img :: > einfo.out 2>&1"));
}

/*
 * Test: FAT12 auto-detection for small data sets.
 */
static void populate_mtools_fat12(struct archive *a)
{
	write_file_entry(a, "tiny.txt", "t", 1, 1136073600);
}

DEFINE_TEST(test_write_format_msdosfs_mtools_fat12)
{
	size_t used;
	char *buff;

	if (!canMtools()) {
		skipping("mtools not available");
		return;
	}

	/* Don't specify fat_type -- let it auto-detect (should pick FAT12
	 * for this small amount of data). */
	buff = create_fat_image(4 * 1024 * 1024, NULL,
	    populate_mtools_fat12, &used);
	assert(buff != NULL);
	assertEqualInt(0, write_image_file("fat12.img", buff, used));

	/* Verify auto-detected as FAT12 by checking BPB. */
	{
		const unsigned char *img = (const unsigned char *)buff;
		uint16_t total_sectors = le16(img + 19);
		uint16_t reserved = le16(img + 14);
		uint8_t num_fats = img[16];
		uint16_t fat_size16 = le16(img + 22);
		uint16_t root_entries = le16(img + 17);
		uint8_t spc = img[13];
		uint32_t root_sectors;
		uint32_t data_sectors;
		uint32_t data_clusters;

		/* Valid image. */
		assert(verify_boot_signature(img, used));
		assert(total_sectors > 0);

		root_sectors =
		    ((root_entries * 32) + 511) / 512;
		data_sectors = total_sectors - reserved
		    - (num_fats * fat_size16) - root_sectors;
		data_clusters = data_sectors / spc;

		/* FAT12 threshold: < 4085 clusters. */
		failure("Expected FAT12 (< 4085 clusters), got %u",
		    data_clusters);
		assert(data_clusters < 4085);
	}
	free(buff);

	/* mtools should be able to read it. */
	assertEqualInt(0,
	    systemf("mdir -i fat12.img :: > fat12.out 2>&1"));
	assertEqualInt(0,
	    systemf("mtype -i fat12.img ::tiny.txt "
	    "> fat12_tiny.out 2>&1"));
	assertTextFileContents("t", "fat12_tiny.out");
}

/*
 * Test: many files in root directory.
 */
static void populate_mtools_many(struct archive *a)
{
	int i;

	for (i = 0; i < 50; i++) {
		char name[32];
		char data[128];
		int datalen;

		snprintf(name, sizeof(name), "item%04d.txt", i);
		datalen = snprintf(data, sizeof(data),
		    "Data for item number %d\n", i);
		write_file_entry(a, name, data, (size_t)datalen, 1136073600);
	}
}

DEFINE_TEST(test_write_format_msdosfs_mtools_many_files)
{
	size_t used;
	char *buff;

	if (!canMtools()) {
		skipping("mtools not available");
		return;
	}

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_mtools_many, &used);
	assert(buff != NULL);
	assertEqualInt(0, write_image_file("fat_many.img", buff, used));
	free(buff);

	/* Spot-check a few files. */
	assertEqualInt(0,
	    systemf("mtype -i fat_many.img ::item0000.txt "
	    "> many0.out 2>&1"));
	assertTextFileContents("Data for item number 0\n", "many0.out");

	assertEqualInt(0,
	    systemf("mtype -i fat_many.img ::item0025.txt "
	    "> many25.out 2>&1"));
	assertTextFileContents("Data for item number 25\n", "many25.out");

	assertEqualInt(0,
	    systemf("mtype -i fat_many.img ::item0049.txt "
	    "> many49.out 2>&1"));
	assertTextFileContents("Data for item number 49\n", "many49.out");
}

/*
 * Test: deep directory nesting (3+ levels).
 */
static void populate_mtools_deep(struct archive *a)
{
	write_dir_entry(a, "a", 1136073600);
	write_dir_entry(a, "a/b", 1136073600);
	write_dir_entry(a, "a/b/c", 1136073600);
	write_dir_entry(a, "a/b/c/d", 1136073600);
	write_file_entry(a, "a/b/c/d/leaf.txt", "leaf data", 9,
	    1136073600);
	write_file_entry(a, "a/mid.txt", "mid data", 8, 1136073600);
}

DEFINE_TEST(test_write_format_msdosfs_mtools_deep_nesting)
{
	size_t used;
	char *buff;

	if (!canMtools()) {
		skipping("mtools not available");
		return;
	}

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_mtools_deep, &used);
	assert(buff != NULL);
	assertEqualInt(0, write_image_file("fat_deep.img", buff, used));
	free(buff);

	/* Traverse and read the deepest file. */
	assertEqualInt(0,
	    systemf("mtype -i fat_deep.img ::a/b/c/d/leaf.txt "
	    "> deep_leaf.out 2>&1"));
	assertTextFileContents("leaf data", "deep_leaf.out");

	/* Mid-level file. */
	assertEqualInt(0,
	    systemf("mtype -i fat_deep.img ::a/mid.txt "
	    "> deep_mid.out 2>&1"));
	assertTextFileContents("mid data", "deep_mid.out");

	/* Verify . and .. are present in each subdirectory. */
	assertEqualInt(0,
	    systemf("mdir -i fat_deep.img ::a > deep_a.out 2>&1"));
	assertEqualInt(0,
	    systemf("grep '\\.' deep_a.out > /dev/null"));
	assertEqualInt(0,
	    systemf("grep '\\.\\.' deep_a.out > /dev/null"));
}

/*
 * Test: FAT32 with directories verified via mtools.
 */
static void populate_mtools_fat32_dirs(struct archive *a)
{
	write_dir_entry(a, "folder", 1136073600);
	write_file_entry(a, "folder/report.txt",
	    "quarterly report data\n", 22, 1136073600);
	write_file_entry(a, "readme.txt",
	    "Read me first", 13, 1136073600);
}

DEFINE_TEST(test_write_format_msdosfs_mtools_fat32_dirs)
{
	size_t buffsize = 64 * 1024 * 1024;
	size_t used;
	char *buff;

	if (!canMtools()) {
		skipping("mtools not available");
		return;
	}

	buff = create_fat_image(buffsize, "32",
	    populate_mtools_fat32_dirs, &used);
	if (buff == NULL) {
		skipping("Unable to allocate 64MB for FAT32 mtools dir test");
		return;
	}
	assertEqualInt(0, write_image_file("fat32dir.img", buff, used));
	free(buff);

	/* Root listing. */
	assertEqualInt(0,
	    systemf("mdir -i fat32dir.img :: > f32root.out 2>&1"));
	assertEqualInt(0,
	    systemf("grep FOLDER f32root.out > /dev/null"));
	assertEqualInt(0,
	    systemf("grep README f32root.out > /dev/null"));

	/* Nested file. */
	assertEqualInt(0,
	    systemf("mtype -i fat32dir.img ::folder/report.txt "
	    "> f32report.out 2>&1"));
	assertTextFileContents("quarterly report data\n", "f32report.out");

	/* Root file. */
	assertEqualInt(0,
	    systemf("mtype -i fat32dir.img ::readme.txt "
	    "> f32readme.out 2>&1"));
	assertTextFileContents("Read me first", "f32readme.out");
}

/*
 * Test: zero-length file.
 */
static void populate_mtools_empty_file(struct archive *a)
{
	write_file_entry(a, "empty.dat", "", 0, 1136073600);
	write_file_entry(a, "notempty.txt", "x", 1, 1136073600);
}

DEFINE_TEST(test_write_format_msdosfs_mtools_empty_file)
{
	size_t used;
	char *buff;

	if (!canMtools()) {
		skipping("mtools not available");
		return;
	}

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_mtools_empty_file, &used);
	assert(buff != NULL);
	assertEqualInt(0,
	    write_image_file("fat_emptyfile.img", buff, used));
	free(buff);

	/* Both files should be listed. */
	assertEqualInt(0,
	    systemf("mdir -i fat_emptyfile.img :: "
	    "> emptyfile.out 2>&1"));
	assertEqualInt(0,
	    systemf("grep EMPTY emptyfile.out > /dev/null"));
	assertEqualInt(0,
	    systemf("grep NOTEMPTY emptyfile.out > /dev/null"));

	/* Non-empty file should read correctly. */
	assertEqualInt(0,
	    systemf("mtype -i fat_emptyfile.img ::notempty.txt "
	    "> notempty.out 2>&1"));
	assertTextFileContents("x", "notempty.out");
}

/*
 * Test: files and dirs with mixed case / special 8.3 chars.
 */
static void populate_mtools_names(struct archive *a)
{
	write_file_entry(a, "UPPER.TXT", "upper", 5, 1136073600);
	write_file_entry(a, "lower.txt", "lower", 5, 1136073600);
	write_file_entry(a, "MiXeD.Dat", "mixed", 5, 1136073600);
	write_file_entry(a, "no_ext", "noext", 5, 1136073600);
	write_file_entry(a, "multi.dot.name.txt", "dots", 4, 1136073600);
}

DEFINE_TEST(test_write_format_msdosfs_mtools_names)
{
	size_t used;
	char *buff;

	if (!canMtools()) {
		skipping("mtools not available");
		return;
	}

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_mtools_names, &used);
	assert(buff != NULL);
	assertEqualInt(0, write_image_file("fat_names.img", buff, used));
	free(buff);

	/* All files should be accessible.  mtools is case-insensitive. */
	assertEqualInt(0,
	    systemf("mtype -i fat_names.img ::UPPER.TXT "
	    "> name1.out 2>&1"));
	assertTextFileContents("upper", "name1.out");

	assertEqualInt(0,
	    systemf("mtype -i fat_names.img ::lower.txt "
	    "> name2.out 2>&1"));
	assertTextFileContents("lower", "name2.out");

	assertEqualInt(0,
	    systemf("mtype -i fat_names.img ::MiXeD.Dat "
	    "> name3.out 2>&1"));
	assertTextFileContents("mixed", "name3.out");

	assertEqualInt(0,
	    systemf("mtype -i fat_names.img ::no_ext "
	    "> name4.out 2>&1"));
	assertTextFileContents("noext", "name4.out");

	assertEqualInt(0,
	    systemf("mtype -i fat_names.img ::multi.dot.name.txt "
	    "> name5.out 2>&1"));
	assertTextFileContents("dots", "name5.out");
}

/*
 * Test: FAT16 explicit option with mtools minfo verification.
 */
static void populate_mtools_fat16_info(struct archive *a)
{
	write_file_entry(a, "info.txt", "FAT16 info test", 15,
	    1136073600);
}

DEFINE_TEST(test_write_format_msdosfs_mtools_fat16_info)
{
	size_t used;
	char *buff;

	if (!canMtools()) {
		skipping("mtools not available");
		return;
	}

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_mtools_fat16_info, &used);
	assert(buff != NULL);
	assertEqualInt(0, write_image_file("fat16info.img", buff, used));
	free(buff);

	/* minfo should succeed and show FAT16 type. */
	assertEqualInt(0,
	    systemf("minfo -i fat16info.img :: > fat16info.out 2>&1"));
	assertEqualInt(0,
	    systemf("grep 'sector size' fat16info.out > /dev/null"));
	assertEqualInt(0,
	    systemf("grep 'cluster size' fat16info.out > /dev/null"));

	/* Verify file content. */
	assertEqualInt(0,
	    systemf("mtype -i fat16info.img ::info.txt "
	    "> info16.out 2>&1"));
	assertTextFileContents("FAT16 info test", "info16.out");
}

/*
 * Test: mcopy can extract multiple files from a FAT image.
 */
static void populate_mtools_mcopy(struct archive *a)
{
	write_file_entry(a, "alpha.txt", "alpha data\n", 11, 1136073600);
	write_file_entry(a, "beta.txt", "beta data\n", 10, 1136073600);
	write_dir_entry(a, "subdir", 1136073600);
	write_file_entry(a, "subdir/gamma.txt", "gamma data\n", 11,
	    1136073600);
}

DEFINE_TEST(test_write_format_msdosfs_mtools_mcopy)
{
	size_t used;
	char *buff;

	if (!canMtools()) {
		skipping("mtools not available");
		return;
	}

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_mtools_mcopy, &used);
	assert(buff != NULL);
	assertEqualInt(0, write_image_file("fat_mcopy.img", buff, used));
	free(buff);

	/* Extract files using mcopy. */
	assertEqualInt(0,
	    systemf("mcopy -i fat_mcopy.img ::alpha.txt "
	    "alpha_ext.txt 2>&1"));
	assertTextFileContents("alpha data\n", "alpha_ext.txt");

	assertEqualInt(0,
	    systemf("mcopy -i fat_mcopy.img ::beta.txt "
	    "beta_ext.txt 2>&1"));
	assertTextFileContents("beta data\n", "beta_ext.txt");

	assertEqualInt(0,
	    systemf("mcopy -i fat_mcopy.img ::subdir/gamma.txt "
	    "gamma_ext.txt 2>&1"));
	assertTextFileContents("gamma data\n", "gamma_ext.txt");
}

/* ================================================================
 * Test: invalid option values are rejected.
 * ================================================================ */
DEFINE_TEST(test_write_format_msdosfs_bad_options)
{
	struct archive *a;

	assert((a = archive_write_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_msdosfs(a));

	/* Invalid fat_type should fail. */
	assertEqualIntA(a, ARCHIVE_FATAL,
	    archive_write_set_format_option(a, "msdosfs",
	    "fat_type", "99"));

	/* Invalid cluster_size (not power of 2) should fail. */
	assertEqualIntA(a, ARCHIVE_FATAL,
	    archive_write_set_format_option(a, "msdosfs",
	    "cluster_size", "3"));

	/* cluster_size 0 should fail. */
	assertEqualIntA(a, ARCHIVE_FATAL,
	    archive_write_set_format_option(a, "msdosfs",
	    "cluster_size", "0"));

	/* cluster_size 256 (too large) should fail. */
	assertEqualIntA(a, ARCHIVE_FATAL,
	    archive_write_set_format_option(a, "msdosfs",
	    "cluster_size", "256"));

	assertEqualIntA(a, ARCHIVE_OK, archive_write_free(a));
}

/* ================================================================
 * Test: format identification after setup.
 * ================================================================ */
DEFINE_TEST(test_write_format_msdosfs_format_id)
{
	struct archive *a;

	assert((a = archive_write_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_msdosfs(a));

	assertEqualInt(ARCHIVE_FORMAT_MSDOSFS, archive_format(a));
	assertEqualString("MSDOSFS", archive_format_name(a));

	assertEqualIntA(a, ARCHIVE_OK, archive_write_free(a));
}

/* ================================================================
 * Test: file larger than 4GB is rejected.
 * ================================================================ */
DEFINE_TEST(test_write_format_msdosfs_large_file)
{
	struct archive *a;
	struct archive_entry *ae;
	size_t used;
	char *buff;
	size_t buffsize = 1024 * 1024;

	buff = malloc(buffsize);
	assert(buff != NULL);

	assert((a = archive_write_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_msdosfs(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_add_filter_none(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_open_memory(a, buff, buffsize, &used));

	/* Create an entry claiming to be 5 GB. */
	ae = archive_entry_new();
	assert(ae != NULL);
	archive_entry_set_pathname(ae, "bigfile.dat");
	archive_entry_set_filetype(ae, AE_IFREG);
	archive_entry_set_size(ae, (int64_t)5 * 1024 * 1024 * 1024);

	/* Should be rejected. */
	assertEqualIntA(a, ARCHIVE_FAILED,
	    archive_write_header(a, ae));

	archive_entry_free(ae);
	assertEqualIntA(a, ARCHIVE_OK, archive_write_free(a));
	free(buff);
}

/* ================================================================
 * Test: volume_label option sets the label in the BPB.
 * ================================================================ */
static void
populate_one_file_label(struct archive *a)
{
	struct archive_entry *ae;

	ae = archive_entry_new();
	archive_entry_set_pathname(ae, "test.txt");
	archive_entry_set_filetype(ae, AE_IFREG);
	archive_entry_set_size(ae, 5);
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_header(a, ae));
	assertEqualInt(5, archive_write_data(a, "hello", 5));
	archive_entry_free(ae);
}

DEFINE_TEST(test_write_format_msdosfs_volume_label)
{
	struct archive *a;
	char *buff;
	size_t buffsize = 2 * 1024 * 1024;
	size_t used;
	const unsigned char *img;

	buff = malloc(buffsize);
	assert(buff != NULL);

	assert((a = archive_write_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_msdosfs(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_option(a, "msdosfs",
	    "volume_label", "TESTLABEL"));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_add_filter_none(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_open_memory(a, buff, buffsize, &used));

	populate_one_file_label(a);

	assertEqualIntA(a, ARCHIVE_OK, archive_write_close(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_write_free(a));

	/* Verify the volume label in the BPB.
	 * For FAT12/16, the BS extension is at offset 36,
	 * vol_lab is at offset 43 (36 + 7 = 43). */
	img = (const unsigned char *)buff;
	assert(used >= 512);
	assert(verify_boot_signature(img, used));

	/* vol_lab is at offset 43 for FAT12/16. */
	assertEqualMem(img + 43, "TESTLABEL  ", 11);

	free(buff);
}

/* ================================================================
 * Test: volume_id option sets the serial number in the BPB.
 * ================================================================ */
DEFINE_TEST(test_write_format_msdosfs_volume_id)
{
	struct archive *a;
	char *buff;
	size_t buffsize = 2 * 1024 * 1024;
	size_t used;
	const unsigned char *img;

	buff = malloc(buffsize);
	assert(buff != NULL);

	assert((a = archive_write_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_msdosfs(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_option(a, "msdosfs",
	    "volume_id", "0xDEADBEEF"));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_add_filter_none(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_open_memory(a, buff, buffsize, &used));

	populate_one_file_label(a);

	assertEqualIntA(a, ARCHIVE_OK, archive_write_close(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_write_free(a));

	/* For FAT12/16, vol_id is at offset 39 (BS ext at 36, +3). */
	img = (const unsigned char *)buff;
	assert(used >= 512);
	assert(verify_boot_signature(img, used));
	assertEqualInt(0xDEADBEEF, le32(img + 39));

	free(buff);
}
