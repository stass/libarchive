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

/*
 * Helpers to check FAT image structure at the byte level.
 */

/* Check boot sector signature at offset 510. */
static int
verify_boot_signature(const unsigned char *img, size_t img_size)
{
	if (img_size < 512)
		return 0;
	return (img[510] == 0x55 && img[511] == 0xAA);
}

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

/* Search the root directory region (FAT12/16) for a short-name entry.
 * Returns pointer to the 32-byte entry or NULL. */
static const unsigned char *
find_root_dir_entry(const unsigned char *img, size_t img_size,
    const char *short_name_11)
{
	/* BPB fields */
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

/*
 * Test: basic FAT16 image with a single file.
 */
DEFINE_TEST(test_write_format_msdosfs_basic)
{
	size_t buffsize = 2 * 1024 * 1024;  /* 2 MB work area */
	char *buff;
	struct archive_entry *ae;
	struct archive *a;
	size_t used;
	const char filedata[] = "Hello, FAT!";

	buff = malloc(buffsize);
	assert(buff != NULL);

	/* Create a new archive in memory. */
	assert((a = archive_write_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_msdosfs(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_option(a, "msdosfs", "fat_type", "16"));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_add_filter_none(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_open_memory(a, buff, buffsize, &used));

	/* Write a single file. */
	assert((ae = archive_entry_new()) != NULL);
	archive_entry_set_mtime(ae, 1, 0);
	archive_entry_copy_pathname(ae, "hello.txt");
	archive_entry_set_mode(ae, AE_IFREG | 0644);
	archive_entry_set_size(ae, (int64_t)sizeof(filedata) - 1);
	assertEqualIntA(a, ARCHIVE_OK, archive_write_header(a, ae));
	archive_entry_free(ae);
	assertEqualIntA(a, (int)sizeof(filedata) - 1,
	    (int)archive_write_data(a, filedata, sizeof(filedata) - 1));

	/* Close the archive. */
	assertEqualIntA(a, ARCHIVE_OK, archive_write_close(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_write_free(a));

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
		/*                    "HELLO   TXT" */
		ent = find_root_dir_entry((const unsigned char *)buff, used,
		    "HELLO   TXT");
		assert(ent != NULL);
		if (ent != NULL) {
			/* Check file size in directory entry. */
			assertEqualInt((int)sizeof(filedata) - 1,
			    (int)le32(ent + 28));
			/* Check ATTR_ARCHIVE is set. */
			assertEqualInt(0x20, ent[11]);
		}
	}

	free(buff);
}

/*
 * Test: directory creation and nested files.
 */
DEFINE_TEST(test_write_format_msdosfs_directory)
{
	size_t buffsize = 2 * 1024 * 1024;
	char *buff;
	struct archive_entry *ae;
	struct archive *a;
	size_t used;

	buff = malloc(buffsize);
	assert(buff != NULL);

	assert((a = archive_write_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_msdosfs(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_option(a, "msdosfs", "fat_type", "16"));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_add_filter_none(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_open_memory(a, buff, buffsize, &used));

	/* Write a directory entry. */
	assert((ae = archive_entry_new()) != NULL);
	archive_entry_set_mtime(ae, 1, 0);
	archive_entry_copy_pathname(ae, "subdir");
	archive_entry_set_mode(ae, S_IFDIR | 0755);
	assertEqualIntA(a, ARCHIVE_OK, archive_write_header(a, ae));
	archive_entry_free(ae);

	/* Write a file inside that directory. */
	assert((ae = archive_entry_new()) != NULL);
	archive_entry_set_mtime(ae, 2, 0);
	archive_entry_copy_pathname(ae, "subdir/inner.txt");
	archive_entry_set_mode(ae, AE_IFREG | 0644);
	archive_entry_set_size(ae, 5);
	assertEqualIntA(a, ARCHIVE_OK, archive_write_header(a, ae));
	archive_entry_free(ae);
	assertEqualIntA(a, 5, (int)archive_write_data(a, "abcde", 5));

	assertEqualIntA(a, ARCHIVE_OK, archive_write_close(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_write_free(a));

	/* Verify image has a valid boot sector. */
	assert(used > 512);
	assert(verify_boot_signature((const unsigned char *)buff, used));

	/* Find the directory in root. */
	{
		const unsigned char *ent;
		/*                    "SUBDIR     " */
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

/*
 * Test: multiple files.
 */
DEFINE_TEST(test_write_format_msdosfs_multiple_files)
{
	size_t buffsize = 2 * 1024 * 1024;
	char *buff;
	struct archive_entry *ae;
	struct archive *a;
	size_t used;
	int i;

	buff = malloc(buffsize);
	assert(buff != NULL);

	assert((a = archive_write_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_msdosfs(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_option(a, "msdosfs", "fat_type", "16"));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_add_filter_none(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_open_memory(a, buff, buffsize, &used));

	/* Write 10 small files. */
	for (i = 0; i < 10; i++) {
		char name[32];
		char data[64];
		int datalen;

		snprintf(name, sizeof(name), "file%d.txt", i);
		datalen = snprintf(data, sizeof(data), "Content of file %d", i);

		assert((ae = archive_entry_new()) != NULL);
		archive_entry_set_mtime(ae, 1000000 + i, 0);
		archive_entry_copy_pathname(ae, name);
		archive_entry_set_mode(ae, AE_IFREG | 0644);
		archive_entry_set_size(ae, datalen);
		assertEqualIntA(a, ARCHIVE_OK, archive_write_header(a, ae));
		archive_entry_free(ae);
		assertEqualIntA(a, datalen,
		    (int)archive_write_data(a, data, datalen));
	}

	assertEqualIntA(a, ARCHIVE_OK, archive_write_close(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_write_free(a));

	assert(used > 512);
	assert(verify_boot_signature((const unsigned char *)buff, used));

	/* Verify all 10 files exist in the root directory. */
	{
		const unsigned char *img = (const unsigned char *)buff;
		for (i = 0; i < 10; i++) {
			char sname[12];
			snprintf(sname, sizeof(sname), "FILE%d   TXT", i);
			assert(find_root_dir_entry(img, used, sname) != NULL);
		}
	}

	free(buff);
}

/*
 * Test: FAT32 with explicit option.
 */
DEFINE_TEST(test_write_format_msdosfs_fat32)
{
	size_t buffsize = 64 * 1024 * 1024;  /* 64 MB for FAT32 */
	char *buff;
	struct archive_entry *ae;
	struct archive *a;
	size_t used;

	buff = malloc(buffsize);
	if (buff == NULL) {
		skipping("Unable to allocate 64MB for FAT32 test");
		return;
	}

	assert((a = archive_write_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_msdosfs(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_option(a, "msdosfs", "fat_type", "32"));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_add_filter_none(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_open_memory(a, buff, buffsize, &used));

	/* Write a file. */
	assert((ae = archive_entry_new()) != NULL);
	archive_entry_set_mtime(ae, 1, 0);
	archive_entry_copy_pathname(ae, "test.dat");
	archive_entry_set_mode(ae, AE_IFREG | 0644);
	archive_entry_set_size(ae, 4);
	assertEqualIntA(a, ARCHIVE_OK, archive_write_header(a, ae));
	archive_entry_free(ae);
	assertEqualIntA(a, 4, (int)archive_write_data(a, "data", 4));

	assertEqualIntA(a, ARCHIVE_OK, archive_write_close(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_write_free(a));

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
	size_t buffsize = 2 * 1024 * 1024;
	char *buff;
	struct archive *a;
	size_t used;

	buff = malloc(buffsize);
	assert(buff != NULL);

	assert((a = archive_write_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_msdosfs(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_option(a, "msdosfs", "fat_type", "16"));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_add_filter_none(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_open_memory(a, buff, buffsize, &used));

	/* Write nothing, just close. */
	assertEqualIntA(a, ARCHIVE_OK, archive_write_close(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_write_free(a));

	/* Should still produce a valid FAT image. */
	assert(used > 512);
	assert(verify_boot_signature((const unsigned char *)buff, used));
	assertEqualInt(512, le16((const unsigned char *)buff + 11));

	free(buff);
}

/*
 * Test: long filename triggers LFN entries.
 */
DEFINE_TEST(test_write_format_msdosfs_longname)
{
	size_t buffsize = 2 * 1024 * 1024;
	char *buff;
	struct archive_entry *ae;
	struct archive *a;
	size_t used;
	const char *longname = "this_is_a_very_long_filename.txt";

	buff = malloc(buffsize);
	assert(buff != NULL);

	assert((a = archive_write_new()) != NULL);
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_msdosfs(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_set_format_option(a, "msdosfs", "fat_type", "16"));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_add_filter_none(a));
	assertEqualIntA(a, ARCHIVE_OK,
	    archive_write_open_memory(a, buff, buffsize, &used));

	/* Write a file with a long name. */
	assert((ae = archive_entry_new()) != NULL);
	archive_entry_set_mtime(ae, 1, 0);
	archive_entry_copy_pathname(ae, longname);
	archive_entry_set_mode(ae, AE_IFREG | 0644);
	archive_entry_set_size(ae, 3);
	assertEqualIntA(a, ARCHIVE_OK, archive_write_header(a, ae));
	archive_entry_free(ae);
	assertEqualIntA(a, 3, (int)archive_write_data(a, "abc", 3));

	assertEqualIntA(a, ARCHIVE_OK, archive_write_close(a));
	assertEqualIntA(a, ARCHIVE_OK, archive_write_free(a));

	assert(used > 512);
	assert(verify_boot_signature((const unsigned char *)buff, used));

	/* The root directory should contain LFN entries (attr=0x0F)
	 * before the short entry. Scan for at least one LFN entry. */
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
