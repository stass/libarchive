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
#include "test.h"

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
 * Helper: create a FAT image in memory using the writer.
 * Returns a malloc'd buffer; caller must free().
 * ================================================================ */
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

/* Helper: write an archive entry for a file with data. */
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
 * Helper: read all data from an archive entry into a buffer.
 * Returns a malloc'd buffer with *out_size bytes; caller frees.
 * ================================================================ */
static char *
read_entry_data(struct archive *a, size_t expected_size, size_t *out_size)
{
	char *buf;
	size_t total;
	const void *p;
	size_t s;
	int64_t o;
	int r;

	buf = (char *)malloc(expected_size + 1);
	if (buf == NULL)
		return (NULL);
	total = 0;

	for (;;) {
		r = archive_read_data_block(a, &p, &s, &o);
		if (r == ARCHIVE_EOF)
			break;
		if (r != ARCHIVE_OK) {
			free(buf);
			return (NULL);
		}
		if (total + s > expected_size) {
			free(buf);
			return (NULL);
		}
		memcpy(buf + total, p, s);
		total += s;
	}

	buf[total] = '\0';
	if (out_size != NULL)
		*out_size = total;
	return (buf);
}

/* ================================================================
 * Test: basic single file round-trip (FAT16).
 * ================================================================ */
static void populate_basic(struct archive *a)
{
	write_file_entry(a, "hello.txt", "Hello, FAT!", 11, 1000000);
}

DEFINE_TEST(test_read_format_msdosfs_basic)
{
	char *buff;
	size_t used;
	struct archive *ar;
	struct archive_entry *ae;
	char *data;
	size_t data_size;

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_basic, &used);
	assert(buff != NULL);

	/* Open for reading. */
	assert((ar = archive_read_new()) != NULL);
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_support_format_all(ar));
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_open_memory(ar, buff, used));

	/* First entry: hello.txt */
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_next_header(ar, &ae));
	assertEqualString("hello.txt", archive_entry_pathname(ae));
	assertEqualInt(11, archive_entry_size(ae));
	assertEqualInt(AE_IFREG, archive_entry_filetype(ae));
	assertEqualInt(ARCHIVE_FORMAT_MSDOSFS, archive_format(ar));

	/* Read data. */
	data = read_entry_data(ar, 11, &data_size);
	assert(data != NULL);
	assertEqualInt(11, (int)data_size);
	assertEqualMem(data, "Hello, FAT!", 11);
	free(data);

	/* No more entries. */
	assertEqualIntA(ar, ARCHIVE_EOF,
	    archive_read_next_header(ar, &ae));

	assertEqualIntA(ar, ARCHIVE_OK, archive_read_close(ar));
	assertEqualInt(ARCHIVE_OK, archive_read_free(ar));
	free(buff);
}

/* ================================================================
 * Test: directory with nested file.
 * ================================================================ */
static void populate_directory(struct archive *a)
{
	write_dir_entry(a, "subdir", 1000000);
	write_file_entry(a, "subdir/inner.txt", "inner content", 13,
	    1000000);
}

DEFINE_TEST(test_read_format_msdosfs_directory)
{
	char *buff;
	size_t used;
	struct archive *ar;
	struct archive_entry *ae;
	int found_dir, found_file;
	char *data;
	size_t data_size;

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_directory, &used);
	assert(buff != NULL);

	assert((ar = archive_read_new()) != NULL);
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_support_format_all(ar));
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_open_memory(ar, buff, used));

	found_dir = 0;
	found_file = 0;

	while (archive_read_next_header(ar, &ae) == ARCHIVE_OK) {
		const char *path = archive_entry_pathname(ae);
		if (strcmp(path, "subdir/") == 0) {
			found_dir = 1;
			assertEqualInt(AE_IFDIR,
			    archive_entry_filetype(ae));
		} else if (strcmp(path, "subdir/inner.txt") == 0) {
			found_file = 1;
			assertEqualInt(AE_IFREG,
			    archive_entry_filetype(ae));
			assertEqualInt(13, archive_entry_size(ae));
			data = read_entry_data(ar, 13, &data_size);
			assert(data != NULL);
			assertEqualInt(13, (int)data_size);
			assertEqualMem(data, "inner content", 13);
			free(data);
		}
	}

	assert(found_dir);
	assert(found_file);

	assertEqualIntA(ar, ARCHIVE_OK, archive_read_close(ar));
	assertEqualInt(ARCHIVE_OK, archive_read_free(ar));
	free(buff);
}

/* ================================================================
 * Test: long filename round-trip.
 * ================================================================ */
static void populate_lfn(struct archive *a)
{
	write_file_entry(a,
	    "this-is-a-very-long-filename-for-testing.txt",
	    "LFN data", 8, 1000000);
}

DEFINE_TEST(test_read_format_msdosfs_lfn)
{
	char *buff;
	size_t used;
	struct archive *ar;
	struct archive_entry *ae;

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_lfn, &used);
	assert(buff != NULL);

	assert((ar = archive_read_new()) != NULL);
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_support_format_all(ar));
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_open_memory(ar, buff, used));

	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_next_header(ar, &ae));
	assertEqualString("this-is-a-very-long-filename-for-testing.txt",
	    archive_entry_pathname(ae));
	assertEqualInt(8, archive_entry_size(ae));

	assertEqualIntA(ar, ARCHIVE_EOF,
	    archive_read_next_header(ar, &ae));

	assertEqualIntA(ar, ARCHIVE_OK, archive_read_close(ar));
	assertEqualInt(ARCHIVE_OK, archive_read_free(ar));
	free(buff);
}

/* ================================================================
 * Test: FAT32 round-trip.
 * ================================================================ */
static void populate_fat32(struct archive *a)
{
	write_dir_entry(a, "testdir", 1000000);
	write_file_entry(a, "testdir/readme.txt", "FAT32 test", 10,
	    1000000);
	write_file_entry(a, "root.txt", "root file", 9, 1000000);
}

DEFINE_TEST(test_read_format_msdosfs_fat32)
{
	char *buff;
	size_t used;
	struct archive *ar;
	struct archive_entry *ae;
	int count;

	buff = create_fat_image(64 * 1024 * 1024, "32",
	    populate_fat32, &used);
	assert(buff != NULL);

	assert((ar = archive_read_new()) != NULL);
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_support_format_all(ar));
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_open_memory(ar, buff, used));

	count = 0;
	while (archive_read_next_header(ar, &ae) == ARCHIVE_OK) {
		count++;
	}
	/* Expect 3 entries: testdir/, testdir/readme.txt, root.txt */
	assertEqualInt(3, count);

	assertEqualIntA(ar, ARCHIVE_OK, archive_read_close(ar));
	assertEqualInt(ARCHIVE_OK, archive_read_free(ar));
	free(buff);
}

/* ================================================================
 * Test: FAT12 auto-detection.
 * ================================================================ */
static void populate_fat12(struct archive *a)
{
	write_file_entry(a, "small.txt", "tiny", 4, 1000000);
}

DEFINE_TEST(test_read_format_msdosfs_fat12)
{
	char *buff;
	size_t used;
	struct archive *ar;
	struct archive_entry *ae;
	char *data;
	size_t data_size;

	/* Small image => auto-detected as FAT12. */
	buff = create_fat_image(512 * 1024, "12",
	    populate_fat12, &used);
	assert(buff != NULL);

	assert((ar = archive_read_new()) != NULL);
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_support_format_all(ar));
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_open_memory(ar, buff, used));

	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_next_header(ar, &ae));
	assertEqualInt(4, archive_entry_size(ae));

	data = read_entry_data(ar, 4, &data_size);
	assert(data != NULL);
	assertEqualInt(4, (int)data_size);
	assertEqualMem(data, "tiny", 4);
	free(data);

	assertEqualIntA(ar, ARCHIVE_EOF,
	    archive_read_next_header(ar, &ae));

	assertEqualIntA(ar, ARCHIVE_OK, archive_read_close(ar));
	assertEqualInt(ARCHIVE_OK, archive_read_free(ar));
	free(buff);
}

/* ================================================================
 * Test: multiple files.
 * ================================================================ */
static void populate_multiple(struct archive *a)
{
	int i;
	for (i = 0; i < 10; i++) {
		char name[32], data[32];
		snprintf(name, sizeof(name), "file%02d.txt", i);
		snprintf(data, sizeof(data), "content-%02d", i);
		write_file_entry(a, name, data, strlen(data), 1000000);
	}
}

DEFINE_TEST(test_read_format_msdosfs_multiple)
{
	char *buff;
	size_t used;
	struct archive *ar;
	struct archive_entry *ae;
	int count;

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_multiple, &used);
	assert(buff != NULL);

	assert((ar = archive_read_new()) != NULL);
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_support_format_all(ar));
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_open_memory(ar, buff, used));

	count = 0;
	while (archive_read_next_header(ar, &ae) == ARCHIVE_OK) {
		assertEqualInt(AE_IFREG, archive_entry_filetype(ae));
		count++;
	}
	assertEqualInt(10, count);

	assertEqualIntA(ar, ARCHIVE_OK, archive_read_close(ar));
	assertEqualInt(ARCHIVE_OK, archive_read_free(ar));
	free(buff);
}

/* ================================================================
 * Test: empty FAT image.
 * ================================================================ */
DEFINE_TEST(test_read_format_msdosfs_empty)
{
	char *buff;
	size_t used;
	struct archive *ar;
	struct archive_entry *ae;

	buff = create_fat_image(4 * 1024 * 1024, "16", NULL, &used);
	assert(buff != NULL);

	assert((ar = archive_read_new()) != NULL);
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_support_format_all(ar));
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_open_memory(ar, buff, used));

	/* Should get EOF immediately. */
	assertEqualIntA(ar, ARCHIVE_EOF,
	    archive_read_next_header(ar, &ae));

	assertEqualIntA(ar, ARCHIVE_OK, archive_read_close(ar));
	assertEqualInt(ARCHIVE_OK, archive_read_free(ar));
	free(buff);
}

/* ================================================================
 * Test: large file spanning multiple clusters.
 * ================================================================ */
static void populate_large(struct archive *a)
{
	char *data;
	size_t datalen = 16384;
	size_t i;

	data = malloc(datalen);
	assert(data != NULL);
	for (i = 0; i < datalen; i++)
		data[i] = (char)(i & 0xFF);

	write_file_entry(a, "bigfile.bin", data, datalen, 1000000);
	free(data);
}

DEFINE_TEST(test_read_format_msdosfs_large)
{
	char *buff;
	size_t used;
	struct archive *ar;
	struct archive_entry *ae;
	char *data;
	size_t data_size;
	size_t i;

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_large, &used);
	assert(buff != NULL);

	assert((ar = archive_read_new()) != NULL);
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_support_format_all(ar));
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_open_memory(ar, buff, used));

	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_next_header(ar, &ae));
	assertEqualString("bigfile.bin", archive_entry_pathname(ae));
	assertEqualInt(16384, archive_entry_size(ae));

	data = read_entry_data(ar, 16384, &data_size);
	assert(data != NULL);
	assertEqualInt(16384, (int)data_size);

	/* Verify content. */
	for (i = 0; i < 16384; i++) {
		if ((unsigned char)data[i] != (i & 0xFF)) {
			failure("Byte mismatch at offset %zu: "
			    "expected %02x, got %02x",
			    i, (unsigned)(i & 0xFF),
			    (unsigned char)data[i]);
			assert(0);
			break;
		}
	}
	free(data);

	assertEqualIntA(ar, ARCHIVE_EOF,
	    archive_read_next_header(ar, &ae));

	assertEqualIntA(ar, ARCHIVE_OK, archive_read_close(ar));
	assertEqualInt(ARCHIVE_OK, archive_read_free(ar));
	free(buff);
}

/* ================================================================
 * Test: deep directory nesting.
 * ================================================================ */
static void populate_deep(struct archive *a)
{
	write_dir_entry(a, "a", 1000000);
	write_dir_entry(a, "a/b", 1000000);
	write_dir_entry(a, "a/b/c", 1000000);
	write_dir_entry(a, "a/b/c/d", 1000000);
	write_file_entry(a, "a/b/c/d/deep.txt", "deep", 4, 1000000);
}

DEFINE_TEST(test_read_format_msdosfs_deep)
{
	char *buff;
	size_t used;
	struct archive *ar;
	struct archive_entry *ae;
	int found_file;

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_deep, &used);
	assert(buff != NULL);

	assert((ar = archive_read_new()) != NULL);
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_support_format_all(ar));
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_open_memory(ar, buff, used));

	found_file = 0;
	while (archive_read_next_header(ar, &ae) == ARCHIVE_OK) {
		if (strcmp(archive_entry_pathname(ae),
		    "a/b/c/d/deep.txt") == 0) {
			found_file = 1;
			assertEqualInt(4, archive_entry_size(ae));
		}
	}
	assert(found_file);

	assertEqualIntA(ar, ARCHIVE_OK, archive_read_close(ar));
	assertEqualInt(ARCHIVE_OK, archive_read_free(ar));
	free(buff);
}

/* ================================================================
 * Test: zero-length file.
 * ================================================================ */
static void populate_zero(struct archive *a)
{
	write_file_entry(a, "empty.txt", "", 0, 1000000);
}

DEFINE_TEST(test_read_format_msdosfs_zero_length)
{
	char *buff;
	size_t used;
	struct archive *ar;
	struct archive_entry *ae;

	buff = create_fat_image(4 * 1024 * 1024, "16",
	    populate_zero, &used);
	assert(buff != NULL);

	assert((ar = archive_read_new()) != NULL);
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_support_format_all(ar));
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_open_memory(ar, buff, used));

	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_next_header(ar, &ae));
	assertEqualString("empty.txt", archive_entry_pathname(ae));
	assertEqualInt(0, archive_entry_size(ae));
	assertEqualInt(AE_IFREG, archive_entry_filetype(ae));

	/* read_data should return EOF immediately. */
	{
		const void *p;
		size_t s;
		int64_t o;
		assertEqualIntA(ar, ARCHIVE_EOF,
		    archive_read_data_block(ar, &p, &s, &o));
	}

	assertEqualIntA(ar, ARCHIVE_EOF,
	    archive_read_next_header(ar, &ae));

	assertEqualIntA(ar, ARCHIVE_OK, archive_read_close(ar));
	assertEqualInt(ARCHIVE_OK, archive_read_free(ar));
	free(buff);
}

/* ================================================================
 * Test: mtools cross-verification -- create image with mtools,
 * read with libarchive.
 * ================================================================ */
DEFINE_TEST(test_read_format_msdosfs_mtools)
{
	struct archive *ar;
	struct archive_entry *ae;
	int found_readme;
	char *data;
	size_t data_size;

	if (!canMtools()) {
		skipping("mtools not available");
		return;
	}

	/* Create a FAT16 image using mtools. */
	assertEqualInt(0,
	    systemf("dd if=/dev/zero of=mtools_test.img "
	    "bs=512 count=8192 >/dev/null 2>&1"));
	assertEqualInt(0,
	    systemf("mformat -i mtools_test.img -T 8192 :: "
	    ">/dev/null 2>&1"));

	/* Copy a test file into the image. */
	assertEqualInt(0,
	    systemf("echo -n 'mtools content' > mtools_input.txt"));
	assertEqualInt(0,
	    systemf("mcopy -i mtools_test.img mtools_input.txt "
	    "::readme.txt >/dev/null 2>&1"));

	/* Now read with libarchive. */
	assert((ar = archive_read_new()) != NULL);
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_support_format_all(ar));
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_open_filename(ar, "mtools_test.img", 10240));

	found_readme = 0;
	while (archive_read_next_header(ar, &ae) == ARCHIVE_OK) {
		const char *path = archive_entry_pathname(ae);
		if (strcmp(path, "readme.txt") == 0 ||
		    strcmp(path, "README.TXT") == 0 ||
		    strcmp(path, "readme.TXT") == 0) {
			found_readme = 1;
			assertEqualInt(AE_IFREG,
			    archive_entry_filetype(ae));
			data = read_entry_data(ar, 256, &data_size);
			if (data != NULL) {
				assertEqualInt(14, (int)data_size);
				assertEqualMem(data,
				    "mtools content", 14);
				free(data);
			}
		}
	}
	assert(found_readme);

	assertEqualIntA(ar, ARCHIVE_OK, archive_read_close(ar));
	assertEqualInt(ARCHIVE_OK, archive_read_free(ar));
}

/* ================================================================
 * Test: mtools image with subdirectories.
 * ================================================================ */
DEFINE_TEST(test_read_format_msdosfs_mtools_dirs)
{
	struct archive *ar;
	struct archive_entry *ae;
	int found_dir, found_file;

	if (!canMtools()) {
		skipping("mtools not available");
		return;
	}

	assertEqualInt(0,
	    systemf("dd if=/dev/zero of=mtools_dirs.img "
	    "bs=512 count=8192 >/dev/null 2>&1"));
	assertEqualInt(0,
	    systemf("mformat -i mtools_dirs.img -T 8192 :: "
	    ">/dev/null 2>&1"));
	assertEqualInt(0,
	    systemf("mmd -i mtools_dirs.img ::testdir "
	    ">/dev/null 2>&1"));
	assertEqualInt(0,
	    systemf("echo -n 'nested file' > mtools_nested.txt"));
	assertEqualInt(0,
	    systemf("mcopy -i mtools_dirs.img mtools_nested.txt "
	    "::testdir/nested.txt >/dev/null 2>&1"));

	assert((ar = archive_read_new()) != NULL);
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_support_format_all(ar));
	assertEqualIntA(ar, ARCHIVE_OK,
	    archive_read_open_filename(ar, "mtools_dirs.img", 10240));

	found_dir = 0;
	found_file = 0;
	while (archive_read_next_header(ar, &ae) == ARCHIVE_OK) {
		const char *path = archive_entry_pathname(ae);
		if (strstr(path, "testdir") != NULL &&
		    archive_entry_filetype(ae) == AE_IFDIR)
			found_dir = 1;
		if (strstr(path, "nested") != NULL &&
		    archive_entry_filetype(ae) == AE_IFREG)
			found_file = 1;
	}
	assert(found_dir);
	assert(found_file);

	assertEqualIntA(ar, ARCHIVE_OK, archive_read_close(ar));
	assertEqualInt(ARCHIVE_OK, archive_read_free(ar));
}
