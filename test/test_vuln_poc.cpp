/*
 * Combined test runner for mp4v2 vulnerability POCs.
 *
 * Each test attempts to read a malformed MP4 file via MP4Read().
 * With the fixes applied, each file should be cleanly rejected
 * (MP4Read returns MP4_INVALID_FILE_HANDLE) without crashing.
 *
 * Build:
 *   c++ -std=c++11 -Iinclude -Ibuild/include -Lbuild -o test_vuln_poc test/test_vuln_poc.cpp -lmp4v2 -Wl,-rpath,build
 *
 * Run (from repo root):
 *   ./test_vuln_poc
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mp4v2/mp4v2.h>

struct TestCase {
    const char* poc_file;
    const char* description;
    bool expect_read_fail;  // true = MP4Read should return invalid handle
    bool (*custom_test)(const char* path);  // non-NULL = custom test function
};

/* Forward declarations of custom test functions */
static bool test_sample_size_overflow(const char* path);
static bool test_offset_overflow(const char* path);
static bool test_sample_alloc(const char* path);

static const TestCase tests[] = {
    { "test/poc_meta_underflow.mp4",        "Vuln #1/#2: Integer underflow in metadata atom parsing", true, NULL },
    { "test/poc_deep_nesting.mp4",          "Vuln #3: Stack overflow via deeply nested atoms", true, NULL },
    { "test/poc_table_alloc.mp4",           "Vuln #4: Unbounded table allocation from bogus entryCount", true, NULL },
    { "test/poc_sample_size_overflow.mp4",  "Vuln #5: Integer overflow in GetSampleSize multiplication", false, test_sample_size_overflow },
    { "test/poc_offset_overflow.mp4",       "Vuln #6: Integer overflow in sampleOffset accumulation", false, test_offset_overflow },
    { "test/poc_realloc_truncation.mp4",    "Vuln #7: MP4Realloc uint32_t truncation on large alloc", true, NULL },
    { "test/poc_sample_alloc.mp4",           "Vuln #8: Uncontrolled allocation from sample size metadata", false, test_sample_alloc },
};

static const int NUM_TESTS = sizeof(tests) / sizeof(tests[0]);

/* Test Vuln #5: file opens successfully but GetSampleSize must detect overflow */
static bool test_sample_size_overflow(const char* path)
{
    MP4FileHandle file = MP4Read(path);
    if (file == MP4_INVALID_FILE_HANDLE) {
        printf("       FAIL: MP4Read unexpectedly rejected the file.\n\n");
        return false;
    }

    /* Get the first audio track */
    MP4TrackId trackId = MP4FindTrackId(file, 0, MP4_AUDIO_TRACK_TYPE, 0);
    if (trackId == MP4_INVALID_TRACK_ID) {
        printf("       FAIL: Could not find audio track.\n\n");
        MP4Close(file, 0);
        return false;
    }

    /* Attempt to get sample size - should return 0 due to overflow detection */
    uint32_t size = MP4GetSampleSize(file, trackId, 1);
    MP4Close(file, 0);

    if (size == 0) {
        printf("       PASS: GetSampleSize correctly detected overflow (returned 0).\n\n");
        return true;
    } else {
        printf("       FAIL: GetSampleSize returned %u (expected 0 from overflow check).\n\n", size);
        return false;
    }
}

/* Test Vuln #6: file opens but ReadSample must fail due to offset exceeding file size */
static bool test_offset_overflow(const char* path)
{
    MP4FileHandle file = MP4Read(path);
    if (file == MP4_INVALID_FILE_HANDLE) {
        printf("       FAIL: MP4Read unexpectedly rejected the file.\n\n");
        return false;
    }

    /* Get the first video track */
    MP4TrackId trackId = MP4FindTrackId(file, 0, MP4_VIDEO_TRACK_TYPE, 0);
    if (trackId == MP4_INVALID_TRACK_ID) {
        printf("       FAIL: Could not find video track.\n\n");
        MP4Close(file, 0);
        return false;
    }

    /* Try to read sample 3: offset computation accumulates sample sizes 1+2
       = 0x80000000 + 0x80000000 = 0x100000000 which overflows uint32 to 0
       but with the fix (uint64_t), it correctly exceeds file size */
    uint8_t* pSample = NULL;
    uint32_t sampleSize = 0;
    bool ok = MP4ReadSample(file, trackId, 3, &pSample, &sampleSize,
                            NULL, NULL, NULL, NULL);
    MP4Close(file, 0);

    if (!ok && pSample == NULL) {
        printf("       PASS: ReadSample correctly failed (offset overflow detected).\n\n");
        return true;
    } else {
        printf("       FAIL: ReadSample succeeded unexpectedly (size=%u).\n\n", sampleSize);
        if (pSample) free(pSample);
        return false;
    }
}

/* Test Vuln #8: file opens but ReadSample must fail because sample size exceeds file size */
static bool test_sample_alloc(const char* path)
{
    MP4FileHandle file = MP4Read(path);
    if (file == MP4_INVALID_FILE_HANDLE) {
        printf("       FAIL: MP4Read unexpectedly rejected the file.\n\n");
        return false;
    }

    /* Get the first video track */
    MP4TrackId trackId = MP4FindTrackId(file, 0, MP4_VIDEO_TRACK_TYPE, 0);
    if (trackId == MP4_INVALID_TRACK_ID) {
        printf("       FAIL: Could not find video track.\n\n");
        MP4Close(file, 0);
        return false;
    }

    /* Attempt to read sample 1: stsz claims size 0xFFFFFFFF (~4GB) but file is tiny.
       The fix should reject this before allocating. */
    uint8_t* pSample = NULL;
    uint32_t sampleSize = 0;
    bool ok = MP4ReadSample(file, trackId, 1, &pSample, &sampleSize,
                            NULL, NULL, NULL, NULL);
    MP4Close(file, 0);

    if (!ok && pSample == NULL) {
        printf("       PASS: ReadSample correctly rejected oversized sample allocation.\n\n");
        return true;
    } else {
        printf("       FAIL: ReadSample succeeded unexpectedly (size=%u).\n\n", sampleSize);
        if (pSample) free(pSample);
        return false;
    }
}

int main(int argc, char** argv)
{
    /* Allow overriding the test directory prefix */
    const char* prefix = "";
    if (argc > 1) {
        prefix = argv[1];
    }
#ifdef POC_TEST_FILES_DIR
    /* If no prefix given, use the compile-time source directory so the test
       works when run from any working directory (e.g. cmake-build-debug/). */
    if (prefix[0] == '\0') {
        prefix = POC_TEST_FILES_DIR;
    }
#endif

    MP4LogSetLevel(MP4_LOG_ERROR);

    int passed = 0;
    int failed = 0;

    printf("Running %d vulnerability POC tests...\n\n", NUM_TESTS);

    for (int i = 0; i < NUM_TESTS; i++) {
        char path[512];
        if (prefix[0]) {
            snprintf(path, sizeof(path), "%s/%s", prefix, tests[i].poc_file);
        } else {
            snprintf(path, sizeof(path), "%s", tests[i].poc_file);
        }

        printf("[%d/%d] %s\n", i + 1, NUM_TESTS, tests[i].description);
        printf("       File: %s\n", path);

        if (!tests[i].expect_read_fail && tests[i].custom_test) {
            /* Special test: file should open, but operation should fail safely */
            if (tests[i].custom_test(path)) {
                passed++;
            } else {
                failed++;
            }
            continue;
        }

        MP4FileHandle file = MP4Read(path);
        if (file == MP4_INVALID_FILE_HANDLE) {
            printf("       PASS: MP4Read correctly rejected the malformed file.\n\n");
            passed++;
        } else {
            printf("       FAIL: File was opened despite being malformed.\n\n");
            MP4Close(file, 0);
            failed++;
        }
    }

    printf("---\nResults: %d passed, %d failed, %d total\n", passed, failed, NUM_TESTS);

    return (failed == 0) ? 0 : 1;
}
