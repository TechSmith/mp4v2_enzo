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
};

static const TestCase tests[] = {
    { "test/poc_meta_underflow.mp4",  "Vuln #1/#2: Integer underflow in metadata atom parsing" },
    { "test/poc_deep_nesting.mp4",    "Vuln #3: Stack overflow via deeply nested atoms" },
    { "test/poc_table_alloc.mp4",     "Vuln #4: Unbounded table allocation from bogus entryCount" },
};

static const int NUM_TESTS = sizeof(tests) / sizeof(tests[0]);

int main(int argc, char** argv)
{
    /* Allow overriding the test directory prefix */
    const char* prefix = "";
    if (argc > 1) {
        prefix = argv[1];
    }

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
