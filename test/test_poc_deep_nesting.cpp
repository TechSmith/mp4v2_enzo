/*
 * Test harness for POC: Stack overflow via deeply nested atoms (Vuln #3)
 *
 * This program attempts to read the malformed MP4 file with deeply nested atoms.
 * - Without fix: crashes with stack overflow (SIGSEGV)
 * - With fix: prints error message and exits cleanly (MP4Read returns invalid handle)
 */

#include <cstdio>
#include <cstdlib>
#include <mp4v2/mp4v2.h>

int main(int argc, char** argv)
{
    const char* filename = "poc_deep_nesting.mp4";
    if (argc > 1) {
        filename = argv[1];
    }

    printf("Testing: %s\n", filename);
    printf("Attempting to read MP4 file with deeply nested atoms...\n");
    printf("(Without fix, this would crash with stack overflow)\n\n");

    /* Suppress verbose logging to keep output clean */
    MP4LogSetLevel(MP4_LOG_ERROR);

    MP4FileHandle file = MP4Read(filename);
    if (file == MP4_INVALID_FILE_HANDLE) {
        printf("PASS: MP4Read correctly rejected the deeply nested file.\n");
        return 0;
    }

    /* If we get here, the file was opened (shouldn't happen with fix) */
    printf("FAIL: File was opened despite exceeding max nesting depth.\n");
    MP4Close(file, 0);

    return 1;
}
