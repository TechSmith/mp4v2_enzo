/*
 * Test harness for POC: Unbounded table allocation (Vuln #4)
 *
 * This program attempts to read the malformed MP4 file with a bogus entryCount.
 * - Without fix: crashes (OOM trying to allocate ~4GB)
 * - With fix: prints error message and exits cleanly
 */

#include <cstdio>
#include <cstdlib>
#include <mp4v2/mp4v2.h>

int main(int argc, char** argv)
{
    const char* filename = "poc_table_alloc.mp4";
    if (argc > 1) {
        filename = argv[1];
    }

    printf("Testing: %s\n", filename);
    printf("Attempting to read MP4 file with bogus table entry count...\n");
    printf("(Without fix, this would attempt a ~4GB allocation)\n\n");

    /* Suppress verbose logging to keep output clean */
    MP4LogSetLevel(MP4_LOG_ERROR);

    MP4FileHandle file = MP4Read(filename);
    if (file == MP4_INVALID_FILE_HANDLE) {
        printf("PASS: MP4Read correctly rejected the malformed file.\n");
        return 0;
    }

    /* If we get here, the file was opened (shouldn't happen with fix) */
    printf("FAIL: File was opened despite having bogus entry count.\n");
    MP4Close(file, 0);

    return 1;
}
