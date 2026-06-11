/*
 * Test harness for POC: Integer underflow in MP4DataAtom::Read()
 *
 * This program attempts to read the malformed MP4 file.
 * - Without fix: crashes (OOM trying to allocate ~4GB) or heap overflow
 * - With fix: prints error message and exits cleanly
 */

#include <cstdio>
#include <cstdlib>
#include <mp4v2/mp4v2.h>

int main(int argc, char** argv)
{
    const char* filename = "poc_meta_underflow.mp4";
    if (argc > 1) {
        filename = argv[1];
    }

    printf("Testing: %s\n", filename);
    printf("Attempting to read malformed MP4 file...\n");

    /* Suppress verbose logging to keep output clean */
    MP4LogSetLevel(MP4_LOG_ERROR);

    MP4FileHandle file = MP4Read(filename);
    if (file == MP4_INVALID_FILE_HANDLE) {
        printf("PASS: MP4Read correctly rejected the malformed file.\n");
        return 0;
    }

    /* If we get here, the file was opened (shouldn't happen with fix) */
    printf("WARNING: File was opened despite being malformed.\n");
    MP4Close(file, 0);

    return 1;
}
