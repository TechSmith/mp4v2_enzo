# mp4v2 Vulnerability Audit

## Status

- **Commit `2becd16`**: Fixed Vuln #1 and #2 (integer underflow in metadata atom parsing)
- **Latest**: Fixed Vuln #3 (recursion depth limit in ReadAtom), Vuln #4 (table entry count validation), Vuln #5 (overflow-checked multiplication in GetSampleSize)
- **Remaining**: 10 vulnerabilities unfixed (see below)

## Build Instructions

```bash
mkdir build && cmake -S . -B build -DBUILD_UTILS=OFF && cmake --build build -j8
```

Test harness for all fixed vulnerabilities:
```bash
./build/mp4v2_test
# Expected: all tests PASS
```

---

## Fixed Vulnerabilities

### Vuln #1 & #2: Integer Underflow in Metadata Atom Parsing

**Fixed in commit `2becd16`**

**Files:** `src/atom_meta.cpp`, `src/atom_sdtp.cpp`

**Affected atoms and their subtraction constants:**
| Atom Class | Location | Expression | Min required `m_size` |
|---|---|---|---|
| `MP4DataAtom` | `atom_meta.cpp:49` | `m_size - 8` | 8 |
| `MP4ItmfHdlrAtom` | `atom_meta.cpp:98` | `m_size - 24` | 24 |
| `MP4MeanAtom` | `atom_meta.cpp:114` | `m_size - 4` | 4 |
| `MP4NameAtom` | `atom_meta.cpp:130` | `m_size - 4` | 4 |
| `MP4SdtpAtom` | `atom_sdtp.cpp:41` | `m_size - 4` | 4 |

**Fix:** Added `if (m_size < N) throw new EXCEPTION(...)` before each subtraction.

**POC:** `test/poc_meta_underflow.mp4` (107 bytes) - triggers via `MP4Read()`.

---

### Vuln #3: No Recursion Depth Limit (Stack Overflow)

**Fixed in:** `src/mp4atom.cpp`

**Problem:** `ReadChildAtoms()` -> `ReadAtom()` -> `Read()` -> `ReadChildAtoms()` is fully recursive with no depth cap. Minimum atom size is 8 bytes, so a 100KB file can nest ~12,000 levels deep, crashing via stack overflow.

**Fix:** Added a depth check at the top of `ReadAtom()` that throws an exception if `pParentAtom->GetDepth() >= 64`. Uses the pre-existing `GetDepth()` method which walks parent pointers.

**POC:** `test/poc_deep_nesting.mp4` (580 bytes) - 70 levels of nested `moof` container atoms.

---

### Vuln #4: Unbounded Table Allocation from File-Controlled entryCount

**Fixed in:** `src/mp4property.cpp`

**Problem:** `MP4TableProperty::Read()` calls `GetCount()` which returns the `entryCount` field read directly from file metadata (e.g., `stsz.sampleCount`, `stsc.entryCount`). No validation against remaining atom size. A count of 0x3FFFFFFF with 4-byte entries = ~4GB allocation from a tiny file.

**Affected atoms:** `stsz`, `stsc`, `stts`, `ctts`, `stss`, `stco`, `co64`, `elst`, any atom using `MP4TableProperty`.

**Fix:** Added validation in `MP4TableProperty::Read()` that computes the minimum bytes per entry from the table's sub-property types and checks `numEntries * minEntrySize <= remaining atom bytes` before allocating.

**POC:** `test/poc_table_alloc.mp4` (80 bytes) - `stco` atom with `entryCount=0x3FFFFFFF` but only 4 bytes of data.

---

### Vuln #5: Integer Overflow in GetSampleSize Multiplication

**Fixed in:** `src/mp4track.cpp`

**Problem:** Both `fixedSampleSize` (from `stsz.sampleSize`) and `m_bytesPerSample` (from audio channel/bitdepth metadata) are attacker-controlled `uint32_t`. Their product can overflow to 0 or a small value. When used as allocation size in `ReadSample`, a small allocation is followed by a read of the "real" amount, causing a heap overflow. Same issue in `GetMaxSampleSize()`.

**Fix:** All multiplications of sample size by `m_bytesPerSample` in `GetSampleSize()` and `GetMaxSampleSize()` now use `uint64_t` intermediate and throw an exception if the result exceeds `UINT32_MAX`:
```cpp
uint64_t result = (uint64_t)fixedSampleSize * m_bytesPerSample;
if (result > UINT32_MAX)
    throw new EXCEPTION("sample size overflow");
return (uint32_t)result;
```

**POC:** `test/poc_sample_size_overflow.mp4` (530 bytes) - `twos` audio track with `channels=2`, `sampleSize=16` (`m_bytesPerSample=4`) and `stsz.sampleSize=0x40000001` (product = 0x100000004, overflows uint32).

---

## Remaining Vulnerabilities (Unfixed)

### Vuln #6: Integer Overflow in sampleOffset Accumulation [HIGH]

**File:** `src/mp4track.cpp:1010-1018`

**Code:**
```cpp
uint32_t sampleOffset = 0;

// ...
for (MP4SampleId i = startSample; i < sampleId; i++) {
    sampleOffset += GetSampleSize(i);  // wraps uint32 with many large samples
}

// Used at line 1025:
return chunkOffset + sampleOffset;  // wrong file position
```

**Problem:** Accumulated sample sizes wrap `uint32_t`, producing a small offset. Combined with `chunkOffset` (from `stco`/`co64`, also attacker-controlled), this yields an arbitrary file seek position.

**Fix:** Use `uint64_t sampleOffset` and validate the final offset against file size:
```cpp
uint64_t sampleOffset = 0;
for (MP4SampleId i = startSample; i < sampleId; i++) {
    sampleOffset += GetSampleSize(i);
}
uint64_t fileOffset = chunkOffset + sampleOffset;
if (fileOffset > m_File.GetSize())
    throw new EXCEPTION("sample offset exceeds file size");
return fileOffset;
```

---

### Vuln #7: MP4Realloc Takes uint32_t (Systemic Truncation) [HIGH]

**File:** `src/mp4util.h:81`

**Code:**
```cpp
inline void* MP4Realloc(void* p, uint32_t newSize) {
    // ...
    void* temp = realloc(p, newSize);
    // ...
}
```

**Problem:** Multiple callers pass `uint64_t` values that are silently truncated:
- `src/mp4file_io.cpp:152` - `m_memoryBufferSize` is `uint64_t`
- `src/mp4array.h:92` - `newSize * sizeof(type)` is a `uint64_t` expression

When truncated, a much smaller buffer is allocated, then writes overflow it.

**Fix:** Change signature to `size_t`:
```cpp
inline void* MP4Realloc(void* p, size_t newSize) {
```
Then audit all call sites for correctness. The `MP4Array::Resize` overflow check at `mp4array.h:90` should be updated to match.

---

### Vuln #8: Uncontrolled Allocation from Sample Size Metadata [HIGH]

**File:** `src/mp4track.cpp:312-323`

**Code:**
```cpp
uint32_t sampleSize = GetSampleSize(sampleId);  // from file metadata
// ...
*pNumBytes = sampleSize;
// ...
if (*ppBytes == NULL) {
    *ppBytes = (uint8_t*)MP4Malloc(*pNumBytes);  // up to 4GB
}
```

**Problem:** No upper-bound validation on `sampleSize` before allocating. A file can claim any sample is ~4GB.

**Fix:** Add a configurable maximum sample size (e.g., 256MB) or at minimum validate against file size:
```cpp
uint32_t sampleSize = GetSampleSize(sampleId);
if (sampleSize > m_File.GetSize())
    throw new EXCEPTION("sample size exceeds file size");
```

---

### Vuln #9: No File Bounds Validation on Seek Position [HIGH]

**File:** `src/mp4track.cpp:310,329`

**Code:**
```cpp
uint64_t fileOffset = GetSampleFileOffset(sampleId);
// ...
m_File.SetPosition( fileOffset, fin );
m_File.ReadBytes( *ppBytes, *pNumBytes, fin );
```

**Problem:** `fileOffset` derives from `stco`/`co64` chunk offsets (entirely attacker-controlled) plus the overflowable `sampleOffset`. No check that the position is within the file before seeking and reading.

**Fix:** Validate before seek:
```cpp
uint64_t fileOffset = GetSampleFileOffset(sampleId);
if (fileOffset + *pNumBytes > m_File.GetSize())
    throw new EXCEPTION("sample read would exceed file bounds");
m_File.SetPosition( fileOffset, fin );
```

---

### Vuln #10: Integer Overflow in ReadString Allocation Doubling [MEDIUM]

**File:** `src/mp4file_io.cpp:354`

**Code:**
```cpp
uint32_t alloced = 64;
// ...
do {
    if (length == alloced) {
        data = (char*) MP4Realloc(data, alloced * 2);  // overflows at 0x80000000
        if (data == NULL)
            return NULL;
        alloced *= 2;  // wraps to 0
    }
    ReadBytes((uint8_t*) &data[length], 1);
    length++;
} while (data[length - 1] != 0);
```

**Problem:** When `alloced` reaches `0x80000000`, `alloced * 2` wraps to 0. `MP4Realloc(data, 0)` frees `data` (implementation-defined), then writes continue to freed memory.

**Fix:** Check for overflow before doubling, or cap string length:
```cpp
if (alloced > UINT32_MAX / 2)
    throw new EXCEPTION("string too long");
alloced *= 2;
data = (char*) MP4Realloc(data, alloced);
```

---

### Vuln #11: Integer Underflow in ReadCountedString Padding [MEDIUM]

**File:** `src/mp4file_io.cpp:424`

**Code:**
```cpp
uint32_t byteLength = charLength * charSize;
// ...
if (fixedLength) {
    const uint8_t padsize = fixedLength - byteLength - 1U;  // underflow!
    if (padsize) {
        uint8_t* padbuf = (uint8_t*) MP4Malloc(padsize);
        ReadBytes(padbuf, padsize);
```

**Problem:** The check at line 401 compares `charLength >= fixedLength` but doesn't account for `byteLength = charLength * charSize` when `charSize > 1`. With `charSize=2`, `charLength=5`, `fixedLength=10`: passes check (5 < 10) but `byteLength=10`, so `padsize = 10 - 10 - 1 = 255` (uint8 wrap). Reads 255 extra bytes.

**Fix:**
```cpp
if (fixedLength && byteLength + 1 < fixedLength) {
    const uint8_t padsize = fixedLength - byteLength - 1U;
    // ...
}
```

---

### Vuln #12: stsc firstSample Integer Overflow [MEDIUM]

**File:** `src/atom_stsc.cpp:78-80`

**Code:**
```cpp
for (uint32_t i = 0; i < count; i++) {
    pFirstSample->SetValue(sampleId, i);
    if (i < count - 1) {
        sampleId +=
            (pFirstChunk->GetValue(i+1) - pFirstChunk->GetValue(i))
            * pSamplesPerChunk->GetValue(i);  // both values attacker-controlled, product overflows
    }
}
```

**Problem:** The multiplication `(chunk_diff) * samplesPerChunk` overflows uint32, corrupting the `firstSample` lookup table used for all subsequent sample-to-chunk mapping. Downstream, out-of-bounds array accesses occur.

**Fix:** Overflow-checked arithmetic:
```cpp
uint64_t delta = (uint64_t)(pFirstChunk->GetValue(i+1) - pFirstChunk->GetValue(i))
                 * pSamplesPerChunk->GetValue(i);
if (delta > UINT32_MAX - sampleId)
    throw new EXCEPTION("stsc firstSample overflow");
sampleId += (uint32_t)delta;
```

---

### Vuln #13: uint64 to uint32 Truncation for Unknown Atom dataSize [MEDIUM]

**File:** `src/mp4atom.cpp:194-195`

**Code:**
```cpp
if (dataSize > 0) {
    pAtom->AddProperty(
        new MP4BytesProperty(*pAtom, "data", dataSize));  // dataSize is uint64_t, ctor takes uint32_t
}
```

**Problem:** `dataSize` can exceed 4GB with extended-size atoms (64-bit size field). The `MP4BytesProperty` constructor takes `uint32_t valueSize`, silently truncating. Creates size inconsistency between `m_end` and actual bytes to read.

**Fix:** Check before creating the property:
```cpp
if (dataSize > UINT32_MAX)
    throw new EXCEPTION("unknown atom too large for BytesProperty");
pAtom->AddProperty(
    new MP4BytesProperty(*pAtom, "data", (uint32_t)dataSize));
```
Or better: skip reading data for atoms > 4GB and just seek past them.

---

### Vuln #14: trun Flags-Based Parsing with Unbounded sampleCount [HIGH]

**File:** `src/atom_trun.cpp:72-83`

**Code:**
```cpp
void MP4TrunAtom::Read()
{
    /* read atom version, flags, and sampleCount */
    ReadProperties(0, 3);

    /* need to create the properties based on the atom flags */
    AddProperties(GetFlags());

    /* now we can read the remaining properties */
    ReadProperties(3);

    Skip(); // to end of atom
}
```

**Context (AddProperties at lines 52-69):** Creates table properties with columns based on `flags`. With all flags (0x100|0x200|0x400|0x800), each entry = 16 bytes. `sampleCount` (property index 2) is read from file as uint32, drives table size via `MP4TableProperty::Read` -> `GetCount()`.

**Problem:** Same root cause as Vuln #4 but via `trun`. A `sampleCount` of 0x10000000 with all flags set requests 4 arrays of 256M entries each (~4GB total).

**Fix:** Same approach as Vuln #4 - validate count against remaining atom size before allocation.

---

### Vuln #15: 4-Bit Sample Size Wrong Nibble Selection [MEDIUM]

**File:** `src/mp4track.cpp:641-646`

**Code:**
```cpp
if (m_stsz_sample_bits == 4) {
    uint8_t value = m_pStszSampleSizeProperty->GetValue((sampleId - 1) / 2);
    if ((sampleId - 1) / 2 == 0) {  // BUG: only matches sampleId=1
        value >>= 4;
    } else value &= 0xf;
    return m_bytesPerSample * value;
}
```

**Problem:** The condition `(sampleId - 1) / 2 == 0` only matches `sampleId == 1`. The intent is to select the high nibble for even-indexed samples and low nibble for odd-indexed. The correct condition should be `(sampleId - 1) % 2 == 0`. For all `sampleId > 2` with even index, the wrong nibble is returned, producing incorrect sample sizes that feed into allocation and file offset logic.

**Fix:**
```cpp
if ((sampleId - 1) % 2 == 0) {
    value >>= 4;   // high nibble for even-indexed samples
} else {
    value &= 0xf;  // low nibble for odd-indexed samples
}
```

---

## Architectural Recommendations

These are systemic issues that individual fixes alone won't fully address:

1. **Change `MP4Realloc` to take `size_t`** - fixes the truncation class of bugs everywhere at once.

2. **Add a max allocation cap** (configurable, default ~256MB) in `MP4Malloc`/`MP4Realloc` - prevents all OOM DoS attacks from malicious files regardless of which code path triggers them.

3. **Add recursion depth limit** in `ReadAtom` - a single check prevents all stack overflow variants.

4. **Validate all table entry counts** against `remaining_atom_bytes / min_entry_size` - a generic check in `MP4TableProperty::Read` fixes all table atoms at once.

5. **Validate file offsets** from `stco`/`co64` against actual file size in `GetSampleFileOffset` - prevents arbitrary position reads.

6. **Use overflow-checked arithmetic** (`__builtin_mul_overflow` / `__builtin_add_overflow`) for all uint32 multiplications on file-controlled values.
