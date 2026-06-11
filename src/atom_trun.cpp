/*
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * The Original Code is MPEG4IP.
 *
 * The Initial Developer of the Original Code is Cisco Systems Inc.
 * Portions created by Cisco Systems Inc. are
 * Copyright (C) Cisco Systems Inc. 2001.  All Rights Reserved.
 *
 * Contributor(s):
 *      Dave Mackie     dmackie@cisco.com
 */

#include "src/impl.h"

namespace mp4v2 {
namespace impl {

///////////////////////////////////////////////////////////////////////////////

MP4TrunAtom::MP4TrunAtom(MP4File &file)
        : MP4Atom(file, "trun")
{
    AddVersionAndFlags();   /* 0, 1 */
    AddProperty( /* 2 */
        new MP4Integer32Property(*this, "sampleCount"));
}

void MP4TrunAtom::AddProperties(uint32_t flags)
{
    if (flags & 0x01) {
        // Note this is a signed 32 value
        AddProperty(
            new MP4Integer32Property(*this, "dataOffset"));
    }
    if (flags & 0x04) {
        AddProperty(
            new MP4Integer32Property(*this, "firstSampleFlags"));
    }

    MP4TableProperty* pTable =
        new MP4TableProperty(*this, "samples",
                             (MP4Integer32Property *)m_pProperties[2]);
    AddProperty(pTable);

    if (flags & 0x100) {
        pTable->AddProperty(
            new MP4Integer32Property(*this, "sampleDuration"));
    }
    if (flags & 0x200) {
        pTable->AddProperty(
            new MP4Integer32Property(*this, "sampleSize"));
    }
    if (flags & 0x400) {
        pTable->AddProperty(
            new MP4Integer32Property(*this, "sampleFlags"));
    }
    if (flags & 0x800) {
        pTable->AddProperty(
            new MP4Integer32Property(*this, "sampleCompositionTimeOffset"));
    }
}

void MP4TrunAtom::Read()
{
    /* read atom version, flags, and sampleCount */
    ReadProperties(0, 3);

    // Vuln #14 fix: validate sampleCount against actual remaining data.
    // The Vuln #4 fix in MP4TableProperty::Read() validates against the atom's
    // declared size (m_end), but a malicious file can set a large atom size in
    // the header. We additionally validate against the real file size here.
    uint32_t flags = GetFlags();
    uint32_t sampleCount =
        ((MP4Integer32Property*)m_pProperties[2])->GetValue();
    if (sampleCount > 0) {
        // Compute bytes per entry based on which flags are set
        uint32_t bytesPerEntry = 0;
        if (flags & 0x100) bytesPerEntry += 4;  // sampleDuration
        if (flags & 0x200) bytesPerEntry += 4;  // sampleSize
        if (flags & 0x400) bytesPerEntry += 4;  // sampleFlags
        if (flags & 0x800) bytesPerEntry += 4;  // sampleCompositionTimeOffset

        if (bytesPerEntry > 0) {
            uint64_t requiredBytes = (uint64_t)sampleCount * bytesPerEntry;
            uint64_t fileSize = m_File.GetSize();
            uint64_t currentPos = m_File.GetPosition();
            uint64_t remaining = (currentPos < fileSize) ? fileSize - currentPos : 0;
            if (requiredBytes > remaining) {
                ostringstream oss;
                oss << "trun sampleCount " << sampleCount
                    << " requires " << requiredBytes
                    << " bytes but only " << remaining << " remain in file";
                throw new EXCEPTION(oss.str().c_str());
            }
        }
    }

    /* need to create the properties based on the atom flags */
    AddProperties(flags);

    /* now we can read the remaining properties */
    ReadProperties(3);

    Skip(); // to end of atom
}

///////////////////////////////////////////////////////////////////////////////

}
} // namespace mp4v2::impl
