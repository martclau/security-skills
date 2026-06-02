/*
   YARA rule template — encodes this skill's four house rules:
     1. All six meta fields, in order: author, date, description, hash, reference, version
     2. Condition opens with a header check AND a filesize guard (anti-FP on swap/dump/disk images)
     3. No imports — structural checks use raw uintXX() only
     4. Strings specific enough to survive a goodware corpus

   Replace every <...> placeholder. Delete the guidance comments before shipping.
   Naming: {CATEGORY}_{PLATFORM}_{FAMILY}_{DETAIL}_{MonthYear}
*/

rule MAL_Win_Family_Detail_MonthYear {
    meta:
        author      = "<Name / Handle / Org>"                 // no URLs; comma-separate multiples
        date         = "<YYYY-MM-DD>"                           // original creation date
        description = "Detects <what> via <how>"               // starts with "Detects", 60-400 chars, no URLs
        hash         = "<sha256-of-the-matched-sample>"         // SHA256 of the file the rule matches; never fabricate
        reference   = "<https://stable-public-url | Internal Research>"
        version     = "1.0"                                    // bump on any logic change
        // optional-only-after-the-six: score = 75  tags = "..."  modified = "YYYY-MM-DD"

    strings:
        // $x = highly specific (one alone is strong evidence)
        $x1 = "<unique mutex / attacker handle / config magic>" ascii wide

        // $s = grouped (meaningful only together)
        $s1 = "<malware-specific token, >= 6 bytes>" ascii
        $s2 = "<another family token>" ascii

        // $a = auxiliary / pre-selection (narrows file type, not a threat signal)
        // $a1 = "<format marker>" ascii

        // $fp = benign markers; if matched, suppress the rule (import-free signed-vendor carve-out)
        // $fp1 = "<Legitimate Vendor / Copyright string>" ascii wide

    condition:
        // ---- House Rule 2: mandatory header + filesize guard (both, first) ----
        uint16(0) == 0x5A4D       // PE "MZ" header — anchor to a real PE (no pe module)
        and filesize < 5MB        // reject swap files, memory dumps, disk images
        // ---- detection logic ----
        and (
            1 of ($x*)
            or all of ($s*)
        )
        // ---- false-positive filter ----
        // and not any of ($fp*)
}

/*
   Header alternatives (House Rule 3 — raw bytes, pick the one matching your target):
     PE   : uint16(0) == 0x5A4D
     PE+sig: uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550   // "PE\0\0"
     ELF  : uint32(0) == 0x464C457F
     MachO: uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or uint32(0) == 0xCAFEBABE or uint32(0) == 0xBEBAFECA
     ZIP/OOXML/APK/JAR: uint32(0) == 0x04034B50
     PDF  : uint32(0) == 0x46445025

   No reliable magic (loose JS / some scripts)? Keep the filesize guard,
   add an extra-tight unique anchor string, and comment why there is no header check.
*/
