/// Known binary file magic bytes → (MIME, FileCategory).
///
/// Each entry: `(prefix_bytes, mime, category)`.
/// Checked in order; first match wins.
pub(crate) static MAGIC_TABLE: &[(&[u8], &str, &str)] = &[
    // ── Images ──────────────────────────────────────────────────────────
    (b"\x89PNG\r\n\x1a\n", "image/png", "image"),
    (b"\xff\xd8\xff", "image/jpeg", "image"),
    (b"GIF87a", "image/gif", "image"),
    (b"GIF89a", "image/gif", "image"),
    (b"RIFF", "image/webp", "image"), // RIFF....WEBP — refined below
    (b"BM", "image/bmp", "image"),
    (b"\x00\x00\x01\x00", "image/x-icon", "image"),
    (b"II\x2a\x00", "image/tiff", "image"), // TIFF little-endian
    (b"MM\x00\x2a", "image/tiff", "image"), // TIFF big-endian
    // ── Audio ───────────────────────────────────────────────────────────
    (b"ID3", "audio/mpeg", "audio"),
    (b"\xff\xfb", "audio/mpeg", "audio"),
    (b"\xff\xf3", "audio/mpeg", "audio"),
    (b"\xff\xf2", "audio/mpeg", "audio"),
    (b"fLaC", "audio/flac", "audio"),
    (b"OggS", "audio/ogg", "audio"),
    // ── Video ───────────────────────────────────────────────────────────
    (b"\x1a\x45\xdf\xa3", "video/webm", "video"), // EBML (Matroska/WebM)
    // ── Documents / Archives ────────────────────────────────────────────
    (b"%PDF", "application/pdf", "document"),
    // OLE2 Compound Document (doc/xls/ppt) — refined by classify_ole()
    (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        "application/x-ole-storage",
        "document",
    ),
    // ── Executables / Binary formats ────────────────────────────────────
    (b"\x7fELF", "application/x-elf", "binary"),
    (b"MZ", "application/x-dosexec", "binary"),
    (b"\xca\xfe\xba\xbe", "application/x-mach-binary", "binary"),
    (b"\xfe\xed\xfa", "application/x-mach-binary", "binary"),
    (b"\xcf\xfa\xed\xfe", "application/x-mach-binary", "binary"),
    // ── Bytecodes ───────────────────────────────────────────────────────
    (b"\x1bLua", "application/x-lua-bytecode", "binary"),
    (b"\xca\xfe\xba\xbe", "application/java-archive", "binary"), // Java class
    // ── Archives ────────────────────────────────────────────────────────
    (b"\x1f\x8b", "application/gzip", "archive"),
    (b"BZh", "application/x-bzip2", "archive"),
    (b"\xfd7zXZ\x00", "application/x-xz", "archive"),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", "archive"),
    (b"Rar!\x1a\x07", "application/x-rar-compressed", "archive"),
    // ── Fonts ───────────────────────────────────────────────────────────
    (b"\x00\x01\x00\x00", "font/sfnt", "font"), // TrueType
    (b"OTTO", "font/otf", "font"),
    (b"wOFF", "font/woff", "font"),
    (b"wOF2", "font/woff2", "font"),
    // ── Databases ───────────────────────────────────────────────────────
    (b"SQLite format 3\x00", "application/x-sqlite3", "binary"),
];

/// Check the RIFF container subtype (at offset 8).
pub(crate) fn refine_riff(buf: &[u8]) -> Option<(&'static str, &'static str)> {
    if buf.len() < 12 {
        return None;
    }
    match &buf[8..12] {
        b"WEBP" => Some(("image/webp", "image")),
        b"AVI " => Some(("video/x-msvideo", "video")),
        b"WAVE" => Some(("audio/wav", "audio")),
        _ => None,
    }
}

/// ZIP-based formats: inspect internal file names to distinguish
/// docx / xlsx / pptx / epub / jar / odt / ods / odp / generic zip.
pub(crate) fn classify_zip(buf: &[u8]) -> (&'static str, &'static str) {
    // ZIP local file header: PK\x03\x04, filename at offset 30
    // We scan the first ~8KB for known internal paths.
    let haystack = if buf.len() > 8192 { &buf[..8192] } else { buf };
    let s = String::from_utf8_lossy(haystack);

    if s.contains("word/") {
        return (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "document",
        );
    }
    if s.contains("xl/") {
        return (
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "spreadsheet",
        );
    }
    if s.contains("ppt/") {
        return (
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "presentation",
        );
    }
    if s.contains("META-INF/container.xml") || s.contains("mimetype") && s.contains("epub") {
        return ("application/epub+zip", "document");
    }
    if s.contains("content.xml") {
        // ODF formats
        if s.contains("office:spreadsheet") {
            return ("application/vnd.oasis.opendocument.spreadsheet", "spreadsheet");
        }
        if s.contains("office:presentation") {
            return ("application/vnd.oasis.opendocument.presentation", "presentation");
        }
        return ("application/vnd.oasis.opendocument.text", "document");
    }
    if s.contains("META-INF/MANIFEST.MF") {
        return ("application/java-archive", "archive");
    }

    ("application/zip", "archive")
}

/// OLE2 Compound Document classification: distinguish .doc / .xls / .ppt
/// by scanning for well-known internal stream names in the raw bytes.
pub(crate) fn classify_ole(buf: &[u8]) -> (&'static str, &'static str) {
    let haystack = if buf.len() > 8192 { &buf[..8192] } else { buf };
    let s = String::from_utf8_lossy(haystack);

    // Word documents contain "W\0o\0r\0d\0D\0o\0c\0u\0m\0e\0n\0t" (UTF-16LE)
    if contains_utf16le(haystack, b"WordDocument") || s.contains("WordDocument") {
        return ("application/msword", "document");
    }
    // Excel files contain "W\0o\0r\0k\0b\0o\0o\0k" (UTF-16LE)
    if contains_utf16le(haystack, b"Workbook") || contains_utf16le(haystack, b"Book") {
        return ("application/vnd.ms-excel", "spreadsheet");
    }
    // PowerPoint files contain specific stream names
    if contains_utf16le(haystack, b"PowerPoint Document") || contains_utf16le(haystack, b"Current User") {
        return ("application/vnd.ms-powerpoint", "presentation");
    }

    // Fallback: generic OLE, still a document
    ("application/x-ole-storage", "document")
}

/// Check if `needle` (ASCII) appears as UTF-16LE inside `haystack`.
fn contains_utf16le(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    let utf16_len = needle.len() * 2;
    if haystack.len() < utf16_len {
        return false;
    }
    'outer: for start in 0..=(haystack.len() - utf16_len) {
        for (i, &b) in needle.iter().enumerate() {
            if haystack[start + i * 2] != b || haystack[start + i * 2 + 1] != 0 {
                continue 'outer;
            }
        }
        return true;
    }
    false
}

/// ftyp-box based detection for MP4/MOV/M4A containers.
pub(crate) fn classify_ftyp(buf: &[u8]) -> Option<(&'static str, &'static str)> {
    // ISO BMFF: offset 4..8 == "ftyp", brand at 8..12
    if buf.len() < 12 {
        return None;
    }
    if &buf[4..8] != b"ftyp" {
        return None;
    }
    let brand = &buf[8..12];
    match brand {
        b"M4A " | b"M4B " => Some(("audio/mp4", "audio")),
        b"qt  " => Some(("video/quicktime", "video")),
        _ => Some(("video/mp4", "video")),
    }
}
