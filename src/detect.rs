use std::path::Path;

use chardetng::{EncodingDetector, Iso2022JpDetection, Utf8Detection};
use tokio::io::AsyncReadExt;

use crate::magic;

/// Maximum bytes to sample for detection. 8 KB is enough for magic bytes,
/// encoding detection, and language heuristics.
const SAMPLE_SIZE: usize = 8192;

/// Detected file type information.
#[derive(Debug, Clone)]
pub struct FileTypeInfo {
    /// Whether the file is binary (vs plain text).
    pub is_binary: bool,
    /// Detected MIME type.
    pub mime: String,
    /// High-level file category.
    pub category: FileCategory,
    /// Text encoding (only for text files, e.g. "UTF-8", "GBK").
    pub encoding: Option<String>,
    /// Detected programming language (only for text files, e.g. "lua", "python").
    pub language: Option<String>,
    /// Detection confidence 0.0–1.0.
    pub confidence: f32,
}

/// High-level file category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileCategory {
    Text,
    Image,
    Video,
    Audio,
    Document,
    Spreadsheet,
    Presentation,
    Archive,
    Font,
    Binary,
    Unknown,
}

impl FileCategory {
    fn from_str(s: &str) -> Self {
        match s {
            "text" => Self::Text,
            "image" => Self::Image,
            "video" => Self::Video,
            "audio" => Self::Audio,
            "document" => Self::Document,
            "spreadsheet" => Self::Spreadsheet,
            "presentation" => Self::Presentation,
            "archive" => Self::Archive,
            "font" => Self::Font,
            "binary" => Self::Binary,
            _ => Self::Unknown,
        }
    }

    /// Lowercase string form suitable for database storage.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Image => "image",
            Self::Video => "video",
            Self::Audio => "audio",
            Self::Document => "document",
            Self::Spreadsheet => "spreadsheet",
            Self::Presentation => "presentation",
            Self::Archive => "archive",
            Self::Font => "font",
            Self::Binary => "binary",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for FileCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─── Public API ──────────────────────────────────────────────────────────────

/// Detect file type from an async reader (reads up to 8 KB).
///
/// `filename` is optional but improves accuracy via extension fallback.
pub async fn detect_file(reader: &mut (impl tokio::io::AsyncRead + Unpin), filename: Option<&str>) -> FileTypeInfo {
    let mut buf = vec![0u8; SAMPLE_SIZE];
    let Ok(n) = reader.read(&mut buf).await else {
        return unknown_info();
    };
    buf.truncate(n);
    detect_buffer(&buf, filename)
}

/// Detect file type from an in-memory buffer.
///
/// `filename` is optional but improves accuracy via extension fallback.
#[must_use]
pub fn detect_buffer(buf: &[u8], filename: Option<&str>) -> FileTypeInfo {
    if buf.is_empty() {
        return FileTypeInfo {
            is_binary: false,
            mime: "text/plain".into(),
            category: FileCategory::Text,
            encoding: Some("UTF-8".into()),
            language: None,
            confidence: 0.5,
        };
    }

    // Step 1: Magic bytes
    if let Some(info) = try_magic(buf) {
        return info;
    }

    // Step 2: ftyp box (MP4/MOV/M4A)
    if let Some((mime, cat)) = magic::classify_ftyp(buf) {
        return FileTypeInfo {
            is_binary: true,
            mime: mime.into(),
            category: FileCategory::from_str(cat),
            encoding: None,
            language: None,
            confidence: 0.9,
        };
    }

    // Step 3: Binary vs text heuristic
    if is_likely_binary(buf) {
        return binary_fallback(buf, filename);
    }

    // Step 4: It's text — detect encoding + language
    text_detection(buf, filename)
}

// ─── Internal ────────────────────────────────────────────────────────────────

fn try_magic(buf: &[u8]) -> Option<FileTypeInfo> {
    // RIFF container — refine subtype
    if buf.starts_with(b"RIFF")
        && let Some((mime, cat)) = magic::refine_riff(buf)
    {
        return Some(FileTypeInfo {
            is_binary: true,
            mime: mime.into(),
            category: FileCategory::from_str(cat),
            encoding: None,
            language: None,
            confidence: 0.95,
        });
    }

    // ZIP container — distinguish Office / EPUB / JAR / plain zip
    if buf.starts_with(b"PK\x03\x04") {
        let (mime, cat) = magic::classify_zip(buf);
        return Some(FileTypeInfo {
            is_binary: true,
            mime: mime.into(),
            category: FileCategory::from_str(cat),
            encoding: None,
            language: None,
            confidence: 0.9,
        });
    }

    // OLE2 Compound Document — distinguish .doc / .xls / .ppt
    if buf.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
        let (mime, cat) = magic::classify_ole(buf);
        return Some(FileTypeInfo {
            is_binary: true,
            mime: mime.into(),
            category: FileCategory::from_str(cat),
            encoding: None,
            language: None,
            confidence: 0.9,
        });
    }

    // Simple prefix match
    for &(prefix, mime, cat) in magic::MAGIC_TABLE {
        if buf.starts_with(prefix) {
            return Some(FileTypeInfo {
                is_binary: true,
                mime: mime.into(),
                category: FileCategory::from_str(cat),
                encoding: None,
                language: None,
                confidence: 0.95,
            });
        }
    }

    None
}

/// Heuristic: if >5% of bytes are null or non-text control chars, it's binary.
fn is_likely_binary(buf: &[u8]) -> bool {
    let sample = if buf.len() > SAMPLE_SIZE {
        &buf[..SAMPLE_SIZE]
    } else {
        buf
    };
    let control_count = sample
        .iter()
        .filter(|&&b| b == 0 || (b < 0x08) || (b == 0x0e) || (b == 0x0f) || (0x1c..0x20).contains(&b))
        .count();
    let ratio = control_count as f64 / sample.len() as f64;
    ratio > 0.05
}

fn binary_fallback(_buf: &[u8], filename: Option<&str>) -> FileTypeInfo {
    // Try extension-based MIME
    let (mime, category) = filename
        .and_then(|f| {
            let guess = mime_guess::from_path(f).first()?;
            let cat = mime_to_category(guess.type_().as_str(), guess.subtype().as_str());
            Some((guess.to_string(), cat))
        })
        .unwrap_or_else(|| ("application/octet-stream".into(), FileCategory::Binary));

    FileTypeInfo {
        is_binary: true,
        mime,
        category,
        encoding: None,
        language: None,
        confidence: if filename.is_some() { 0.6 } else { 0.3 },
    }
}

fn text_detection(buf: &[u8], filename: Option<&str>) -> FileTypeInfo {
    // Encoding detection
    let mut detector = EncodingDetector::new(Iso2022JpDetection::Allow);
    detector.feed(buf, true);
    let encoding_ref = detector.guess(None, Utf8Detection::Allow);
    let encoding_name = encoding_ref.name().to_string();

    // Language detection via hyperpolyglot
    let language = detect_language(buf, filename);

    // MIME: use language hint or extension
    let mime = language
        .as_deref()
        .and_then(language_to_mime)
        .or_else(|| filename.and_then(|f| mime_guess::from_path(f).first().map(|m| m.to_string())))
        .unwrap_or_else(|| "text/plain".into());

    let category = if mime.starts_with("text/") || language.is_some() {
        FileCategory::Text
    } else {
        mime_to_category_from_string(&mime)
    };

    FileTypeInfo {
        is_binary: false,
        mime,
        category,
        encoding: Some(encoding_name),
        language,
        confidence: 0.8,
    }
}

fn detect_language(_buf: &[u8], filename: Option<&str>) -> Option<String> {
    // Filename-based detection (most reliable for programming languages)
    let name = filename?;
    let path = Path::new(name);

    // Try hyperpolyglot (reads file, so only works with real paths)
    // For buffer-only detection, fall back to extension map
    if path.exists()
        && let Ok(Some(det)) = hyperpolyglot::detect(path)
    {
        return Some(det.language().to_lowercase());
    }

    // Extension-based language mapping
    extension_to_language(path.extension()?.to_str()?)
}

fn language_to_mime(lang: &str) -> Option<String> {
    let mime = match lang {
        "javascript" | "jsx" => "text/javascript",
        "typescript" | "tsx" => "text/typescript",
        "python" => "text/x-python",
        "rust" => "text/x-rust",
        "go" => "text/x-go",
        "java" => "text/x-java",
        "c" => "text/x-c",
        "c++" | "cpp" => "text/x-c++",
        "c#" => "text/x-csharp",
        "ruby" => "text/x-ruby",
        "php" => "text/x-php",
        "swift" => "text/x-swift",
        "kotlin" => "text/x-kotlin",
        "lua" => "text/x-lua",
        "shell" | "bash" | "sh" => "text/x-shellscript",
        "sql" => "text/x-sql",
        "css" => "text/css",
        "html" => "text/html",
        "xml" => "text/xml",
        "json" => "application/json",
        "yaml" | "yml" => "text/yaml",
        "toml" => "text/x-toml",
        "markdown" => "text/markdown",
        _ => return None,
    };
    Some(mime.into())
}

fn mime_to_category(type_str: &str, subtype: &str) -> FileCategory {
    match type_str {
        "text" => FileCategory::Text,
        "image" => FileCategory::Image,
        "video" => FileCategory::Video,
        "audio" => FileCategory::Audio,
        "font" => FileCategory::Font,
        "application" => match subtype {
            "pdf" | "rtf" | "msword" | "x-ole-storage" => FileCategory::Document,
            "vnd.ms-excel" => FileCategory::Spreadsheet,
            "vnd.ms-powerpoint" => FileCategory::Presentation,
            "zip" | "gzip" | "x-tar" | "x-7z-compressed" | "x-rar-compressed" => FileCategory::Archive,
            s if s.contains("wordprocessing") || s.contains("opendocument.text") => FileCategory::Document,
            s if s.contains("spreadsheet") => FileCategory::Spreadsheet,
            s if s.contains("presentation") => FileCategory::Presentation,
            "json" | "xml" | "javascript" | "typescript" => FileCategory::Text,
            _ => FileCategory::Binary,
        },
        _ => FileCategory::Unknown,
    }
}

fn mime_to_category_from_string(mime: &str) -> FileCategory {
    let parts: Vec<&str> = mime.splitn(2, '/').collect();
    if parts.len() == 2 {
        mime_to_category(parts[0], parts[1])
    } else {
        FileCategory::Unknown
    }
}

fn extension_to_language(ext: &str) -> Option<String> {
    let lang = match ext.to_lowercase().as_str() {
        "js" | "mjs" | "cjs" => "javascript",
        "jsx" => "jsx",
        "ts" | "mts" | "cts" => "typescript",
        "tsx" => "tsx",
        "py" | "pyw" | "pyi" => "python",
        "rs" => "rust",
        "go" => "go",
        "java" => "java",
        "c" | "h" => "c",
        "cpp" | "cc" | "cxx" | "hpp" | "hxx" => "c++",
        "cs" => "c#",
        "rb" => "ruby",
        "php" => "php",
        "swift" => "swift",
        "kt" | "kts" => "kotlin",
        "lua" => "lua",
        "sh" | "bash" | "zsh" | "fish" => "shell",
        "ps1" | "psm1" => "powershell",
        "sql" => "sql",
        "css" | "scss" | "sass" | "less" => "css",
        "html" | "htm" => "html",
        "xml" | "xsl" | "xslt" | "xsd" | "svg" => "xml",
        "json" | "jsonc" | "json5" => "json",
        "yaml" | "yml" => "yaml",
        "toml" => "toml",
        "md" | "markdown" => "markdown",
        "r" | "rmd" => "r",
        "dart" => "dart",
        "scala" => "scala",
        "zig" => "zig",
        "nim" => "nim",
        "ex" | "exs" => "elixir",
        "erl" | "hrl" => "erlang",
        "hs" => "haskell",
        "ml" | "mli" => "ocaml",
        "clj" | "cljs" => "clojure",
        "pl" | "pm" => "perl",
        "vue" => "vue",
        "svelte" => "svelte",
        "tf" | "hcl" => "hcl",
        "dockerfile" => "dockerfile",
        "makefile" => "makefile",
        "cmake" => "cmake",
        "proto" => "protobuf",
        "graphql" | "gql" => "graphql",
        "ini" | "cfg" | "conf" => "ini",
        "log" | "txt" => "plaintext",
        "csv" | "tsv" => "csv",
        _ => return None,
    };
    Some(lang.into())
}

fn unknown_info() -> FileTypeInfo {
    FileTypeInfo {
        is_binary: false,
        mime: "application/octet-stream".into(),
        category: FileCategory::Unknown,
        encoding: None,
        language: None,
        confidence: 0.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_png() {
        let buf = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        let info = detect_buffer(buf, Some("test.png"));
        assert_eq!(info.mime, "image/png");
        assert_eq!(info.category, FileCategory::Image);
        assert!(info.is_binary);
    }

    #[test]
    fn detect_pdf() {
        let buf = b"%PDF-1.5 some content here";
        let info = detect_buffer(buf, Some("doc.pdf"));
        assert_eq!(info.mime, "application/pdf");
        assert_eq!(info.category, FileCategory::Document);
    }

    #[test]
    fn detect_plain_text() {
        let buf = b"Hello, world! This is plain text content.";
        let info = detect_buffer(buf, Some("readme.txt"));
        assert!(!info.is_binary);
        assert_eq!(info.category, FileCategory::Text);
        assert!(info.encoding.is_some());
    }

    #[test]
    fn detect_lua_source() {
        let buf = b"local function hello()\n  print('Hello')\nend\nhello()";
        let info = detect_buffer(buf, Some("script.lua"));
        assert!(!info.is_binary);
        assert_eq!(info.category, FileCategory::Text);
        assert_eq!(info.language.as_deref(), Some("lua"));
    }

    #[test]
    fn detect_empty() {
        let info = detect_buffer(b"", None);
        assert_eq!(info.mime, "text/plain");
        assert!(!info.is_binary);
    }

    #[test]
    fn detect_zip() {
        let buf = b"PK\x03\x04some random zip data here nothing special";
        let info = detect_buffer(buf, Some("archive.zip"));
        assert_eq!(info.category, FileCategory::Archive);
    }

    #[test]
    fn detect_docx_like() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"PK\x03\x04");
        buf.extend_from_slice(&[0u8; 26]); // padding
        buf.extend_from_slice(b"word/document.xml");
        let info = detect_buffer(&buf, Some("report.docx"));
        assert_eq!(info.category, FileCategory::Document);
        assert!(info.mime.contains("wordprocessing"));
    }

    #[test]
    fn detect_ole_doc() {
        // OLE2 header + UTF-16LE "WordDocument"
        let mut buf = vec![0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
        buf.extend_from_slice(&[0u8; 100]); // padding
        // Write "WordDocument" in UTF-16LE
        for &b in b"WordDocument" {
            buf.push(b);
            buf.push(0);
        }
        let info = detect_buffer(&buf, Some("old.doc"));
        assert_eq!(info.category, FileCategory::Document);
        assert_eq!(info.mime, "application/msword");
    }

    #[test]
    fn detect_ole_xls() {
        let mut buf = vec![0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
        buf.extend_from_slice(&[0u8; 100]);
        for &b in b"Workbook" {
            buf.push(b);
            buf.push(0);
        }
        let info = detect_buffer(&buf, Some("data.xls"));
        assert_eq!(info.category, FileCategory::Spreadsheet);
        assert_eq!(info.mime, "application/vnd.ms-excel");
    }
}
