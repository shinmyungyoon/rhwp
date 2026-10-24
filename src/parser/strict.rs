//! Bounded, non-recovering input APIs for HWP 5 and HWPX.
//!
//! These limits cover input validation, not all model or rendering allocations.
//! Applications that process untrusted documents still need process isolation.
//! The existing parsing APIs retain their recovery behavior.
//! Validation covers container structure, XML structure and core namespaces,
//! and HWP record framing. It is not full schema or semantic validation.

use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read};

use crate::model::bin_data::{BinDataContent, BinDataType};
use crate::model::document::Document;

use super::{cfb_reader, header, tags};

/// Limits for one strict document load. Byte budgets include opaque resources.
/// HWP record levels also have a fixed limit of 63. HWPX paragraph nesting
/// has a fixed limit of 16 to prevent recovery in the model parser.
#[derive(Clone, Copy, Debug)]
pub struct InputLimits {
    pub max_input_bytes: usize,
    pub max_entries: usize,
    pub max_entry_bytes: usize,
    pub max_expanded_bytes: usize,
    pub max_xml_nodes: u32,
    pub max_xml_depth: usize,
    pub max_records: usize,
    pub max_record_depth: usize,
}

impl Default for InputLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 256 * 1024 * 1024,
            max_entries: 16_384,
            max_entry_bytes: 256 * 1024 * 1024,
            max_expanded_bytes: 512 * 1024 * 1024,
            max_xml_nodes: 2_000_000,
            max_xml_depth: 128,
            max_records: 2_000_000,
            max_record_depth: 63,
        }
    }
}

#[derive(Debug)]
pub enum StrictParseError {
    LimitExceeded(&'static str),
    InvalidInput(String),
    Unsupported(&'static str),
    Parse(super::ParseError),
}

impl std::fmt::Display for StrictParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LimitExceeded(name) => write!(f, "Document input exceeds the {name} limit"),
            Self::InvalidInput(message) => write!(f, "Invalid document input: {message}"),
            Self::Unsupported(message) => write!(f, "Strict loading does not support {message}"),
            Self::Parse(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for StrictParseError {}

fn invalid(message: impl std::fmt::Display) -> StrictParseError {
    StrictParseError::InvalidInput(message.to_string())
}

/// Load HWP 5 or HWPX without container recovery or lossy XML decoding.
/// Encrypted documents and HWP 3/HML are not supported by this API.
pub fn parse_document_strict(data: &[u8]) -> Result<Document, StrictParseError> {
    parse_document_strict_with_limits(data, &InputLimits::default())
}

/// Load with caller-selected input limits. The input bytes are not modified.
pub fn parse_document_strict_with_limits(
    data: &[u8],
    limits: &InputLimits,
) -> Result<Document, StrictParseError> {
    if data.len() > limits.max_input_bytes {
        return Err(StrictParseError::LimitExceeded("raw input bytes"));
    }
    let mut document = if data.starts_with(b"PK\x03\x04") {
        parse_hwpx(data, limits)?
    } else if data.starts_with(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1") {
        parse_hwp(data, limits)?
    } else {
        return Err(StrictParseError::Unsupported("this file format"));
    };
    if document.sections.iter().any(|section| {
        section.paragraphs.iter().any(|paragraph| {
            paragraph.line_segs.len() > paragraph.text.chars().count().saturating_add(64)
        })
    }) {
        return Err(invalid("inconsistent paragraph line segment count"));
    }
    document
        .doc_info
        .seal_raw_provenance(&document.doc_properties);
    document.seal_body_raw_provenance();
    Ok(document)
}

struct Budget {
    bytes: usize,
    nodes: u32,
    records: usize,
}

impl Budget {
    fn new(limits: &InputLimits) -> Self {
        Self {
            bytes: limits.max_expanded_bytes,
            nodes: limits.max_xml_nodes,
            records: limits.max_records,
        }
    }

    fn read(
        &mut self,
        reader: impl Read,
        limits: &InputLimits,
    ) -> Result<Vec<u8>, StrictParseError> {
        let allowance = self.bytes.min(limits.max_entry_bytes);
        let mut output = Vec::new();
        reader
            .take((allowance as u64).saturating_add(1))
            .read_to_end(&mut output)
            .map_err(invalid)?;
        if output.len() > allowance {
            return Err(StrictParseError::LimitExceeded("expanded bytes"));
        }
        self.bytes -= output.len();
        Ok(output)
    }
}

fn safe_name(name: &str, directory: bool) -> Result<(), StrictParseError> {
    safe_raw_name(name.as_bytes(), directory)?;
    if name.chars().any(char::is_control) {
        return Err(invalid("unsafe package entry name"));
    }
    Ok(())
}

fn safe_raw_name(name: &[u8], directory: bool) -> Result<(), StrictParseError> {
    let path = if directory {
        name.strip_suffix(b"/").unwrap_or(name)
    } else {
        name
    };
    if path.is_empty()
        || path.iter().any(|byte| matches!(*byte, b'\\' | b':' | 0))
        || path
            .split(|byte| *byte == b'/')
            .any(|part| matches!(part, b"" | b"." | b".."))
    {
        return Err(invalid("unsafe package entry name"));
    }
    Ok(())
}

fn u16_at(data: &[u8], at: usize) -> Result<u16, StrictParseError> {
    let end = at
        .checked_add(2)
        .ok_or_else(|| invalid("ZIP offset overflow"))?;
    let bytes = data.get(at..end).ok_or_else(|| invalid("truncated ZIP"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], at: usize) -> Result<u32, StrictParseError> {
    let end = at
        .checked_add(4)
        .ok_or_else(|| invalid("ZIP offset overflow"))?;
    let bytes = data.get(at..end).ok_or_else(|| invalid("truncated ZIP"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

struct ZipEntry {
    name: String,
    expanded: u32,
    method: u16,
    payload: std::ops::Range<usize>,
}

// ZIP readers can collapse duplicate central-directory names. Inspect the raw
// directory before constructing ZipArchive so that its map cannot hide them.
fn zip_directory(data: &[u8], limits: &InputLimits) -> Result<Vec<ZipEntry>, StrictParseError> {
    let eocd = (data.len().saturating_sub(65_557)..data.len().saturating_sub(21))
        .rev()
        .find(|&at| {
            data.get(at..at + 4) == Some(b"PK\x05\x06")
                && u16_at(data, at + 20).is_ok_and(|length| {
                    at.checked_add(22)
                        .and_then(|end| end.checked_add(usize::from(length)))
                        == Some(data.len())
                })
        })
        .ok_or_else(|| invalid("missing ZIP end record"))?;
    let count = u16_at(data, eocd + 10)?;
    let central_size = u32_at(data, eocd + 12)?;
    let central_start = u32_at(data, eocd + 16)?;
    if count == u16::MAX || central_size == u32::MAX || central_start == u32::MAX {
        return Err(StrictParseError::Unsupported("ZIP64 packages"));
    }
    if u16_at(data, eocd + 4)? != 0
        || u16_at(data, eocd + 6)? != 0
        || u16_at(data, eocd + 8)? != count
    {
        return Err(StrictParseError::Unsupported("multi-disk ZIP packages"));
    }
    if usize::from(count) > limits.max_entries {
        return Err(StrictParseError::LimitExceeded("entry count"));
    }
    let mut at = central_start as usize;
    if at.checked_add(central_size as usize) != Some(eocd) {
        return Err(invalid("inconsistent ZIP directory extent"));
    }
    let mut entries = Vec::new();
    let mut names = HashSet::new();
    let mut ranges = Vec::new();
    for _ in 0..count {
        let header_end = at
            .checked_add(46)
            .filter(|end| *end <= eocd)
            .ok_or_else(|| invalid("truncated ZIP central directory"))?;
        if data.get(at..at + 4) != Some(b"PK\x01\x02") {
            return Err(invalid("truncated ZIP central directory"));
        }
        let flags = u16_at(data, at + 8)?;
        let method = u16_at(data, at + 10)?;
        let compressed = u32_at(data, at + 20)?;
        let expanded = u32_at(data, at + 24)?;
        let name_length = usize::from(u16_at(data, at + 28)?);
        let extra_length = usize::from(u16_at(data, at + 30)?);
        let comment_length = usize::from(u16_at(data, at + 32)?);
        let local = u32_at(data, at + 42)?;
        if [compressed, expanded, local].contains(&u32::MAX) {
            return Err(StrictParseError::Unsupported("ZIP64 entries"));
        }
        if flags & 0x41 != 0 {
            return Err(StrictParseError::Unsupported("encrypted ZIP entries"));
        }
        if method != 0 && method != 8 {
            return Err(StrictParseError::Unsupported("this ZIP compression method"));
        }
        if u16_at(data, at + 34)? != 0 {
            return Err(invalid("invalid ZIP disk number"));
        }
        let end = header_end
            .checked_add(name_length)
            .and_then(|end| end.checked_add(extra_length))
            .and_then(|end| end.checked_add(comment_length))
            .ok_or_else(|| invalid("ZIP directory entry size overflow"))?;
        if end > eocd {
            return Err(invalid("truncated ZIP entry"));
        }
        let raw_name = &data[at + 46..at + 46 + name_length];
        safe_raw_name(raw_name, raw_name.ends_with(b"/"))?;
        if flags & 0x800 != 0 {
            std::str::from_utf8(raw_name).map_err(invalid)?;
        }
        if !names.insert(raw_name.to_vec()) {
            return Err(invalid("duplicate ZIP entry name"));
        }
        let local = local as usize;
        let local_header_end = local
            .checked_add(30)
            .filter(|end| *end <= central_start as usize)
            .ok_or_else(|| invalid("invalid ZIP local header offset"))?;
        if data.get(local..local + 4) != Some(b"PK\x03\x04") {
            return Err(invalid("invalid ZIP local header"));
        }
        let local_name_length = usize::from(u16_at(data, local + 26)?);
        let local_extra_length = usize::from(u16_at(data, local + 28)?);
        let payload = local_header_end
            .checked_add(local_name_length)
            .and_then(|end| end.checked_add(local_extra_length))
            .ok_or_else(|| invalid("ZIP local header size overflow"))?;
        let payload_end = payload
            .checked_add(compressed as usize)
            .ok_or_else(|| invalid("ZIP entry size overflow"))?;
        if payload_end > central_start as usize
            || data.get(local + 30..local + 30 + local_name_length) != Some(raw_name)
            || u16_at(data, local + 6)? != flags
            || u16_at(data, local + 8)? != method
        {
            return Err(invalid("inconsistent ZIP local header"));
        }
        if flags & 8 == 0
            && (u32_at(data, local + 14)? != u32_at(data, at + 16)?
                || u32_at(data, local + 18)? != compressed
                || u32_at(data, local + 22)? != expanded)
        {
            return Err(invalid("inconsistent ZIP local sizes or checksum"));
        }
        let entry_end = if flags & 8 != 0 {
            let checksum = u32_at(data, at + 16)?;
            let check = |descriptor: usize| {
                let end = descriptor.checked_add(12)?;
                if end > central_start as usize {
                    return None;
                }
                (u32_at(data, descriptor).ok()? == checksum
                    && u32_at(data, descriptor + 4).ok()? == compressed
                    && u32_at(data, descriptor + 8).ok()? == expanded)
                    .then_some(end)
            };
            // An unsigned descriptor can have a CRC equal to the optional
            // signature. Match all fields before choosing either encoding.
            let signed = payload_end.checked_add(4).and_then(|descriptor| {
                (data.get(payload_end..descriptor) == Some(b"PK\x07\x08"))
                    .then(|| check(descriptor))
                    .flatten()
            });
            check(payload_end)
                .or(signed)
                .ok_or_else(|| invalid("truncated or inconsistent ZIP data descriptor"))?
        } else {
            payload_end
        };
        ranges.push((local, entry_end));
        entries.push(ZipEntry {
            name: String::new(),
            expanded,
            method,
            payload: payload..payload_end,
        });
        at = end;
    }
    if at != eocd {
        return Err(invalid("unexpected ZIP directory data"));
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(invalid("overlapping ZIP entries"));
    }
    Ok(entries)
}

trait DecodedZipName {
    fn checked_name(self) -> Result<String, StrictParseError>;
}

impl DecodedZipName for &str {
    fn checked_name(self) -> Result<String, StrictParseError> {
        Ok(self.to_string())
    }
}

impl<'a, E: std::fmt::Display> DecodedZipName for Result<std::borrow::Cow<'a, str>, E> {
    fn checked_name(self) -> Result<String, StrictParseError> {
        self.map(std::borrow::Cow::into_owned).map_err(invalid)
    }
}

fn package_names(entries: &[ZipEntry]) -> Result<(), StrictParseError> {
    let mut names = HashSet::new();
    for entry in entries {
        safe_name(&entry.name, entry.name.ends_with('/'))?;
        if !names.insert(entry.name.trim_end_matches('/')) {
            return Err(invalid("duplicate decoded ZIP entry name"));
        }
    }
    let files: HashSet<_> = entries
        .iter()
        .filter(|entry| !entry.name.ends_with('/'))
        .map(|entry| entry.name.as_str())
        .collect();
    for entry in entries {
        let mut prefix = entry.name.as_str();
        while let Some((parent, _)) = prefix.rsplit_once('/') {
            if files.contains(parent) {
                return Err(invalid("ZIP file and directory name conflict"));
            }
            prefix = parent;
        }
    }
    Ok(())
}

const OPF_NS: &str = "http://www.idpf.org/2007/opf/";
const HEAD_NS: &str = "http://www.hancom.co.kr/hwpml/2011/head";
const SECTION_NS: &str = "http://www.hancom.co.kr/hwpml/2011/section";

fn xml<'a>(
    bytes: &'a [u8],
    limits: &InputLimits,
    budget: &mut Budget,
) -> Result<roxmltree::Document<'a>, StrictParseError> {
    let text = std::str::from_utf8(bytes).map_err(invalid)?;
    let mut reader = quick_xml::Reader::from_str(text);
    let mut depth = 0usize;
    loop {
        use quick_xml::events::Event;
        match reader.read_event().map_err(invalid)? {
            Event::DocType(_) => return Err(invalid("XML document types are not allowed")),
            Event::Start(_) => {
                depth += 1;
                if depth > limits.max_xml_depth {
                    return Err(StrictParseError::LimitExceeded("XML depth"));
                }
            }
            Event::Empty(_) if depth >= limits.max_xml_depth => {
                return Err(StrictParseError::LimitExceeded("XML depth"));
            }
            Event::End(_) => depth = depth.saturating_sub(1),
            Event::Eof => break,
            _ => {}
        }
    }
    let document = roxmltree::Document::parse_with_options(
        text,
        roxmltree::ParsingOptions {
            allow_dtd: false,
            nodes_limit: budget.nodes,
            ..Default::default()
        },
    )
    .map_err(invalid)?;
    let nodes = u32::try_from(document.descendants().count())
        .map_err(|_| StrictParseError::LimitExceeded("XML nodes"))?;
    budget.nodes = budget
        .nodes
        .checked_sub(nodes)
        .ok_or(StrictParseError::LimitExceeded("XML nodes"))?;
    Ok(document)
}

fn root(
    document: &roxmltree::Document<'_>,
    namespace: &str,
    name: &str,
) -> Result<(), StrictParseError> {
    if !document.root_element().has_tag_name((namespace, name)) {
        return Err(invalid("unexpected XML root or namespace"));
    }
    Ok(())
}

fn core_xml(document: &roxmltree::Document<'_>) -> Result<(), StrictParseError> {
    const NAMESPACES: &[&str] = &[
        OPF_NS,
        HEAD_NS,
        SECTION_NS,
        "http://www.hancom.co.kr/hwpml/2011/app",
        "http://www.hancom.co.kr/hwpml/2011/paragraph",
        "http://www.hancom.co.kr/hwpml/2016/paragraph",
        "http://www.hancom.co.kr/hwpml/2011/core",
        "http://www.hancom.co.kr/hwpml/2011/history",
        "http://www.hancom.co.kr/hwpml/2011/master-page",
        "http://www.hancom.co.kr/hwpml/2016/ooxmlchart",
        "http://www.hancom.co.kr/hwpml/2016/HwpUnitChar",
        "http://www.hancom.co.kr/schema/2011/hpf",
        "http://purl.org/dc/elements/1.1/",
        "http://www.idpf.org/2007/ops",
        "urn:oasis:names:tc:opendocument:xmlns:config:1.0",
    ];
    for node in document.descendants().filter(roxmltree::Node::is_element) {
        if !node
            .tag_name()
            .namespace()
            .is_some_and(|namespace| NAMESPACES.contains(&namespace))
        {
            return Err(StrictParseError::Unsupported("this HWPX element namespace"));
        }
        let expected = match node.tag_name().name() {
            "package" | "manifest" | "spine" | "item" | "itemref" | "metadata" | "meta" => {
                Some(OPF_NS)
            }
            "head" | "refList" => Some(HEAD_NS),
            "sec" => Some(SECTION_NS),
            "p" | "run" | "t" | "tbl" | "tr" | "tc" | "subList" | "linesegarray" | "lineseg" => {
                Some("http://www.hancom.co.kr/hwpml/2011/paragraph")
            }
            _ => None,
        };
        if expected.is_some_and(|expected| node.tag_name().namespace() != Some(expected)) {
            return Err(invalid("unexpected HWPX element namespace"));
        }
        if node.tag_name().name() == "p"
            && node
                .ancestors()
                .filter(|ancestor| ancestor.is_element() && ancestor.tag_name().name() == "p")
                .count()
                > 16
        {
            return Err(StrictParseError::LimitExceeded("HWPX paragraph nesting"));
        }
    }
    Ok(())
}

fn parse_hwpx(data: &[u8], limits: &InputLimits) -> Result<Document, StrictParseError> {
    let mut entries = zip_directory(data, limits)?;
    let mut archive = zip::ZipArchive::new(Cursor::new(data)).map_err(invalid)?;
    if archive.len() != entries.len() {
        return Err(invalid("inconsistent ZIP entry count"));
    }
    // Use the ZIP reader's encoding rules, but keep index-based reads so that
    // CP437 names do not need a UTF-8-to-raw lookup round trip.
    for (index, entry) in entries.iter_mut().enumerate() {
        entry.name = archive
            .by_index(index)
            .map_err(invalid)?
            .name()
            .checked_name()?;
    }
    package_names(&entries)?;
    if !entries.iter().any(|entry| entry.name == "mimetype") {
        return Err(invalid("missing HWPX media type"));
    }
    let mut budget = Budget::new(limits);
    let mut manifest = None;
    let mut section_count = None;
    let mut xml_roots = HashMap::new();
    for (index, entry) in entries.iter().enumerate() {
        let mut file = archive.by_index(index).map_err(invalid)?;
        let allowance = budget.bytes.min(limits.max_entry_bytes);
        if u64::from(entry.expanded) > allowance as u64 {
            return Err(StrictParseError::LimitExceeded("expanded bytes"));
        }
        if entry.method == 8
            && inflate(
                &data[entry.payload.clone()],
                allowance,
                DeflateFraming::Exact,
                |_| {},
            )? != entry.expanded as usize
        {
            return Err(invalid("ZIP deflate output size mismatch"));
        }
        let bytes = budget.read(&mut file, limits)?;
        if bytes.len() as u64 != u64::from(entry.expanded) {
            return Err(invalid("ZIP expanded size mismatch"));
        }
        if entry.name == "mimetype" && bytes != b"application/hwp+zip" {
            return Err(invalid("unexpected HWPX media type"));
        }
        let lower = entry.name.to_ascii_lowercase();
        if lower.ends_with(".xml") || lower.ends_with(".hpf") {
            let document = xml(&bytes, limits, &mut budget)?;
            let element = document.root_element();
            xml_roots.insert(
                entry.name.clone(),
                (
                    element.tag_name().namespace().unwrap_or("").to_string(),
                    element.tag_name().name().to_string(),
                ),
            );
            if document
                .descendants()
                .any(|node| node.is_element() && node.tag_name().name() == "encryption-data")
            {
                return Err(StrictParseError::Unsupported("encrypted HWPX documents"));
            }
            if entry.name == "Contents/content.hpf" {
                root(&document, OPF_NS, "package")?;
                core_xml(&document)?;
                validate_manifest(&document, &entries)?;
                manifest = Some(bytes);
            } else if entry.name == "Contents/header.xml" {
                root(&document, HEAD_NS, "head")?;
                core_xml(&document)?;
                section_count = Some(
                    element
                        .attribute("secCnt")
                        .ok_or_else(|| invalid("missing HWPX section count"))?
                        .parse::<usize>()
                        .map_err(invalid)?,
                );
                super::hwpx::header::parse_hwpx_header(
                    std::str::from_utf8(&bytes).map_err(invalid)?,
                )
                .map_err(invalid)?;
            } else if entry.name.starts_with("Contents/") {
                core_xml(&document)?;
                if element.has_tag_name((SECTION_NS, "sec")) {
                    super::hwpx::section::parse_hwpx_section(
                        std::str::from_utf8(&bytes).map_err(invalid)?,
                    )
                    .map_err(invalid)?;
                } else if element.tag_name().name() == "masterPage" {
                    super::hwpx::section::parse_hwpx_master_page(
                        std::str::from_utf8(&bytes).map_err(invalid)?,
                    )
                    .map_err(invalid)?;
                }
            }
        }
    }
    let manifest = manifest.ok_or_else(|| invalid("missing HWPX package manifest"))?;
    let info =
        super::hwpx::content::parse_content_hpf(std::str::from_utf8(&manifest).map_err(invalid)?)
            .map_err(invalid)?;
    if info.section_files.is_empty() || section_count != Some(info.section_files.len()) {
        return Err(invalid("inconsistent HWPX section count"));
    }
    for href in &info.section_files {
        let name = package_path(href)?;
        if xml_roots.get(&name) != Some(&(SECTION_NS.to_string(), "sec".to_string())) {
            return Err(invalid("missing HWPX section or unexpected namespace"));
        }
    }
    let document = super::hwpx::parse_hwpx(data).map_err(invalid)?;
    if document.sections.len() != info.section_files.len() {
        return Err(invalid("HWPX parser did not load every section"));
    }
    Ok(document)
}

fn package_path(href: &str) -> Result<String, StrictParseError> {
    safe_name(href, false)?;
    if href.contains(['%', '?', '#']) {
        return Err(StrictParseError::Unsupported("encoded package references"));
    }
    Ok(href.to_string())
}

fn validate_manifest(
    document: &roxmltree::Document<'_>,
    entries: &[ZipEntry],
) -> Result<(), StrictParseError> {
    for name in ["manifest", "spine"] {
        if document
            .root_element()
            .children()
            .filter(|node| node.has_tag_name((OPF_NS, name)))
            .count()
            != 1
        {
            return Err(invalid("missing or duplicate HWPX package structure"));
        }
    }
    let names: HashSet<_> = entries.iter().map(|entry| entry.name.as_str()).collect();
    let mut ids = HashSet::new();
    let mut paths = HashSet::new();
    let mut spine = HashSet::new();
    let mut sections = HashSet::new();
    for node in document.descendants().filter(roxmltree::Node::is_element) {
        if node.tag_name().name() == "item" {
            if !node.has_tag_name((OPF_NS, "item")) {
                return Err(invalid("unexpected manifest item namespace"));
            }
            if !node
                .parent()
                .is_some_and(|parent| parent.has_tag_name((OPF_NS, "manifest")))
            {
                return Err(invalid("unexpected manifest item location"));
            }
            let id = node
                .attribute("id")
                .filter(|id| !id.is_empty())
                .ok_or_else(|| invalid("missing manifest item ID"))?;
            if !ids.insert(id) {
                return Err(invalid("duplicate manifest item ID"));
            }
            if node.attribute("isEmbeded") != Some("0") {
                let href = node
                    .attribute("href")
                    .ok_or_else(|| invalid("missing manifest reference"))?;
                let path = package_path(href)?;
                if href.contains("section")
                    && node.attribute("media-type") == Some("application/xml")
                {
                    sections.insert(id);
                }
                if !names.contains(path.as_str()) || !paths.insert(path) {
                    return Err(invalid("missing or duplicate manifest resource"));
                }
            }
        }
    }
    for node in document
        .descendants()
        .filter(|node| node.has_tag_name((OPF_NS, "itemref")))
    {
        let id = node
            .attribute("idref")
            .ok_or_else(|| invalid("missing spine reference"))?;
        if !node
            .parent()
            .is_some_and(|parent| parent.has_tag_name((OPF_NS, "spine")))
        {
            return Err(invalid("unexpected spine item location"));
        }
        if !ids.contains(id) || !spine.insert(id) {
            return Err(invalid("missing or duplicate spine item"));
        }
    }
    if sections.is_empty() || !sections.is_subset(&spine) {
        return Err(invalid("missing HWPX section spine references"));
    }
    Ok(())
}

fn records(
    data: &[u8],
    limits: &InputLimits,
    budget: &mut Budget,
    first_tag: u16,
) -> Result<(), StrictParseError> {
    let mut at = 0usize;
    let mut previous_depth = 0usize;
    let mut first = true;
    let mut mappings = false;
    while at < data.len() {
        let value = u32_at(data, at).map_err(|_| invalid("truncated HWP record header"))?;
        let tag = (value & 0x3ff) as u16;
        let level = ((value >> 10) & 0x3ff) as usize;
        let mut size = (value >> 20) as usize;
        at += 4;
        if size == 0xfff {
            size = u32_at(data, at).map_err(|_| invalid("truncated HWP record size"))? as usize;
            at += 4;
        }
        if first && (tag != first_tag || level != 0) {
            return Err(invalid("unexpected first HWP record"));
        }
        if !first && first_tag == tags::HWPTAG_DOCUMENT_PROPERTIES && tag == first_tag {
            return Err(invalid("duplicate HWP document properties"));
        }
        if first_tag == tags::HWPTAG_DOCUMENT_PROPERTIES && tag == tags::HWPTAG_ID_MAPPINGS {
            if mappings {
                return Err(invalid("duplicate HWP ID mappings"));
            }
            mappings = true;
        }
        if level > limits.max_record_depth.min(63) || level > previous_depth + 1 {
            return Err(StrictParseError::LimitExceeded("HWP record depth"));
        }
        budget.records = budget
            .records
            .checked_sub(1)
            .ok_or(StrictParseError::LimitExceeded("HWP record count"))?;
        if first_tag == tags::HWPTAG_PARA_HEADER && level == 0 && tag != tags::HWPTAG_PARA_HEADER {
            return Err(invalid("unexpected top-level HWP body record"));
        }
        let bad_size = match tag {
            tags::HWPTAG_PARA_HEADER => size < 22,
            tags::HWPTAG_PARA_TEXT => !size.is_multiple_of(2),
            tags::HWPTAG_PARA_CHAR_SHAPE => !size.is_multiple_of(8),
            tags::HWPTAG_PARA_LINE_SEG => !size.is_multiple_of(36),
            tags::HWPTAG_PARA_RANGE_TAG => !size.is_multiple_of(12),
            tags::HWPTAG_CTRL_HEADER => size < 4,
            _ => false,
        };
        if bad_size {
            return Err(invalid("invalid HWP record payload size"));
        }
        let end = at
            .checked_add(size)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| invalid("truncated HWP record payload"))?;
        if tag == tags::HWPTAG_PARA_TEXT {
            hwp_text(&data[at..end])?;
        }
        at = end;
        previous_depth = level;
        first = false;
    }
    if first {
        return Err(invalid("empty HWP record stream"));
    }
    if first_tag == tags::HWPTAG_DOCUMENT_PROPERTIES && !mappings {
        return Err(invalid("missing HWP ID mappings"));
    }
    Ok(())
}

fn hwp_text(data: &[u8]) -> Result<(), StrictParseError> {
    let mut at = 0usize;
    while at < data.len() {
        let unit = u16_at(data, at)?;
        if matches!(unit, 1..=9 | 11..=12 | 14..=23) {
            if at + 16 > data.len() || u16_at(data, at + 14)? != unit {
                return Err(invalid("truncated or unmatched HWP text control"));
            }
            at += 16;
        } else if (0xd800..=0xdbff).contains(&unit) {
            if at + 4 > data.len() || !(0xdc00..=0xdfff).contains(&u16_at(data, at + 2)?) {
                return Err(invalid("unpaired HWP UTF-16 surrogate"));
            }
            at += 4;
        } else if (0xdc00..=0xdfff).contains(&unit) {
            return Err(invalid("unpaired HWP UTF-16 surrogate"));
        } else if unit == 13 && at + 2 != data.len() {
            return Err(invalid("HWP text follows a paragraph end control"));
        } else {
            at += 2;
        }
    }
    Ok(())
}

fn parse_hwp(data: &[u8], limits: &InputLimits) -> Result<Document, StrictParseError> {
    let mut compound = cfb::CompoundFile::open_strict(Cursor::new(data)).map_err(invalid)?;
    let mut paths = Vec::new();
    for entry in compound.walk() {
        if paths.len() >= limits.max_entries {
            return Err(StrictParseError::LimitExceeded("entry count"));
        }
        paths.push((entry.path().to_path_buf(), entry.is_stream(), entry.len()));
    }
    let mut budget = Budget::new(limits);
    let header_path = resolve_cfb_path(&compound, "/FileHeader")?;
    let info_path = resolve_cfb_path(&compound, "/DocInfo")?;
    let header_bytes = budget.read(
        compound.open_stream("/FileHeader").map_err(invalid)?,
        limits,
    )?;
    if header_bytes.len() != 256 {
        return Err(invalid("HWP FileHeader must contain 256 bytes"));
    }
    let header = header::parse_file_header(&header_bytes).map_err(invalid)?;
    if header.flags.encrypted
        || header.flags.distribution
        || header.flags.drm
        || header.flags.public_key_encrypted
    {
        return Err(StrictParseError::Unsupported(
            "encrypted or protected HWP documents",
        ));
    }
    if compound.exists("/ViewText") {
        return Err(StrictParseError::Unsupported("HWP ViewText streams"));
    }
    let raw_doc_info = read_cfb_stream(&mut compound, "/DocInfo", limits)?;
    let doc_info_bytes = decode_hwp(&raw_doc_info, header.flags.compressed, limits, &mut budget)?;
    records(
        &doc_info_bytes,
        limits,
        &mut budget,
        tags::HWPTAG_DOCUMENT_PROPERTIES,
    )?;
    let (doc_info, properties) =
        super::doc_info::parse_doc_info(&doc_info_bytes).map_err(invalid)?;
    if properties.section_count == 0 {
        return Err(invalid("HWP has no sections"));
    }
    let body_path = resolve_cfb_path(&compound, "/BodyText")?;
    let mut section_paths = HashMap::new();
    for index in 0..properties.section_count {
        let path = resolve_cfb_path(&compound, &format!("/BodyText/Section{index}"))?;
        section_paths.insert(path, index);
    }
    let mut sections = HashSet::new();
    let mut bin_streams = HashMap::new();
    for resource in &doc_info.bin_data_list {
        if matches!(resource.data_type, BinDataType::Link) {
            continue;
        }
        let extension = resource.extension.as_deref().unwrap_or(
            if matches!(resource.data_type, BinDataType::Storage) {
                "OLE"
            } else {
                "dat"
            },
        );
        let path = resolve_cfb_path(
            &compound,
            &format!("/BinData/BIN{:04X}.{extension}", resource.storage_id),
        )?;
        if bin_streams.insert(path, resource).is_some() {
            return Err(invalid("duplicate HWP binary resource ID"));
        }
    }
    let mut binary_contents = Vec::new();
    let mut found_binary = HashSet::new();
    for (path, stream, length) in &paths {
        if !stream
            || path == std::path::Path::new(&header_path)
            || path == std::path::Path::new(&info_path)
        {
            continue;
        }
        if *length > limits.max_entry_bytes as u64 {
            return Err(StrictParseError::LimitExceeded("entry bytes"));
        }
        let name = path
            .to_str()
            .ok_or_else(|| invalid("invalid CFB stream name"))?;
        let raw = read_cfb_stream(&mut compound, name, limits)?;
        if let Some(index) = section_paths.get(name) {
            if !sections.insert(*index) {
                return Err(invalid("invalid HWP section name"));
            }
            let bytes = decode_hwp(&raw, header.flags.compressed, limits, &mut budget)?;
            records(&bytes, limits, &mut budget, tags::HWPTAG_PARA_HEADER)?;
            super::body_text::parse_body_text_section(&bytes).map_err(invalid)?;
        } else if let Some(resource) = bin_streams.get(name) {
            let compressed = super::bin_data_stream_is_compressed(
                resource.compression,
                header.flags.compressed,
                false,
            );
            let mut bytes = decode_hwp(&raw, compressed, limits, &mut budget)?;
            if matches!(resource.data_type, BinDataType::Storage)
                && bytes.len() >= 12
                && bytes[4..12] == *b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
            {
                bytes.drain(..4);
            }
            binary_contents.push(BinDataContent {
                id: resource.storage_id,
                data: bytes.into(),
                extension: resource.extension.clone().unwrap_or_else(|| {
                    if matches!(resource.data_type, BinDataType::Storage) {
                        "OLE"
                    } else {
                        "dat"
                    }
                    .to_string()
                }),
            });
            found_binary.insert(name.to_string());
        } else {
            if path.starts_with(&body_path) {
                return Err(invalid("unexpected HWP body stream"));
            }
            budget.bytes = budget
                .bytes
                .checked_sub(raw.len())
                .ok_or(StrictParseError::LimitExceeded("expanded bytes"))?;
        }
    }
    if sections.len() != usize::from(properties.section_count)
        || (0..properties.section_count).any(|index| !sections.contains(&index))
        || found_binary.len() != bin_streams.len()
    {
        return Err(invalid("missing HWP section or binary resource"));
    }
    let reader = cfb_reader::CfbReader::open_strict(data).map_err(invalid)?;
    let mut document = super::parse_hwp_with_cfb(
        reader,
        data,
        None,
        super::Hwp5DocumentOpenDecompressionLimits {
            max_stream_input_bytes: limits.max_entry_bytes,
            max_stream_output_bytes: limits.max_entry_bytes,
            max_total_output_bytes: limits.max_expanded_bytes,
        },
    )
    .map_err(StrictParseError::Parse)?;
    // The compatibility parser excludes modeled streams by their conventional
    // spelling. Case aliases must not survive as opaque streams that could
    // overwrite newly serialized content after an edit.
    let mut modeled_paths: HashSet<_> = section_paths
        .keys()
        .chain(bin_streams.keys())
        .cloned()
        .collect();
    modeled_paths.extend([header_path, info_path]);
    for preview in ["/PrvImage", "/PrvText"] {
        if compound.exists(preview) {
            modeled_paths.insert(resolve_cfb_path(&compound, preview)?);
        }
    }
    document
        .extra_streams
        .retain(|(path, _)| !modeled_paths.contains(path));
    // Keep the validated bytes. A later lazy read must not retry decompression
    // with a different limit or replace corrupt data with its compressed input.
    document.bin_data_content = binary_contents;
    Ok(document)
}

// Resolve each stored component through CFB's own name comparison. Rust Unicode
// lowercasing does not implement the compound-file name identity rules.
fn resolve_cfb_path(
    compound: &cfb::CompoundFile<Cursor<&[u8]>>,
    expected: &str,
) -> Result<String, StrictParseError> {
    let mut path = std::path::PathBuf::from("/");
    for name in expected.split('/').filter(|name| !name.is_empty()) {
        if matches!(name, "." | "..") {
            return Err(invalid("invalid CFB stream path"));
        }
        let entry = compound.entry(path.join(name)).map_err(invalid)?;
        path.push(entry.name());
    }
    path.into_os_string()
        .into_string()
        .map_err(|_| invalid("invalid CFB stream name"))
}

fn read_cfb_stream(
    compound: &mut cfb::CompoundFile<Cursor<&[u8]>>,
    name: &str,
    limits: &InputLimits,
) -> Result<Vec<u8>, StrictParseError> {
    let stream = compound.open_stream(name).map_err(invalid)?;
    let mut raw_budget = Budget::new(limits);
    raw_budget.bytes = limits.max_entry_bytes;
    raw_budget.read(stream, limits)
}

fn decode_hwp(
    raw: &[u8],
    compressed: bool,
    limits: &InputLimits,
    budget: &mut Budget,
) -> Result<Vec<u8>, StrictParseError> {
    if compressed {
        let allowance = budget.bytes.min(limits.max_entry_bytes);
        let mut output = Vec::new();
        let length = inflate(raw, allowance, DeflateFraming::Hwp, |chunk| {
            output.extend_from_slice(chunk)
        })?;
        budget.bytes -= length;
        Ok(output)
    } else {
        budget.read(raw, limits)
    }
}

enum DeflateFraming {
    Exact,
    Hwp,
}

fn inflate(
    raw: &[u8],
    limit: usize,
    framing: DeflateFraming,
    mut write: impl FnMut(&[u8]),
) -> Result<usize, StrictParseError> {
    let mut decoder = flate2::Decompress::new(false);
    let mut crc = flate2::Crc::new();
    let mut produced = 0usize;
    let mut chunk = [0u8; 8192];
    loop {
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let status = decoder
            .decompress(
                &raw[before_in as usize..],
                &mut chunk,
                flate2::FlushDecompress::Finish,
            )
            .map_err(invalid)?;
        let written = (decoder.total_out() - before_out) as usize;
        if written > limit.saturating_sub(produced) {
            return Err(StrictParseError::LimitExceeded("expanded bytes"));
        }
        produced += written;
        if matches!(framing, DeflateFraming::Hwp) {
            crc.update(&chunk[..written]);
        }
        write(&chunk[..written]);
        if status == flate2::Status::StreamEnd {
            let trailing = &raw[decoder.total_in() as usize..];
            // HWP can retain the GZIP CRC32/ISIZE trailer without its header.
            // ZIP entries require exact raw DEFLATE consumption instead.
            if !trailing.is_empty()
                && (!matches!(framing, DeflateFraming::Hwp)
                    || trailing.len() != 8
                    || u32_at(trailing, 0)? != crc.sum()
                    || u32_at(trailing, 4)? != crc.amount())
            {
                return Err(invalid("trailing compressed stream data"));
            }
            return Ok(produced);
        }
        if before_in == decoder.total_in() && written == 0 {
            return Err(invalid("truncated compressed stream"));
        }
    }
}
