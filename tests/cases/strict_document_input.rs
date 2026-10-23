use std::io::{Cursor, Write};

use rhwp::document_core::DocumentCore;
use rhwp::parser::{
    parse_document, parse_document_strict, parse_document_strict_with_limits, InputLimits,
};

const CONTENT: &str = r#"<opf:package xmlns:opf="http://www.idpf.org/2007/opf/"><opf:manifest><opf:item id="header" href="Contents/header.xml" media-type="application/xml"/><opf:item id="section0" href="Contents/section0.xml" media-type="application/xml"/></opf:manifest><opf:spine><opf:itemref idref="section0"/></opf:spine></opf:package>"#;
const HEADER: &str = r#"<hh:head xmlns:hh="http://www.hancom.co.kr/hwpml/2011/head" secCnt="1"/>"#;
const SECTION: &str = r#"<hs:sec xmlns:hs="http://www.hancom.co.kr/hwpml/2011/section" xmlns:hp="http://www.hancom.co.kr/hwpml/2011/paragraph"><hp:p id="0" paraPrIDRef="0" styleIDRef="0"><hp:run charPrIDRef="0"><hp:t>Sample</hp:t></hp:run></hp:p></hs:sec>"#;

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

// A raw ZIP builder preserves duplicate central-directory names, unlike writers
// that reject duplicates or replace them before the input reaches the parser.
fn zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut central = Vec::new();
    for (name, payload) in entries {
        let offset = bytes.len() as u32;
        let length = payload.len() as u32;
        let crc = crc32(payload);
        bytes.extend_from_slice(b"PK\x03\x04");
        bytes.extend_from_slice(&20u16.to_le_bytes());
        bytes.extend_from_slice(&0x800u16.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 6]);
        bytes.extend_from_slice(&crc.to_le_bytes());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(&length.to_le_bytes());
        bytes.extend_from_slice(&(name.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(payload);

        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0x800u16.to_le_bytes());
        central.extend_from_slice(&[0u8; 6]);
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&length.to_le_bytes());
        central.extend_from_slice(&length.to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0u8; 12]);
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let start = bytes.len() as u32;
    bytes.extend_from_slice(&central);
    bytes.extend_from_slice(b"PK\x05\x06");
    bytes.extend_from_slice(&[0u8; 4]);
    bytes.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    bytes.extend_from_slice(&(central.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&start.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes
}

fn hwpx_with(header: &[u8], section: &[u8], extra: &[(&str, &[u8])]) -> Vec<u8> {
    let mut entries = vec![
        ("mimetype", b"application/hwp+zip".as_slice()),
        ("Contents/content.hpf", CONTENT.as_bytes()),
        ("Contents/header.xml", header),
        ("Contents/section0.xml", section),
    ];
    entries.extend_from_slice(extra);
    zip(&entries)
}

fn hwpx() -> Vec<u8> {
    let document = rhwp::model::document::Document {
        doc_info: doc_info(),
        sections: vec![Default::default()],
        ..Default::default()
    };
    let context =
        rhwp::serializer::hwpx::context::SerializeContext::collect_from_document(&document);
    let header = rhwp::serializer::hwpx::header::write_header(&document, &context).unwrap();
    hwpx_with(&header, SECTION.as_bytes(), &[])
}

fn doc_info() -> rhwp::model::document::DocInfo {
    rhwp::model::document::DocInfo {
        font_faces: vec![
            vec![rhwp::model::style::Font {
                name: "Sample Font".to_string(),
                ..Default::default()
            }];
            7
        ],
        char_shapes: vec![Default::default()],
        para_shapes: vec![Default::default()],
        styles: vec![Default::default()],
        tab_defs: vec![Default::default()],
        border_fills: vec![Default::default()],
        ..Default::default()
    }
}

fn record(tag: u16, level: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = (u32::from(tag) | (u32::from(level) << 10) | ((payload.len() as u32) << 20))
        .to_le_bytes()
        .to_vec();
    bytes.extend_from_slice(payload);
    bytes
}

fn body() -> Vec<u8> {
    let mut header = vec![0u8; 22];
    header[..4].copy_from_slice(&7u32.to_le_bytes());
    let mut bytes = record(rhwp::parser::tags::HWPTAG_PARA_HEADER, 0, &header);
    let text: Vec<u8> = "Sample\r"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    bytes.extend(record(rhwp::parser::tags::HWPTAG_PARA_TEXT, 1, &text));
    bytes
}

fn hwp(body: &[u8], compressed: bool, extra: &[(&str, &[u8])]) -> Vec<u8> {
    let mut compound =
        cfb::CompoundFile::create_with_version(cfb::Version::V3, Cursor::new(Vec::new())).unwrap();
    compound.create_storage("/BodyText").unwrap();
    let header = rhwp::model::document::FileHeader {
        version: rhwp::model::document::HwpVersion {
            major: 5,
            ..Default::default()
        },
        compressed,
        flags: u32::from(compressed),
        ..Default::default()
    };
    let header_bytes = rhwp::serializer::header::serialize_file_header(&header);
    let properties = rhwp::model::document::DocProperties {
        section_count: 1,
        ..Default::default()
    };
    let doc_info = rhwp::serializer::doc_info::serialize_doc_info(&doc_info(), &properties);
    let compress = |bytes: &[u8]| {
        if compressed {
            let mut writer =
                flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            writer.write_all(bytes).unwrap();
            writer.finish().unwrap()
        } else {
            bytes.to_vec()
        }
    };
    for (name, payload) in [
        ("/FileHeader", header_bytes),
        ("/DocInfo", compress(&doc_info)),
        ("/BodyText/Section0", compress(body)),
    ] {
        compound
            .create_stream(name)
            .unwrap()
            .write_all(&payload)
            .unwrap();
    }
    for (name, payload) in extra {
        compound
            .create_stream(name)
            .unwrap()
            .write_all(payload)
            .unwrap();
    }
    compound.into_inner().into_inner()
}

fn rejected(bytes: &[u8]) {
    assert!(parse_document_strict(bytes).is_err());
    assert!(DocumentCore::from_bytes_strict(bytes).is_err());
}

#[test]
fn strict_input_valid_synthetic_documents_load_through_public_apis() {
    for bytes in [hwpx(), hwp(&body(), false, &[]), hwp(&body(), true, &[])] {
        let original = bytes.clone();
        let document = parse_document_strict(&bytes).unwrap();
        assert_eq!(document.sections.len(), 1);
        assert_eq!(document.sections[0].paragraphs[0].text.trim_end(), "Sample");
        DocumentCore::from_bytes_strict(&bytes).unwrap();
        rhwp::wasm_api::HwpDocument::from_bytes_strict(&bytes).unwrap();
        assert_eq!(bytes, original);
        let saved = rhwp::serializer::hwpx::serialize_hwpx(&document).unwrap();
        assert_eq!(parse_document_strict(&saved).unwrap().sections.len(), 1);
    }
}

#[test]
fn strict_input_rejects_unclosed_xml_while_recovery_remains_available() {
    let damaged = SECTION.replace("</hs:sec>", "");
    let bytes = hwpx_with(HEADER.as_bytes(), damaged.as_bytes(), &[]);
    assert!(parse_document(&bytes).is_ok());
    rejected(&bytes);
}

#[test]
fn strict_input_rejects_duplicate_raw_zip_names() {
    let bytes = hwpx_with(
        HEADER.as_bytes(),
        SECTION.as_bytes(),
        &[("Contents/section0.xml", SECTION.as_bytes())],
    );
    assert!(parse_document(&bytes).is_ok());
    rejected(&bytes);
}

#[test]
fn strict_input_rejects_xml_structure_encoding_namespace_and_entities() {
    for section in [
        SECTION.replace("</hp:t>", "</hp:run>"),
        SECTION.replace("Sample", "&missing;"),
        SECTION.replace("Sample", "&#0;"),
        SECTION.replace("id=\"0\"", "id=\"0\" id=\"1\""),
        SECTION.replace("http://www.hancom.co.kr/hwpml/2011/section", "urn:other"),
        SECTION.replace("http://www.hancom.co.kr/hwpml/2011/paragraph", "urn:other"),
        SECTION.replace(
            "http://www.hancom.co.kr/hwpml/2011/paragraph",
            "http://www.hancom.co.kr/hwpml/2011/head",
        ),
        format!("<!DOCTYPE sec>{SECTION}"),
        format!("<!DOCTYPE sec [<!ENTITY value \"text\">]>{SECTION}"),
        format!("<!DOCTYPE sec SYSTEM \"https://example.invalid/schema\">{SECTION}"),
        format!("{SECTION}<other/>"),
    ] {
        rejected(&hwpx_with(HEADER.as_bytes(), section.as_bytes(), &[]));
    }
    rejected(&hwpx_with(b"<head>\xff</head>", SECTION.as_bytes(), &[]));
    let legal =
        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><!-- <!DOCTYPE text> -->{SECTION}");
    parse_document_strict(&hwpx_with(HEADER.as_bytes(), legal.as_bytes(), &[])).unwrap();
}

#[test]
fn strict_input_checks_opaque_zip_entries_and_safe_names() {
    for name in [
        "../data", "/data", "a//data", "a/./data", "a\\data", "C:data",
    ] {
        rejected(&hwpx_with(
            HEADER.as_bytes(),
            SECTION.as_bytes(),
            &[(name, b"data")],
        ));
    }
    parse_document_strict(&hwpx_with(
        HEADER.as_bytes(),
        SECTION.as_bytes(),
        &[("BinData/한글.bin", b"data")],
    ))
    .unwrap();
    let mut bytes = hwpx_with(
        HEADER.as_bytes(),
        SECTION.as_bytes(),
        &[("extra.bin", b"unique payload")],
    );
    let at = bytes
        .windows(14)
        .position(|bytes| bytes == b"unique payload")
        .unwrap();
    bytes[at] ^= 1;
    rejected(&bytes);
    rejected(&hwpx_with(
        HEADER.as_bytes(),
        SECTION.as_bytes(),
        &[("a", b""), ("a/file", b"")],
    ));
}

#[test]
fn strict_input_checks_streaming_zip_descriptors_and_compressed_limits() {
    let mut writer = zip::ZipWriter::new_stream(Vec::new());
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, payload) in [
        ("mimetype", b"application/hwp+zip".as_slice()),
        ("Contents/content.hpf", CONTENT.as_bytes()),
        ("Contents/header.xml", HEADER.as_bytes()),
        ("Contents/section0.xml", SECTION.as_bytes()),
        ("extra.bin", &[0u8; 8192]),
    ] {
        writer.start_file(name, options).unwrap();
        writer.write_all(payload).unwrap();
    }
    let bytes = writer.finish().unwrap().into_inner();
    parse_document_strict(&bytes).unwrap();
    let limits = InputLimits {
        max_entry_bytes: 4096,
        ..Default::default()
    };
    assert!(parse_document_strict_with_limits(&bytes, &limits).is_err());
    let mut damaged = bytes;
    let descriptor = damaged
        .windows(4)
        .position(|bytes| bytes == b"PK\x07\x08")
        .unwrap();
    damaged[descriptor + 4] ^= 1;
    rejected(&damaged);
}

#[test]
fn strict_input_requires_all_manifest_resources_and_consistent_sections() {
    let bytes = zip(&[
        ("Contents/content.hpf", CONTENT.as_bytes()),
        ("Contents/header.xml", HEADER.as_bytes()),
    ]);
    rejected(&bytes);
    rejected(&hwpx_with(
        HEADER.replace("secCnt=\"1\"", "secCnt=\"2\"").as_bytes(),
        SECTION.as_bytes(),
        &[],
    ));
    let content = CONTENT.replace("idref=\"section0\"", "idref=\"absent\"");
    rejected(&zip(&[
        ("Contents/content.hpf", content.as_bytes()),
        ("Contents/header.xml", HEADER.as_bytes()),
        ("Contents/section0.xml", SECTION.as_bytes()),
    ]));
}

#[test]
fn strict_input_enforces_configurable_budgets() {
    let bytes = hwpx_with(
        HEADER.as_bytes(),
        SECTION.as_bytes(),
        &[("extra.bin", &[0u8; 256])],
    );
    let limits = [
        InputLimits {
            max_input_bytes: bytes.len() - 1,
            ..Default::default()
        },
        InputLimits {
            max_entries: 4,
            ..Default::default()
        },
        InputLimits {
            max_entry_bytes: 128,
            ..Default::default()
        },
        InputLimits {
            max_expanded_bytes: CONTENT.len() + HEADER.len() + SECTION.len() + 255,
            ..Default::default()
        },
        InputLimits {
            max_xml_nodes: 4,
            ..Default::default()
        },
        InputLimits {
            max_xml_depth: 2,
            ..Default::default()
        },
    ];
    for limits in limits {
        assert!(parse_document_strict_with_limits(&bytes, &limits).is_err());
        assert!(DocumentCore::from_bytes_strict_with_limits(&bytes, &limits).is_err());
    }
    let bytes = hwp(&body(), false, &[]);
    for limits in [
        InputLimits {
            max_records: 2,
            ..Default::default()
        },
        InputLimits {
            max_record_depth: 0,
            ..Default::default()
        },
        InputLimits {
            max_expanded_bytes: 256,
            ..Default::default()
        },
    ] {
        assert!(parse_document_strict_with_limits(&bytes, &limits).is_err());
    }
}

#[test]
fn strict_input_rejects_truncated_and_short_hwp_records() {
    for suffix in [&[1u8][..], &[1u8, 2], &[1u8, 2, 3]] {
        let mut damaged = body();
        damaged.extend_from_slice(suffix);
        let bytes = hwp(&damaged, false, &[]);
        assert!(parse_document(&bytes).is_ok());
        rejected(&bytes);
    }
    let short = record(rhwp::parser::tags::HWPTAG_PARA_HEADER, 0, &[]);
    rejected(&hwp(&short, false, &[]));
    rejected(&hwp(&[], false, &[]));
    let mut damaged = body();
    damaged.extend_from_slice(&((100u32 << 20) | 67).to_le_bytes());
    rejected(&hwp(&damaged, false, &[]));
    for text in [&[0x00, 0xd8][..], &[0x09, 0x00], &[0x0d, 0x00, 0x41, 0x00]] {
        let mut damaged = record(rhwp::parser::tags::HWPTAG_PARA_HEADER, 0, &[0; 22]);
        damaged.extend(record(rhwp::parser::tags::HWPTAG_PARA_TEXT, 1, text));
        rejected(&hwp(&damaged, false, &[]));
    }
}

#[test]
fn strict_input_does_not_use_permissive_cfb_header_recovery() {
    let mut bytes = hwp(&body(), false, &[]);
    assert_eq!(u16::from_le_bytes([bytes[26], bytes[27]]), 3);
    bytes[40..44].copy_from_slice(&1u32.to_le_bytes());
    assert!(parse_document(&bytes).is_ok());
    rejected(&bytes);
}

#[test]
fn strict_input_rejects_protected_and_unsupported_variants() {
    let mut bytes = hwp(&body(), false, &[]);
    let mut compound = cfb::CompoundFile::open(Cursor::new(&mut bytes)).unwrap();
    let mut header = vec![0u8; 256];
    std::io::Read::read_exact(
        &mut compound.open_stream("/FileHeader").unwrap(),
        &mut header,
    )
    .unwrap();
    header[36] = 2;
    compound
        .create_stream("/FileHeader")
        .unwrap()
        .write_all(&header)
        .unwrap();
    drop(compound);
    rejected(&bytes);
    rejected(&hwp(&body(), false, &[("/ViewText", b"unsupported")]));
    rejected(b"HWP Document File V3.00");
    let mut bytes = hwpx();
    let eocd = bytes.len() - 22;
    bytes[eocd + 10..eocd + 12].copy_from_slice(&u16::MAX.to_le_bytes());
    rejected(&bytes);
}
