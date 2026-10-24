use std::io::{Cursor, Read, Write};

use rhwp::document_core::DocumentCore;

const ORIGINAL: &str = "원본 문장";
const CURRENT: &str = "수정한 문장";
const VERSION: &[u8] = br#"<hv:HCFVersion xmlns:hv="http://www.hancom.co.kr/hwpml/2011/version" targetApplication="WORDPROCESSOR" major="5" minor="0" micro="3" buildNumber="0" os="1" xmlVersion="1.5" application="Synthetic" appVersion="1.0"/>"#;
const SETTINGS: &[u8] =
    br#"<settings xmlns="urn:synthetic:settings"><printInfo copies="2"/></settings>"#;
const RESOURCE: &[u8] = b"independent synthetic resource bytes";

fn original_png() -> Vec<u8> {
    fn chunk(out: &mut Vec<u8>, name: &[u8; 4], bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(bytes);
        let mut checksum = crc32fast::Hasher::new();
        checksum.update(name);
        checksum.update(bytes);
        out.extend_from_slice(&checksum.finalize().to_be_bytes());
    }
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut header = Vec::new();
    header.extend_from_slice(&2u32.to_be_bytes());
    header.extend_from_slice(&2u32.to_be_bytes());
    header.extend_from_slice(&[8, 2, 0, 0, 0]);
    chunk(&mut png, b"IHDR", &header);
    let mut compressed =
        flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    compressed
        .write_all(&[0, 255, 0, 0, 0, 255, 0, 0, 0, 0, 255, 255, 255, 255])
        .unwrap();
    chunk(&mut png, b"IDAT", &compressed.finish().unwrap());
    chunk(&mut png, b"IEND", &[]);
    png
}

fn synthetic_document(body: &str, preview: &str) -> Vec<u8> {
    let section = format!(
        r#"<hs:sec xmlns:hs="http://www.hancom.co.kr/hwpml/2011/section" xmlns:hp="http://www.hancom.co.kr/hwpml/2011/paragraph"><hp:p id="0" paraPrIDRef="0" styleIDRef="0" pageBreak="0" columnBreak="0" merged="0"><hp:run charPrIDRef="0"><hp:t>{body}</hp:t></hp:run></hp:p></hs:sec>"#
    );
    let thumbnail = original_png();
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, bytes) in [
        ("mimetype", b"application/hwp+zip".as_slice()),
        ("version.xml", VERSION),
        ("settings.xml", SETTINGS),
        ("Preview/PrvText.txt", preview.as_bytes()),
        ("Preview/PrvImage.png", thumbnail.as_slice()),
        ("BinData/resource.bin", RESOURCE),
        ("Contents/content.hpf", br#"<opf:package xmlns:opf="http://www.idpf.org/2007/opf/"><opf:manifest><opf:item id="section0" href="Contents/section0.xml" media-type="application/xml"/><opf:item id="resource1" href="BinData/resource.bin" media-type="application/octet-stream" isEmbeded="1"/></opf:manifest><opf:spine><opf:itemref idref="section0"/></opf:spine></opf:package>"#.as_slice()),
        ("Contents/header.xml", br##"<hh:head xmlns:hh="http://www.hancom.co.kr/hwpml/2011/head" version="1.4" secCnt="1"><hh:refList><hh:charProperties itemCnt="1"><hh:charPr id="0" height="1000" textColor="#000000"></hh:charPr></hh:charProperties><hh:paraProperties itemCnt="1"><hh:paraPr id="0"></hh:paraPr></hh:paraProperties><hh:styles itemCnt="1"><hh:style id="0" type="PARA" name="Normal" engName="Normal" paraPrIDRef="0" charPrIDRef="0" nextStyleIDRef="0"/></hh:styles></hh:refList></hh:head>"##.as_slice()),
        ("Contents/section0.xml", section.as_bytes()),
    ] {
        zip.start_file(name, zip::write::SimpleFileOptions::default()).unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn entry(bytes: &[u8], name: &str) -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let mut output = Vec::new();
    archive
        .by_name(name)
        .unwrap()
        .read_to_end(&mut output)
        .unwrap();
    output
}

fn check_saved_document(bytes: &[u8]) {
    let preview = String::from_utf8(entry(bytes, "Preview/PrvText.txt")).unwrap();
    assert!(preview.contains(CURRENT), "{preview:?}");
    assert!(!preview.contains(ORIGINAL), "{preview:?}");
    let reopened = DocumentCore::from_bytes(bytes).unwrap();
    assert_eq!(reopened.document().sections[0].paragraphs[0].text, CURRENT);
    for (path, expected) in [
        ("version.xml", VERSION),
        ("settings.xml", SETTINGS),
        ("Preview/PrvImage.png", original_png().as_slice()),
    ] {
        assert_eq!(entry(bytes, path), expected, "{path}");
    }
    let archive = zip::ZipArchive::new(Cursor::new(bytes)).unwrap();
    let resources = archive
        .file_names()
        .filter(|name| name.starts_with("BinData/"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    assert_eq!(resources.len(), 1);
    assert_eq!(entry(bytes, &resources[0]), RESOURCE);
}

#[test]
fn preview_tracks_edited_text_and_preserves_other_package_entries() {
    let source = synthetic_document(ORIGINAL, ORIGINAL);
    let mut document = DocumentCore::from_bytes(&source).unwrap();
    document
        .replace_all_native(ORIGINAL, CURRENT, true)
        .unwrap();
    let saved = document.export_hwpx_native().unwrap();
    check_saved_document(&saved);
    let reopened = DocumentCore::from_bytes(&saved).unwrap();
    check_saved_document(&reopened.export_hwpx_native().unwrap());
}

#[test]
fn saving_without_edits_rebuilds_a_stale_preview() {
    let source = synthetic_document(CURRENT, ORIGINAL);
    let document = DocumentCore::from_bytes(&source).unwrap();
    let saved = document.export_hwpx_native().unwrap();
    check_saved_document(&saved);
    let reopened = DocumentCore::from_bytes(&saved).unwrap();
    check_saved_document(&reopened.export_hwpx_native().unwrap());
}
