#![cfg(not(target_arch = "wasm32"))]

use std::fs;
use std::io::{Cursor, Write};
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Output};

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("rhwp-publication-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn synthetic_hwpx(empty: bool) -> Vec<u8> {
    let section = if empty {
        r#"<hs:sec xmlns:hs="http://www.hancom.co.kr/hwpml/2011/section"/>"#
    } else {
        r#"<hs:sec xmlns:hs="http://www.hancom.co.kr/hwpml/2011/section" xmlns:hp="http://www.hancom.co.kr/hwpml/2011/paragraph"><hp:p id="0" paraPrIDRef="0" styleIDRef="0" pageBreak="0" columnBreak="0" merged="0"><hp:run charPrIDRef="0"><hp:t>원본 문장</hp:t></hp:run></hp:p></hs:sec>"#
    };
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, contents) in [
        ("mimetype", "application/hwp+zip"),
        (
            "Contents/content.hpf",
            r#"<opf:package xmlns:opf="http://www.idpf.org/2007/opf/"><opf:manifest><opf:item id="section0" href="Contents/section0.xml" media-type="application/xml"/></opf:manifest><opf:spine><opf:itemref idref="section0"/></opf:spine></opf:package>"#,
        ),
        (
            "Contents/header.xml",
            r##"<hh:head xmlns:hh="http://www.hancom.co.kr/hwpml/2011/head" version="1.4" secCnt="1"><hh:refList><hh:charProperties itemCnt="1"><hh:charPr id="0" height="1000" textColor="#000000"></hh:charPr></hh:charProperties><hh:paraProperties itemCnt="1"><hh:paraPr id="0"></hh:paraPr></hh:paraProperties><hh:styles itemCnt="1"><hh:style id="0" type="PARA" name="Normal" engName="Normal" paraPrIDRef="0" charPrIDRef="0" nextStyleIDRef="0"/></hh:styles></hh:refList></hh:head>"##,
        ),
        ("Contents/section0.xml", section),
    ] {
        zip.start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(contents.as_bytes()).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn run(args: &[&str]) -> Output {
    let executable = std::env::var("CARGO_BIN_EXE_rhwp")
        .unwrap_or_else(|_| env!("CARGO_BIN_EXE_rhwp").to_string());
    Command::new(executable).args(args).output().unwrap()
}

fn redaction_hwpx(text: &str, empty_tail: bool) -> Vec<u8> {
    let original = synthetic_hwpx(false);
    let mut source = zip::ZipArchive::new(Cursor::new(original)).unwrap();
    let mut output = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for index in 0..source.len() {
        let mut entry = source.by_index(index).unwrap();
        let name = entry.name().to_string();
        let mut contents = String::new();
        std::io::Read::read_to_string(&mut entry, &mut contents).unwrap();
        if name == "Contents/section0.xml" {
            contents = contents.replace("원본 문장", text);
        }
        if empty_tail && name == "Contents/header.xml" {
            contents = contents.replace("secCnt=\"1\"", "secCnt=\"2\"");
        }
        if empty_tail && name == "Contents/content.hpf" {
            contents = contents.replace(
                "</opf:manifest>",
                "<opf:item id=\"section1\" href=\"Contents/section1.xml\" media-type=\"application/xml\"/></opf:manifest>",
            );
            contents = contents.replace(
                "</opf:spine>",
                "<opf:itemref idref=\"section1\"/></opf:spine>",
            );
        }
        output
            .start_file(name, zip::write::SimpleFileOptions::default())
            .unwrap();
        output.write_all(contents.as_bytes()).unwrap();
    }
    if empty_tail {
        output
            .start_file(
                "Contents/section1.xml",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        output
            .write_all(br#"<hs:sec xmlns:hs="http://www.hancom.co.kr/hwpml/2011/section"/>"#)
            .unwrap();
    }
    output.finish().unwrap().into_inner()
}

#[test]
fn failed_redaction_verification_reports_no_published_output() {
    let directory = TestDirectory::new();
    let source = directory.0.join("source.hwpx");
    let output = directory.0.join("output.hwpx");
    let original = redaction_hwpx("person@example.com", true);
    fs::write(&source, &original).unwrap();
    fs::write(&output, b"existing output").unwrap();
    for json_mode in [true, false] {
        let mut args = vec![
            "edit",
            "redact",
            source.to_str().unwrap(),
            "--kind",
            "email",
            "--verify",
            "-o",
            output.to_str().unwrap(),
        ];
        if json_mode {
            args.push("--json");
        }
        let result = run(&args);
        assert_eq!(result.status.code(), Some(3), "{result:?}");
        assert_eq!(fs::read(&source).unwrap(), original);
        assert_eq!(fs::read(&output).unwrap(), b"existing output");
        assert!(!String::from_utf8_lossy(&result.stdout).contains("마스킹 완료"));
        if json_mode {
            let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
            assert_eq!(report["redactedCount"], 1);
            assert!(report["changedPages"].is_null(), "{report}");
            assert!(report.get("output").is_none(), "{report}");
            assert!(report.get("outputFormat").is_none(), "{report}");
            assert_eq!(report["verify"]["identical"], false);
            assert!(report["verify"]["diffCount"].as_u64().unwrap() > 0);
        } else {
            assert!(String::from_utf8_lossy(&result.stderr).contains("검증 실패"));
        }
    }
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
}

#[test]
fn redaction_publication_controls_report_only_successful_saves() {
    for (text, dry_run, publishes) in [
        ("person@example.com", false, true),
        ("no sensitive content", false, false),
        ("person@example.com", true, false),
    ] {
        let directory = TestDirectory::new();
        let source = directory.0.join("source.hwpx");
        let output = directory.0.join("output.hwpx");
        let original = redaction_hwpx(text, false);
        fs::write(&source, &original).unwrap();
        fs::write(&output, b"existing output").unwrap();
        let mut args = vec![
            "edit",
            "redact",
            source.to_str().unwrap(),
            "--kind",
            "email",
            "--verify",
            "--json",
            "-o",
            output.to_str().unwrap(),
        ];
        if dry_run {
            args.push("--dry-run");
        }
        let result = run(&args);
        assert!(result.status.success(), "{result:?}");
        let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(fs::read(&source).unwrap(), original);
        assert_eq!(report.get("output").is_some(), publishes, "{report}");
        assert_eq!(report.get("outputFormat").is_some(), publishes, "{report}");
        if publishes {
            assert_eq!(report["verify"]["identical"], true);
            assert!(!report["changedPages"].is_null(), "{report}");
            let reopened = run(&["export-text", output.to_str().unwrap(), "--json"]);
            assert!(reopened.status.success(), "{reopened:?}");
            assert!(!String::from_utf8_lossy(&reopened.stdout).contains(text));
        } else {
            assert_eq!(fs::read(&output).unwrap(), b"existing output");
            assert!(report["changedPages"].is_null(), "{report}");
            assert!(report.get("verify").is_none(), "{report}");
        }
    }
}

#[test]
fn failed_text_edit_verification_reports_no_published_output() {
    let directory = TestDirectory::new();
    let source = directory.0.join("source.hwpx");
    let output = directory.0.join("output.hwpx");
    let original = redaction_hwpx("person@example.com", true);
    fs::write(&source, &original).unwrap();
    for edit in [
        vec!["replace-text", "--find", "person", "--replace", "reader"],
        vec![
            "insert-text",
            "--section",
            "0",
            "--para",
            "0",
            "--offset",
            "0",
            "--text",
            "new ",
        ],
        vec!["insert-paragraph", "--section", "0", "--para", "0"],
    ] {
        fs::write(&output, b"existing output").unwrap();
        let mut args = vec!["edit", edit[0], source.to_str().unwrap()];
        args.extend_from_slice(&edit[1..]);
        args.extend_from_slice(&["-o", output.to_str().unwrap(), "--verify", "--json"]);
        let result = run(&args);
        assert_eq!(result.status.code(), Some(3), "{result:?}");
        let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert!(report["changedPages"].is_null(), "{report}");
        assert!(report.get("output").is_none(), "{report}");
        assert!(report.get("outputFormat").is_none(), "{report}");
        assert_eq!(report["verify"]["identical"], false);
        assert_eq!(fs::read(&output).unwrap(), b"existing output");
        assert_eq!(fs::read(&source).unwrap(), original);
    }
}

#[cfg(unix)]
fn operations(input: &Path, output: &Path) -> Vec<Vec<String>> {
    let is_hwp = output.extension().and_then(|extension| extension.to_str()) == Some("hwp");
    let input = input.to_str().unwrap();
    let output = output.to_str().unwrap();
    if is_hwp {
        return vec![vec![
            "convert".to_string(),
            input.to_string(),
            output.to_string(),
            "--json".to_string(),
        ]];
    }
    [
        vec!["export-hwpx", input, output, "--json"],
        vec![
            "edit",
            "insert-text",
            input,
            "--section",
            "0",
            "--para",
            "0",
            "--offset",
            "0",
            "--text",
            "새 ",
            "-o",
            output,
            "--json",
        ],
        vec![
            "edit",
            "replace-text",
            input,
            "--find",
            "원본",
            "--replace",
            "수정",
            "-o",
            output,
            "--json",
        ],
        vec![
            "edit",
            "insert-paragraph",
            input,
            "--section",
            "0",
            "--para",
            "0",
            "-o",
            output,
            "--json",
        ],
    ]
    .into_iter()
    .map(|args| args.into_iter().map(str::to_string).collect())
    .collect()
}

#[test]
fn rejected_conversion_verification_preserves_existing_output_and_source() {
    let directory = TestDirectory::new();
    let source = directory.0.join("source.hwpx");
    let output = directory.0.join("output.hwpx");
    let original = synthetic_hwpx(true);
    fs::write(&source, &original).unwrap();
    fs::write(&output, b"existing output").unwrap();
    let result = run(&[
        "export-hwpx",
        source.to_str().unwrap(),
        output.to_str().unwrap(),
        "--verify",
        "--json",
    ]);
    assert_eq!(result.status.code(), Some(3), "{result:?}");
    assert_eq!(fs::read(&source).unwrap(), original);
    assert_eq!(fs::read(&output).unwrap(), b"existing output");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["verify"]["identical"], false);
    assert_eq!(report["bytes"], 0);
    assert!(report.get("output").is_none(), "{report}");
    assert!(report.get("format").is_none(), "{report}");
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
}

#[test]
fn successful_edit_replaces_output_with_reopenable_content() {
    let directory = TestDirectory::new();
    let source = directory.0.join("source.hwpx");
    let output = directory.0.join("output.hwpx");
    let original = synthetic_hwpx(false);
    fs::write(&source, &original).unwrap();
    let opened = run(&["export-text", source.to_str().unwrap(), "--json"]);
    assert!(opened.status.success(), "{opened:?}");
    fs::write(&output, b"existing output").unwrap();
    let result = run(&[
        "edit",
        "replace-text",
        source.to_str().unwrap(),
        "--find",
        "원본",
        "--replace",
        "수정",
        "-o",
        output.to_str().unwrap(),
        "--json",
    ]);
    assert!(result.status.success(), "{result:?}");
    let saved = run(&["export-text", output.to_str().unwrap(), "--json"]);
    assert!(saved.status.success(), "{saved:?}");
    let report: serde_json::Value = serde_json::from_slice(&saved.stdout).unwrap();
    assert!(report["pages"]
        .as_array()
        .unwrap()
        .iter()
        .any(|page| page["text"].as_str().unwrap().contains("수정 문장")));
    assert_eq!(fs::read(&source).unwrap(), original);
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 2);
}

#[cfg(unix)]
#[test]
fn conversion_and_edits_reject_leaf_and_parent_symlinks() {
    use std::os::unix::fs::symlink;

    let directory = TestDirectory::new();
    let source = directory.0.join("source.hwpx");
    let original = synthetic_hwpx(false);
    fs::write(&source, &original).unwrap();
    let outside = directory.0.join("outside");
    fs::create_dir(&outside).unwrap();
    let protected = outside.join("protected.hwpx");
    fs::write(&protected, b"protected bytes").unwrap();
    let leaf = directory.0.join("leaf.hwpx");
    symlink(&protected, &leaf).unwrap();
    let leaf_hwp = directory.0.join("leaf.hwp");
    symlink(&protected, &leaf_hwp).unwrap();
    let parent = directory.0.join("linked-parent");
    symlink(&outside, &parent).unwrap();
    for extension in ["hwp", "hwpx"] {
        for args in operations(&source, &directory.0.join(format!("control.{extension}"))) {
            let result = run(&args.iter().map(String::as_str).collect::<Vec<_>>());
            assert!(result.status.success(), "{args:?}: {result:?}");
        }
    }
    for destination in [
        leaf.clone(),
        parent.join("protected.hwpx"),
        leaf_hwp,
        parent.join("protected.hwp"),
    ] {
        for args in operations(&source, &destination) {
            let result = run(&args.iter().map(String::as_str).collect::<Vec<_>>());
            assert_eq!(result.status.code(), Some(1), "{args:?}: {result:?}");
            assert_eq!(fs::read(&protected).unwrap(), b"protected bytes");
            assert_eq!(fs::read(&source).unwrap(), original);
            assert!(fs::symlink_metadata(&leaf)
                .unwrap()
                .file_type()
                .is_symlink());
        }
    }
    assert_eq!(fs::read_dir(&outside).unwrap().count(), 1);
}
