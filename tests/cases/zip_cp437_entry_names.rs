use rhwp::parser::hwpx::reader::HwpxReader;
use std::io::{Cursor, Write};

#[test]
fn legacy_cp437_entry_name_is_preserved() {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file("x.xml", zip::write::SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"<p/>").unwrap();
    let mut bytes = writer.finish().unwrap().into_inner();
    let positions: Vec<_> = bytes
        .windows(5)
        .enumerate()
        .filter_map(|(index, name)| (name == b"x.xml").then_some(index))
        .collect();
    assert_eq!(positions.len(), 2);
    for index in positions {
        bytes[index] = 0x82;
    }

    let mut reader = HwpxReader::open(&bytes).unwrap();
    assert_eq!(reader.file_names(), vec!["é.xml"]);
    assert_eq!(reader.read_file("é.xml").unwrap(), "<p/>");
}
