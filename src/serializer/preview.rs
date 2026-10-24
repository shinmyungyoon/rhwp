use crate::model::document::Document;

pub(super) fn build_preview_text(doc: &Document) -> String {
    // Use the same bounded body-text excerpt for both container formats.
    let mut remaining = 1000;
    let mut output = String::new();
    for section in &doc.sections {
        for paragraph in &section.paragraphs {
            let text = paragraph.text.trim_end_matches('\0');
            if text.is_empty() {
                continue;
            }
            for character in text.chars().chain("\r\n".chars()) {
                output.push(character);
                remaining -= 1;
                if remaining == 0 {
                    return output;
                }
            }
        }
    }
    output
}
