//! Streaming Office Open XML for large files (decision 034): a bounded zip
//! reader and writer, an incremental XML tokenizer and Word body paragraphs.
//! Nothing here holds a whole package or part in memory.

pub mod docx;
pub mod xml;
pub mod zip;

/// Why a package could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum OoxmlError {
    #[error("zip package: {0}")]
    Zip(&'static str),
    #[error("XML: {0}")]
    Xml(&'static str),
    #[error("limit reached: {0}")]
    Limit(&'static str),
    #[error("input or output: {0}")]
    Io(#[from] std::io::Error),
    #[error("staged upload: {0}")]
    Source(String),
}

#[cfg(test)]
mod tests {
    use super::docx::{self, Body, Paragraph};
    use super::xml::{Token, Tokenizer};
    use super::zip::{central_directory, crc32, data_offset, Inflater, ZipLimits, ZipWriter};
    use super::OoxmlError;

    async fn package(parts: &[(&str, &[u8], u8)]) -> Vec<u8> {
        let mut writer = ZipWriter::new(Vec::new());
        for (name, data, level) in parts {
            writer.start(name, *level).await.unwrap();
            for piece in data.chunks(7_777) {
                writer.write(piece).await.unwrap();
            }
        }
        writer.finish().await.unwrap().0
    }

    async fn inflate(bytes: &[u8], name: &str) -> Result<Vec<u8>, OoxmlError> {
        let mut source = bytes;
        let entries = central_directory(&mut source, ZipLimits::default()).await?;
        let entry = entries.iter().find(|e| e.name == name).unwrap();
        let start = data_offset(&mut source, entry).await? as usize;
        let mut inflater = Inflater::new(entry);
        let mut out = Vec::new();
        for piece in bytes[start..start + entry.compressed as usize].chunks(1_000) {
            inflater.feed(piece, &mut |d| {
                out.extend_from_slice(d);
                Ok(())
            })?;
        }
        Ok(out)
    }

    #[test]
    fn crc_matches_the_standard_check_value() {
        assert_eq!(crc32(0, b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(crc32(0, b"12345"), b"6789"), 0xcbf4_3926);
    }

    #[tokio::test]
    async fn written_packages_read_back_entry_by_entry() {
        let xml: Vec<u8> = (0..200_000u32)
            .flat_map(|i| (i % 251).to_le_bytes())
            .collect();
        let bytes = package(&[
            ("word/document.xml", &xml, 6),
            ("word/media/a.png", b"stored", 0),
        ])
        .await;
        assert_eq!(inflate(&bytes, "word/document.xml").await.unwrap(), xml);
        assert_eq!(
            inflate(&bytes, "word/media/a.png").await.unwrap(),
            b"stored"
        );
    }

    #[tokio::test]
    async fn unsafe_names_bombs_and_corruption_are_refused() {
        // A path traversal name never reaches the writer, so patch one in.
        assert!(ZipWriter::new(Vec::new())
            .start("ab/../x", 0)
            .await
            .is_err());
        let mut bytes = package(&[("word/xx.xml", b"x", 0)]).await;
        let at = bytes
            .windows(11)
            .rposition(|w| w == b"word/xx.xml")
            .unwrap();
        bytes[at..at + 3].copy_from_slice(b"../");
        assert!(matches!(
            central_directory(&mut bytes.as_slice(), ZipLimits::default()).await,
            Err(OoxmlError::Zip(_))
        ));
        // 1,000:1 expansion is refused before any byte is inflated.
        let zeros = vec![0u8; 20 << 20];
        let bomb = package(&[("word/document.xml", &zeros, 9)]).await;
        assert!(matches!(
            central_directory(&mut bomb.as_slice(), ZipLimits::default()).await,
            Err(OoxmlError::Limit(_))
        ));
        let generous = ZipLimits {
            max_ratio: 10_000,
            ..ZipLimits::default()
        };
        assert!(central_directory(&mut bomb.as_slice(), generous)
            .await
            .is_ok());
        // A flipped data byte fails the CRC or the deflate stream.
        let text = b"<w:document><w:body><w:p/></w:body></w:document>".repeat(500);
        let mut good = package(&[("word/document.xml", &text, 6)]).await;
        let entries = central_directory(&mut good.as_slice(), ZipLimits::default())
            .await
            .unwrap();
        let start = data_offset(&mut good.as_slice(), &entries[0])
            .await
            .unwrap() as usize;
        good[start + 20] ^= 0x55;
        assert!(inflate(&good, "word/document.xml").await.is_err());
        // Duplicate names are refused.
        let twice = package(&[("a.xml", b"1", 0), ("A.xml", b"2", 0)]).await;
        assert!(
            central_directory(&mut twice.as_slice(), ZipLimits::default())
                .await
                .is_err()
        );
    }

    fn tokens(xml: &[u8], step: usize) -> Result<Vec<String>, OoxmlError> {
        let mut t = Tokenizer::default();
        let mut out = Vec::new();
        let chunks: Vec<&[u8]> = xml.chunks(step).collect();
        for (i, chunk) in chunks.iter().enumerate() {
            t.feed(chunk, i + 1 == chunks.len(), &mut |token| {
                out.push(match token {
                    Token::Start { name, empty, .. } => {
                        format!("<{name}{}>", if empty { "/" } else { "" })
                    }
                    Token::End { name } => format!("</{name}>"),
                    Token::Text(text) => text.into_owned(),
                });
                Ok(())
            })?;
        }
        Ok(out)
    }

    #[test]
    fn tokens_do_not_depend_on_how_input_is_split() {
        let xml = br#"<?xml version="1.0"?><!-- c --><w:p a="x>y" b='&amp;'><w:t>a &lt; b &#x263A;</w:t><![CDATA[<raw>]]><w:br/></w:p>"#;
        let whole = tokens(xml, xml.len()).unwrap();
        assert_eq!(
            whole,
            [
                "<p>",
                "<t>",
                "a < b \u{263a}",
                "</t>",
                "<raw>",
                "<br/>",
                "</p>"
            ]
        );
        for step in 1..12 {
            assert_eq!(tokens(xml, step).unwrap(), whole, "step {step}");
        }
    }

    #[test]
    fn entities_doctypes_depth_and_mismatches_are_refused() {
        assert!(tokens(b"<!DOCTYPE x [<!ENTITY a 'b'>]><x/>", 5).is_err());
        assert!(tokens(b"<x>&custom;</x>", 3).is_err());
        assert!(tokens(b"<a><b></a></b>", 4).is_err());
        assert!(tokens(b"<a><b>", 4).is_err());
        let deep = "<a>".repeat(129) + &"</a>".repeat(129);
        assert!(matches!(
            tokens(deep.as_bytes(), 64),
            Err(OoxmlError::Limit(_))
        ));
        let ok = "<a>".repeat(128) + &"</a>".repeat(128);
        assert!(tokens(ok.as_bytes(), 64).is_ok());
        let long = format!("<a>{}</a>", "x".repeat(super::xml::MAX_TOKEN_BYTES + 10));
        assert!(matches!(
            tokens(long.as_bytes(), 1 << 16),
            Err(OoxmlError::Limit(_))
        ));
    }

    #[test]
    fn word_body_paragraphs_round_trip_through_the_writer() {
        let source = [
            Paragraph {
                text: "Title".into(),
                level: 1,
            },
            Paragraph {
                text: "a & b < c\tTabbed\nNext line".into(),
                level: 0,
            },
            Paragraph {
                text: String::new(),
                level: 0,
            },
            Paragraph {
                text: "বাংলা 👩‍💻".into(),
                level: 3,
            },
        ];
        let mut xml = String::from(docx::DOCUMENT_HEAD);
        for p in &source {
            docx::paragraph_xml(&p.text, p.level, p.level == 0, &mut xml);
        }
        xml.push_str(r#"<w:p><mc:AlternateContent><mc:Choice><w:t>box</w:t></mc:Choice><mc:Fallback><w:t>box</w:t></mc:Fallback></mc:AlternateContent></w:p>"#);
        xml.push_str(docx::DOCUMENT_TAIL);
        for step in [1, 13, xml.len()] {
            let mut body = Body::default();
            let chunks: Vec<&[u8]> = xml.as_bytes().chunks(step).collect();
            for (i, chunk) in chunks.iter().enumerate() {
                body.feed(chunk, i + 1 == chunks.len()).unwrap();
            }
            let got = body.take();
            assert_eq!(&got[..4], &source, "step {step}");
            assert_eq!(got[4].text, "box");
        }
    }
}
