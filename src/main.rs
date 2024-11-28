use base64::prelude::{BASE64_STANDARD, BASE64_STANDARD_NO_PAD};
use base64::Engine;
use csv::Writer;
use encoding_rs::{UTF_16BE, UTF_16LE, UTF_8};
use evtx::{EvtxParser, ParserSettings};
use regex::Regex;
use serde_json::Value;
use std::error::Error;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::string::FromUtf16Error;
use std::{env, str};
use std::sync::LazyLock;
use walkdir::WalkDir;

static TOKEN_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\w+/]+").unwrap());

fn is_base64(s: &str) -> bool {
    if BASE64_STANDARD_NO_PAD.decode(s).is_ok() {
        true
    } else {
        BASE64_STANDARD.decode(s).is_ok()
    }
}

fn is_utf8(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if bytes.len() < 5 {
        return false;
    }
    UTF_8.decode_without_bom_handling(bytes).0.is_ascii()
}

fn is_utf16_le(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if bytes.len() < 5 {
        return false;
    }
    UTF_16LE.decode_without_bom_handling(bytes).0.is_ascii()
}

fn is_utf16_be(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if bytes.len() < 5 {
        return false;
    }
    UTF_16BE.decode_without_bom_handling(bytes).0.is_ascii()
}

fn extract_evtx_files(dir: &Path) -> Vec<PathBuf> {
    WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.path().is_file()
                && entry.path().extension().and_then(|s| s.to_str()) == Some("evtx")
        })
        .map(|entry| entry.path().to_path_buf())
        .collect()
}

fn read_evtx_file(file_path: &Path) -> Option<EvtxParser<File>> {
    match EvtxParser::from_path(file_path) {
        Ok(evtx_parser) => {
            let mut parse_config = ParserSettings::default();
            parse_config = parse_config.separate_json_attributes(true);
            parse_config = parse_config.num_threads(0);

            let evtx_parser = evtx_parser.with_configuration(parse_config);
            Some(evtx_parser)
        }
        Err(e) => {
            eprintln!("{e}");
            None
        }
    }
}

fn extract_payload(data: &Value) -> Vec<Value> {
    let ch = data["Event"]["System"]["Channel"].as_str();
    let id = data["Event"]["System"]["EventID"].as_i64();
    let mut values = vec![];
    if let Some(ch) = ch {
        if let Some(id) = id {
            if ch == "Security" && id == 4688 {
                let v = data["Event"]["EventData"]["CommandLine"].clone();
                values.push(v);
            } else if ch == "Microsoft-Windows-Sysmon/Operational" && id == 1 {
                let v = data["Event"]["EventData"]["CommandLine"].clone();
                values.push(v);
                let v = data["Event"]["EventData"]["ParentCommandLine"].clone();
                values.push(v);
            } else if ch == "Microsoft-Windows-PowerShell/Operational" && id == 4104 {
                let v = data["Event"]["EventData"]["ScriptBlockText"].clone();
                values.push(v);
            } else if ch == "Microsoft-Windows-PowerShell/Operational" && id == 4103 {
                let v = data["Event"]["EventData"]["Payload"].clone();
                values.push(v);
            }
        }
    }
    values.iter().filter(|v| !v.is_null()).cloned().collect()
}

fn tokenize(payload_str: &str) -> Vec<&str> {
    TOKEN_REGEX.find_iter(payload_str).map(|mat| mat.as_str()).collect()
}

fn utf16_le_to_string(bytes: &[u8]) -> Result<String, FromUtf16Error> {
    let utf16_data: Vec<u16> = bytes
        .chunks(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16(&utf16_data)
}

fn utf16_be_to_string(bytes: &[u8]) -> Result<String, FromUtf16Error> {
    let utf16_data: Vec<u16> = bytes
        .chunks(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
        .collect();
    String::from_utf16(&utf16_data)
}

fn process_record(
    wtr: &mut Writer<File>,
    file: &Path,
    payload_str: &str,
) -> Result<(), Box<dyn Error>> {
    let tokens = tokenize(payload_str);
    for token in tokens {
        if is_base64(token) {
            if token.len() < 10 || token.chars().all(|c| c.is_alphabetic()) {
                // Skip short tokens and all alphabetic tokens
                continue;
            }
            let payload = match BASE64_STANDARD_NO_PAD.decode(token) {
                Ok(payload) => payload,
                Err(_) => BASE64_STANDARD.decode(token).unwrap(),
            };
            let file_name = file.file_name().unwrap().to_str().unwrap();
            if is_utf16_le(&payload) {
                println!(
                    "Possible Base64 + UTF-16 LE({}): {}, {}",
                    file_name,
                    utf16_le_to_string(&payload).unwrap(),
                    token
                );
                wtr.write_record([
                    "Possible Base64 + UTF-16 LE",
                    file_name,
                    utf16_le_to_string(&payload).unwrap().as_str(),
                    token,
                ])?;
            } else if is_utf16_be(&payload) {
                println!(
                    "Possible Base64 + UTF-16 BE({}): {}, {}",
                    file_name,
                    utf16_be_to_string(&payload).unwrap(),
                    token
                );
                wtr.write_record([
                    "Possible Base64 + UTF-16 BE",
                    file_name,
                    utf16_be_to_string(&payload).unwrap().as_str(),
                    token,
                ])?;
            } else if is_utf8(&payload) {
                println!(
                    "Possible Base64 + UTF-8({:?}): {}, {}",
                    file_name,
                    str::from_utf8(&payload).unwrap(),
                    token
                );
                wtr.write_record([
                    "Possible Base64 + UTF-8",
                    file_name,
                    str::from_utf8(&payload).unwrap(),
                    token,
                ])?;
            } else {
                let kind = infer::get(&payload);
                if let Some(k) = kind {
                        println!(
                            "Possible Base64 + binary({:?}): {}, {}",
                            file_name,
                            k.to_string().as_str(),
                            token
                        );
                        wtr.write_record([
                            "Possible Base64 + binary",
                            file_name,
                            k.to_string().as_str(),
                            token,
                        ])?;
                };
            }
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <directory>", args[0]);
        std::process::exit(1);
    }
    let mut wtr = Writer::from_path("output.csv")?;
    wtr.write_record(["Type", "Filename", "Decoded Text", "Original Text"])?;
    let dir = Path::new(&args[1]);
    let evtx_files = extract_evtx_files(dir);
    for file in evtx_files {
        if let Some(mut parser) = read_evtx_file(&file) {
            let records = parser.records_json_value();
            for rec in records {
                if let Ok(rec_data) = &rec.as_ref() {
                    let payloads = extract_payload(&rec_data.data);
                    for payload in payloads {
                        if let Some(payload_str) = payload.as_str() {
                            process_record(&mut wtr, &file, payload_str)?;
                        }
                    }
                }
            }
        }
    }
    wtr.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::FromUtf16Error;

    fn utf16le_to_string(bytes: &[u8]) -> Result<String, FromUtf16Error> {
        let utf16_data: Vec<u16> = bytes
            .chunks(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        String::from_utf16(&utf16_data)
    }

    fn utf16be_to_string(bytes: &[u8]) -> Result<String, FromUtf16Error> {
        let utf16_data: Vec<u16> = bytes
            .chunks(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
            .collect();
        String::from_utf16(&utf16_data)
    }

    #[test]
    fn test_is_base64() {
        assert!(is_base64("SGVsbG8sIHdvcmxkIQ"));
        assert!(is_base64("SGVsbG8sIHdvcmxkIQ=="));
        assert!(!is_base64("Hello, world!"));
    }

    #[test]
    fn test_is_utf8() {
        assert!(is_utf8("Hello, world!".as_bytes()));
        assert!(!is_utf8("こんにちは、世界！".as_bytes()));
    }

    #[test]
    fn test_is_utf16() {
        let utf16le_bytes = vec![0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00];
        let utf16be_bytes = vec![0x00, 0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F];
        match utf16le_to_string(&utf16le_bytes) {
            Ok(string) => println!("utf16 Converted string: {}", string),
            Err(e) => println!("Failed to convert: {}", e),
        }
        match utf16be_to_string(&utf16be_bytes) {
            Ok(string) => println!("utf16 Converted string: {}", string),
            Err(e) => println!("Failed to convert: {}", e),
        }
        assert!(is_utf16_le(utf16le_bytes.as_slice()));
        assert!(!is_utf16_le(utf16be_bytes.as_slice()));
        assert!(is_utf16_be(utf16be_bytes.as_slice()));
        assert!(!is_utf16_be(utf16le_bytes.as_slice()));
    }
}
