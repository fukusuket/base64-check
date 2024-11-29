use crate::Base64Data::Unknown;
use base64::prelude::{BASE64_STANDARD, BASE64_STANDARD_NO_PAD};
use base64::Engine;
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Cell, CellAlignment, ContentArrangement, Table};
use csv::Writer;
use encoding_rs::{UTF_16BE, UTF_16LE, UTF_8};
use evtx::{EvtxParser, ParserSettings};
use infer::Type;
use regex::Regex;
use serde_json::Value;
use std::error::Error;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::string::FromUtf16Error;
use std::sync::LazyLock;
use std::{env, fmt, str};
use walkdir::WalkDir;

static TOKEN_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\w+/]+").unwrap());

struct EvtxInfo {
    ts: String,
    computer: String,
    rec_id: String,
    file_name: String,
    event: String,
}

impl EvtxInfo {
    fn new(val: &Value, file_name: String, event: Event) -> Self {
        let d = &val["Event"]["System"];
        let ts = d["TimeCreated_attributes"]["SystemTime"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let computer = d["Computer"].as_str().unwrap_or_default().to_string();
        let rec_id = d["EventRecordID"].as_i64().unwrap().to_string();
        Self {
            ts,
            computer,
            rec_id,
            file_name,
            event: event.to_string(),
        }
    }
}

#[derive(Clone)]
enum Event {
    Security4688,
    Sysmon1,
    PowerShell4104,
    PowerShell4103,
}

impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Event::Security4688 => write!(f, "Sec 4688"),
            Event::Sysmon1 => write!(f, "Sysmon 1"),
            Event::PowerShell4104 => write!(f, "PwSh 4104"),
            Event::PowerShell4103 => write!(f, "PwSh 4103"),
        }
    }
}

enum Base64Data {
    Utf8(String, String),
    Utf16Le(String, String),
    Utf16Be(String, String),
    Binary(String, Vec<u8>, Option<Type>),
    Unknown(String),
}

impl Base64Data {
    fn new(token: &str, payload: &[u8]) -> Self {
        if is_utf16_le(payload) {
            let s = utf16_le_to_string(payload).unwrap();
            return Base64Data::Utf16Le(token.to_string(), s);
        } else if is_utf16_be(payload) {
            let s = utf16_be_to_string(payload).unwrap();
            return Base64Data::Utf16Be(token.to_string(), s);
        } else if is_utf8(payload) {
            let s = str::from_utf8(payload).unwrap();
            return Base64Data::Utf8(token.to_string(), s.to_string());
        } else {
            let kind = infer::get(payload);
            if let Some(k) = kind {
                return Base64Data::Binary(token.to_string(), payload.to_vec(), Some(k));
            }
        }
        Unknown(token.to_string())
    }

    fn base64(&self) -> String {
        match self {
            Base64Data::Utf8(s, _)
            | Base64Data::Utf16Le(s, _)
            | Base64Data::Utf16Be(s, _)
            | Base64Data::Binary(s, _, _)
            | Base64Data::Unknown(s) => s.to_string(),
        }
    }

    fn decoded(&self) -> String {
        match self {
            Base64Data::Utf8(_, s) | Base64Data::Utf16Le(_, s) | Base64Data::Utf16Be(_, s) => {
                s.chars().filter(|&c| !c.is_control()).collect()
            }
            Base64Data::Binary(_, _, _) | Base64Data::Unknown(_) => "".to_string(),
        }
    }

    fn file_type(&self) -> String {
        match self {
            Base64Data::Utf8(_, _) | Base64Data::Utf16Le(_, _) | Base64Data::Utf16Be(_, _) => {
                "TXT".to_string()
            }
            Base64Data::Binary(_, _, kind) => {
                if let Some(kind) = kind {
                    kind.to_string()
                } else {
                    "Unknown".to_string()
                }
            }
            Base64Data::Unknown(_) => "Unknown".to_string(),
        }
    }

    fn len(&self) -> usize {
        match self {
            Base64Data::Utf8(_, s) | Base64Data::Utf16Le(_, s) | Base64Data::Utf16Be(_, s) => {
                s.len()
            }
            Base64Data::Binary(_, bytes, _) => bytes.len(),
            Base64Data::Unknown(s) => s.len(),
        }
    }
    fn is_binary(&self) -> String {
        match self {
            Base64Data::Binary(_, _, _) | Base64Data::Unknown(_) => "Y".to_string(),
            _ => "N".to_string(),
        }
    }

    fn is_double_encoding(&self) -> String {
        match self {
            Base64Data::Utf8(_, s) | Base64Data::Utf16Le(_, s) | Base64Data::Utf16Be(_, s) => {
                match is_base64(s) {
                    true => "Y".to_string(),
                    false => "N".to_string(),
                }
            }
            _ => "N".to_string(),
        }
    }
}

impl fmt::Display for Base64Data {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Base64Data::Utf8(_, _) => write!(f, "UTF-8"),
            Base64Data::Utf16Le(_, _) => write!(f, "UTF-16 LE"),
            Base64Data::Utf16Be(_, _) => write!(f, "UTF-16 BE"),
            Base64Data::Binary(_, _, _) => write!(f, "Binary"),
            Unknown(_) => write!(f, "Unknown"),
        }
    }
}

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

fn extract_payload(data: &Value) -> Vec<(Value, Event)> {
    let ch = data["Event"]["System"]["Channel"].as_str();
    let id = data["Event"]["System"]["EventID"].as_i64();
    let mut values = vec![];
    if let Some(ch) = ch {
        if let Some(id) = id {
            if ch == "Security" && id == 4688 {
                let v = data["Event"]["EventData"]["CommandLine"].clone();
                values.push((v, Event::Security4688));
            } else if ch == "Microsoft-Windows-Sysmon/Operational" && id == 1 {
                let v = data["Event"]["EventData"]["CommandLine"].clone();
                values.push((v, Event::Sysmon1));
                let v = data["Event"]["EventData"]["ParentCommandLine"].clone();
                values.push((v, Event::Sysmon1));
            } else if ch == "Microsoft-Windows-PowerShell/Operational" && id == 4104 {
                let v = data["Event"]["EventData"]["ScriptBlockText"].clone();
                values.push((v, Event::PowerShell4104));
            } else if ch == "Microsoft-Windows-PowerShell/Operational" && id == 4103 {
                let v = data["Event"]["EventData"]["Payload"].clone();
                values.push((v, Event::PowerShell4103));
            }
        }
    }
    values
        .iter()
        .filter(|(v, _)| !v.is_null())
        .cloned()
        .collect()
}

fn tokenize(payload_str: &str) -> Vec<&str> {
    TOKEN_REGEX
        .find_iter(payload_str)
        .map(|mat| mat.as_str())
        .collect()
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
    file: &Path,
    possible_base64: &str,
    data: &Value,
    event: Event,
) -> Vec<Vec<String>> {
    let evtx = EvtxInfo::new(data, file.to_string_lossy().to_string(), event);
    let mut records = Vec::new();
    let tokens = tokenize(possible_base64);
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
            let b64 = Base64Data::new(token, &payload);
            if matches!(b64, Base64Data::Unknown(_)) {
                continue;
            }
            let row = vec![
                evtx.ts.clone(),
                evtx.computer.clone(),
                b64.base64(),
                b64.decoded(),
                b64.len().to_string(),
                b64.is_binary(),
                b64.is_double_encoding(),
                b64.file_type(),
                b64.to_string(),
                evtx.event.clone(),
                evtx.rec_id.clone(),
                evtx.file_name.clone(),
            ];
            records.push(row);
        }
    }
    records
}
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <directory>", args[0]);
        std::process::exit(1);
    }
    let header = vec!["Timestamp", "Computer", "Base64 String", "Decoded String"];
    let mut header_cells = vec![];
    for header_str in &header {
        header_cells.push(Cell::new(header_str).set_alignment(CellAlignment::Center));
    }
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::DynamicFullWidth)
        .set_header(header_cells);
    let mut wtr = Writer::from_path("output.csv")?;
    let csv_header = vec![
        "Timestamp",
        "Computer",
        "Base64 String",
        "Decoded String",
        "Length",
        "Binary",
        "Double Encoding",
        "Encoding",
        "File Type",
        "Event",
        "Record ID",
        "File Name",
    ];
    wtr.write_record(csv_header)?;
    let dir = Path::new(&args[1]);
    let evtx_files = extract_evtx_files(dir);
    for file in evtx_files {
        if let Some(mut parser) = read_evtx_file(&file) {
            let records = parser.records_json_value();
            for rec in records {
                if let Ok(rec_data) = &rec.as_ref() {
                    let possible_base64_contains_strings = extract_payload(&rec_data.data);
                    for (possible_base64, e) in possible_base64_contains_strings {
                        if let Some(possible_base64) = possible_base64.as_str() {
                            let rows = process_record(&file, possible_base64, &rec_data.data, e);
                            for row in rows {
                                table.add_row(&row[0..4]);
                                wtr.write_record(&row)?;
                            }
                        }
                    }
                }
            }
        }
    }
    println!("{table}");
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
