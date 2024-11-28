# base64-utf-detect
## What-is
This is a tool to check if the data in the evtx file is base64 encoded and if it is, it will decode(utf-8/utf-16 le/utf-16 be/binary) it and print it out.

## Target EventID
```Rust
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
```

## How-to-use
```bash
cargo build --release
./target/release/base64-utf-detect <evtx-directory>
```

## Output
### Stdout
```bash
 % ./target/release/base64-utf-detect /hayabusa-sample-evtx
 Possible Base64 + UTF-8("Microsoft-Windows-Sysmon%4Operational.evtx"): {"request_sequence":0}, eyJyZXF1ZXN0X3NlcXVlbmNlIjowfQ
```

### File
Simply output `output.csv` in the current directory
```csv
Type,Filename,Decoded Text,Original Text
Possible Base64 + UTF-8("Microsoft-Windows-Sysmon%4Operational.evtx"): {"request_sequence":0}, eyJyZXF1ZXN0X3NlcXVlbmNlIjowfQ
```
