# base64-utf-detect
## what-is
This is a tool to check if the data in the evtx file is base64 encoded and if it is, it will decode(utf-8/utf-16 le/utf-16 be) it and print it out.

## target event id
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

## how-to-use
```bash
cargo build --release
./target/release/base64-utf-detect <evtx-directory>
```

## output
### stdout
```bash
 % ./target/release/base64-utf-detect /hayabusa-sample-evtx
Possible Base64 + UTF-8("Powershell-Invoke-Obfuscation-many.evtx"): 0C S
Possible Base64 + UTF-8("Powershell-Invoke-Obfuscation-many.evtx"): 0C S
Possible Base64 + UTF-8("Powershell-Invoke-Obfuscation-many.evtx"): wlZ+a
Possible Base64 + UTF-8("Powershell-Invoke-Obfuscation-many.evtx"): wlZ+a
Possible Base64 + UTF-8("Powershell-Invoke-Obfuscation-many.evtx"): wlZ+a
Possible Base64 + UTF-8("Powershell-Invoke-Obfuscation-many.evtx"): wlZ+a
Possible Base64 + UTF-8("Powershell-Invoke-Obfuscation-many.evtx"): wlZ+a
```

### file
Simply output `output.csv` in the current directory
