# base64-check
## how-to-use
```bash
cargo build --release
./target/release/base64-check <evtx-directory>
```

## output
```bash
 % ./target/release/base64-check /hayabusa-sample-evtx
Possible Base64 + UTF-8("Powershell-Invoke-Obfuscation-many.evtx"): 0C S
Possible Base64 + UTF-8("Powershell-Invoke-Obfuscation-many.evtx"): 0C S
Possible Base64 + UTF-8("Powershell-Invoke-Obfuscation-many.evtx"): wlZ+a
Possible Base64 + UTF-8("Powershell-Invoke-Obfuscation-many.evtx"): wlZ+a
Possible Base64 + UTF-8("Powershell-Invoke-Obfuscation-many.evtx"): wlZ+a
Possible Base64 + UTF-8("Powershell-Invoke-Obfuscation-many.evtx"): wlZ+a
Possible Base64 + UTF-8("Powershell-Invoke-Obfuscation-many.evtx"): wlZ+a
```