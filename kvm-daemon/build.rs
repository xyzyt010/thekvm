fn main() {
    // Windows version resource: SmartScreen/Defender verdict dialogs and
    // file Properties show a real product identity instead of a blank
    // anonymous binary (unsigned, anonymous binaries score worst in
    // reputation heuristics). Not a substitute for Authenticode signing —
    // see packaging/windows/README-signing.md — but standard hygiene.
    #[cfg(target_os = "windows")]
    {
        let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
        // winres needs numeric comma-separated version components.
        let numeric = version
            .split('.')
            .map(|part| {
                part.chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>()
            })
            .map(|part| {
                if part.is_empty() {
                    "0".to_owned()
                } else {
                    part
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        let mut resource = winres::WindowsResource::new();
        resource
            .set("ProductName", "TheKVM")
            .set("FileDescription", "TheKVM privileged receiver service")
            .set("CompanyName", "TheKVM project")
            .set("OriginalFilename", "kvm-daemon.exe")
            .set("LegalCopyright", "GPL-3.0-or-later, TheKVM project")
            .set("ProductVersion", &version)
            .set("FileVersion", &numeric);
        if let Err(error) = resource.compile() {
            eprintln!("winres version resource failed: {error:#}");
        }
    }
}
