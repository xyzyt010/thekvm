fn main() {
    slint_build::compile("ui/app.slint").unwrap();
    // Windows version resource: see kvm-daemon/build.rs — a named product
    // identity instead of an anonymous binary in verdict dialogs.
    #[cfg(target_os = "windows")]
    {
        let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
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
            .set("FileDescription", "TheKVM cross-device control UI")
            .set("CompanyName", "TheKVM project")
            .set("OriginalFilename", "kvm-ui.exe")
            .set("LegalCopyright", "GPL-3.0-or-later, TheKVM project")
            .set("ProductVersion", &version)
            .set("FileVersion", &numeric);
        // Declare per-monitor DPI awareness. Without it Windows treats the
        // process as 96-DPI-unaware and bitmap-stretches the whole window
        // on any scaled display (125% is the common default): every control
        // then renders ~1.25x too large, the right edge falls outside the
        // window and nothing lines up. Slint already layouts in logical
        // pixels, so the declaration only removes the stretch.
        resource.set_manifest(
            r#"<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" processorArchitecture="*" name="TheKVM.kvm-ui" type="win32"/>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">PerMonitorV2, PerMonitor</dpiAwareness>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true/pm</dpiAware>
    </windowsSettings>
  </application>
</assembly>"#,
        );
        if let Err(error) = resource.compile() {
            eprintln!("winres version resource failed: {error:#}");
        }
    }
}
