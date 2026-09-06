; TheKVM Windows installer (Inno Setup 7).
;
; Replaces the former hand-rolled setup.exe: Inno owns elevation (UAC),
; the wizard UI, file replacement, Add/Remove Programs, and uninstall.
; This script only adds the product-specific steps, mirroring the audited
; install-service.ps1 behavior:
;   - stop/remove any previous TheKVM service BEFORE files are replaced
;     (a running service locks kvm-daemon.exe and broke the old installer),
;   - configure receiver state in %ProgramData%\TheKVM,
;   - lock the data directory down to LocalSystem + Administrators,
;   - register/start the LocalSystem service, add the firewall rule.
;
; Build: iscc packaging\windows\thekvm.iss   (output: dist\thekvm-<ver>-setup.exe)

#define MyAppName "TheKVM"
#define MyAppVersion "0.1.7"
#define MyAppPublisher "TheKVM project"
#define MyAppURL "https://github.com/xyzyt010/thekvm"
#define ServiceName "TheKVM"
#define FirewallRule "TheKVM QUIC and discovery"

[Setup]
AppId={{1030A265-B33F-44EE-9E39-FDA314E213FD}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\TheKVM
DefaultGroupName=TheKVM
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
WizardStyle=modern
WizardImageFile=assets\wizard-image.bmp
SetupIconFile=assets\setup.ico
UninstallDisplayIcon={app}\kvm-ui.exe
Compression=lzma2/ultra64
SolidCompression=yes
OutputDir=..\..\dist
OutputBaseFilename=thekvm-{#MyAppVersion}-setup
CloseApplications=yes
RestartApplications=no
DisableWelcomePage=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "..\..\target\release\kvm-daemon.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\target\release\kvm-ui.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\TheKVM UI"; Filename: "{app}\kvm-ui.exe"
Name: "{group}\Uninstall TheKVM"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\kvm-ui.exe"; Description: "Launch TheKVM"; Flags: nowait postinstall skipifsilent

[Code]
var
  OptionsPage: TWizardPage;
  DeviceNameEdit: TNewEdit;
  LockScreenCheck: TNewCheckBox;

function SetEnv(const Name: String; const Value: String): Boolean;
  external 'SetEnvironmentVariableW@kernel32.dll stdcall';

function DataDir(): String;
begin
  Result := ExpandConstant('{commonappdata}\TheKVM');
end;

function DaemonPath(): String;
begin
  Result := ExpandConstant('{app}\kvm-daemon.exe');
end;

function RunHidden(const ExeFile: String; const Args: String; var ResultCode: Integer): Boolean;
begin
  Result := Exec(ExeFile, Args, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure SoftRun(const ExeFile: String; const Args: String);
var
  ResultCode: Integer;
begin
  RunHidden(ExeFile, Args, ResultCode);
end;

procedure InitializeWizard();
var
  NameLabel, LockHint: TNewStaticText;
begin
  OptionsPage := CreateCustomPage(wpSelectDir,
    'Receiver options', 'How should this machine identify itself?');
  NameLabel := TNewStaticText.Create(OptionsPage);
  NameLabel.Parent := OptionsPage.Surface;
  NameLabel.Top := 8;
  NameLabel.Width := OptionsPage.SurfaceWidth;
  NameLabel.Caption := 'Device name shown to nearby machines during discovery and pairing:';
  DeviceNameEdit := TNewEdit.Create(OptionsPage);
  DeviceNameEdit.Parent := OptionsPage.Surface;
  DeviceNameEdit.Top := NameLabel.Top + 24;
  DeviceNameEdit.Width := OptionsPage.SurfaceWidth;
  DeviceNameEdit.Text := GetComputerNameString();
  LockScreenCheck := TNewCheckBox.Create(OptionsPage);
  LockScreenCheck.Parent := OptionsPage.Surface;
  LockScreenCheck.Top := DeviceNameEdit.Top + 36;
  LockScreenCheck.Width := OptionsPage.SurfaceWidth;
  LockScreenCheck.Caption := 'Allow lock-screen control (privileged service)';
  { Product default: lock-screen control ships enabled. The user can still
    untick this box or flip the switch in the app's Settings tab later. }
  LockScreenCheck.Checked := True;
  LockHint := TNewStaticText.Create(OptionsPage);
  LockHint.Parent := OptionsPage.Surface;
  LockHint.Top := LockScreenCheck.Top + 24;
  LockHint.Width := OptionsPage.SurfaceWidth;
  LockHint.Caption :=
    'Lets paired machines drive this keyboard and mouse on the ' +
    'Windows login and lock screens.';
end;

{ Stop anything that locks the binaries before Inno replaces them. }
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  SoftRun('sc.exe', 'stop {#ServiceName}');
  SoftRun('sc.exe', 'delete {#ServiceName}');
  SoftRun('taskkill.exe', '/F /IM kvm-ui.exe');
  SoftRun('taskkill.exe', '/F /IM kvm-daemon.exe');
  Result := '';
end;

function ConfigureDaemon(): Boolean;
var
  ResultCode: Integer;
  Args, DeviceName: String;
begin
  SetEnv('THEKVM_DATA_DIR', DataDir());
  DeviceName := Trim(DeviceNameEdit.Text);
  StringChangeEx(DeviceName, '"', '', True);
  Args := 'configure --mode receiver-only';
  if DeviceName <> '' then
    Args := Args + ' --device-name ' + AddQuotes(DeviceName);
  if LockScreenCheck.Checked then
    Args := Args + ' --allow-lock-screen-control'
  else
    Args := Args + ' --disable-lock-screen-control';
  Args := Args + ' --clear-auto-connect';
  if (not RunHidden(DaemonPath(), Args, ResultCode)) or (ResultCode <> 0) then
  begin
    MsgBox('TheKVM configuration failed (exit code ' + IntToStr(ResultCode) +
      '). The install cannot continue.', mbError, MB_OK);
    Result := False;
    Exit;
  end;
  { DPAPI machine-protected identity: only LocalSystem + Administrators. }
  SoftRun('icacls.exe', AddQuotes(DataDir()) +
    ' /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"');
  Result := True;
end;

function RegisterService(): Boolean;
var
  ResultCode: Integer;
  BinPath, Daemon: String;
begin
  Result := False;
  Daemon := DaemonPath();
  { sc.exe parses `binPath= <remainder-of-line>`; quoted exe plus service
    arguments must arrive as one token after `binPath=`. }
  BinPath := 'binPath= ' + AddQuotes(Daemon + ' serve --service');
  if not RunHidden('sc.exe', 'create {#ServiceName} ' + BinPath +
    ' start= auto obj= LocalSystem', ResultCode) then
  begin
    MsgBox('Could not run sc.exe to register the service.', mbError, MB_OK);
    Exit;
  end;
  if ResultCode <> 0 then
  begin
    { create fails when a previous entry survived; delete once and retry. }
    SoftRun('sc.exe', 'delete {#ServiceName}');
    if (not RunHidden('sc.exe', 'create {#ServiceName} ' + BinPath +
      ' start= auto obj= LocalSystem', ResultCode)) or (ResultCode <> 0) then
    begin
      MsgBox('Could not register the TheKVM service (exit code ' +
        IntToStr(ResultCode) + ').', mbError, MB_OK);
      Exit;
    end;
  end;
  SoftRun('sc.exe', 'description {#ServiceName} "TheKVM privileged receiver service"');
  SoftRun('sc.exe', 'failure {#ServiceName} reset= 86400 actions= restart/5000/restart/5000/restart/10000');
  if (not RunHidden('sc.exe', 'start {#ServiceName}', ResultCode)) or (ResultCode <> 0) then
  begin
    MsgBox('The service was registered but could not be started (exit code ' +
      IntToStr(ResultCode) + '). Reboot and check services.msc.', mbError, MB_OK);
    Exit;
  end;
  Result := True;
end;

{ True when the rule exists, checked through netsh so every creation
  method is verified the same way. }
function RuleVerified(): Boolean;
var
  ResultCode: Integer;
begin
  Result := RunHidden('netsh.exe', 'advfirewall firewall show rule name=' +
    AddQuotes('{#FirewallRule}') + ' verbose', ResultCode) and (ResultCode = 0);
end;

{ True when at least one firewall profile enforces rules. Runs PowerShell
  and treats any failure to query as "on" (fail safe: keep the warning). }
function AnyFirewallProfileOn(): Boolean;
var
  ResultCode: Integer;
  PSPath: String;
begin
  PSPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  Result := True;
  if RunHidden(PSPath, '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ' +
    AddQuotes('if ((Get-NetFirewallProfile -ErrorAction Stop | ' +
    'Where-Object { $_.Enabled } | Measure-Object).Count -eq 0) { exit 42 }'),
    ResultCode) then
    Result := ResultCode <> 42;
end;

procedure AddFirewallRule();
var
  PSPath, LogFile: String;
  Output: AnsiString;
begin
  { Idempotent: drop any previous rule first. }
  SoftRun('netsh.exe', 'advfirewall firewall delete rule name=' +
    AddQuotes('{#FirewallRule}'));
  PSPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  LogFile := ExpandConstant('{tmp}\thekvm-firewall.log');

  { Method 1: modern PowerShell cmdlet. Output goes to a log file so a
    failure is diagnosable instead of a mystery. }
  SoftRun(PSPath, '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command ' +
    AddQuotes('Remove-NetFirewallRule -DisplayName ' +
    AddQuotes(AddQuotes('{#FirewallRule}')) + ' -ErrorAction SilentlyContinue; ' +
    'New-NetFirewallRule -DisplayName ' + AddQuotes(AddQuotes('{#FirewallRule}')) +
    ' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 42110,42111 ' +
    '-Program ' + AddQuotes(AddQuotes(DaemonPath())) +
    ' -Profile Domain,Private,Public -ErrorAction Stop ' +
    '> ' + AddQuotes(LogFile) + ' 2>&1'));
  if RuleVerified() then
    Exit;

  { Method 2: classic netsh fallback. Its exit code is unreliable, so the
    show-rule check below decides success, not this call. }
  SoftRun('cmd.exe', '/c ' + AddQuotes('netsh.exe advfirewall firewall add rule name=' +
    AddQuotes('{#FirewallRule}') + ' dir=in action=allow protocol=UDP ' +
    'localport=42110,42111 program=' + AddQuotes(DaemonPath()) +
    ' enable=yes > ' + AddQuotes(LogFile) + ' 2>&1'));
  if RuleVerified() then
    Exit;

  { If every firewall profile is off, nothing filters inbound traffic, so
    pairing works without a rule. Stay silent instead of alarming the user;
    the log records why. }
  if not AnyFirewallProfileOn() then
  begin
    Output := '';
    LoadStringFromFile(LogFile, Output);
    Log('Firewall rule not verified but all profiles are off; pairing is unfiltered. Last output: ' + Output);
    Exit;
  end;

  Output := '';
  LoadStringFromFile(LogFile, Output);
  MsgBox('The firewall rule could not be added automatically. ' +
    'Pairing needs UDP ports 42110-42111 inbound for kvm-daemon.exe. ' +
    'Details were saved to ' + LogFile + ' :' + #13#10 + Output,
    mbError, MB_OK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if not ConfigureDaemon() then
      Abort();
    if not RegisterService() then
      Abort();
    AddFirewallRule();
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    SoftRun('sc.exe', 'stop {#ServiceName}');
    SoftRun('sc.exe', 'delete {#ServiceName}');
    SoftRun('netsh.exe', 'advfirewall firewall delete rule name=' +
      AddQuotes('{#FirewallRule}'));
  end;
end;
