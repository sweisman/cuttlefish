[Setup]
AppName=Cuttlefish
AppVersion=1.0
AppId={{A8F3C2D1-4B7E-4F2A-9C3D-1E5B6A7F8D9C}
DefaultDirName={autopf}\Cuttlefish
UninstallDisplayName=Cuttlefish Uninstaller
OutputBaseFilename=CuttlefishInstaller
SetupIconFile=etc\connect.ico
UninstallDisplayIcon={app}\Cuttlefish.exe
Compression=lzma/ultra
SolidCompression=yes
PrivilegesRequired=admin
LicenseFile=etc\eula.rtf

[Files]
Source: "certs\*"; DestDir: "{app}\certs"; Flags: recursesubdirs
Source: "files\*.*"; DestDir: "{app}"

[Registry]
; Service throttle parameter
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Services\Cuttlefish\Parameters"; ValueType: dword; ValueName: "AppThrottle"; ValueData: "25000"
; Remove old NSIS-created uninstall entry if upgrading from NSIS installer
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Uninstall\Cuttlefish"; Flags: deletekey

[Run]
Filename: "{app}\nssm.exe"; Parameters: "install Cuttlefish ""{app}\Cuttlefish.exe"" -u tunnel1.dummyserver.com -p 1163 -w ""{app}"" -s certs\server.pem -c certs\user.pem"; Flags: runhidden waituntilterminated
Filename: "{sys}\net.exe"; Parameters: "START Cuttlefish"; Flags: runhidden waituntilterminated

[UninstallRun]
Filename: "{sys}\net.exe"; Parameters: "STOP Cuttlefish"; Flags: runhidden
Filename: "{app}\nssm.exe"; Parameters: "remove Cuttlefish confirm"; Flags: runhidden

[UninstallDelete]
Type: filesandordirs; Name: "{app}\certs"

[Code]
var
  ServerCodePage: TInputQueryWizardPage;

procedure InitializeWizard;
begin
  ServerCodePage := CreateInputQueryPage(wpSelectDir,
    'Server Code', 'Enter the Server Code provided to you.',
    'Please enter the Server Code that was provided to you.');
  ServerCodePage.Add('Server Code:', False);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID = ServerCodePage.ID) and (ServerCodePage.Values[0] = '') then
  begin
    MsgBox('Please enter a Server Code.', mbError, MB_OK);
    Result := False;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  WinHttpReq: Variant;
  ExecResult: Integer;
begin
  if CurStep = ssInstall then
  begin
    Exec(ExpandConstant('{sys}\net.exe'), 'STOP Cuttlefish', '', SW_HIDE, ewWaitUntilTerminated, ExecResult);
    Exec(ExpandConstant('{app}\nssm.exe'), 'remove Cuttlefish confirm', '', SW_HIDE, ewWaitUntilTerminated, ExecResult);
  end;

  if CurStep = ssPostInstall then
  begin
    try
      WinHttpReq := CreateOleObject('WinHttp.WinHttpRequest.5.1');
      WinHttpReq.Open('GET',
        'http://dummyserver.com/service/installer?CN=' + ServerCodePage.Values[0],
        False);
      WinHttpReq.Send('');
      if WinHttpReq.Status = 200 then
        SaveStringToFile(ExpandConstant('{app}\certs\user.pem'), WinHttpReq.ResponseText, False)
      else
      begin
        MsgBox('Problem downloading Cuttlefish Encryption Certificate (HTTP ' +
          IntToStr(WinHttpReq.Status) + ').', mbError, MB_OK);
        Abort;
      end;
    except
      MsgBox('Problem downloading Cuttlefish Encryption Certificate: ' +
        GetExceptionMessage, mbError, MB_OK);
      Abort;
    end;
  end;
end;
