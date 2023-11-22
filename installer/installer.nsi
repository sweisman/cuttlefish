SetCompressor /SOLID lzma
OutFile "CuttlefishInstaller.exe"
Name "Cuttlefish Installer v1.0"
Caption "Cuttlefish Service Installer"
Icon ".\etc\connect.ico"
UninstallIcon ".\etc\delete.ico"
SetDateSave on
SetDatablockOptimize on
SetOverwrite on
CRCCheck on
SilentInstall normal
XPStyle on

var IsAdmin
var ServerCode
var SetServerCodeField
var SetServerCodeLabel
var SetServerCodeDialog

!addplugindir "plugins"

!include "nsDialogs.nsh"
!include ".\etc\lib.nsh"
!include ".\etc\install-log.nsh"

InstallDir $PROGRAMFILES\Cuttlefish

LicenseText "Click 'I Agree' to accept the terms of this agreement and continue with the installation."
LicenseData ".\etc\eula.rtf"

Page license /ENABLECANCEL
Page directory /ENABLECANCEL
Page custom SetServerCode SetServerCodeExit
Page instfiles

Function .onInit
    InitPluginsDir

    !insertmacro IsUserAdmin $IsAdmin
    StrCmp $IsAdmin "1" GoodUser
    MessageBox MB_OK "Cuttlefish must be installed by an Administrator"
    Quit

    GoodUser:
FunctionEnd

Section "" ; No components page, name is not important

DetailPrint "ServerCode $ServerCode"

SetOutPath $INSTDIR

;;;;;;;;;;;;;;;;;; CLEAR DETRITUS

ReadRegStr $0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Cuttlefish" "UninstallString"
StrCmp $0 "" SkipUninstall

DetailPrint "Old installation of Cuttlefish found - uninstalling"
ExecDos::exec /TIMEOUT=9000 "$0 /S" "" "$INSTDIR\install.log"
Pop $0
DetailPrint "Uninstall: $0"

SkipUninstall:

ExecDos::exec /TIMEOUT=9000 'net STOP Cuttlefish' "" "$INSTDIR\install.log"
Pop $0
DetailPrint "Stop Cuttlefish service: $0"

ExecDos::exec /TIMEOUT=9000 '"$INSTDIR\nssm.exe" remove Cuttlefish confirm' "" "$INSTDIR\install.log"
Pop $0
DetailPrint "Remove Cuttlefish Service: $0"

File /r .\certs

;;;;;;;;;;;;;;;;;; DOWNLOAD USER CERTIFICATE

inetc::get /NOCANCEL /CAPTION "Download Cuttlefish Encryption Certificate" "http://dummyserver.com/service/installer?CN=$ServerCode" "$INSTDIR\certs\user.pem" /END
Pop $0
DetailPrint "Download Cuttlefish Encryption Certificate Status: $0"
StrCmp $0 "OK" GoodCert

MessageBox MB_OK "Problem downloading Cuttlefish Encryption Certificate ($0)."
Quit

GoodCert:

File .\files\*.*

;;;;;;;;;;;;;;;;; CREATE REGISTRY KEYS

WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Cuttlefish" "DisplayName" "Cuttlefish Uninstaller"
WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Cuttlefish" "UninstallString" "$INSTDIR\uninstall.exe"

;;;;;;;;;;;;;;;;; INSTALL SERVICE

ExecDos::exec /TIMEOUT=9000 '"$INSTDIR\nssm.exe" install Cuttlefish "$INSTDIR\Cuttlefish.exe" -u tunnel1.dummyserver.com -p 1163 -w """$INSTDIR""" -s certs\server.pem -c certs\user.pem' "" "$INSTDIR\install.log"
Pop $0
DetailPrint "Install Cuttlefish Service: $0"

WriteRegDWORD HKLM "SYSTEM\CurrentControlSet\Services\Cuttlefish\Parameters" "AppThrottle" 25000

ExecDos::exec /TIMEOUT=9000  'NET START Cuttlefish' "" "$INSTDIR\install.log"
Pop $0
DetailPrint "Start Cuttlefish Service: $0"

;;;;;;;;;;;;;;;;;; UNINSTALLER

WriteUninstaller "uninstall.exe"

SectionEnd

Section "Uninstall"
    ExecDos::exec /TIMEOUT=9000 'NET STOP Cuttlefish'
    Pop $0
    DetailPrint "Stop Cuttlefish service: $0"

    ExecDos::exec /TIMEOUT=9000 '"$INSTDIR\nssm.exe" remove Cuttlefish confirm'
    Pop $0
    DetailPrint "Remove Cuttlefish Service: $0"

    RMDir /r "$INSTDIR\certs"
    Delete "$INSTDIR\uninstall.exe"
    Delete "$INSTDIR\nssm.exe"
    Delete "$INSTDIR\Cuttlefish.exe"
    Delete "$INSTDIR\install.log"

    DeleteRegKey HKLM "SYSTEM\CurrentControlSet\Services\Cuttlefish"
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Cuttlefish"
SectionEnd
