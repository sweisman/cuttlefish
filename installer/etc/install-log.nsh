!macro AddItem Path
    FileWrite $InstallLog "${Path}$\r$\n"
!macroend

!macro File FilePath FileName
    IfFileExists "$OUTDIR\${FileName}" +2
    FileWrite $InstallLog "$OUTDIR\${FileName}$\r$\n"
    File "${FilePath}${FileName}"
!macroend

!macro CreateShortcut FilePath FilePointer Pamameters Icon IconIndex
    FileWrite $InstallLog "${FilePath}$\r$\n"
    CreateShortcut "${FilePath}" "${FilePointer}" "${Pamameters}" "${Icon}" "${IconIndex}"
!macroend

!macro CopyFiles SourcePath DestPath
    IfFileExists "${DestPath}" +2
    FileWrite $InstallLog "${DestPath}$\r$\n"
    CopyFiles "${SourcePath}" "${DestPath}"
!macroend

!macro Rename SourcePath DestPath
    IfFileExists "${DestPath}" +2
    FileWrite $InstallLog "${DestPath}$\r$\n"
    Rename "${SourcePath}" "${DestPath}"
!macroend

!macro CreateDirectory Path
    CreateDirectory "${Path}"
    FileWrite $InstallLog "${Path}$\r$\n"
!macroend

!macro SetOutPath Path
    SetOutPath "${Path}"
    FileWrite $InstallLog "${Path}$\r$\n"
!macroend

!macro WriteUninstaller Path
    WriteUninstaller "${Path}"
    FileWrite $InstallLog "${Path}$\r$\n"
!macroend

!macro WriteRegStr RegRoot UnInstallPath Key Value
    FileWrite $InstallLog "${RegRoot} ${UnInstallPath}$\r$\n"
    WriteRegStr "${RegRoot}" "${UnInstallPath}" "${Key}" "${Value}"
!macroend

!macro WriteRegDWORD RegRoot UnInstallPath Key Value
    FileWrite $InstallLog "${RegRoot} ${UnInstallPath}$\r$\n"
    WriteRegStr "${RegRoot}" "${UnInstallPath}" "${Key}" "${Value}"
!macroend
