[Setup]
AppName=Forest Sentinel
AppVersion=1.0.0
AppPublisher=Forest Sentinel Systems
AppSupportURL=https://github.com/ForestSentinel
AppUpdatesURL=https://github.com/ForestSentinel
DefaultDirName={autopf}\Forest Sentinel
DefaultGroupName=Forest Sentinel
OutputDir=.\Instalador
OutputBaseFilename=ForestSentinel_Setup_v1.0.0
SetupIconFile=assets\icon.ico
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64
UninstallDisplayIcon={app}\Forest Sentinel.exe
DisableProgramGroupPage=yes
ShowLanguageDialog=yes

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[LangOptions]
brazilianportuguese.LanguageName=Português/Brasil

[Files]
; Copia tudo de dentro de dist\ForestSentinel para o diretório de destino
Source: "dist\Forest Sentinel\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
; Menu Iniciar
Name: "{group}\Forest Sentinel"; Filename: "{app}\Forest Sentinel.exe"
Name: "{group}\{cm:UninstallProgram,Forest Sentinel}"; Filename: "{uninstallexe}"
; Desktop
Name: "{autodesktop}\Forest Sentinel"; Filename: "{app}\Forest Sentinel.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Run]
; Iniciar após a instalação com privilégios de Admin
Filename: "{app}\Forest Sentinel.exe"; Description: "Executar Forest Sentinel"; Flags: nowait postinstall runascurrentuser

[Dirs]
; Garante permissões de escrita para pastas cruciais do sistema
Name: "{app}\config"; Permissions: users-modify
Name: "{app}\logs"; Permissions: users-modify
Name: "{app}\models"; Permissions: users-modify
Name: "{app}\assets"; Permissions: users-modify

[UninstallDelete]
Type: filesandordirs; Name: "{app}\*"
