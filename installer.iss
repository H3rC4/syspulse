; SysPulse Inno Setup Installer Script v0.3.1
; Compilar con Inno Setup 7: https://jrsoftware.org/isdl.php
; Resultado: output/SysPulse-Setup-0.3.1.exe

#define MyAppName "SysPulse"
#define MyAppVersion "0.3.1"
#define MyAppPublisher "H3rC4"
#define MyAppURL "https://github.com/H3rC4/syspulse"
#define MyAppExeName "syspulse.exe"
#define GitHubAPI "https://api.github.com/repos/H3rC4/syspulse/releases/latest"

[Setup]
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputDir=output
OutputBaseFilename=SysPulse-Setup-{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
SetupIconFile=assets\icon.ico
UninstallDisplayIcon={app}\icon.ico
WizardStyle=modern
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible
DisableDirPage=no
DisableProgramGroupPage=yes
CreateAppDir=yes
UninstallFilesDir={app}\unins
UninstallDisplayName={#MyAppName} {#MyAppVersion}
UninstallLogMode=append
AppendDefaultDirName=yes
CloseApplications=force
CloseApplicationsFilter=*.exe

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startup"; Description: "Iniciar automáticamente con Windows"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "target\release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "assets\icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Comment: "Abrir SysPulse"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon; WorkingDir: "{app}"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}\locales"

[Registry]
; Auto-start con Windows (opcional, se maneja desde la app)
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#MyAppName}"; ValueData: """{app}\{#MyAppExeName}"" --background"; Flags: uninsdeletevalue; Tasks: startup

[Code]
var
  UpdateCheckLabel: TNewStaticText;
  UpdateAvailable: Boolean;
  LatestVersion: String;
  DownloadURL: String;

procedure CheckForUpdates(); forward;
function CompareVersions(v1, v2: String): Integer; forward;

function InitializeSetup(): Boolean;
begin
  Result := True;
  UpdateAvailable := False;
  LatestVersion := '';
  DownloadURL := '';
  // Verificar actualizaciones en segundo plano
  CheckForUpdates();
end;

procedure CheckForUpdates();
var
  WinHttpReq: Variant;
  JsonText: String;
  TagName, AssetUrl: String;
  Remaining: String;
  PosTag, PosUrl, EndPos: Integer;
begin
  try
    WinHttpReq := CreateOleObject('WinHttp.WinHttpRequest.5.1');
    WinHttpReq.Open('GET', '{#GitHubAPI}', True);
    WinHttpReq.SetRequestHeader('User-Agent', 'SysPulse-Installer');
    WinHttpReq.SetRequestHeader('Accept', 'application/vnd.github.v3+json');
    WinHttpReq.Send('');
    WinHttpReq.WaitForResponse(5);
    
    if WinHttpReq.Status = 200 then begin
      JsonText := WinHttpReq.ResponseText;
      
      // Extraer tag_name (ej: "v0.3.1")
      PosTag := Pos('"tag_name":"', JsonText);
      if PosTag > 0 then begin
        PosTag := PosTag + 12;
        Remaining := Copy(JsonText, PosTag, Length(JsonText) - PosTag + 1);
        EndPos := Pos('"', Remaining);
        if EndPos > 0 then begin
          TagName := Copy(Remaining, 1, EndPos - 1);
          LatestVersion := TagName;
          
          // Comparar versiones
          if CompareVersions(TagName, '{#MyAppVersion}') > 0 then begin
            // Extraer browser_download_url del primer asset .exe
            PosUrl := Pos('"browser_download_url":"', JsonText);
            if PosUrl > 0 then begin
              PosUrl := PosUrl + 24;
              Remaining := Copy(JsonText, PosUrl, Length(JsonText) - PosUrl + 1);
              EndPos := Pos('"', Remaining);
              if EndPos > 0 then begin
                AssetUrl := Copy(Remaining, 1, EndPos - 1);
                if Pos('.exe', AssetUrl) > 0 then begin
                  DownloadURL := AssetUrl;
                  UpdateAvailable := True;
                end;
              end;
            end;
          end;
        end;
      end;
    end;
  except
    // Silencioso si falla (sin internet, API rate limit, etc.)
  end;
end;

function GetNextVersionPart(var S: String): Integer;
var
  P: Integer;
begin
  P := Pos('.', S);
  if P > 0 then begin
    Result := StrToIntDef(Copy(S, 1, P - 1), 0);
    S := Copy(S, P + 1, Length(S) - P);
  end else begin
    Result := StrToIntDef(S, 0);
    S := '';
  end;
end;

function CompareVersions(v1, v2: String): Integer;
// Retorna: 1 si v1 > v2, 0 si igual, -1 si v1 < v2
var
  n1, n2: Integer;
begin
  // Remover 'v' prefix si existe
  if Pos('v', v1) = 1 then v1 := Copy(v1, 2, Length(v1) - 1);
  if Pos('v', v2) = 1 then v2 := Copy(v2, 2, Length(v2) - 1);

  while (Length(v1) > 0) or (Length(v2) > 0) do begin
    n1 := GetNextVersionPart(v1);
    n2 := GetNextVersionPart(v2);
    if n1 > n2 then begin Result := 1; Exit; end;
    if n1 < n2 then begin Result := -1; Exit; end;
  end;
  Result := 0;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if (CurPageID = wpWelcome) and UpdateAvailable then begin
    // Mostrar aviso de actualización disponible
    UpdateCheckLabel := TNewStaticText.Create(WizardForm);
    with UpdateCheckLabel do begin
      Parent := WizardForm.WelcomePage;
      Left := ScaleX(0);
      Top := ScaleY(WizardForm.WelcomeLabel2.Top + WizardForm.WelcomeLabel2.Height + 10);
      Width := WizardForm.WelcomePage.Width;
      Height := ScaleY(60);
      Caption := '⚠ Nueva versión disponible: ' + LatestVersion + #13#10 +
                 'Tienes instalada la v{#MyAppVersion}. Se recomienda descargar la última versión desde:'#13#10 +
                 '{#MyAppURL}/releases/latest';
      Font.Color := clRed;
      Font.Style := [fsBold];
      Font.Size := 9;
      WordWrap := True;
    end;
  end;
end;

procedure CancelButtonClick(CurPageID: Integer; var Cancel, Confirm: Boolean);
var
  ErrorCode: Integer;
begin
  if CurPageID = wpWelcome then begin
    if UpdateAvailable and (MsgBox('Hay una versión más nueva (' + LatestVersion + ').'#13#10 +
         '¿Quieres cancelar e ir a la página de descargas?', mbConfirmation, MB_YESNO) = IDYES) then begin
      Cancel := False;
      ShellExec('open', '{#MyAppURL}/releases/latest', '', '', SW_SHOWNORMAL, ewNoWait, ErrorCode);
      WizardForm.Close;
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then begin
    // Log de desinstalación si se desea
  end;
end;