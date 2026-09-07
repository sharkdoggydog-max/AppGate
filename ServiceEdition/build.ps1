$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    & 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe' /nologo /target:winexe /platform:x64 /optimize+ /win32manifest:app.manifest /out:AppGateService.exe /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.Security.dll /r:System.Runtime.Serialization.dll /r:System.ServiceProcess.dll /r:System.Core.dll /r:System.Management.dll /r:Microsoft.CSharp.dll Core.cs App.cs Tests.cs WindowGuard.cs
    if ($LASTEXITCODE -ne 0) { throw 'Compilation failed' }
} finally { Pop-Location }
