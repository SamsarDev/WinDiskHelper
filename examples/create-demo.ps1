<#
.SYNOPSIS
  Crea un árbol de prueba reproducible para demostrar WinStorageAudit.

.DESCRIPTION
  Solo escribe dentro de la carpeta indicada, que debe no existir o estar vacía.
  Los archivos son datos ficticios, y los tamaños se logran con archivos dispersos o contenido repetido.

.EXAMPLE
  .\examples\create-demo.ps1 -Path C:\Temp\wsa-demo
#>
param([Parameter(Mandatory = $true)][string]$Path)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($Path)
if ((Test-Path $root) -and (Get-ChildItem -Force $root | Select-Object -First 1)) {
    throw "La carpeta '$root' no está vacía. Indique una carpeta nueva."
}

$old = (Get-Date).AddYears(-2).ToUniversalTime()

function New-Demo([string]$Relative, [long]$Bytes = 64, [datetime]$When = $old, [byte]$Fill = 65) {
    $file = Join-Path $root $Relative
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($file))
    $stream = [IO.File]::Create($file)
    try {
        $block = [byte[]]::new([Math]::Min($Bytes, 64KB))
        for ($i = 0; $i -lt $block.Length; $i++) { $block[$i] = $Fill }
        $left = $Bytes
        while ($left -gt 0) {
            $count = [Math]::Min($left, $block.Length)
            $stream.Write($block, 0, $count)
            $left -= $count
        }
    } finally { $stream.Dispose() }
    [IO.File]::SetCreationTimeUtc($file, $When)
    [IO.File]::SetLastWriteTimeUtc($file, $When)
}

function Invoke-Git([string]$Repo) {
    & git -C $Repo @args 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "git falló en $Repo" }
}

$user = 'Users\demo'

# Descargas: antigüedad sola no significa basura.
New-Demo "$user\Downloads\instalador-viejo.exe" 40MB
New-Demo "$user\Downloads\fotos-viaje.zip" 30MB -Fill 66
New-Demo "$user\Downloads\informe.zip" 12MB -Fill 67
New-Demo "$user\Downloads\informe (1).zip" 12MB -Fill 67

# Temporales reales y una carpeta que solo se llama temp.
New-Demo "$user\AppData\Local\Temp\instalacion-abandonada\datos.bin" 25MB
New-Demo "$user\AppData\Local\Temp\en-uso\archivo.bin" 15MB -When (Get-Date).ToUniversalTime()
New-Demo "$user\Trabajo\temp\borrador-importante.docx" 120MB -Fill 68

# Cachés y artefactos con marcadores que los demuestran.
New-Demo "$user\AppData\Local\npm-cache\_cacache\content\a.bin" 35MB
New-Demo "$user\.nuget\packages\demo.pkg\1.0.0\demo.nupkg" 20MB
New-Demo "$user\Proyectos\web\package.json"
New-Demo "$user\Proyectos\web\package-lock.json"
New-Demo "$user\Proyectos\web\node_modules\libreria\index.js" 45MB
New-Demo "$user\Proyectos\web\dist\bundle.js" 11MB
New-Demo "$user\Proyectos\api\Api.csproj"
New-Demo "$user\Proyectos\api\bin\Debug\Api.dll" 22MB
New-Demo "$user\Proyectos\api\obj\Debug\Api.pdb" 14MB
New-Demo "$user\Proyectos\ml\requirements.txt"
New-Demo "$user\Proyectos\ml\.venv\pyvenv.cfg"
New-Demo "$user\Proyectos\ml\.venv\Lib\paquete.py" 30MB
New-Demo "$user\Proyectos\ml\__pycache__\m.cpython-312.pyc" 2KB

# Una carpeta «bin» sin proyecto: no debe considerarse artefacto.
New-Demo "$user\Herramientas\bin\mi-script-unico.exe" 18MB

# Datos que nunca son basura.
New-Demo "$user\AppData\Local\Docker\wsl\disk\docker_data.vhdx" 60MB
New-Demo "$user\MaquinasVirtuales\laboratorio.vhdx" 50MB
New-Demo "$user\Datos\clientes.sqlite" 16MB
New-Demo "$user\.ssh\id_ed25519" 1KB

# Archivos personales y duplicados de contenido sensible.
New-Demo "$user\Documentos\tesis.docx" 2MB -Fill 69
New-Demo "$user\Documentos\Antiguo\tesis-copia.docx" 2MB -Fill 69
New-Demo "$user\Imagenes\boda\foto1.jpg" 6MB -Fill 70
New-Demo "$user\Imagenes\respaldo-fotos\foto1.jpg" 6MB -Fill 70
New-Demo "$user\Videos\familia.mp4" 90MB -Fill 71
New-Demo "$user\Musica\album.flac" 28MB

# Mismo tamaño, distinto contenido: no son duplicados.
New-Demo "$user\Varios\a.bin" 3MB -Fill 72
New-Demo "$user\Varios\b.bin" 3MB -Fill 73

# Repositorios Git con distintos estados. Git escribe avisos en stderr: se valida su código de salida.
$ErrorActionPreference = 'Continue'
function New-Repo([string]$Relative) {
    $repo = Join-Path $root $Relative
    [void][IO.Directory]::CreateDirectory($repo)
    & git init -q -b main $repo
    Invoke-Git $repo config user.email demo@example.invalid
    Invoke-Git $repo config user.name Demo
    Invoke-Git $repo config commit.gpgsign false
    return $repo
}

function Add-Commit([string]$Repo, [string]$File) {
    Set-Content -Encoding utf8 (Join-Path $Repo $File) "contenido de $File"
    Invoke-Git $Repo add -A
    Invoke-Git $Repo commit -q -m "cambio en $File"
}

$noRemote = New-Repo "$user\Proyectos\sin-remoto"
Add-Commit $noRemote 'notas.md'
Set-Content -Encoding utf8 (Join-Path $noRemote 'notas.md') 'cambio sin confirmar'
Set-Content -Encoding utf8 (Join-Path $noRemote 'nuevo.txt') 'archivo sin versionar'

$origin = New-Repo 'servidor-simulado\origen'
Add-Commit $origin 'readme.md'
$clone = Join-Path $root "$user\Proyectos\con-remoto"
& git clone -q $origin $clone 2>$null
Invoke-Git $clone config user.email demo@example.invalid
Invoke-Git $clone config user.name Demo
Invoke-Git $clone config commit.gpgsign false
Add-Commit $clone 'sin-publicar.txt'
Set-Content -Encoding utf8 (Join-Path $clone '.gitignore') ".env`n"
Set-Content -Encoding utf8 (Join-Path $clone '.env') 'DEMO_KEY=valor-ficticio'
Invoke-Git $clone add .gitignore
Invoke-Git $clone stash push -q

$clean = Join-Path $root "$user\Proyectos\limpio"
& git clone -q $origin $clean 2>$null

Write-Host "Árbol de demostración creado en $root"
