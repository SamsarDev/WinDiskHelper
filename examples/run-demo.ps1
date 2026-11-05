<#
.SYNOPSIS
  Demostración reproducible: crea datos de prueba y los analiza sin tocar el equipo real.

.DESCRIPTION
  WINSTORAGEAUDIT_SANDBOX_ROOT confina las ubicaciones conocidas a la carpeta de demostración
  y omite las consultas al sistema real. WINSTORAGEAUDIT_HOME guarda los resultados en esa misma carpeta.

.EXAMPLE
  .\examples\run-demo.ps1 -Path C:\Temp\wsa-demo -Exe .\publish\winstorageaudit.exe
#>
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [string]$Exe = (Join-Path $PSScriptRoot '..\publish\winstorageaudit.exe')
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($Path)
$data = Join-Path $root 'datos'
$output = Join-Path $root 'salida'
$tool = [IO.Path]::GetFullPath($Exe)
if (-not (Test-Path $tool)) { throw "No se encontró el ejecutable: $tool" }

& (Join-Path $PSScriptRoot 'create-demo.ps1') -Path $data

$env:WINSTORAGEAUDIT_SANDBOX_ROOT = $data
$env:WINSTORAGEAUDIT_HOME = $output

& $tool config add-backup (Join-Path $data 'Users\demo\Imagenes\respaldo-fotos')
& $tool scan --deep --path $data
& $tool recommendations --top 60
& $tool report --format html --output (Join-Path $output 'reporte.html')
& $tool report --format json --output (Join-Path $output 'reporte.json')
& $tool report --format plan --output (Join-Path $output 'plan.md')

Write-Host "Reportes en $output"
