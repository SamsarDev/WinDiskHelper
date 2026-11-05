# WinStorageAudit

Auditoría de almacenamiento para Windows 11, basada en evidencias. Ayuda a entender qué ocupa espacio, qué se podría limpiar, qué conviene respaldar antes de tocar nada, qué aplicaciones podrían estar en desuso y qué herramientas de Windows pueden recuperar espacio.

**Es de solo lectura: no borra, mueve ni modifica nada de lo que analiza.** Funciona sin conexión, sin telemetría y sin privilegios de administrador. Sus reglas son deterministas; no usa IA para decidir nada.

> Principio de diseño: una recomendación de limpieza incorrecta es peor que una oportunidad de limpieza no detectada.

## Qué responde

| Pregunta | Comandos |
|---|---|
| ¿Qué ocupa realmente el espacio? | `scan`, `top`, `browse`, `report` |
| ¿Qué podría eliminar? | `recommendations`, `report --format plan` |
| ¿Qué debería respaldar antes? | `analyze backups`, `analyze git` |
| ¿Qué aplicaciones podrían estar en desuso? | `analyze apps` |
| ¿Qué herramientas de Windows pueden ayudar? | `maintenance`, `analyze maintenance` |

## Estado de las funcionalidades

| Funcionalidad | Estado | Observaciones |
|---|---|---|
| Análisis de discos, perfil y rutas; exclusiones; cancelación; progreso | Implementado | |
| Tamaño lógico y físico, enlaces duros, dispersos, compresión NTFS | Implementado | El modo rápido comprueba menos; ver [Limitaciones](#limitaciones) |
| Reglas de descargas, temporales, desarrollo y residuos | Implementado | Catálogo en [docs/detection-rules.md](docs/detection-rules.md) |
| Duplicados por etapas con hash completo | Implementado | No lee archivos solo en la nube |
| Git: remotos, cambios, stashes, ramas, worktrees, submódulos, ignorados | Implementado | Estado local; nunca contacta con el servidor |
| Archivos personales y verificación contra destinos locales | Implementado | Destinos de red no admitidos |
| Inventario de aplicaciones y evidencia de uso | Parcial | UserAssist sin privilegios; Prefetch solo como administrador; cobertura incompleta por naturaleza |
| Mantenimiento de Windows | Parcial | DISM y puntos de restauración requieren administrador: se indican sin ejecutarse |
| Reporte HTML, JSON y plan revisable | Implementado | |
| Historial SQLite y comparación | Implementado | Compara categorías y carpetas destacadas, no todo el árbol |
| Limpieza automática, desinstalación, interfaz gráfica | No incluido | Fuera de alcance en esta versión; ver [docs/backlog.md](docs/backlog.md) |

## Requisitos

- Windows 11 x64. El ejecutable portable no necesita .NET.
- Git en `PATH` para analizar repositorios. Sin Git, el análisis continúa y lo indica.
- Para compilar: SDK de .NET 10.

## Instalación y compilación

```bash
dotnet publish src/WinStorageAudit.Cli -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -p:EnableCompressionInSingleFile=true -p:DebugType=none -o publish
```

El resultado es `publish\winstorageaudit.exe`, que se puede copiar a cualquier carpeta. No crea servicios ni entradas de arranque. .NET extrae la biblioteca nativa de SQLite a una carpeta temporal del usuario al ejecutarse.

Pruebas:

```bash
dotnet test WinStorageAudit.sln
```

## Primer análisis

```bash
winstorageaudit scan --quick
```

```bash
winstorageaudit report --open
```

Sin argumentos, `scan` analiza el perfil del usuario.

## Comandos

```bash
winstorageaudit scan --deep --drive C:
```

```bash
winstorageaudit scan --path "D:\Projects" --path "E:\Datos" --exclude node_modules
```

```bash
winstorageaudit analyze git --path "D:\Projects"
```

```bash
winstorageaudit analyze duplicates --path "D:\Fotos"
```

```bash
winstorageaudit analyze apps
```

```bash
winstorageaudit recommendations --class limpieza --risk bajo --sort size --top 30
```

```bash
winstorageaudit recommendations --id a1b2c3d4e5f6
```

```bash
winstorageaudit recommendations --interactive
```

```bash
winstorageaudit top folders --top 30
```

```bash
winstorageaudit browse
```

```bash
winstorageaudit report --format plan
```

```bash
winstorageaudit config add-backup "E:\Respaldo"
```

```bash
winstorageaudit analyze backups --verify-hashes
```

```bash
winstorageaudit history compare 1 2
```

Cada comando admite `--help`. Códigos de salida: `0` correcto, `1` error de datos, `2` uso incorrecto, `130` cancelado con Ctrl+C (los resultados parciales se conservan y quedan marcados).

### Análisis rápido y profundo

| | `--quick` (predeterminado) | `--deep` |
|---|---|---|
| Enumeración, categorías, reglas de limpieza | Sí | Sí |
| Estado de Git | Sí | Sí, y añade archivos ignorados importantes |
| Tamaño físico | Exacto solo en archivos marcados como comprimidos o dispersos | Consulta todos; detecta compresión WOF |
| Enlaces duros | Desde 1 MiB y en la carpeta de Windows | Todos los archivos |
| Duplicados, aplicaciones, residuos, Docker | No | Sí |

## Dónde se guardan los datos

| Dato | Ubicación |
|---|---|
| Configuración | `%APPDATA%\WinStorageAudit\config.json` |
| Historial | `%LOCALAPPDATA%\WinStorageAudit\history.db` |
| Último resultado | `%LOCALAPPDATA%\WinStorageAudit\last-result.json` |
| Reportes | `%LOCALAPPDATA%\WinStorageAudit\reports\` |

`config path` los muestra, y `history clear --yes --include-reports` y `config reset --yes` los eliminan. `WINSTORAGEAUDIT_HOME` los concentra en otra carpeta. **Los reportes y el historial contienen rutas y nombres de archivo personales**; nunca contienen contenido de archivos ni hashes.

## Demostración reproducible

Crea un árbol ficticio en una carpeta nueva y lo analiza. `WINSTORAGEAUDIT_SANDBOX_ROOT` confina las ubicaciones conocidas a esa carpeta y omite las consultas al sistema real:

```bash
powershell -ExecutionPolicy Bypass -File examples\run-demo.ps1 -Path C:\Temp\wsa-demo -Exe publish\winstorageaudit.exe
```

El árbol incluye casos que **no** deben considerarse basura: discos virtuales, una base de datos, una carpeta `bin` sin proyecto y una carpeta `temp` con un documento.

## Limitaciones

- La suma de archivos no equivale al uso del volumen: los metadatos de NTFS, las instantáneas y las carpetas inaccesibles no se pueden enumerar sin privilegios.
- El espacio físico es una estimación: se redondea al tamaño de clúster y no contempla archivos residentes en la MFT.
- Los enlaces simbólicos, junctions y puntos de montaje no se siguen: su destino se cuenta solo si está dentro de lo analizado.
- Los archivos solo en la nube se cuentan como tamaño lógico, pero nunca se leen. Las carpetas remotas sin copia local no se recorren.
- Comparar con hash puede actualizar la fecha de último acceso de los archivos leídos, si Windows la mantiene activa. El contenido y la fecha de modificación no cambian.
- `git status` puede ejecutar filtros `clean` configurados en el propio repositorio. Ver [docs/security.md](docs/security.md).
- Windows no conserva un historial completo de ejecución. «Sin evidencia» no significa «sin uso».
- El formato de UserAssist no está documentado oficialmente: los valores que no coinciden con lo esperado se descartan.
- El tamaño de las aplicaciones procede del registro; puede faltar o estar desactualizado.
- La interfaz interactiva (`browse`, `--interactive`) no tiene pruebas automatizadas.

## Documentación

- [Arquitectura](docs/architecture.md)
- [Reglas de detección](docs/detection-rules.md)
- [Fuentes de datos de Windows](docs/windows-data-sources.md)
- [Modelo de seguridad](docs/security.md)
- [Mejoras futuras](docs/backlog.md)
