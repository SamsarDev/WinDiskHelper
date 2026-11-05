# Reglas de detección

Cada hallazgo explica qué se encontró, por qué importa, con qué evidencia, qué se puede hacer, qué se podría perder y cuánto se podría recuperar. Los umbrales son configurables con `config set`.

## Escalas

| Concepto | Valores |
|---|---|
| Confianza | Alta, Media, Baja, Desconocida |
| Riesgo | Bajo, Moderado, Alto, Crítico |
| Clasificación | Candidato de limpieza, Revisión manual, Respaldar prioritariamente, Mantener, Información insuficiente |
| Tipo de recurso | Caché regenerable, Artefacto de compilación, Dependencia descargada, Entorno de desarrollo activo, Datos persistentes de aplicaciones, Información de usuario potencialmente irremplazable |

## Barreras del motor

Se aplican a todos los hallazgos, sea cual sea la regla:

1. Una ruta protegida no puede ser candidata: pasa a «Mantener» con riesgo crítico. Protegidas: la carpeta de Windows, `ProgramData\Package Cache`, `ProgramData\Microsoft`, `AppData\Local\Docker`, `AppData\Local\Packages`, `System Volume Information`, `$Recycle.Bin`, `Recovery`, `Boot`, raíces de unidad y la raíz del perfil.
2. La confianza alta exige al menos dos evidencias; si no, baja a media.
3. Los entornos activos, los datos persistentes y los datos de usuario no pueden ser candidatos: pasan a revisión manual.
4. «Mantener» siempre declara cero bytes recuperables.

## Cálculo sin superposiciones

- Se cuentan primero los candidatos y luego las revisiones, de la ruta más corta a la más larga.
- Lo contenido en una ruta ya contada suma cero.
- Una carpeta en revisión descuenta los candidatos que contiene.
- En un grupo de duplicados se conserva siempre una copia, y las copias dentro de una carpeta ya contada no suman.
- Los bytes con enlaces duros no se consideran recuperables al borrar una sola ruta.
- El reporte separa espacio ocupado, potencialmente recuperable, recuperable tras revisión y efectivamente liberado (siempre 0).

## Limpieza

| Regla | Detecta | Evidencia requerida | Clasificación | Confianza máx. | Riesgo |
|---|---|---|---|---|---|
| `DEV-ARTIFACT` | Artefactos de compilación y dependencias | Marcador junto a la carpeta; Git cuando es posible | Candidato o revisión | Alta | Bajo |
| `DEV-CACHE` | Cachés de herramientas | Ubicación exacta y estructura interna si se conoce | Candidato o revisión | Alta | Bajo o moderado |
| `TMP-USER` | Contenido antiguo del TEMP real | Ubicación real y sin escrituras recientes en todo el subárbol | Candidato | Media | Bajo |
| `TMP-NAMED` | Carpeta llamada «temp» en otro lugar | Solo el nombre | Revisión | Baja | Moderado |
| `LOG-OLD` | `.log` grande y antiguo en datos de aplicación | Extensión, ubicación y antigüedad | Revisión | Media | Bajo |
| `DL-INSTALLER`, `DL-ARCHIVE` | Instaladores y comprimidos antiguos | Extensión y antigüedad | Revisión | Baja | Moderado |
| `DL-COPY` | Copia aparente: `a (1).zip` | Patrón de nombre, original presente y mismo tamaño | Revisión | Media | Bajo |
| `DL-LARGE` | Descarga grande y antigua | Tamaño y antigüedad | Revisión | Baja | Moderado o alto |
| `LARGE-STALE` | Archivo personal grande y antiguo | Tamaño y antigüedad | Revisión | Baja | Según contenido |
| `RES-ORPHAN` | Posible resto de una aplicación | Ver abajo | Revisión | Media | Moderado |
| `DUP-CONFIRMED` | Copias idénticas | Hash SHA-256 completo e identidad física distinta | Candidato solo en Descargas y sin contenido sensible | Media | Bajo a alto |
| `VD-KEEP` | Discos virtuales | Extensión | Mantener | Alta | Crítico |
| `DB-KEEP` | Bases de datos y respaldos | Extensión | Mantener | Media | Alto |

### Artefactos reconocidos

Un nombre genérico solo cuenta si el directorio padre demuestra el tipo de proyecto.

| Herramienta | Carpeta | Marcador necesario | Tipo |
|---|---|---|---|
| .NET | `bin`, `obj`, `TestResults` | `.csproj`, `.fsproj`, `.vbproj` o solución | Artefacto |
| Visual Studio | `.vs` | Solución o proyecto | Entorno activo |
| Node.js | `node_modules` | `package.json` | Dependencia |
| Node.js | `dist`, `.next`, `.nuxt`, `.output`, `.turbo`, `.parcel-cache`, `.svelte-kit` | `package.json` | Artefacto o caché |
| Python | Cualquier carpeta con `pyvenv.cfg` | El propio archivo | Entorno activo |
| Python | `__pycache__` | Solo contiene `.pyc` | Caché |
| Python | `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.tox`, `htmlcov` | Marcador de caché o proyecto | Caché o artefacto |
| Flutter/Dart | `build`, `.dart_tool` | `pubspec.yaml` | Artefacto o caché |
| Gradle | `build`, `.gradle` | Script de Gradle | Artefacto |
| Maven | `target` | `pom.xml` | Artefacto |

**Ajustes de la decisión:**

- Git informa archivos versionados dentro: revisión manual.
- Git confirma que no hay archivos versionados: confianza alta.
- Fuera de un repositorio: confianza media, como máximo.
- `node_modules` sin archivo de bloqueo: revisión manual.
- `dist` sin repositorio ni archivo de bloqueo: revisión manual con confianza baja.
- Actividad reciente (14 días): nunca confianza alta; las dependencias pasan a revisión.
- Nunca se detectan artefactos dentro de `node_modules`, `site-packages`, `.pnpm`, `extensions` ni carpetas ocultas directas del perfil. Este criterio surgió de un falso positivo real: el `dist` de una extensión instalada es su código en uso.

### Cachés reconocidas

Se exige la ruta exacta; un nombre parecido en otro lugar no cuenta.

| Herramienta | Ubicación | Marcador | Acción sugerida |
|---|---|---|---|
| NuGet | `~\.nuget\packages` | | `dotnet nuget locals global-packages --clear` |
| npm | `%LOCALAPPDATA%\npm-cache` | `_cacache` | `npm cache verify` o `npm cache clean --force` |
| pnpm | `%LOCALAPPDATA%\pnpm\store` | | `pnpm store prune` (solo revisión) |
| Yarn | `%LOCALAPPDATA%\Yarn\Cache` | | `yarn cache clean` |
| pip | `%LOCALAPPDATA%\pip\Cache` | `http`, `http-v2` o `wheels` | `pip cache purge` |
| uv | `%LOCALAPPDATA%\uv\cache` | | `uv cache clean` |
| Gradle | `~\.gradle\caches` | `modules-2` | Consultar la documentación de Gradle |
| Maven | `~\.m2\repository` | | Revisión: puede contener artefactos instalados localmente |
| Dart/Flutter | `%LOCALAPPDATA%\Pub\Cache` | `hosted` | `dart pub cache clean` |
| VS Code | `Cache`, `CachedData`, `Code Cache`, `CachedExtensionVSIXs` en `%APPDATA%\Code` | | Cerrar VS Code y eliminar solo esa carpeta |
| JetBrains | `%LOCALAPPDATA%\JetBrains\*\caches` | | File > Invalidate Caches |
| Visual Studio | `%LOCALAPPDATA%\Microsoft\VisualStudio\*\ComponentModelCache` | | Cerrar Visual Studio y eliminar solo esa carpeta |

### Residuos de aplicaciones (`RES-ORPHAN`)

Solo se ejecuta con inventario de aplicaciones. Examina el primer nivel de Program Files, ProgramData, `%LOCALAPPDATA%` y `%APPDATA%`, y **exige todo lo siguiente**:

1. Tamaño mínimo (50 MiB).
2. Sin coincidencia con nombre, editor o ubicación de ninguna aplicación inventariada.
3. Sin escrituras en todo el subárbol durante 180 días.
4. Sin referencias en `PATH`, servicios de Windows ni claves de arranque `Run`.
5. Sin subcarpetas inaccesibles, y fuera de una lista de carpetas compartidas conocidas.

Nunca supera la confianza media. Baja a baja si contiene ejecutables, porque podría ser una aplicación portable.

## Respaldo

| Regla | Detecta | Clasificación | Confianza | Riesgo |
|---|---|---|---|---|
| `BKP-GIT:no-remote` | Repositorio sin remoto | Respaldar | Alta | Crítico |
| `BKP-GIT:local-work` | Cambios, archivos sin versionar, stashes, commits o ignorados importantes | Respaldar | Media | Alto |
| `BKP-GIT:unreadable` | Estado no determinable | Información insuficiente | Desconocida | Moderado |
| `BKP-PERSONAL:*` | Archivos personales sin copia verificada | Respaldar | Media | Alto |

Se clasifican por extensión y ubicación, sin leer el contenido. Fuera del análisis personal quedan repositorios, carpetas de sistema, aplicaciones y artefactos.

**Puntuación de prioridad de Git:** sin remoto 100; cambios sin confirmar 30; commits sin publicar 25; stashes 20; archivos sin versionar 15; ignorados importantes 10; estado no legible 3.

**Estados de respaldo:**

| Estado | Criterio |
|---|---|
| Copia verificada | SHA-256 idéntico. Solo con `--verify-hashes` |
| Posible copia encontrada | Mismo nombre y tamaño |
| Sin copia encontrada | No hay coincidencia en los destinos configurados |
| Respaldo no verificable | La copia está solo en la nube, o el archivo está en una carpeta sincronizada |
| No evaluado | No hay destinos configurados |

## Aplicaciones

| Clasificación | Criterio |
|---|---|
| Evidencia de ejecución reciente | Última evidencia dentro de 30 días |
| Sin evidencia en los últimos 30, 60 o 90 días | La última evidencia es más antigua que ese umbral |
| Sin evidencia histórica disponible | Hay fuentes disponibles y datos para cruzar, pero sin coincidencias. Confianza baja |
| Uso desconocido | Sin fuentes disponibles, o sin ubicación ni identificador con que cruzar |

`APP-UNUSED` solo sugiere revisión manual con confianza baja, solo con evidencia antigua y nunca para componentes del sistema. Nunca se afirma que una aplicación «nunca se ha abierto».

**Cruce de evidencia:** ejecutable dentro de la ubicación de instalación, identificador de paquete, nombre de ejecutable (Prefetch) o acceso directo con nombre idéntico.

## Umbrales predeterminados

| Clave de `config set` | Valor |
|---|---|
| `old-download-days` | 90 |
| `stale-file-days` | 180 |
| `temp-age-days` | 30 |
| `log-age-days` | 60 |
| `residue-age-days` | 180 |
| `active-days` | 14 |
| `large-file-mb` | 1024 |
| `min-finding-mb` | 10 |
| `duplicate-min-mb` | 1 |
| `usage-recent-days`, `usage-medium-days`, `usage-long-days` | 30, 60, 90 |
