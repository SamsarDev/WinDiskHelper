# Arquitectura

Monolito modular en C# / .NET 10. La lógica no depende de la presentación, así que una interfaz gráfica futura podría reutilizar los analizadores tal como están.

```
Cli ──────► Core ◄────── Infrastructure
 │           ▲
 └─► Reporting ─┘
```

| Proyecto | Responsabilidad | Dependencias externas |
|---|---|---|
| `WinStorageAudit.Core` | Modelo, reglas, analizadores y orquestación | Ninguna |
| `WinStorageAudit.Infrastructure` | Win32, registro, procesos, SQLite | `Microsoft.Data.Sqlite` |
| `WinStorageAudit.Reporting` | HTML, JSON y plan de limpieza | Ninguna |
| `WinStorageAudit.Cli` | Comandos, progreso y tablas | `Spectre.Console` |

## Flujo de un análisis

`AuditPipeline` ejecuta las etapas en este orden. Si una falla, se anota en las limitaciones y las demás continúan:

1. **Enumeración.** `IFileScanner` recorre los directorios y entrega un lote por carpeta a `IScanObserver`.
2. **Agregación.** `ScanCollector` acumula totales y candidatos en estructuras acotadas.
3. **Git.** `GitAnalyzer` evalúa los repositorios descubiertos y comprueba si los artefactos están versionados.
4. **Respaldos.** `BackupVerifier` compara con los destinos configurados.
5. **Duplicados.** `DuplicateDetector` confirma por etapas.
6. **Aplicaciones.** Se cruza el inventario con la evidencia de uso.
7. **Mantenimiento.** `IMaintenanceProbe` obtiene el estado y `MaintenanceAdvisor` lo convierte en recomendaciones.
8. **Recomendaciones.** `RecommendationEngine` ejecuta las reglas, aplica barreras de seguridad y calcula totales sin superposiciones.

## Decisiones principales

| Decisión | Motivo |
|---|---|
| `FindFirstFileExW` con P/Invoke en lugar de `System.IO` | Da el atributo y la etiqueta de reanálisis, necesarios para no seguir enlaces ni tocar contenido en la nube |
| No seguir nunca enlaces, junctions ni puntos de montaje | Elimina ciclos y doble conteo sin mantener un registro de carpetas visitadas |
| Recorrido por lotes de carpeta, con paralelismo limitado | El observador usa un solo bloqueo con poca contención, y el total de cada carpeta surge del recorrido |
| Contexto heredado (`DirectoryContext`) | Clasifica millones de archivos sin comparar la ruta completa con cada regla |
| Memoria acotada | Solo se retienen los mayores archivos y carpetas, un árbol de carpetas relevantes y listas con límite. Los excesos se cuentan y se avisan |
| Barreras en el motor, no en cada regla | Una regla defectuosa no puede proponer una ruta protegida ni declarar confianza alta sin evidencia |
| Analizador de argumentos propio | Ayuda y errores completamente en español, sin dependencias adicionales |
| Publicación sin recorte (*trimming*) | La serialización JSON por reflexión es más simple; el ejecutable pesa unos 38 MiB |
| Sin .NET específico de Windows en Core | Las reglas se prueban con un escáner en memoria y datos controlados |

## Interfaces y por qué existen

| Interfaz | Permite |
|---|---|
| `IFileScanner`, `IScanObserver` | Probar las reglas con un árbol en memoria |
| `IProcessRunner` | Centralizar la ejecución segura de procesos externos |
| `IInstalledAppSource`, `IUsageEvidenceSource` | Añadir fuentes y simular su ausencia |
| `IFileIdentityProvider` | Reconocer enlaces duros en el detector de duplicados |
| `IMaintenanceProbe` | Separar la consulta del sistema de la lógica de recomendación |

## Rendimiento

Una ejecución real, con unidad SSD y modo rápido, enumeró cerca de 1,09 millones de archivos de un perfil en menos de un minuto (49 a 74 s), incluido el análisis de unos 50 repositorios. Es una medición en un solo equipo, no un compromiso de rendimiento.

## Pruebas

- `tests/WinStorageAudit.UnitTests`: reglas, motor, análisis de Git, clasificación de uso, mantenimiento y reportes. No requieren Windows ni Git.
- `tests/WinStorageAudit.IntegrationTests`: escáner real, Git real, SQLite, registro y el ejecutable de extremo a extremo. Requieren Windows, NTFS y Git, y trabajan solo en carpetas temporales propias.
