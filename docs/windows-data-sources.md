# Fuentes de datos de Windows

Cuando se indica «comprobado», se ejecutó en Windows 11 (compilación 26200) como usuario estándar durante el desarrollo.

## Sistema de archivos

| Fuente | Uso | Limitaciones |
|---|---|---|
| [`FindFirstFileExW`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfileexw) | Nombres, tamaños, fechas, atributos, etiqueta de reanálisis | Sin número de enlaces duros |
| [`GetCompressedFileSizeW`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getcompressedfilesizew) | Bytes en disco de archivos comprimidos y dispersos | Con archivo normal devuelve el tamaño real; se redondea al clúster |
| [`GetFileInformationByHandle`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle) | Número de enlaces e identidad física | Abre un manejador con `FILE_READ_ATTRIBUTES` y `FILE_FLAG_OPEN_NO_RECALL` |
| [Constantes de atributos](https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants) | Detectar contenido en la nube: `OFFLINE`, `RECALL_ON_OPEN`, `RECALL_ON_DATA_ACCESS` | Depende de que el proveedor los establezca |

**Comprobado por pruebas automatizadas:** enlaces duros, junctions, compresión NTFS, archivos dispersos, carpetas sin permiso y archivos bloqueados. El contenido en la nube se probó con el atributo `OFFLINE`, sin un proveedor real como OneDrive. **Por eso, el comportamiento con un proveedor real queda sin verificar.**

**Espacio no contabilizado:** Windows muestra más uso del que se puede enumerar. La diferencia procede de metadatos de NTFS, instantáneas, `System Volume Information` y carpetas protegidas.

## Aplicaciones instaladas

| Fuente | Uso | Limitaciones |
|---|---|---|
| [Registro de desinstalación](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key) (HKLM y HKCU, 32 y 64 bits) | Nombre, editor, versión, ubicación, tamaño, fecha | `InstallLocation` y `EstimatedSize` suelen faltar. La documentación no indica la unidad de `EstimatedSize`; se interpreta como KiB, por convención. `InstallDate` puede ser la fecha del último mantenimiento |
| `Get-AppxPackage` (PowerShell de Windows) | Paquetes MSIX del usuario actual | No lista paquetes de otros usuarios |

**Descartado:** `Win32_Product`. Enumerarlo es lento y es conocido por provocar comprobaciones de los productos MSI. No se obtuvo la página oficial que lo describe (la dirección consultada devolvió 404), así que esta decisión se apoya en conocimiento previo, no en una cita verificada.

## Evidencia de ejecución

Windows no ofrece un historial completo y fiable de ejecución.

| Fuente | Decisión | Permisos | Qué registra | Limitaciones |
|---|---|---|---|---|
| UserAssist (`HKCU\...\Explorer\UserAssist`) | **Usada** | Usuario estándar, comprobado | Última ejecución y recuento de lanzamientos desde la interfaz gráfica | Sin documentación oficial. No registra consola, servicios ni tareas programadas. Solo la última fecha. Se puede borrar. Formato tomado de fuentes forenses, que difieren en detalles; se validó localmente la longitud de 72 bytes y fechas coherentes en el desplazamiento 60 |
| Prefetch (`C:\Windows\Prefetch`) | **Usada si hay acceso** | Administrador. Como usuario estándar: acceso denegado, comprobado | Nombre de ejecutable y fecha del archivo `.pf` | Solo nombre, sin ruta. Puede estar deshabilitado. No se interpreta el formato interno |
| BAM (`HKLM\...\Services\bam\State`) | Descartada | Acceso denegado como usuario estándar, comprobado | Ejecuciones recientes | Sin documentación oficial; requiere privilegios |
| Evento 4688 de seguridad | Descartada | Administrador | Creación de procesos | Exige habilitar una auditoría, y no se cambia la configuración del sistema |
| Fecha de último acceso de ejecutables | Descartada | Usuario estándar | Último acceso | Antivirus e indexado también la actualizan: no demuestra ejecución |
| Amcache, SRUM | Descartadas | Administrador | Datos forenses | Formatos no documentados y uso desproporcionado para esta herramienta |

**Observación futura consentida:** sería viable una tarea programada opcional que tome muestras de procesos en ejecución y las guarde localmente. Queda en el [backlog](backlog.md), porque el producto no instala nada permanente.

## Mantenimiento

| Elemento | Detección sin privilegios | Referencia |
|---|---|---|
| Sensor de almacenamiento | `HKCU\...\StorageSense\Parameters\StoragePolicy`, valor `01`, y existencia de directiva. **La clave no está documentada oficialmente**; si falta, el estado es «No determinado» | [Soporte de Microsoft](https://support.microsoft.com/en-us/windows/manage-drive-space-with-storage-sense-654f6ada-7bfc-45e5-966b-e24aded96ad5) |
| Papelera | [`SHQueryRecycleBinW`](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shqueryrecyclebinw). Comprobado | |
| Hibernación | Tamaño de `hiberfil.sys`, `powercfg /a`. Comprobado | [powercfg](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options) |
| WinSxS | Solo tamaño aparente (análisis profundo). El Explorador lo sobrestima por los enlaces duros | [Tamaño real](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/determine-the-actual-size-of-the-winsxs-folder), [limpieza](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/clean-up-the-winsxs-folder) |
| Almacenamiento reservado | No evaluado: indicado como comando | [DISM](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-storage-reserve) |
| Puntos de restauración | No evaluado: indicado como comando | [Soporte de Microsoft](https://support.microsoft.com/en-us/windows/system-protection-e9126e6e-fa64-4f5f-874d-9db90e57645a) |
| Caché de Windows Update, Windows.old, volcados, registros | Tamaño de carpeta, omitiendo lo inaccesible | Soporte de Microsoft (arriba) |
| Archivo de paginación | Tamaño de `pagefile.sys`. Comprobado | [Microsoft Learn](https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/introduction-to-the-page-file) |
| Docker Desktop | `docker system df --format json`, solo en análisis profundo, y tamaño de sus discos. Comprobado | [df](https://docs.docker.com/reference/cli/docker/system/df/), [prune](https://docs.docker.com/reference/cli/docker/system/prune/) |
| WSL | `HKCU\...\Lxss`, valores `DistributionName`, `BasePath` y `VhdFileName`. Comprobado | [Espacio en disco](https://learn.microsoft.com/en-us/windows/wsl/disk-space) |

**Notas:**

- `wsl --manage <distribución> --set-sparse true` no aparece en la página de espacio en disco consultada; se confirmó con `wsl --help` en el equipo de desarrollo.
- Microsoft desaconseja modificar con herramientas de Windows los archivos de WSL en AppData, por lo que nunca se recomienda hacerlo a mano.
- La documentación de `docker system prune` indica que `--volumes` elimina volúmenes anónimos. El potencial estimado de Docker excluye los volúmenes por completo.
- Durante el desarrollo se leyeron estas páginas: limpieza de WinSxS, powercfg, `GetCompressedFileSizeW`, almacenamiento reservado, espacio en disco de WSL, `docker system df` y `prune`, `git status`, `SHQueryRecycleBinW`, Sensor de almacenamiento y registro de desinstalación. **Las demás referencias se citan de memoria y no se abrieron**: `FindFirstFileExW`, `GetFileInformationByHandle`, protección del sistema, archivo de paginación y Windows Installer.

## Git

Se usan [`git status --porcelain=v2`](https://git-scm.com/docs/git-status), `for-each-ref`, `rev-list`, `config` y `ls-files`. La documentación recomienda `--no-optional-locks` para procesos en segundo plano, y así se hace. La comparación usa referencias remotas locales, que pueden estar desactualizadas: nunca se ejecuta `fetch`.
