# Modelo de seguridad

**Objetivo:** ayudar a liberar espacio sin arriesgar información. La herramienta observa y recomienda; quien decide y actúa es siempre el usuario.

## Operaciones permitidas

| Sobre | Operación |
|---|---|
| Archivos analizados | Leer metadatos. Abrir con `FILE_READ_ATTRIBUTES` y sin recuperar contenido remoto |
| Contenido de archivos | Leer solo para: comparar duplicados (`--deep`, `analyze duplicates`), verificar respaldos (`--verify-hashes`) y los primeros 7 bytes de un archivo `.git` |
| Registro | Solo lectura |
| Git | `status`, `config` (lectura), `for-each-ref`, `rev-list`, `rev-parse`, `ls-files` |
| Otras herramientas | `docker system df`, `powercfg /a`, `Get-AppxPackage` |
| Datos propios | Escribir y eliminar configuración, historial, último resultado y reportes en sus carpetas, o en la salida indicada con `--output` |

## Operaciones prohibidas (no implementadas)

- Eliminar, mover, truncar o modificar archivos analizados.
- Desinstalar aplicaciones, cambiar la configuración de Windows o del registro.
- Ejecutar `fetch`, `commit`, `stash apply`, `push` o cualquier comando de Git que modifique un repositorio.
- Ejecutar limpieza de Docker, DISM, compactación de discos o `powercfg /hibernate`.
- Instalar servicios o tareas, solicitar elevación, usar telemetría o comunicarse con servicios externos.
- Ejecutar scripts descargados.
- Acceder a rutas de red sin `--allow-network`. Los destinos de respaldo de red no se admiten.

El manifiesto declara `asInvoker`: nunca se solicita elevación.

## Controles

| Riesgo | Control | Verificación |
|---|---|---|
| Recomendación incorrecta | Evidencia múltiple, barreras del motor, rutas protegidas | Pruebas de reglas y motor |
| Modificar datos durante el análisis | Sin API de escritura sobre lo analizado | Pruebas que comparan tamaño, fechas, atributos y hash antes y después |
| Reescribir el índice de Git | `--no-optional-locks` y `GIT_OPTIONAL_LOCKS=0` | Prueba de huella del repositorio, incluida `.git` |
| Ejecución de código por `core.fsmonitor` | `-c core.fsmonitor=false` | Revisión de código, sin prueba dedicada |
| Inyección de comandos | `ProcessStartInfo.ArgumentList`, sin shell, con límite de tiempo | Prueba con argumento hostil |
| Inyección en el reporte | JSON escapado, inserción como texto, CSP `default-src 'none'` | Pruebas con rutas hostiles |
| Inyección en consola | `Markup.Escape` o `Text` | Prueba con rutas con corchetes |
| Inyección SQL | Consultas parametrizadas | Prueba con ruta hostil |
| Credenciales en remotos | Se eliminan de la URL antes de guardarla | Pruebas |
| Secretos en `.env` | Solo se evalúa el nombre, nunca el contenido | Prueba que busca el valor en la salida |
| Hidratar contenido en la nube | Atributos revisados en el recorrido y antes de cada lectura | Pruebas con atributo `OFFLINE`; sin proveedor real |
| Doble conteo y bucles | No se siguen enlaces; identidad física para enlaces duros | Pruebas |
| Sobrescribir un reporte | Se exige `--force` | Prueba de extremo a extremo |
| Borrado de datos propios | Se exige confirmación o `--yes`; solo archivos de la herramienta | Prueba de extremo a extremo |

## Riesgos conocidos

1. **Filtros de Git.** `git status` puede ejecutar un filtro `clean` definido en la configuración local de un repositorio, y no hay forma de desactivarlos todos por opción. Un repositorio clonado no trae esa configuración, pero un directorio copiado de una fuente no confiable sí podría. Git protege contra repositorios de otros propietarios con `safe.directory`, y esta herramienta informa ese caso como no verificable. **No analice carpetas de origen no confiable.**
2. **Fecha de último acceso.** Leer contenido puede actualizarla si Windows la mantiene activa. No se evita porque hacerlo requeriría abrir el archivo con permiso de escritura de atributos. El contenido y la fecha de modificación no cambian.
3. **Datos personales en reportes.** Reportes, historial y último resultado contienen rutas y nombres de archivo, y remotos de Git sin credenciales. Se guardan en el perfil del usuario, con los permisos heredados de esa carpeta, **sin cifrar**. El reporte lo advierte; puede eliminarlos con `history clear --yes --include-reports`.
4. **Recomendaciones que envejecen.** Un resultado guardado refleja el momento del análisis. El plan y los reportes indican comprobar cada ruta antes de actuar.
5. **Heurísticas por nombre.** Un proyecto con estructura inusual podría clasificarse mal. Por eso se usan marcadores, Git y confianza limitada, pero **ningún resultado reemplaza la revisión del usuario**.
6. **Comandos sugeridos.** Algunos, como `npm cache clean --force`, los ejecuta el usuario bajo su responsabilidad. La herramienta nunca los ejecuta.
7. **Variables de entorno.** `WINSTORAGEAUDIT_SANDBOX_ROOT` cambia lo que la herramienta considera ubicaciones conocidas, de modo que quien controle el entorno podría alterar la clasificación. Como nada se ejecuta ni elimina, el efecto se limita a las recomendaciones mostradas.

## Si se añade limpieza en el futuro

Debe estar desactivada por defecto y operar solo sobre elementos seleccionados. Debe mostrar una vista previa, pedir confirmación explícita y revalidar ruta, identidad y estado justo antes de actuar. Debe rechazar rutas protegidas, enlaces y elementos modificados, y registrar resultados. Una cuarentena o la Papelera no cuentan como espacio liberado.
