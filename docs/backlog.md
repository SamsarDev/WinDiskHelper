# Mejoras futuras

Nada de lo que aparece aquí está implementado.

## Limitaciones pendientes

| Tema | Situación actual | Mejora |
|---|---|---|
| Proveedores en la nube | Probado solo con el atributo `OFFLINE` | Probar con OneDrive real, incluidas carpetas sin copia local |
| Interfaz interactiva | `browse` y `--interactive` sin pruebas automatizadas | Pruebas con una consola simulada |
| Progreso interactivo | Sin prueba automatizada | Prueba con consola simulada |
| Filtros de Git | Riesgo documentado | Investigar si se puede consultar el estado sin ejecutar filtros `clean` |
| Comparación histórica | Solo categorías y carpetas destacadas | Comparar el árbol retenido |
| Reportes | Sin cifrar | Opción para anonimizar rutas en reportes compartidos |
| Residuos | Lista de carpetas compartidas escrita a mano | Ampliarla con datos de uso real |
| Enlaces duros en modo rápido | Solo desde 1 MiB y en Windows | Usar `GetFileInformationByName` en Windows 11 24H2 o posterior, que no necesita abrir el archivo |
| Espacio no contabilizado | Solo una nota general | Mostrar «usado por el volumen menos enumerado» cuando se analiza una unidad completa |
| Discos en HDD | Sin medición | Ajustar el paralelismo según el tipo de unidad |
| Localización | Solo español | Separar los textos en recursos |

## Funcionalidades diferidas

- Observación opcional de uso con una tarea programada, local y consentida. Nunca sería obligatoria.
- Evaluación con privilegios de administrador cuando el usuario ya los tenga: DISM `/AnalyzeComponentStore` y `vssadmin`.
- Modo de limpieza, con los controles de [security.md](security.md).
- Reconocer más cachés: Rust (Cargo), Go, Conda, Android SDK, Playwright, Hugging Face.
- Tabla de hallazgos en el reporte exportable a CSV.
- Interfaz gráfica sobre `Core`.
- Lista de carpetas compartidas de residuos configurable por el usuario.

## Fuera de alcance

Aplicaciones móviles, servicios en la nube, IA integrada, monitoreo obligatorio, limpieza programada, desinstalación automática, editor de registro, administrador de particiones, antivirus, recuperación forense y optimización de RAM.
