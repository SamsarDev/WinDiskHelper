using System.Text.Json;
using WinStorageAudit.Core.Model;
using WinStorageAudit.Core.Scanning;

namespace WinStorageAudit.Core.Maintenance;

/// <summary>
/// Convierte el estado detectado en recomendaciones. Lógica pura: no ejecuta nada.
/// Los comandos son texto para que el usuario los revise. Referencias en docs/windows-data-sources.md.
/// </summary>
public static class MaintenanceAdvisor
{
    private const string SettingsStorage = "Configuración > Sistema > Almacenamiento";
    private const string RefStorageSense = "https://support.microsoft.com/en-us/windows/manage-drive-space-with-storage-sense-654f6ada-7bfc-45e5-966b-e24aded96ad5";
    private const string RefWinSxsSize = "https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/determine-the-actual-size-of-the-winsxs-folder";
    private const string RefWinSxsClean = "https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/clean-up-the-winsxs-folder";
    private const string RefPowercfg = "https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options";
    private const string RefReserved = "https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-storage-reserve";
    private const string RefWsl = "https://learn.microsoft.com/en-us/windows/wsl/disk-space";
    private const string RefDockerDf = "https://docs.docker.com/reference/cli/docker/system/df/";
    private const string RefDockerPrune = "https://docs.docker.com/reference/cli/docker/system/prune/";
    private const string Admin = "Administrador";
    private const string Standard = "Usuario estándar";

    private static string B(long? bytes) => bytes is { } v ? PathUtil.FormatBytes(v) : "no medible sin privilegios";

    public static IReadOnlyList<MaintenanceItem> Build(MaintenanceSnapshot s)
    {
        var items = new List<MaintenanceItem>
        {
            StorageSense(s),
            RecycleBin(s),
            TemporaryFiles(),
            ComponentStore(s),
            Hibernation(s),
            ReservedStorage(),
            RestorePoints(),
            PageFile(s),
        };

        if (s.UpdateDownloadBytes is > 0) items.Add(UpdateCache(s));
        if (s.WindowsOldBytes is > 0) items.Add(WindowsOld(s));
        var dumps = (s.MemoryDumpBytes ?? 0) + (s.MiniDumpBytes ?? 0) + (s.UserCrashDumpBytes ?? 0);
        if (dumps > 0) items.Add(Dumps(s, dumps));
        if (s.WindowsLogsBytes is > 1024L * 1024 * 1024) items.Add(WindowsLogs(s));
        if (s.WindowsInstallerBytes != null) items.Add(WindowsInstaller(s));
        if (s.DockerInstalled) items.Add(Docker(s));
        if (s.WslInstalled || s.WslDistributions.Count > 0) items.Add(Wsl(s));

        items.Add(AdvancedResetBase());
        if (s.DockerInstalled) items.Add(AdvancedDockerVolumes());
        return items;
    }

    private static MaintenanceItem StorageSense(MaintenanceSnapshot s) => new()
    {
        Id = "MNT-STORAGE-SENSE",
        Title = "Sensor de almacenamiento",
        Description = "Elimina temporales y el contenido antiguo de la Papelera automáticamente. Las descargas y el contenido en la nube solo se tocan si se configuran.",
        Relevance = s.StorageSenseEnabled == true ? "Ya está activo: revise que su configuración sea la deseada." : "Evita que los temporales se acumulen sin intervención.",
        DetectedState = s.StorageSenseManagedByPolicy ? "Administrado por directiva de la organización"
            : s.StorageSenseEnabled switch { true => "Activado", false => "Desactivado", _ => "No determinado" },
        SettingsPath = SettingsStorage + " > Sensor de almacenamiento",
        RequiredPermissions = Standard,
        Consequences = "Según la configuración, puede borrar elementos de la Papelera y, si lo habilita, de Descargas.",
        ReversibilityNote = "La opción se puede desactivar; lo ya eliminado no se recupera.",
        Reference = RefStorageSense,
        Severity = s.StorageSenseEnabled == true ? MaintenanceSeverity.Informational : MaintenanceSeverity.Recommended,
    };

    private static MaintenanceItem RecycleBin(MaintenanceSnapshot s) => new()
    {
        Id = "MNT-RECYCLE-BIN",
        Title = "Papelera de reciclaje",
        Description = "Los archivos enviados a la Papelera siguen ocupando espacio hasta vaciarla.",
        Relevance = s.RecycleBinBytes is > 0 ? "Contiene elementos que aún ocupan disco." : "No hay elementos que recuperar.",
        DetectedState = s.RecycleBinBytes is { } b ? $"{PathUtil.FormatBytes(b)} en {s.RecycleBinItems:N0} elementos" : "No determinado",
        EstimatedRecoverableBytes = s.RecycleBinBytes,
        SettingsPath = "Explorador: clic derecho en la Papelera > Vaciar",
        RequiredPermissions = Standard,
        Consequences = "Los elementos dejan de poder restaurarse. Revise el contenido antes.",
        ReversibilityNote = "Irreversible una vez vaciada.",
        Reference = RefStorageSense,
        Severity = s.RecycleBinBytes is > 0 ? MaintenanceSeverity.Recommended : MaintenanceSeverity.Informational,
    };

    private static MaintenanceItem TemporaryFiles() => new()
    {
        Id = "MNT-TEMP",
        Title = "Archivos temporales del sistema",
        Description = "Windows muestra las categorías que puede limpiar y su tamaño antes de borrarlas.",
        Relevance = "Es la vía compatible para limpiar temporales del sistema, en lugar de borrar carpetas a mano.",
        DetectedState = "Consulte el desglose en Configuración; el tamaño exacto lo calcula Windows.",
        SettingsPath = SettingsStorage + " > Archivos temporales",
        RequiredPermissions = Standard + " (algunas categorías piden " + Admin.ToLowerInvariant() + ")",
        Consequences = "Desmarque «Descargas» si aparece en la lista, salvo que quiera borrarla.",
        ReversibilityNote = "Lo eliminado no se recupera.",
        Reference = RefStorageSense,
        Severity = MaintenanceSeverity.Recommended,
    };

    private static MaintenanceItem ComponentStore(MaintenanceSnapshot s) => new()
    {
        Id = "MNT-WINSXS",
        Title = "Almacén de componentes (WinSxS)",
        Description = "El Explorador sobrestima WinSxS porque muchos archivos son enlaces duros compartidos con Windows. Nunca borre su contenido a mano: puede impedir el arranque y las actualizaciones.",
        Relevance = "El análisis indica el tamaño real y si conviene limpiar. Windows ya lo limpia automáticamente de forma periódica.",
        DetectedState = s.WinSxsApparentBytes is { } b
            ? $"Tamaño aparente enumerado: {PathUtil.FormatBytes(b)}. El tamaño real requiere el análisis de DISM."
            : "No medido. El análisis de DISM requiere privilegios de administrador.",
        Command = "Dism.exe /Online /Cleanup-Image /AnalyzeComponentStore   (solo analiza)\nDism.exe /Online /Cleanup-Image /StartComponentCleanup   (limpia; solo si el análisis lo recomienda)",
        RequiredPermissions = Admin,
        Consequences = "StartComponentCleanup elimina versiones anteriores de inmediato, sin el periodo de gracia de 30 días de la tarea automática.",
        ReversibilityNote = "Las versiones de componentes eliminadas no se recuperan.",
        Reference = RefWinSxsSize + " · " + RefWinSxsClean,
        Severity = MaintenanceSeverity.Informational,
    };

    private static MaintenanceItem Hibernation(MaintenanceSnapshot s) => new()
    {
        Id = "MNT-HIBERNATION",
        Title = "Hibernación (hiberfil.sys)",
        Description = "Reserva espacio para guardar la memoria al hibernar. Inicio rápido también depende de este archivo.",
        Relevance = s.HiberfilBytes is > 0 ? "Puede reducirse o desactivarse si no usa la hibernación." : "No se detectó el archivo o la hibernación está desactivada.",
        DetectedState = s.HiberfilBytes is { } b ? "hiberfil.sys ocupa " + PathUtil.FormatBytes(b) : "hiberfil.sys no detectado",
        EstimatedRecoverableBytes = s.HiberfilBytes,
        Command = "powercfg /a   (ver estados disponibles)\npowercfg /hibernate /size 0  seguido de  powercfg /hibernate /type reduced   (conserva solo Inicio rápido)\npowercfg /hibernate off   (desactiva hibernación e Inicio rápido)",
        RequiredPermissions = Admin + " para cambiarlo",
        Consequences = "Sin hibernación no se puede hibernar el equipo ni usar Inicio rápido. Un portátil puede perder la sesión al agotarse la batería.",
        ReversibilityNote = "Reversible con «powercfg /hibernate on».",
        Reference = RefPowercfg,
        Severity = s.HiberfilBytes is > 0 ? MaintenanceSeverity.Informational : MaintenanceSeverity.Informational,
    };

    private static MaintenanceItem ReservedStorage() => new()
    {
        Id = "MNT-RESERVED",
        Title = "Almacenamiento reservado",
        Description = "Windows reserva espacio para que las actualizaciones se puedan instalar aunque el disco esté casi lleno.",
        Relevance = "Solo informativo: desactivarlo no se recomienda como limpieza rutinaria.",
        DetectedState = "No evaluado: la consulta requiere privilegios de administrador.",
        Command = "DISM.exe /Online /Get-ReservedStorageState   (solo consulta)",
        RequiredPermissions = Admin,
        Consequences = "Sin esta reserva, una actualización puede fallar por falta de espacio.",
        ReversibilityNote = "El estado se puede volver a cambiar con DISM.",
        Reference = RefReserved,
        Severity = MaintenanceSeverity.Informational,
    };

    private static MaintenanceItem RestorePoints() => new()
    {
        Id = "MNT-RESTORE-POINTS",
        Title = "Puntos de restauración",
        Description = "Las instantáneas se guardan en «System Volume Information», invisible para un usuario estándar; explican parte del espacio no contabilizado.",
        Relevance = "Solo informativo. Eliminarlos no se recomienda como limpieza rutinaria.",
        DetectedState = "No evaluado sin privilegios de administrador.",
        Command = "vssadmin list shadowstorage   (solo consulta)",
        SettingsPath = "Panel de control > Sistema > Protección del sistema",
        RequiredPermissions = Admin,
        Consequences = "Perder puntos de restauración limita la recuperación ante un problema del sistema.",
        ReversibilityNote = "Los puntos eliminados no se recuperan.",
        Reference = "https://support.microsoft.com/en-us/windows/system-protection-e9126e6e-fa64-4f5f-874d-9db90e57645a",
        Severity = MaintenanceSeverity.Informational,
    };

    private static MaintenanceItem PageFile(MaintenanceSnapshot s) => new()
    {
        Id = "MNT-PAGEFILE",
        Title = "Archivo de paginación",
        Description = "Extiende la memoria virtual. Windows lo administra automáticamente.",
        Relevance = "Solo informativo. No se recomienda desactivarlo para ganar espacio.",
        DetectedState = $"pagefile.sys: {B(s.PagefileBytes)}; swapfile.sys: {B(s.SwapfileBytes)}",
        RequiredPermissions = Admin + " para cambiarlo",
        Consequences = "Desactivarlo puede provocar cierres de aplicaciones e impedir que se generen volcados de memoria.",
        ReversibilityNote = "La configuración es reversible, con reinicio.",
        Reference = "https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/introduction-to-the-page-file",
        Severity = MaintenanceSeverity.Informational,
    };

    private static MaintenanceItem UpdateCache(MaintenanceSnapshot s) => new()
    {
        Id = "MNT-UPDATE-CACHE",
        Title = "Caché de Windows Update",
        Description = "Paquetes descargados por Windows Update.",
        Relevance = "Se puede limpiar desde la herramienta de archivos temporales, sin tocar la carpeta.",
        DetectedState = @"C:\Windows\SoftwareDistribution\Download: " + B(s.UpdateDownloadBytes),
        EstimatedRecoverableBytes = s.UpdateDownloadBytes,
        SettingsPath = SettingsStorage + " > Archivos temporales > Limpieza de Windows Update",
        RequiredPermissions = Standard + " o " + Admin.ToLowerInvariant() + ", según la categoría",
        Consequences = "Una actualización pendiente quizá necesite volver a descargarse.",
        ReversibilityNote = "Windows descarga de nuevo lo que necesite.",
        Reference = RefStorageSense,
        Severity = MaintenanceSeverity.Recommended,
    };

    private static MaintenanceItem WindowsOld(MaintenanceSnapshot s) => new()
    {
        Id = "MNT-WINDOWS-OLD",
        Title = "Instalación anterior de Windows",
        Description = "Windows.old permite volver a la versión anterior durante un tiempo limitado.",
        Relevance = "Suele ser de gran tamaño y Windows lo elimina por sí mismo pasado ese plazo.",
        DetectedState = @"C:\Windows.old: " + B(s.WindowsOldBytes),
        EstimatedRecoverableBytes = s.WindowsOldBytes,
        SettingsPath = SettingsStorage + " > Archivos temporales > Instalaciones anteriores de Windows",
        RequiredPermissions = Admin,
        Consequences = "No podrá volver a la versión anterior. Compruebe antes que no contenga archivos personales.",
        ReversibilityNote = "Irreversible.",
        Reference = RefStorageSense,
        Severity = MaintenanceSeverity.Recommended,
    };

    private static MaintenanceItem Dumps(MaintenanceSnapshot s, long total) => new()
    {
        Id = "MNT-DUMPS",
        Title = "Volcados de memoria",
        Description = "Archivos generados tras un fallo del sistema o de una aplicación.",
        Relevance = "Solo sirven para diagnosticar fallos.",
        DetectedState = $"MEMORY.DMP: {B(s.MemoryDumpBytes)}; Minidump: {B(s.MiniDumpBytes)}; CrashDumps del usuario: {B(s.UserCrashDumpBytes)}",
        EstimatedRecoverableBytes = total,
        SettingsPath = SettingsStorage + " > Archivos temporales > Archivos de volcado de memoria",
        RequiredPermissions = Admin + " para los del sistema",
        Consequences = "Se pierde información útil para investigar fallos recientes.",
        ReversibilityNote = "Irreversible.",
        Reference = RefStorageSense,
        Severity = MaintenanceSeverity.Recommended,
    };

    private static MaintenanceItem WindowsLogs(MaintenanceSnapshot s) => new()
    {
        Id = "MNT-LOGS",
        Title = "Registros de Windows",
        Description = @"C:\Windows\Logs ocupa más de lo habitual.",
        Relevance = "Puede indicar errores repetidos de un componente.",
        DetectedState = B(s.WindowsLogsBytes),
        SettingsPath = SettingsStorage + " > Archivos temporales",
        RequiredPermissions = Admin,
        Consequences = "No borre archivos en uso. Investigue primero qué componente los genera.",
        ReversibilityNote = "Irreversible.",
        Reference = RefStorageSense,
        Severity = MaintenanceSeverity.Informational,
    };

    private static MaintenanceItem WindowsInstaller(MaintenanceSnapshot s) => new()
    {
        Id = "MNT-INSTALLER",
        Title = @"C:\Windows\Installer: no tocar",
        Description = "Contiene datos necesarios para reparar, actualizar y desinstalar programas. Borrar su contenido puede dejar aplicaciones imposibles de actualizar o eliminar.",
        Relevance = "Se muestra para evitar una limpieza manual peligrosa.",
        DetectedState = "Tamaño enumerado: " + B(s.WindowsInstallerBytes),
        RequiredPermissions = "No aplica",
        Consequences = "Nunca borre manualmente su contenido.",
        ReversibilityNote = "Sin reinstalar el software afectado, no es reversible.",
        Reference = "https://learn.microsoft.com/en-us/windows/win32/msi/windows-installer-portal",
        Severity = MaintenanceSeverity.Informational,
    };

    private static MaintenanceItem Docker(MaintenanceSnapshot s)
    {
        var disks = string.Join("; ", s.DockerVirtualDisks.Select(d => $"{d.Path}: {PathUtil.FormatBytes(d.Bytes)}"));
        var (summary, reclaimable) = ParseDockerDf(s.DockerDfJson);
        var state = summary ?? (s.DockerError != null ? "No se pudo consultar: " + s.DockerError : "Motor no consultado (use «scan --deep» con Docker en ejecución).");
        return new MaintenanceItem
        {
            Id = "MNT-DOCKER",
            Title = "Docker Desktop",
            Description = "Las imágenes, contenedores, volúmenes y la caché de compilación se guardan en un disco virtual. No elimine ese archivo: destruiría todo su contenido.",
            Relevance = "«docker system df» indica qué parte se considera recuperable.",
            DetectedState = state + (disks.Length > 0 ? ". Discos: " + disks : ""),
            EstimatedRecoverableBytes = reclaimable,
            Command = "docker system df -v   (solo consulta)\ndocker builder prune   (caché de compilación)\ndocker image prune   (imágenes sin etiqueta)",
            RequiredPermissions = Standard,
            Consequences = "Las imágenes eliminadas se tendrán que volver a descargar o compilar. Los volúmenes no se ven afectados por estos comandos.",
            ReversibilityNote = "Regenerable si dispone de los Dockerfile o del registro de origen.",
            Reference = RefDockerDf + " · " + RefDockerPrune,
            Severity = MaintenanceSeverity.Informational,
        };
    }

    private static MaintenanceItem Wsl(MaintenanceSnapshot s)
    {
        var list = s.WslDistributions.Count == 0 ? "No se encontraron distribuciones registradas"
            : string.Join("; ", s.WslDistributions.Select(d => $"{d.Distribution}: {(d.Bytes is { } b ? PathUtil.FormatBytes(b) : "tamaño desconocido")}"));
        return new MaintenanceItem
        {
            Id = "MNT-WSL",
            Title = "Distribuciones WSL",
            Description = "Cada distribución vive en un disco virtual que crece con el uso y no siempre se reduce al borrar archivos dentro. Microsoft desaconseja modificar estos archivos con herramientas de Windows.",
            Relevance = "Borrar datos dentro de la distribución puede no devolver espacio a Windows sin un paso adicional.",
            DetectedState = list,
            Command = "wsl --export <distribución> <archivo.tar>   (respaldo)\nwsl --shutdown\nwsl --manage <distribución> --set-sparse true   (el espacio liberado vuelve a Windows)",
            RequiredPermissions = Standard,
            Consequences = "Eliminar el disco o ejecutar «wsl --unregister» destruye todos los datos de la distribución.",
            ReversibilityNote = "Modificar el disco puede no ser reversible: exporte primero.",
            Reference = RefWsl,
            Severity = MaintenanceSeverity.Informational,
        };
    }

    private static MaintenanceItem AdvancedResetBase() => new()
    {
        Id = "ADV-RESETBASE",
        Title = "DISM /ResetBase: no es una limpieza rutinaria",
        Description = "Elimina todas las versiones reemplazadas de los componentes.",
        Relevance = "Se documenta para que conozca su efecto. Esta herramienta no lo recomienda ni lo ejecuta.",
        DetectedState = "No aplica",
        Command = "Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase",
        RequiredPermissions = Admin,
        Consequences = "Las actualizaciones instaladas dejan de poder desinstalarse.",
        ReversibilityNote = "Irreversible.",
        Reference = RefWinSxsClean,
        Severity = MaintenanceSeverity.Advanced,
    };

    private static MaintenanceItem AdvancedDockerVolumes() => new()
    {
        Id = "ADV-DOCKER-VOLUMES",
        Title = "docker system prune --volumes: no es una limpieza rutinaria",
        Description = "Además de los recursos sin usar, elimina volúmenes anónimos que no use ningún contenedor.",
        Relevance = "Un volumen sin contenedor puede seguir conteniendo una base de datos. Esta herramienta no lo recomienda ni lo ejecuta.",
        DetectedState = "No aplica",
        Command = "docker system prune --volumes",
        RequiredPermissions = Standard,
        Consequences = "Puede eliminar datos persistentes de forma permanente.",
        ReversibilityNote = "Irreversible.",
        Reference = RefDockerPrune,
        Severity = MaintenanceSeverity.Advanced,
    };

    /// <summary>Interpreta «docker system df --format json»: una línea JSON por tipo de recurso.</summary>
    public static (string? Summary, long? ReclaimableBytes) ParseDockerDf(string? output)
    {
        if (string.IsNullOrWhiteSpace(output)) return (null, null);
        var parts = new List<string>();
        long total = 0;
        var known = false;
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            try
            {
                using var doc = JsonDocument.Parse(line);
                var root = doc.RootElement;
                if (root.ValueKind != JsonValueKind.Object) continue;
                var type = root.TryGetProperty("Type", out var t) ? t.GetString() : "?";
                var size = root.TryGetProperty("Size", out var z) ? z.GetString() : "?";
                var reclaim = root.TryGetProperty("Reclaimable", out var r) ? r.GetString() : "?";
                parts.Add($"{type}: {size} (recuperable: {reclaim})");

                // Los volúmenes se excluyen: pueden tener datos persistentes aunque Docker los considere recuperables.
                if (type is "Images" or "Containers" or "Build Cache" && TryParseDockerSize(reclaim, out var value))
                {
                    total += value;
                    known = true;
                }
            }
            catch (JsonException) { return (null, null); }
        }
        return parts.Count == 0 ? (null, null) : (string.Join("; ", parts), known ? total : null);
    }

    private static bool TryParseDockerSize(string? text, out long bytes)
    {
        bytes = 0;
        if (string.IsNullOrWhiteSpace(text)) return false;
        var token = text.Split(' ')[0].Trim();
        var i = 0;
        while (i < token.Length && (char.IsDigit(token[i]) || token[i] == '.')) i++;
        if (i == 0 || !double.TryParse(token[..i], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var v)) return false;
        double factor = token[i..].ToUpperInvariant() switch
        {
            "B" or "" => 1, "KB" or "KIB" => 1e3, "MB" or "MIB" => 1e6, "GB" or "GIB" => 1e9, "TB" or "TIB" => 1e12, _ => -1,
        };
        if (factor < 0) return false;
        bytes = (long)(v * factor);
        return true;
    }
}
