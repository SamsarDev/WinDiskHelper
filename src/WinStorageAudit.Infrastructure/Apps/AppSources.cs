using System.Globalization;
using System.Text.Json;
using Microsoft.Win32;
using WinStorageAudit.Core;
using WinStorageAudit.Core.Apps;
using WinStorageAudit.Core.Model;

namespace WinStorageAudit.Infrastructure.Apps;

/// <summary>Registro de desinstalación de HKLM y HKCU, vistas de 32 y 64 bits. Solo lectura.</summary>
public sealed class RegistryAppSource : IInstalledAppSource
{
    private const string UninstallKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

    public string Name => "Registro de desinstalación";

    public Task<IReadOnlyList<InstalledApp>> ReadAsync(CancellationToken ct)
    {
        var apps = new List<InstalledApp>();
        foreach (var (hive, hiveName) in new[] { (RegistryHive.LocalMachine, "HKLM"), (RegistryHive.CurrentUser, "HKCU") })
        {
            foreach (var (view, viewName) in new[] { (RegistryView.Registry64, "64 bits"), (RegistryView.Registry32, "32 bits") })
            {
                ct.ThrowIfCancellationRequested();
                using var root = RegistryKey.OpenBaseKey(hive, view);
                using var key = root.OpenSubKey(UninstallKey, false);
                if (key == null) continue;
                foreach (var subName in key.GetSubKeyNames())
                {
                    using var sub = key.OpenSubKey(subName, false);
                    if (sub == null) continue;
                    var app = Parse(n => sub.GetValue(n), $"{Name} ({hiveName}, {viewName})");
                    if (app != null) apps.Add(app);
                }
            }
        }
        return Task.FromResult<IReadOnlyList<InstalledApp>>(apps);
    }

    /// <summary>Se omiten componentes ocultos del sistema y parches que dependen de otro producto.</summary>
    public static InstalledApp? Parse(Func<string, object?> value, string source)
    {
        var name = (value("DisplayName") as string)?.Trim();
        if (string.IsNullOrEmpty(name)) return null;
        if (value("SystemComponent") is int and 1) return null;
        if (!string.IsNullOrEmpty(value("ParentKeyName") as string)) return null;

        var location = (value("InstallLocation") as string)?.Trim().Trim('"');
        return new InstalledApp
        {
            Name = name,
            Publisher = (value("Publisher") as string)?.Trim(),
            Version = (value("DisplayVersion") as string)?.Trim(),
            InstallLocation = string.IsNullOrEmpty(location) ? null : location,
            EstimatedSizeBytes = value("EstimatedSize") is int kb && kb > 0 ? kb * 1024L : null, // Por convención, kilobytes.
            InstallDate = ParseDate(value("InstallDate") as string),
            Source = source,
            IsSystemLike = UsageClassifier.LooksLikeSystemComponent(name),
        };
    }

    private static DateTime? ParseDate(string? text) =>
        DateTime.TryParseExact(text, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var d) ? d : null;
}

/// <summary>Paquetes MSIX/AppX del usuario. Usa Get-AppxPackage: nunca Win32_Product, que puede activar reparaciones.</summary>
public sealed class AppxAppSource(IProcessRunner runner) : IInstalledAppSource
{
    private const string Query = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; Get-AppxPackage | Where-Object { -not $_.IsFramework -and -not $_.IsResourcePackage -and $_.SignatureKind -ne 'System' } | Select-Object Name,Publisher,Version,InstallLocation,PackageFamilyName | ConvertTo-Json -Compress";

    public string Name => "Aplicaciones empaquetadas (MSIX/AppX)";

    public async Task<IReadOnlyList<InstalledApp>> ReadAsync(CancellationToken ct)
    {
        var shell = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell", "v1.0", "powershell.exe");
        var result = await runner.RunAsync(shell, ["-NoProfile", "-NonInteractive", "-Command", Query], null, TimeSpan.FromSeconds(60), null, ct);
        if (result.StartFailed || result.ExitCode != 0)
            throw new InvalidOperationException(result.TimedOut ? "Tiempo límite excedido" : "No se pudo consultar Get-AppxPackage");
        return Parse(result.StandardOutput);
    }

    public static IReadOnlyList<InstalledApp> Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return [];
        using var doc = JsonDocument.Parse(json);
        var elements = doc.RootElement.ValueKind == JsonValueKind.Array ? doc.RootElement.EnumerateArray().ToList() : [doc.RootElement];
        var apps = new List<InstalledApp>();
        foreach (var e in elements)
        {
            var name = Str(e, "Name");
            if (string.IsNullOrEmpty(name)) continue;
            apps.Add(new InstalledApp
            {
                Name = name,
                Publisher = Str(e, "Publisher"),
                Version = Str(e, "Version"),
                InstallLocation = Str(e, "InstallLocation"),
                PackageFamilyName = Str(e, "PackageFamilyName"),
                Source = "MSIX/AppX",
                IsSystemLike = UsageClassifier.LooksLikeSystemComponent(name),
            });
        }
        return apps;
    }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}

/// <summary>
/// UserAssist: registra lanzamientos desde la interfaz gráfica del Shell, con última fecha y recuento.
/// No registra ejecuciones por consola, servicios ni tareas programadas, y el formato no está documentado
/// oficialmente, por lo que un valor que no cumpla la estructura esperada se descarta.
/// </summary>
public sealed class UserAssistSource : IUsageEvidenceSource
{
    private const string Root = @"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";

    private static readonly Dictionary<string, Environment.SpecialFolder> KnownFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        ["{6D809377-6AF0-444B-8957-A3773F02200E}"] = Environment.SpecialFolder.ProgramFiles,
        ["{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}"] = Environment.SpecialFolder.ProgramFilesX86,
        ["{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}"] = Environment.SpecialFolder.System,
        ["{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}"] = Environment.SpecialFolder.SystemX86,
        ["{F38BF404-1D43-42F2-9305-67DE0B28FC23}"] = Environment.SpecialFolder.Windows,
        ["{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}"] = Environment.SpecialFolder.CommonPrograms,
        ["{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}"] = Environment.SpecialFolder.Programs,
        ["{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"] = Environment.SpecialFolder.DesktopDirectory,
    };

    public string Name => "UserAssist";

    public Task<UsageSourceData> ReadAsync(CancellationToken ct)
    {
        var records = new List<RawUsageRecord>();
        using var root = Registry.CurrentUser.OpenSubKey(Root, false);
        if (root == null)
            return Task.FromResult(new UsageSourceData(new UsageSourceStatus(Name, false, 0, "Clave no encontrada"), []));

        foreach (var guid in root.GetSubKeyNames())
        {
            using var count = root.OpenSubKey(guid + @"\Count", false);
            if (count == null) continue;
            foreach (var valueName in count.GetValueNames())
            {
                if (count.GetValue(valueName) is byte[] data && TryParse(valueName, data) is { } record) records.Add(record);
            }
        }
        return Task.FromResult(new UsageSourceData(new UsageSourceStatus(Name, true, records.Count, "Solo lanzamientos desde la interfaz gráfica; sin historial, solo la última ejecución"), records));
    }

    public static RawUsageRecord? TryParse(string rot13Name, byte[] data)
    {
        if (data.Length != 72) return null;
        var path = ResolveKnownFolder(Rot13(rot13Name));
        if (path.StartsWith("UEME_", StringComparison.OrdinalIgnoreCase)) return null;
        var fileTime = BitConverter.ToInt64(data, 60);
        DateTime? lastRun = null;
        if (fileTime > 0)
        {
            try { lastRun = DateTime.FromFileTimeUtc(fileTime); }
            catch (ArgumentOutOfRangeException) { return null; }
        }
        return new RawUsageRecord("UserAssist", path, lastRun, BitConverter.ToInt32(data, 4));
    }

    public static string Rot13(string input) => string.Create(input.Length, input, static (span, source) =>
    {
        for (var i = 0; i < source.Length; i++)
        {
            var c = source[i];
            span[i] = c switch
            {
                >= 'a' and <= 'z' => (char)('a' + (c - 'a' + 13) % 26),
                >= 'A' and <= 'Z' => (char)('A' + (c - 'A' + 13) % 26),
                _ => c,
            };
        }
    });

    private static string ResolveKnownFolder(string path)
    {
        if (path.Length < 38 || path[0] != '{' || path[37] != '}') return path;
        if (!KnownFolders.TryGetValue(path[..38], out var folder)) return path;
        return Environment.GetFolderPath(folder) + path[38..];
    }
}

/// <summary>Prefetch: nombre de ejecutable y fecha del archivo. Requiere administrador; solo se leen metadatos.</summary>
public sealed class PrefetchSource(string? directory = null) : IUsageEvidenceSource
{
    public string Name => "Prefetch";

    public Task<UsageSourceData> ReadAsync(CancellationToken ct)
    {
        var folder = directory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
        try
        {
            var records = new List<RawUsageRecord>();
            foreach (var file in new DirectoryInfo(folder).EnumerateFiles("*.pf"))
            {
                var dash = file.Name.LastIndexOf('-');
                if (dash <= 0) continue;
                records.Add(new RawUsageRecord(Name, file.Name[..dash], file.LastWriteTimeUtc, null));
            }
            return Task.FromResult(new UsageSourceData(new UsageSourceStatus(Name, true, records.Count, "Fecha del archivo .pf; depende de que Prefetch esté habilitado"), records));
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            var reason = ex is UnauthorizedAccessException ? "Acceso denegado: requiere administrador" : "No disponible";
            return Task.FromResult(new UsageSourceData(new UsageSourceStatus(Name, false, 0, reason), []));
        }
    }
}

/// <summary>Enumera ejecutables de la instalación, con profundidad acotada, solo si alguna fuente registra solo nombres.</summary>
public static class AppExecutableEnricher
{
    public static void Enrich(IEnumerable<InstalledApp> apps)
    {
        var options = new EnumerationOptions { IgnoreInaccessible = true, RecurseSubdirectories = true, MaxRecursionDepth = 2, AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.Offline };
        foreach (var app in apps.Where(a => a.InstallLocation is { Length: > 3 } && !a.IsSystemLike))
        {
            try
            {
                if (Directory.Exists(app.InstallLocation))
                    app.ExecutableNames = [.. Directory.EnumerateFiles(app.InstallLocation!, "*.exe", options).Take(100).Select(Path.GetFileName)!];
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }
}

/// <summary>Rutas referenciadas por PATH, servicios y arranque: una carpeta referenciada nunca se considera residual.</summary>
public static class SystemReferenceProvider
{
    public static IReadOnlyList<string> Read()
    {
        var refs = new List<string>();
        refs.AddRange((Environment.GetEnvironmentVariable("PATH") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries));
        try
        {
            using var services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", false);
            if (services != null)
            {
                foreach (var name in services.GetSubKeyNames())
                {
                    using var svc = services.OpenSubKey(name, false);
                    if (svc?.GetValue("ImagePath", null, RegistryValueOptions.None) is string image) refs.Add(image);
                }
            }
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException) { }

        foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
        {
            using var run = hive.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", false);
            if (run == null) continue;
            refs.AddRange(run.GetValueNames().Select(n => run.GetValue(n) as string).Where(v => v != null)!);
        }
        return refs;
    }
}
