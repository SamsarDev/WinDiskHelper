using WinStorageAudit.Core.Model;
using WinStorageAudit.Core.Scanning;

namespace WinStorageAudit.Core;

/// <summary>Recorre el sistema de archivos sin leer contenido y sin modificar nada.</summary>
public interface IFileScanner
{
    Task ScanAsync(ScanRequest request, IScanObserver observer, ScanProgress progress, CoverageTracker coverage, CancellationToken ct);
}

/// <summary>Recibe un lote por directorio. Las llamadas pueden ser concurrentes.</summary>
public interface IScanObserver
{
    DirectoryContext EnterDirectory(DirectorySnapshot snapshot, DirectoryContext? parent);
    void ExitDirectory(DirectorySnapshot snapshot, DirectoryContext context, DirectoryTotals totals);
}

public sealed record ProcessResult(int ExitCode, string StandardOutput, string StandardError, bool TimedOut, bool StartFailed);

/// <summary>Ejecuta herramientas con argumentos estructurados, nunca a través de un shell.</summary>
public interface IProcessRunner
{
    Task<ProcessResult> RunAsync(string executable, IReadOnlyList<string> arguments, string? workingDirectory,
        TimeSpan timeout, IReadOnlyDictionary<string, string>? environment, CancellationToken ct);
}

public interface IInstalledAppSource
{
    string Name { get; }
    Task<IReadOnlyList<InstalledApp>> ReadAsync(CancellationToken ct);
}

public sealed record RawUsageRecord(string Source, string ExecutablePathOrId, DateTime? LastRunUtc, int? RunCount);

public sealed record UsageSourceData(UsageSourceStatus Status, IReadOnlyList<RawUsageRecord> Records);

public interface IUsageEvidenceSource
{
    string Name { get; }
    Task<UsageSourceData> ReadAsync(CancellationToken ct);
}

/// <summary>Identidad física de un archivo sin leer su contenido (volumen + índice).</summary>
public interface IFileIdentityProvider
{
    (ulong Volume, ulong FileId, int Links)? TryGetIdentity(string path);
}

/// <summary>Estado detectado del sistema, obtenido sin alterar nada.</summary>
public sealed record MaintenanceSnapshot
{
    public string SystemDrive { get; init; } = "C:\\";
    public bool IsElevated { get; init; }
    public bool? StorageSenseEnabled { get; init; }
    public bool StorageSenseManagedByPolicy { get; init; }
    public long? RecycleBinBytes { get; init; }
    public long? RecycleBinItems { get; init; }
    public long? HiberfilBytes { get; init; }
    public string? SleepStatesOutput { get; init; }
    public long? PagefileBytes { get; init; }
    public long? SwapfileBytes { get; init; }
    public long? WinSxsApparentBytes { get; init; }
    public long? WindowsInstallerBytes { get; init; }
    public long? UpdateDownloadBytes { get; init; }
    public long? WindowsOldBytes { get; init; }
    public long? MemoryDumpBytes { get; init; }
    public long? MiniDumpBytes { get; init; }
    public long? UserCrashDumpBytes { get; init; }
    public long? WindowsLogsBytes { get; init; }
    public bool DockerInstalled { get; init; }
    public string? DockerDfJson { get; init; }
    public string? DockerError { get; init; }
    public IReadOnlyList<(string Path, long Bytes)> DockerVirtualDisks { get; init; } = [];
    public bool WslInstalled { get; init; }
    public IReadOnlyList<(string Distribution, string VhdPath, long? Bytes)> WslDistributions { get; init; } = [];
}

public interface IMaintenanceProbe
{
    Task<MaintenanceSnapshot> ProbeAsync(bool includeExpensive, CancellationToken ct);
}
