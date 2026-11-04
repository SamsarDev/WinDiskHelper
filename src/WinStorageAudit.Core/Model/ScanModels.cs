namespace WinStorageAudit.Core.Model;

public sealed record ScanRequest
{
    public required IReadOnlyList<string> Roots { get; init; }
    public ScanMode Mode { get; init; } = ScanMode.Quick;
    public IReadOnlyList<string> Exclusions { get; init; } = [];
    public int MaxConcurrency { get; init; } = 4;

    /// <summary>En modo rápido, solo se abren archivos de al menos este tamaño para contar sus enlaces duros.</summary>
    public long HardLinkCheckMinBytes { get; init; } = 1024 * 1024;

    public int MaxDepth { get; init; } = 512;
    public bool AllowNetworkRoots { get; init; }
}

/// <summary>Entrada de archivo obtenida exclusivamente de metadatos; nunca se lee su contenido.</summary>
public sealed record FileEntry
{
    public required string Name { get; init; }
    public long LogicalBytes { get; init; }

    /// <summary>Espacio físico atribuido. Cero para las rutas repetidas de un mismo archivo con enlaces duros.</summary>
    public long PhysicalBytes { get; init; }

    public FileAttributes Attributes { get; init; }
    public DateTime CreationUtc { get; init; }
    public DateTime LastWriteUtc { get; init; }

    /// <summary>Número de enlaces duros; 0 si no se consultó.</summary>
    public int LinkCount { get; init; }

    public bool IsOnlineOnly { get; init; }
    public bool IsLink { get; init; }
    public bool IsSparseOrCompressed { get; init; }

    /// <summary>Se contó en otra ruta como el mismo archivo físico.</summary>
    public bool IsRepeatedHardLink { get; init; }
}

public sealed record DirectorySnapshot
{
    public required string FullPath { get; init; }
    public required string Name { get; init; }
    public required IReadOnlyList<FileEntry> Files { get; init; }
    public required IReadOnlyList<string> Subdirectories { get; init; }
    public DateTime LastWriteUtc { get; init; }

    public bool HasFile(string name) => Files.Any(f => f.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
    public bool HasSubdirectory(string name) => Subdirectories.Any(d => d.Equals(name, StringComparison.OrdinalIgnoreCase));
}

public sealed class DirectoryTotals
{
    public long LogicalBytes { get; set; }
    public long PhysicalBytes { get; set; }

    /// <summary>Físico de archivos con más de un enlace duro: borrar esta ruta quizá no libere ese espacio.</summary>
    public long HardLinkedPhysicalBytes { get; set; }

    public long OnlineOnlyLogicalBytes { get; set; }
    public long FileCount { get; set; }
    public long DirectoryCount { get; set; }
    public long ExecutableCount { get; set; }
    public DateTime NewestWriteUtc { get; set; }
    public int InaccessibleDirectories { get; set; }

    public void Add(DirectoryTotals o)
    {
        LogicalBytes += o.LogicalBytes;
        PhysicalBytes += o.PhysicalBytes;
        HardLinkedPhysicalBytes += o.HardLinkedPhysicalBytes;
        OnlineOnlyLogicalBytes += o.OnlineOnlyLogicalBytes;
        FileCount += o.FileCount;
        DirectoryCount += o.DirectoryCount + 1;
        ExecutableCount += o.ExecutableCount;
        InaccessibleDirectories += o.InaccessibleDirectories;
        if (o.NewestWriteUtc > NewestWriteUtc) NewestWriteUtc = o.NewestWriteUtc;
    }

    /// <summary>Estimación prudente: excluye lo compartido por enlaces duros.</summary>
    public long ReclaimablePhysicalBytes => Math.Max(0, PhysicalBytes - HardLinkedPhysicalBytes);
}

public sealed record ScanIssue(ScanIssueKind Kind, string Path, string Detail);

/// <summary>Registro acotado de limitaciones; los contadores siguen creciendo aunque se agote la muestra.</summary>
public sealed class CoverageTracker
{
    private readonly Lock _lock = new();
    private readonly List<ScanIssue> _samples = [];
    private readonly Dictionary<ScanIssueKind, long> _counts = [];
    private readonly int _maxSamples;

    public CoverageTracker(int maxSamples = 500) => _maxSamples = maxSamples;

    public void Report(ScanIssueKind kind, string path, string detail = "")
    {
        lock (_lock)
        {
            _counts[kind] = _counts.GetValueOrDefault(kind) + 1;
            if (_samples.Count < _maxSamples) _samples.Add(new ScanIssue(kind, path, detail));
        }
    }

    public CoverageReport ToReport(IEnumerable<string> notes, bool cancelled)
    {
        lock (_lock)
        {
            return new CoverageReport
            {
                WasCancelled = cancelled,
                IssueCounts = new Dictionary<ScanIssueKind, long>(_counts),
                IssueSamples = [.. _samples],
                Notes = [.. notes],
            };
        }
    }
}

public sealed record CoverageReport
{
    public bool WasCancelled { get; init; }
    public IReadOnlyDictionary<ScanIssueKind, long> IssueCounts { get; init; } = new Dictionary<ScanIssueKind, long>();
    public IReadOnlyList<ScanIssue> IssueSamples { get; init; } = [];
    public IReadOnlyList<string> Notes { get; init; } = [];
}

/// <summary>Contadores observables mientras el análisis está en curso.</summary>
public sealed class ScanProgress
{
    private long _files, _directories, _physicalBytes, _errors;
    private volatile string _stage = "Preparando";
    private volatile string _currentPath = "";

    public long Files => Interlocked.Read(ref _files);
    public long Directories => Interlocked.Read(ref _directories);
    public long PhysicalBytes => Interlocked.Read(ref _physicalBytes);
    public long Errors => Interlocked.Read(ref _errors);
    public string Stage { get => _stage; set => _stage = value; }
    public string CurrentPath { get => _currentPath; set => _currentPath = value; }

    public void AddDirectory(long files, long physicalBytes, string path)
    {
        Interlocked.Increment(ref _directories);
        Interlocked.Add(ref _files, files);
        Interlocked.Add(ref _physicalBytes, physicalBytes);
        _currentPath = path;
    }

    public void AddError() => Interlocked.Increment(ref _errors);
}

public sealed record VolumeSummary
{
    public required string Root { get; init; }
    public string? Label { get; init; }
    public string? FileSystem { get; init; }
    public string? DriveType { get; init; }
    public long TotalBytes { get; init; }
    public long FreeBytes { get; init; }
    public long UsedBytes => TotalBytes - FreeBytes;
    public long ClusterBytes { get; init; }
}

public sealed record KnownLocations
{
    public required string UserProfile { get; init; }
    public required string Downloads { get; init; }
    public required string Temp { get; init; }
    public required string LocalAppData { get; init; }
    public required string RoamingAppData { get; init; }
    public required string ProgramData { get; init; }
    public required string ProgramFiles { get; init; }
    public required string ProgramFilesX86 { get; init; }
    public required string WindowsDirectory { get; init; }
    public IReadOnlyList<string> CloudSyncRoots { get; init; } = [];

    /// <summary>Crea ubicaciones confinadas dentro de un directorio: para pruebas y demostraciones.</summary>
    public static KnownLocations UnderRoot(string root) => new()
    {
        UserProfile = Path.Combine(root, "Users", "demo"),
        Downloads = Path.Combine(root, "Users", "demo", "Downloads"),
        Temp = Path.Combine(root, "Users", "demo", "AppData", "Local", "Temp"),
        LocalAppData = Path.Combine(root, "Users", "demo", "AppData", "Local"),
        RoamingAppData = Path.Combine(root, "Users", "demo", "AppData", "Roaming"),
        ProgramData = Path.Combine(root, "ProgramData"),
        ProgramFiles = Path.Combine(root, "Program Files"),
        ProgramFilesX86 = Path.Combine(root, "Program Files (x86)"),
        WindowsDirectory = Path.Combine(root, "Windows"),
    };
}
