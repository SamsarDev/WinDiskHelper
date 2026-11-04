namespace WinStorageAudit.Core.Model;

public sealed record StorageItem
{
    public required string Path { get; init; }
    public long LogicalBytes { get; init; }
    public long PhysicalBytes { get; init; }
    public double PercentOfAnalyzed { get; init; }
    public required string ContentType { get; init; }
    public StorageCategory Category { get; init; }
    public RiskLevel Risk { get; init; }
    public IReadOnlyList<string> Evidence { get; init; } = [];

    /// <summary>Espacio recuperable según hallazgos dentro de esta ruta. Null si no hay ninguno.</summary>
    public long? ReclaimableBytes { get; set; }

    public DateTime LastWriteUtc { get; init; }
}

public sealed record BreakdownEntry(string Key, long LogicalBytes, long PhysicalBytes, long FileCount);

public sealed class TreeNode
{
    public required string Name { get; init; }
    public required string FullPath { get; init; }
    public long LogicalBytes { get; init; }
    public long PhysicalBytes { get; init; }
    public long FileCount { get; init; }
    public StorageCategory Category { get; init; }
    public List<TreeNode> Children { get; init; } = [];
}

public sealed record StorageSummary
{
    public long LogicalBytes { get; init; }
    public long PhysicalBytes { get; init; }
    public long OnlineOnlyLogicalBytes { get; init; }
    public long FileCount { get; init; }
    public long DirectoryCount { get; init; }
    public long RepeatedHardLinkLogicalBytes { get; init; }
    public IReadOnlyList<StorageItem> TopFolders { get; init; } = [];
    public IReadOnlyList<StorageItem> TopFiles { get; init; } = [];
    public IReadOnlyList<StorageItem> Concentrations { get; init; } = [];
    public IReadOnlyList<BreakdownEntry> ByCategory { get; init; } = [];
    public IReadOnlyList<BreakdownEntry> ByExtension { get; init; } = [];
    public IReadOnlyList<TreeNode> Tree { get; init; } = [];
}

public sealed record GitRemoteInfo(string Name, string SanitizedUrl);

public sealed record GitBranchInfo
{
    public required string Name { get; init; }
    public string? Upstream { get; init; }
    public bool UpstreamGone { get; init; }
    public int? Ahead { get; init; }
    public int? Behind { get; init; }

    /// <summary>Commits no alcanzables desde ninguna referencia remota local.</summary>
    public int? CommitsNotOnAnyRemoteRef { get; init; }
}

public sealed record GitRepositoryStatus
{
    public required string Path { get; init; }
    public bool IsWorktree { get; init; }
    public bool IsBare { get; init; }
    public bool IsSubmodule { get; init; }
    public bool IsNestedInRepository { get; init; }
    public long SizeBytes { get; init; }
    public long GitDirBytes { get; init; }
    public string? CurrentBranch { get; init; }
    public bool IsDetached { get; init; }
    public string? Upstream { get; init; }
    public IReadOnlyList<GitRemoteInfo> Remotes { get; init; } = [];
    public IReadOnlyList<GitBranchInfo> Branches { get; init; } = [];
    public int StagedChanges { get; init; }
    public int UnstagedChanges { get; init; }
    public int UntrackedFiles { get; init; }
    public int ConflictedFiles { get; init; }
    public int Ahead { get; init; }
    public int Behind { get; init; }
    public int StashCount { get; init; }
    public int Submodules { get; init; }
    public IReadOnlyList<string> SensitiveIgnored { get; init; } = [];
    public IReadOnlyList<string> States { get; init; } = [];
    public string? Error { get; init; }
    public bool HasUncommittedWork => StagedChanges + UnstagedChanges + ConflictedFiles > 0;
    public int UnpublishedCommitsTotal => Branches.Sum(b => b.CommitsNotOnAnyRemoteRef ?? 0);
}

public sealed record PersonalFileGroup
{
    public required PersonalKind Kind { get; init; }
    public long Bytes { get; init; }
    public long FileCount { get; init; }
    public long OnlineOnlyCount { get; init; }
    public IReadOnlyList<string> TopFolders { get; init; } = [];
    public IReadOnlyList<PersonalFileRecord> Largest { get; init; } = [];
}

public sealed record PersonalFileRecord
{
    public required string Path { get; init; }
    public required PersonalKind Kind { get; init; }
    public long Bytes { get; init; }
    public DateTime LastWriteUtc { get; init; }
    public bool IsOnlineOnly { get; init; }
    public BackupState BackupState { get; set; } = BackupState.NotEvaluated;
    public string? BackupDetail { get; set; }
}

public sealed record BackupPriority(int Rank, string Target, string Reason, long SizeBytes);

public sealed record BackupReport
{
    public IReadOnlyList<PersonalFileGroup> PersonalGroups { get; init; } = [];
    public IReadOnlyDictionary<BackupState, long> StateCounts { get; init; } = new Dictionary<BackupState, long>();
    public IReadOnlyList<string> Destinations { get; init; } = [];
    public IReadOnlyList<BackupPriority> Priorities { get; init; } = [];
    public IReadOnlyList<PersonalFileRecord> Unprotected { get; init; } = [];
    public bool HashesVerified { get; init; }
}

public sealed record DuplicateGroup
{
    public required long FileSizeBytes { get; init; }
    public required IReadOnlyList<string> Paths { get; init; }
    public long RedundantBytes => FileSizeBytes * Math.Max(0, Paths.Count - 1);
    public bool ContainsSensitiveContent { get; init; }
}

public sealed record DuplicateReport
{
    public bool Evaluated { get; init; }
    public long FilesConsidered { get; init; }
    public long FilesHashed { get; init; }
    public long BytesRead { get; init; }
    public long SkippedOnlineOnly { get; init; }
    public long SkippedLocked { get; init; }
    public long HardLinkGroupsIgnored { get; init; }
    public IReadOnlyList<DuplicateGroup> Groups { get; init; } = [];
}

public sealed record UsageEvidence(string Source, DateTime? LastRunUtc, string Detail);

public sealed record InstalledApp
{
    public required string Name { get; init; }
    public string? Publisher { get; init; }
    public string? Version { get; init; }
    public string? InstallLocation { get; init; }
    public long? EstimatedSizeBytes { get; init; }
    public DateTime? InstallDate { get; init; }
    public required string Source { get; init; }
    public string? PackageFamilyName { get; init; }
    public bool IsSystemLike { get; init; }

    /// <summary>Ejecutables hallados en la instalación; permite cruzar fuentes que solo registran el nombre.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public IReadOnlyList<string> ExecutableNames { get; set; } = [];

    public UsageClass Usage { get; set; } = UsageClass.Unknown;
    public Confidence UsageConfidence { get; set; } = Confidence.Unknown;
    public DateTime? LastRunUtc { get; set; }
    public IReadOnlyList<UsageEvidence> Evidence { get; set; } = [];
    public string? Suggestion { get; set; }
}

public sealed record UsageSourceStatus(string Name, bool Available, int Records, string Detail);

public sealed record AppReport
{
    public bool Evaluated { get; init; }
    public IReadOnlyList<InstalledApp> Apps { get; init; } = [];
    public IReadOnlyList<UsageSourceStatus> Sources { get; init; } = [];
    public IReadOnlyList<string> SourceErrors { get; init; } = [];
}

public sealed record MaintenanceItem
{
    public required string Id { get; init; }
    public required string Title { get; init; }
    public required string Description { get; init; }
    public required string Relevance { get; init; }
    public required string DetectedState { get; init; }
    public long? EstimatedRecoverableBytes { get; init; }
    public string? Command { get; init; }
    public string? SettingsPath { get; init; }
    public required string RequiredPermissions { get; init; }
    public required string Consequences { get; init; }
    public required string ReversibilityNote { get; init; }
    public required string Reference { get; init; }
    public MaintenanceSeverity Severity { get; init; }
}

public sealed record AuditResult
{
    public string SchemaVersion { get; init; } = "1";
    public string ToolVersion { get; init; } = "0.1.0";
    public DateTime StartedUtc { get; init; }
    public DateTime FinishedUtc { get; init; }
    public ScanMode Mode { get; init; }
    public IReadOnlyList<string> Roots { get; init; } = [];
    public IReadOnlyList<string> Exclusions { get; init; } = [];
    public IReadOnlyList<VolumeSummary> Volumes { get; init; } = [];
    public required StorageSummary Storage { get; init; }
    public IReadOnlyList<Finding> Findings { get; init; } = [];
    public required ReclaimSummary Reclaim { get; init; }
    public IReadOnlyList<GitRepositoryStatus> GitRepositories { get; init; } = [];
    public bool GitAvailable { get; init; }
    public BackupReport Backup { get; init; } = new();
    public DuplicateReport Duplicates { get; init; } = new();
    public AppReport Apps { get; init; } = new();
    public IReadOnlyList<MaintenanceItem> Maintenance { get; init; } = [];
    public required CoverageReport Coverage { get; init; }
}
