using WinStorageAudit.Core.Apps;
using WinStorageAudit.Core.Model;
using WinStorageAudit.Core.Scanning;

namespace WinStorageAudit.Core.Cleanup;

/// <summary>Umbrales configurables de las reglas. Ver docs/detection-rules.md.</summary>
public sealed record AuditThresholds
{
    public int OldDownloadDays { get; init; } = 90;
    public int StaleFileDays { get; init; } = 180;
    public int TempAgeDays { get; init; } = 30;
    public int LogAgeDays { get; init; } = 60;
    public int ResidueAgeDays { get; init; } = 180;
    public int ActiveEnvironmentDays { get; init; } = 14;
    public long LargeFileBytes { get; init; } = 1024L * 1024 * 1024;
    public long LargeDownloadBytes { get; init; } = 500L * 1024 * 1024;
    public long MinFindingBytes { get; init; } = 10L * 1024 * 1024;
    public long ResidueMinBytes { get; init; } = 50L * 1024 * 1024;
    public long NamedTempMinBytes { get; init; } = 100L * 1024 * 1024;
    public long DuplicateMinBytes { get; init; } = 1024 * 1024;
    public int UsageRecentDays { get; init; } = 30;
    public int UsageMediumDays { get; init; } = 60;
    public int UsageLongDays { get; init; } = 90;
    public int MaxFindingsPerRule { get; init; } = 500;
}

public sealed record RuleContext
{
    public required ScanCollector Scan { get; init; }
    public required StorageSummary Storage { get; init; }
    public required KnownLocations Locations { get; init; }
    public required AuditThresholds Thresholds { get; init; }
    public required DateTime NowUtc { get; init; }
    public DuplicateReport Duplicates { get; init; } = new();
    public IReadOnlyList<GitRepositoryStatus> Repositories { get; init; } = [];
    public bool GitAvailable { get; init; }
    public AppReport? Apps { get; init; }
    public IReadOnlyList<string> SystemReferences { get; init; } = [];
    public BackupReport? Backup { get; init; }

    public double AgeDays(DateTime utc) => utc == default ? double.PositiveInfinity : (NowUtc - utc).TotalDays;
}

public interface IRule
{
    string Id { get; }
    IEnumerable<Finding> Evaluate(RuleContext context);
}

public sealed record EngineResult(IReadOnlyList<Finding> Findings, ReclaimSummary Reclaim, IReadOnlyList<string> Notes);

/// <summary>
/// Ejecuta las reglas y aplica barreras finales independientes de cada regla: una regla defectuosa
/// no puede convertir una ruta protegida en candidata ni asignar confianza alta sin evidencia.
/// </summary>
public sealed class RecommendationEngine(IEnumerable<IRule> rules)
{
    public static IReadOnlyList<IRule> DefaultRules() =>
    [
        new DevArtifactRule(), new DevCacheRule(), new UserTempRule(), new NamedTempRule(), new OldLogRule(),
        new DownloadsRule(), new LargeStaleFileRule(), new VirtualDiskRule(), new DatabaseRule(),
        new AppResidueRule(), new DuplicateRule(), new GitBackupRule(), new PersonalBackupRule(), new UnusedAppRule(),
    ];

    public EngineResult Run(RuleContext context)
    {
        var protectedPaths = new ProtectedPaths(context.Locations);
        var notes = new List<string>();
        var findings = new List<Finding>();

        foreach (var rule in rules)
        {
            try
            {
                findings.AddRange(rule.Evaluate(context).Take(context.Thresholds.MaxFindingsPerRule).Select(f => Enforce(f, protectedPaths)));
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                notes.Add($"La regla {rule.Id} falló y sus hallazgos se omitieron: {ex.Message}");
            }
        }

        var counted = ReclaimCalculator.Apply(findings);
        var summary = new ReclaimSummary
        {
            OccupiedPhysicalBytes = context.Storage.PhysicalBytes,
            CandidateReclaimableBytes = counted.Where(f => f.Recommendation == RecommendationClass.CleanupCandidate).Sum(f => f.CountedReclaimableBytes),
            ReviewReclaimableBytes = counted.Where(f => f.Recommendation == RecommendationClass.ManualReview).Sum(f => f.CountedReclaimableBytes),
        };
        var ordered = counted
            .OrderBy(f => f.Recommendation == RecommendationClass.BackupPriority ? 0 : 1)
            .ThenByDescending(f => f.EstimatedReclaimableBytes)
            .ThenByDescending(f => f.DetectedSizeBytes)
            .ToList();
        return new EngineResult(ordered, summary, notes);
    }

    /// <summary>Barreras de seguridad finales. Se prueban en RecommendationEngineTests.</summary>
    public static Finding Enforce(Finding f, ProtectedPaths protectedPaths)
    {
        var result = f with { EstimatedReclaimableBytes = Math.Clamp(f.EstimatedReclaimableBytes, 0, Math.Max(f.DetectedSizeBytes, f.EstimatedReclaimableBytes)) };

        if (result.Confidence == Confidence.High && result.Evidence.Count < 2)
            result = result with { Confidence = Confidence.Medium };

        if (result.Recommendation == RecommendationClass.CleanupCandidate)
        {
            if (result.ResourceKind is ResourceKind.IrreplaceableUserData or ResourceKind.PersistentAppData or ResourceKind.ActiveEnvironment)
                result = result with { Recommendation = RecommendationClass.ManualReview };

            if (!result.IsAggregate && protectedPaths.IsProtected(result.PathOrResource))
            {
                result = result with
                {
                    Recommendation = RecommendationClass.Keep,
                    RiskLevel = RiskLevel.Critical,
                    EstimatedReclaimableBytes = 0,
                    Evidence = [.. result.Evidence, "Ruta protegida: no puede proponerse su eliminación."],
                };
            }
        }

        if (result.Recommendation == RecommendationClass.Keep) result = result with { EstimatedReclaimableBytes = 0 };
        return result;
    }
}

/// <summary>
/// Evita sumar varias veces el mismo espacio. Procesa candidatos antes que revisiones, y rutas
/// superiores antes que inferiores: lo contenido en una ruta ya contada suma cero.
/// </summary>
public static class ReclaimCalculator
{
    public static List<Finding> Apply(IReadOnlyList<Finding> findings)
    {
        var results = new Finding[findings.Count];
        var counted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var descendantBytes = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);

        var order = findings
            .Select((f, i) => (Finding: f, Index: i))
            .Where(x => x.Finding.Recommendation is RecommendationClass.CleanupCandidate or RecommendationClass.ManualReview)
            .OrderBy(x => x.Finding.Category == FindingArea.Duplicates ? 1 : 0)
            .ThenBy(x => x.Finding.Recommendation == RecommendationClass.CleanupCandidate ? 0 : 1)
            .ThenBy(x => x.Finding.PathOrResource.Length)
            .ToList();

        foreach (var (finding, index) in order)
        {
            long value;
            if (finding.Category == FindingArea.Duplicates && finding.RelatedPaths.Count > 1)
            {
                // Una copia dentro de una carpeta ya contada no suma; siempre debe conservarse una copia en total.
                var outside = finding.RelatedPaths.Count(p => !IsCovered(p, counted));
                var size = finding.EstimatedReclaimableBytes / Math.Max(1, finding.RelatedPaths.Count - 1);
                value = size * Math.Max(0, outside - 1);
            }
            else if (finding.IsAggregate)
            {
                value = finding.EstimatedReclaimableBytes;
            }
            else if (IsCovered(finding.PathOrResource, counted))
            {
                value = 0;
            }
            else
            {
                value = Math.Max(0, finding.EstimatedReclaimableBytes - descendantBytes.GetValueOrDefault(finding.PathOrResource));
                counted.Add(finding.PathOrResource);
                foreach (var ancestor in PathUtil.Ancestors(finding.PathOrResource))
                    descendantBytes[ancestor] = descendantBytes.GetValueOrDefault(ancestor) + value;
            }
            results[index] = finding with { CountedReclaimableBytes = value };
        }

        for (var i = 0; i < findings.Count; i++)
            results[i] ??= findings[i] with { CountedReclaimableBytes = 0 };
        return [.. results];
    }

    private static bool IsCovered(string path, HashSet<string> counted)
    {
        if (counted.Contains(path)) return true;
        foreach (var ancestor in PathUtil.Ancestors(path))
            if (counted.Contains(ancestor)) return true;
        return false;
    }
}
