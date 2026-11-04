using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using WinStorageAudit.Core.Apps;
using WinStorageAudit.Core.Backup;
using WinStorageAudit.Core.Cleanup;
using WinStorageAudit.Core.Git;
using WinStorageAudit.Core.Maintenance;
using WinStorageAudit.Core.Model;
using WinStorageAudit.Core.Scanning;

namespace WinStorageAudit.Core;

public static class AuditJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.Default,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };
}

/// <summary>Qué analizadores se ejecutan. Rápido: respuesta útil. Profundo: añade los costosos.</summary>
public sealed record AuditOptions
{
    public required ScanRequest Request { get; init; }
    public AuditThresholds Thresholds { get; init; } = new();
    public bool RunGit { get; init; } = true;
    public bool GitIncludeIgnored { get; init; }
    public bool RunDuplicates { get; init; }
    public bool RunApps { get; init; }
    public bool RunMaintenance { get; init; } = true;
    public bool MaintenanceExpensive { get; init; }
    public IReadOnlyList<string> BackupDestinations { get; init; } = [];
    public bool VerifyBackups { get; init; }
    public bool VerifyBackupHashes { get; init; }
    public int MaxTrackedChecks { get; init; } = 2000;

    public static AuditOptions ForMode(ScanRequest request, AuditThresholds thresholds, IReadOnlyList<string> destinations)
    {
        var deep = request.Mode == ScanMode.Deep;
        return new AuditOptions
        {
            Request = request,
            Thresholds = thresholds,
            GitIncludeIgnored = deep,
            RunDuplicates = deep,
            RunApps = deep,
            MaintenanceExpensive = deep,
            BackupDestinations = destinations,
            VerifyBackups = destinations.Count > 0,
        };
    }
}

public sealed record AuditDependencies
{
    public required IFileScanner Scanner { get; init; }
    public required IFileIdentityProvider Identity { get; init; }
    public required IProcessRunner Processes { get; init; }
    public required KnownLocations Locations { get; init; }
    public Func<IReadOnlyList<string>, IReadOnlyList<VolumeSummary>> VolumeReader { get; init; } = _ => [];
    public IReadOnlyList<IInstalledAppSource> AppSources { get; init; } = [];
    public IReadOnlyList<IUsageEvidenceSource> UsageSources { get; init; } = [];
    public IMaintenanceProbe? MaintenanceProbe { get; init; }
    public Func<IReadOnlyList<string>> SystemReferences { get; init; } = () => [];
    public Action<IEnumerable<InstalledApp>>? AppExecutableEnricher { get; init; }
    public string GitExecutable { get; init; } = "git";
    public Func<DateTime> Clock { get; init; } = () => DateTime.UtcNow;
}

/// <summary>Coordina los analizadores. No contiene presentación. Nada de lo que orquesta escribe en lo analizado.</summary>
public sealed class AuditPipeline(AuditDependencies deps)
{
    public async Task<AuditResult> RunAsync(AuditOptions options, ScanProgress progress, CancellationToken ct)
    {
        var started = deps.Clock();
        var coverage = new CoverageTracker();
        var notes = new List<string>();
        var request = options.Request;
        var collector = new ScanCollector(deps.Locations, new CollectorLimits { DuplicateMinBytes = options.Thresholds.DuplicateMinBytes }, options.RunDuplicates);

        progress.Stage = "Enumerando archivos";
        await deps.Scanner.ScanAsync(request, collector, progress, coverage, ct);
        var storage = collector.BuildSummary();
        AddScanNotes(request, collector, notes);

        IReadOnlyList<GitRepositoryStatus> repos = [];
        var gitAvailable = false;
        var duplicates = new DuplicateReport();
        AppReport? apps = null;
        IReadOnlyList<MaintenanceItem> maintenance = [];

        if (!ct.IsCancellationRequested)
        {
            await Guarded("Git", notes, ct, async () =>
            {
                if (!options.RunGit) return;
                var git = new GitAnalyzer(deps.Processes, deps.GitExecutable);
                gitAvailable = await git.IsAvailableAsync(ct);
                if (!gitAvailable)
                {
                    notes.Add("Git no está disponible: no se evaluaron repositorios ni se confirmó si los artefactos están versionados.");
                    return;
                }
                progress.Stage = $"Analizando {collector.Repositories.Count} repositorios Git";
                repos = await AnalyzeRepositoriesAsync(git, collector, options, ct);
                progress.Stage = "Comprobando artefactos con Git";
                await CheckTrackedAsync(git, collector, options, notes, ct);
            });

            await Guarded("Respaldos", notes, ct, async () =>
            {
                if (!options.VerifyBackups && deps.Locations.CloudSyncRoots.Count == 0) return;
                progress.Stage = "Comparando con destinos de respaldo";
                await new BackupVerifier(deps.Scanner).VerifyAsync(collector.PersonalFiles, options.BackupDestinations, options.VerifyBackupHashes, deps.Locations, coverage, ct);
            });

            await Guarded("Duplicados", notes, ct, async () =>
            {
                if (!options.RunDuplicates) return;
                progress.Stage = "Buscando duplicados";
                duplicates = await new DuplicateDetector(deps.Identity).DetectAsync(collector.DuplicateCandidates, s => progress.CurrentPath = s, ct);
                if (duplicates.SkippedLocked > 0) notes.Add($"{duplicates.SkippedLocked} archivos bloqueados o ilegibles no se compararon para buscar duplicados.");
                if (collector.DuplicateCandidatesDropped > 0) notes.Add($"Búsqueda de duplicados limitada: {collector.DuplicateCandidatesDropped:N0} archivos excedieron el límite de memoria y no se compararon.");
            });

            await Guarded("Aplicaciones", notes, ct, async () =>
            {
                if (!options.RunApps) return;
                progress.Stage = "Inventariando aplicaciones";
                apps = await BuildAppReportAsync(options.Thresholds, ct);
            });

            await Guarded("Mantenimiento", notes, ct, async () =>
            {
                if (!options.RunMaintenance || deps.MaintenanceProbe == null) return;
                progress.Stage = "Consultando el estado de Windows";
                maintenance = MaintenanceAdvisor.Build(await deps.MaintenanceProbe.ProbeAsync(options.MaintenanceExpensive, ct));
            });
        }

        var backup = BackupReportBuilder.Build(collector, repos, options.BackupDestinations, options.VerifyBackupHashes);
        if (collector.PersonalFilesDropped > 0) notes.Add($"{collector.PersonalFilesDropped:N0} archivos personales superaron el límite de seguimiento: se contaron, pero no se evaluó su respaldo.");

        progress.Stage = "Generando recomendaciones";
        var engine = new RecommendationEngine(RecommendationEngine.DefaultRules());
        var outcome = engine.Run(new RuleContext
        {
            Scan = collector,
            Storage = storage,
            Locations = deps.Locations,
            Thresholds = options.Thresholds,
            NowUtc = deps.Clock(),
            Duplicates = duplicates,
            Repositories = repos,
            GitAvailable = gitAvailable,
            Apps = apps,
            Backup = backup,
            SystemReferences = apps != null ? deps.SystemReferences() : [],
        });
        notes.AddRange(outcome.Notes);
        if (apps == null) notes.Add("Sin inventario de aplicaciones no se evaluaron posibles residuos de aplicaciones (requiere «scan --deep» o «analyze apps»).");
        if (!options.RunDuplicates) notes.Add("No se buscaron duplicados en este análisis (requiere «scan --deep» o «analyze duplicates»).");
        if (ct.IsCancellationRequested) notes.Add("Análisis cancelado: los resultados son parciales y los tamaños pueden estar subestimados.");

        AnnotateReclaim(storage, outcome.Findings);
        var roots = request.Roots;
        return new AuditResult
        {
            StartedUtc = started,
            FinishedUtc = deps.Clock(),
            Mode = request.Mode,
            Roots = roots,
            Exclusions = request.Exclusions,
            Volumes = deps.VolumeReader(roots),
            Storage = storage,
            Findings = outcome.Findings,
            Reclaim = outcome.Reclaim,
            GitRepositories = repos,
            GitAvailable = gitAvailable,
            Backup = backup,
            Duplicates = duplicates,
            Apps = apps ?? new AppReport(),
            Maintenance = maintenance,
            Coverage = coverage.ToReport(notes, ct.IsCancellationRequested),
        };
    }

    private static void AddScanNotes(ScanRequest request, ScanCollector collector, List<string> notes)
    {
        notes.Add("La suma de archivos no equivale al uso del volumen: los metadatos de NTFS, las instantáneas y las carpetas inaccesibles no se pueden enumerar sin privilegios.");
        notes.Add("El espacio físico es una estimación: se redondea al tamaño de clúster y no contempla archivos residentes en la MFT.");
        if (request.Mode == ScanMode.Quick)
        {
            notes.Add($"Análisis rápido: los enlaces duros solo se comprueban en archivos desde {PathUtil.FormatBytes(request.HardLinkCheckMinBytes)} y en la carpeta de Windows; la compresión WOF no se detecta. «scan --deep» es más exacto.");
        }
        if (collector.DownloadFilesDropped > 0) notes.Add($"Límite de memoria en Descargas: {collector.DownloadFilesDropped:N0} archivos no se evaluaron.");
    }

    private static async Task Guarded(string name, List<string> notes, CancellationToken ct, Func<Task> action)
    {
        if (ct.IsCancellationRequested) return;
        try { await action(); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            notes.Add($"El módulo «{name}» falló y sus resultados están incompletos: {ex.Message}");
        }
    }

    private static async Task<IReadOnlyList<GitRepositoryStatus>> AnalyzeRepositoriesAsync(GitAnalyzer git, ScanCollector collector, AuditOptions options, CancellationToken ct)
    {
        var results = new List<GitRepositoryStatus>();
        await Parallel.ForEachAsync(collector.Repositories, new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, options.Request.MaxConcurrency), CancellationToken = ct }, async (candidate, token) =>
        {
            var status = await git.AnalyzeAsync(candidate, options.GitIncludeIgnored, token);
            lock (results) results.Add(status);
        });
        return [.. results.OrderByDescending(BackupReportBuilder.GitPriorityScore).ThenByDescending(r => r.SizeBytes)];
    }

    private static async Task CheckTrackedAsync(GitAnalyzer git, ScanCollector collector, AuditOptions options, List<string> notes, CancellationToken ct)
    {
        var candidates = collector.DevResources.Where(r => r.RepoRoot != null && r.Artifact != null).OrderByDescending(r => r.Totals.PhysicalBytes).ToList();
        var limit = Math.Min(options.MaxTrackedChecks, candidates.Count);
        await Parallel.ForEachAsync(candidates.Take(limit), new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, options.Request.MaxConcurrency), CancellationToken = ct }, async (r, token) =>
        {
            r.HasTrackedFiles = await git.HasTrackedFilesAsync(r.RepoRoot!, r.Path, token);
        });
        if (candidates.Count > limit) notes.Add($"{candidates.Count - limit} artefactos pequeños no se comprobaron con Git; su confianza se limita a media.");
    }

    private async Task<AppReport> BuildAppReportAsync(AuditThresholds thresholds, CancellationToken ct)
    {
        var errors = new List<string>();
        var apps = new List<InstalledApp>();
        foreach (var source in deps.AppSources)
        {
            try { apps.AddRange(await source.ReadAsync(ct)); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                errors.Add($"{source.Name}: {ex.Message}");
            }
        }

        var sourcesData = new List<UsageSourceData>();
        foreach (var source in deps.UsageSources)
        {
            try { sourcesData.Add(await source.ReadAsync(ct)); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                sourcesData.Add(new UsageSourceData(new UsageSourceStatus(source.Name, false, 0, ex.Message), []));
            }
        }

        var distinct = apps.GroupBy(a => (a.Name.ToUpperInvariant(), a.Version?.ToUpperInvariant())).Select(g => g.OrderByDescending(a => a.InstallLocation?.Length ?? 0).First())
            .OrderBy(a => a.Name, StringComparer.CurrentCultureIgnoreCase).ToList();

        // Solo se enumeran carpetas de instalación si alguna fuente disponible registra nombres sin ruta (Prefetch).
        if (sourcesData.Any(s => s.Status.Available && s.Records.Any(r => !r.ExecutablePathOrId.Contains('\\')))) deps.AppExecutableEnricher?.Invoke(distinct);
        UsageClassifier.Classify(distinct, sourcesData, thresholds, deps.Clock());
        return new AppReport { Evaluated = true, Apps = distinct, Sources = [.. sourcesData.Select(s => s.Status)], SourceErrors = errors };
    }

    /// <summary>Indica en cada carpeta o archivo destacado cuánto espacio recuperable contienen sus hallazgos.</summary>
    private static void AnnotateReclaim(StorageSummary storage, IReadOnlyList<Finding> findings)
    {
        var bytesByPath = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in findings.Where(f => !f.IsAggregate && f.CountedReclaimableBytes > 0))
        {
            bytesByPath[f.PathOrResource] = bytesByPath.GetValueOrDefault(f.PathOrResource) + f.CountedReclaimableBytes;
            foreach (var ancestor in PathUtil.Ancestors(f.PathOrResource))
                bytesByPath[ancestor] = bytesByPath.GetValueOrDefault(ancestor) + f.CountedReclaimableBytes;
        }

        foreach (var item in storage.TopFolders.Concat(storage.TopFiles).Concat(storage.Concentrations))
            if (bytesByPath.TryGetValue(item.Path, out var value)) item.ReclaimableBytes = value;
    }
}
