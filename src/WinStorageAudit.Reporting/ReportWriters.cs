using System.Reflection;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using WinStorageAudit.Core;
using WinStorageAudit.Core.Model;
using WinStorageAudit.Core.Scanning;

namespace WinStorageAudit.Reporting;

public static class JsonReportWriter
{
    public static void Write(AuditResult result, Stream output) => JsonSerializer.Serialize(output, result, AuditJson.Options);
}

/// <summary>
/// Reporte HTML autónomo. Los datos viajan como JSON con &lt; &gt; &amp; escapados dentro de un bloque
/// que el navegador no ejecuta, y el script los inserta solo como nodos de texto.
/// </summary>
public static class HtmlReportWriter
{
    public const string PrivacyNote = "Este reporte contiene rutas y nombres de archivo personales. Se generó localmente y no se envió a ningún servicio; compártalo con cuidado.";

    private static readonly JsonSerializerOptions PayloadOptions = new()
    {
        Encoder = JavaScriptEncoder.Default,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    public static string Render(AuditResult r, int rowLimit = 2000)
    {
        var payload = JsonSerializer.Serialize(BuildPayload(r, rowLimit), PayloadOptions);
        return LoadTemplate().Replace("__REPORT_DATA__", payload, StringComparison.Ordinal);
    }

    private static string LoadTemplate()
    {
        var assembly = Assembly.GetExecutingAssembly();
        using var stream = assembly.GetManifestResourceStream("WinStorageAudit.Reporting.Assets.report.template.html")
            ?? throw new InvalidOperationException("No se encontró la plantilla del reporte.");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        return reader.ReadToEnd();
    }

    private static object StorageRow(StorageItem i) => new
    {
        path = i.Path,
        physical = i.PhysicalBytes,
        logical = i.LogicalBytes,
        percent = Math.Round(i.PercentOfAnalyzed, 2),
        contentType = i.ContentType,
        risk = i.Risk.Es(),
        riskRank = (int)i.Risk,
        reclaimable = i.ReclaimableBytes,
        evidenceText = string.Join(". ", i.Evidence),
    };

    private static object BuildPayload(AuditResult r, int rowLimit)
    {
        var truncated = new List<string>();
        IEnumerable<T> Limit<T>(IReadOnlyCollection<T> rows, string name)
        {
            if (rows.Count <= rowLimit) return rows;
            truncated.Add($"{name}: {rowLimit:N0} de {rows.Count:N0}");
            return rows.Take(rowLimit);
        }

        var personal = r.Backup.Unprotected.Concat(r.Backup.PersonalGroups.SelectMany(g => g.Largest)).DistinctBy(f => f.Path, StringComparer.OrdinalIgnoreCase).ToList();
        var backupItems = r.Findings.Count(f => f.RequiresBackup);

        return new
        {
            version = r.ToolVersion,
            started = r.StartedUtc,
            finished = r.FinishedUtc,
            duration = FormatDuration(r.FinishedUtc - r.StartedUtc),
            mode = r.Mode == ScanMode.Deep ? "Profundo" : "Rápido",
            cancelled = r.Coverage.WasCancelled,
            roots = r.Roots,
            exclusions = r.Exclusions,
            privacyNote = PrivacyNote,
            truncated,
            counts = new { backupItems },
            volumes = r.Volumes.Select(v => new { root = v.Root, label = v.Label, fileSystem = v.FileSystem, total = v.TotalBytes, free = v.FreeBytes }),
            reclaim = new
            {
                occupied = r.Reclaim.OccupiedPhysicalBytes,
                candidate = r.Reclaim.CandidateReclaimableBytes,
                review = r.Reclaim.ReviewReclaimableBytes,
            },
            storage = new
            {
                logical = r.Storage.LogicalBytes,
                onlineOnly = r.Storage.OnlineOnlyLogicalBytes,
                repeatedLinks = r.Storage.RepeatedHardLinkLogicalBytes,
                files = r.Storage.FileCount,
                directories = r.Storage.DirectoryCount,
                topFolders = r.Storage.TopFolders.Select(StorageRow),
                topFiles = r.Storage.TopFiles.Select(StorageRow),
                concentrations = r.Storage.Concentrations.Select(i => new { path = i.Path, physical = i.PhysicalBytes }),
                categories = r.Storage.ByCategory.Select(c => new { key = Enum.TryParse<StorageCategory>(c.Key, out var cat) ? cat.Es() : c.Key, physical = c.PhysicalBytes }),
                extensions = r.Storage.ByExtension.Select(e => new { key = e.Key, physical = e.PhysicalBytes, logical = e.LogicalBytes, files = e.FileCount }),
            },
            findings = Limit(r.Findings, "hallazgos").Select(f => new
            {
                id = f.Id,
                rule = f.RuleId,
                area = f.Category.Es(),
                path = f.PathOrResource,
                classification = f.Recommendation.Es(),
                risk = f.RiskLevel.Es(),
                riskRank = (int)f.RiskLevel,
                confidence = f.Confidence.Es(),
                confidenceRank = (int)f.Confidence,
                size = f.DetectedSizeBytes,
                reclaimable = f.EstimatedReclaimableBytes,
                counted = f.CountedReclaimableBytes,
                description = f.Description,
                relevance = f.Relevance,
                evidence = f.Evidence,
                action = f.RecommendedAction,
                loss = f.PotentialLoss,
                reversibility = f.Reversibility.Es(),
                kind = f.ResourceKind == ResourceKind.None ? null : f.ResourceKind.Es(),
                related = f.RelatedPaths,
                requiresBackup = f.RequiresBackup,
                requiresElevation = f.RequiresElevation,
            }),
            duplicates = new
            {
                evaluated = r.Duplicates.Evaluated,
                considered = r.Duplicates.FilesConsidered,
                hashed = r.Duplicates.FilesHashed,
                read = r.Duplicates.BytesRead,
                groups = r.Duplicates.Groups.Count,
                linksIgnored = r.Duplicates.HardLinkGroupsIgnored,
            },
            gitAvailable = r.GitAvailable,
            repositories = Limit(r.GitRepositories, "repositorios").Select(g => new
            {
                path = g.Path,
                size = g.SizeBytes,
                remotes = string.Join(", ", g.Remotes.Select(x => x.Name + " (" + x.SanitizedUrl + ")")),
                branch = g.IsDetached ? "HEAD separado" : g.CurrentBranch,
                states = g.States,
                statesText = string.Join(" ", g.States),
            }),
            backup = new
            {
                destinations = r.Backup.Destinations,
                states = r.Backup.StateCounts.Select(kv => new { key = kv.Key.Es(), value = kv.Value }),
                priorities = r.Backup.Priorities.Select(p => new { rank = p.Rank, target = p.Target, reason = p.Reason, size = p.SizeBytes }),
                groups = r.Backup.PersonalGroups.Select(g => new { kind = g.Kind.Es(), bytes = g.Bytes, files = g.FileCount }),
                files = Limit(personal, "archivos personales").Select(f => new { path = f.Path, kind = f.Kind.Es(), bytes = f.Bytes, modified = f.LastWriteUtc, state = f.BackupState.Es(), detail = f.BackupDetail }),
            },
            apps = new
            {
                evaluated = r.Apps.Evaluated,
                errors = r.Apps.SourceErrors,
                sources = r.Apps.Sources.Select(s => new { name = s.Name, available = s.Available, records = s.Records, detail = s.Detail }),
                list = Limit(r.Apps.Apps, "aplicaciones").Select(a => new
                {
                    name = a.Name,
                    publisher = a.Publisher,
                    version = a.Version,
                    location = a.InstallLocation,
                    size = a.EstimatedSizeBytes,
                    installed = a.InstallDate,
                    lastRun = a.LastRunUtc,
                    usage = a.Usage.Es(),
                    confidence = a.UsageConfidence.Es(),
                    source = a.Source,
                    suggestion = a.Suggestion,
                    evidence = a.Evidence.Select(e => $"{e.Source}: {(e.LastRunUtc is { } d ? d.ToString("yyyy-MM-dd") : "sin fecha")} ({e.Detail})"),
                }),
            },
            maintenance = r.Maintenance.Select(m => new
            {
                title = m.Title,
                severity = m.Severity.Es(),
                advanced = m.Severity == MaintenanceSeverity.Advanced,
                description = m.Description,
                relevance = m.Relevance,
                state = m.DetectedState,
                recoverable = m.EstimatedRecoverableBytes,
                command = m.Command,
                settings = m.SettingsPath,
                permissions = m.RequiredPermissions,
                consequences = m.Consequences,
                reversibility = m.ReversibilityNote,
                reference = m.Reference,
            }),
            coverage = new
            {
                notes = r.Coverage.Notes,
                counts = r.Coverage.IssueCounts.Select(kv => new { key = kv.Key.Es(), value = kv.Value }),
                samples = r.Coverage.IssueSamples.Select(i => new { kind = i.Kind.Es(), path = i.Path, detail = i.Detail }),
            },
        };
    }

    private static string FormatDuration(TimeSpan t) => t.TotalMinutes >= 1 ? $"{(int)t.TotalMinutes} min {t.Seconds} s" : $"{Math.Max(t.TotalSeconds, 0):0.#} s";
}

/// <summary>Plan de limpieza para leer y ejecutar a mano: nunca es un script ejecutable.</summary>
public static class CleanupPlanWriter
{
    public static string Render(AuditResult r)
    {
        var sb = new StringBuilder();
        var b = PathUtil.FormatBytes;
        sb.AppendLine("# Plan de limpieza revisable").AppendLine();
        sb.AppendLine($"Análisis: {r.FinishedUtc:yyyy-MM-dd HH:mm} UTC. Rutas: {string.Join("; ", r.Roots)}").AppendLine();
        sb.AppendLine("Este plan no es un script. **WinStorageAudit no ejecutó ninguna acción.** Compruebe cada ruta antes de actuar, porque pudo cambiar desde el análisis.").AppendLine();
        sb.AppendLine($"- Espacio ocupado por lo analizado: {b(r.Reclaim.OccupiedPhysicalBytes)}");
        sb.AppendLine($"- Potencialmente recuperable (candidatos): {b(r.Reclaim.CandidateReclaimableBytes)}");
        sb.AppendLine($"- Podría recuperarse tras revisión manual: {b(r.Reclaim.ReviewReclaimableBytes)}");
        sb.AppendLine("- Efectivamente liberado: 0 B. Enviar a la Papelera tampoco libera espacio hasta vaciarla.").AppendLine();

        var backups = r.Findings.Where(f => f.Recommendation == RecommendationClass.BackupPriority).ToList();
        if (backups.Count > 0)
        {
            sb.AppendLine("## 1. Antes de nada: respaldar").AppendLine();
            foreach (var f in backups) sb.AppendLine($"- [ ] `{Sanitize(f.PathOrResource)}`: {f.RecommendedAction}");
            sb.AppendLine();
        }

        Section(sb, "## 2. Candidatos de limpieza", r.Findings.Where(f => f.Recommendation == RecommendationClass.CleanupCandidate));
        Section(sb, "## 3. Revisión manual", r.Findings.Where(f => f.Recommendation == RecommendationClass.ManualReview));

        var routine = r.Maintenance.Where(m => m.Severity == MaintenanceSeverity.Recommended).ToList();
        if (routine.Count > 0)
        {
            sb.AppendLine("## 4. Herramientas de Windows").AppendLine();
            foreach (var m in routine)
                sb.AppendLine($"- [ ] **{m.Title}** ({m.DetectedState}): {m.SettingsPath ?? m.Command}. Consecuencias: {m.Consequences}");
            sb.AppendLine();
        }
        return sb.ToString();
    }

    private static void Section(StringBuilder sb, string title, IEnumerable<Finding> findings)
    {
        var list = findings.OrderByDescending(f => f.CountedReclaimableBytes).ToList();
        if (list.Count == 0) return;
        sb.AppendLine(title).AppendLine();
        foreach (var f in list)
        {
            sb.AppendLine($"- [ ] `{Sanitize(f.PathOrResource)}` · {PathUtil.FormatBytes(f.EstimatedReclaimableBytes)} · riesgo {f.RiskLevel.Es().ToLowerInvariant()} · confianza {f.Confidence.Es().ToLowerInvariant()}");
            sb.AppendLine($"  - Qué hacer: {f.RecommendedAction}");
            sb.AppendLine($"  - Qué podría perder: {f.PotentialLoss}");
        }
        sb.AppendLine();
    }

    private static string Sanitize(string s) => s.Replace("`", "'").Replace("\r", " ").Replace("\n", " ");
}
