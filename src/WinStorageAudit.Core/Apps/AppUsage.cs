using System.Text.RegularExpressions;
using WinStorageAudit.Core.Cleanup;
using WinStorageAudit.Core.Model;
using WinStorageAudit.Core.Scanning;

namespace WinStorageAudit.Core.Apps;

/// <summary>
/// Cruza el inventario con evidencia de ejecución y clasifica de forma conservadora.
/// La ausencia de evidencia nunca se presenta como ausencia de uso.
/// </summary>
public static partial class UsageClassifier
{
    [GeneratedRegex("[^a-z0-9]+")]
    private static partial Regex NonAlnum();

    private static readonly string[] SystemLikeTokens =
    [
        "redistributable", "runtime", "driver", "sdk", "update for", "security update", "hotfix", "framework",
        "webview2", "bootstrapper", "targeting pack", "chipset", "firmware", "vcredist", "windows kit",
    ];

    public static bool LooksLikeSystemComponent(string name) =>
        SystemLikeTokens.Any(t => name.Contains(t, StringComparison.OrdinalIgnoreCase));

    public static void Classify(IReadOnlyList<InstalledApp> apps, IReadOnlyList<UsageSourceData> sources, AuditThresholds t, DateTime nowUtc)
    {
        var anySource = sources.Any(s => s.Status.Available);
        var records = sources.Where(s => s.Status.Available).SelectMany(s => s.Records).ToList();

        foreach (var app in apps)
        {
            var evidence = FindEvidence(app, records);
            app.Evidence = evidence;
            var latest = evidence.Where(e => e.LastRunUtc != null).Select(e => e.LastRunUtc!.Value).DefaultIfEmpty().Max();
            app.LastRunUtc = latest == default ? null : latest;
            var matchable = !string.IsNullOrEmpty(app.InstallLocation) || !string.IsNullOrEmpty(app.PackageFamilyName);

            if (latest != default)
            {
                var days = (nowUtc - latest).TotalDays;
                app.Usage = days < t.UsageRecentDays ? UsageClass.RecentExecution
                    : days < t.UsageMediumDays ? UsageClass.NoEvidence30Days
                    : days < t.UsageLongDays ? UsageClass.NoEvidence60Days
                    : UsageClass.NoEvidence90Days;
                app.UsageConfidence = app.Usage == UsageClass.RecentExecution ? Confidence.High : evidence.Count > 1 ? Confidence.Medium : Confidence.Low;
            }
            else if (anySource && matchable)
            {
                app.Usage = UsageClass.NoHistoricalEvidence;
                app.UsageConfidence = Confidence.Low;
            }
            else
            {
                app.Usage = UsageClass.Unknown;
                app.UsageConfidence = Confidence.Unknown;
            }

            app.Suggestion = Suggest(app);
        }
    }

    private static string? Suggest(InstalledApp app)
    {
        if (app.IsSystemLike) return "Componente de sistema o dependencia: no se sugiere desinstalar.";
        return app.Usage switch
        {
            UsageClass.NoEvidence90Days => "Sin ejecuciones recientes registradas: si no la reconoce como necesaria, valore desinstalarla desde Configuración.",
            UsageClass.NoEvidence60Days or UsageClass.NoEvidence30Days => "Observar: el periodo sin evidencia aún es corto.",
            UsageClass.NoHistoricalEvidence => "No hay registros, lo que no implica que no se use: puede ejecutarse por consola, como servicio o antes de que empezaran los registros.",
            _ => null,
        };
    }

    private static List<UsageEvidence> FindEvidence(InstalledApp app, List<RawUsageRecord> records)
    {
        var result = new List<UsageEvidence>();
        var location = app.InstallLocation?.TrimEnd('\\');
        var nameKey = Key(app.Name);

        foreach (var r in records)
        {
            var id = r.ExecutablePathOrId;
            string? detail = null;

            if (!string.IsNullOrEmpty(location) && location.Length > 3 && PathUtil.IsSameOrUnder(id, location))
                detail = "Ejecutable dentro de la carpeta de instalación";
            else if (!string.IsNullOrEmpty(app.PackageFamilyName) && id.StartsWith(app.PackageFamilyName + "!", StringComparison.OrdinalIgnoreCase))
                detail = "Identificador de aplicación empaquetada";
            else if (!id.Contains('\\') && app.ExecutableNames.Contains(id, StringComparer.OrdinalIgnoreCase))
                detail = "Nombre de ejecutable presente en la carpeta de instalación";
            else if (id.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) && nameKey.Length >= 5 && Key(Path.GetFileNameWithoutExtension(id)) == nameKey)
                detail = "Acceso directo con el mismo nombre";

            if (detail != null)
            {
                var count = r.RunCount is { } n ? $", {n} ejecuciones registradas" : "";
                result.Add(new UsageEvidence(r.Source, r.LastRunUtc, detail + count));
            }
        }

        return [.. result.OrderByDescending(e => e.LastRunUtc).Take(5)];
    }

    private static string Key(string s) => NonAlnum().Replace(s.ToLowerInvariant(), "");
}

public sealed class UnusedAppRule : IRule
{
    public string Id => "APP-UNUSED";

    public IEnumerable<Finding> Evaluate(RuleContext c)
    {
        if (c.Apps is not { Evaluated: true } report) yield break;

        foreach (var app in report.Apps.Where(a => a.Usage == UsageClass.NoEvidence90Days && !a.IsSystemLike).OrderByDescending(a => a.EstimatedSizeBytes ?? 0))
        {
            yield return new Finding
            {
                RuleId = Id,
                Category = FindingArea.Applications,
                PathOrResource = app.Name,
                Description = $"Aplicación sin evidencia de ejecución en los últimos {c.Thresholds.UsageLongDays} días.",
                Relevance = "Podría estar en desuso. Las fuentes de Windows no registran todas las formas de ejecutar un programa.",
                Evidence = [.. app.Evidence.Select(e => $"{e.Source}: {(e.LastRunUtc is { } d ? d.ToString("yyyy-MM-dd") : "sin fecha")} ({e.Detail})"), "Fuente: " + app.Source],
                Recommendation = RecommendationClass.ManualReview,
                Confidence = Confidence.Low,
                RiskLevel = RiskLevel.Moderate,
                Reversibility = Reversibility.RecoverableWithEffort,
                RecommendedAction = "Si decide que no la necesita, desinstálela desde Configuración > Aplicaciones. Esta herramienta nunca desinstala nada.",
                PotentialLoss = "Configuración y licencias de la aplicación; algunas se ejecutan en segundo plano sin dejar evidencia.",
                DetectedSizeBytes = app.EstimatedSizeBytes ?? 0,
                EstimatedReclaimableBytes = app.EstimatedSizeBytes ?? 0,
                ResourceKind = ResourceKind.None,
            };
        }
    }
}
