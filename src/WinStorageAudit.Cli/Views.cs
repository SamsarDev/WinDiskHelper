using Spectre.Console;
using Spectre.Console.Rendering;
using WinStorageAudit.Core.Model;
using WinStorageAudit.Core.Scanning;
using WinStorageAudit.Infrastructure.Persistence;

namespace WinStorageAudit.Cli;

/// <summary>Toda la salida pasa por Text o Markup.Escape: una ruta con corchetes no se interpreta como formato.</summary>
public static class Views
{
    private static string B(long bytes) => PathUtil.FormatBytes(bytes);
    private static Text T(string? s) => new(s ?? "—");
    private static Markup Num(string s) => new(Markup.Escape(s));

    private static string RiskColor(RiskLevel r) => r switch
    {
        RiskLevel.Low => "green", RiskLevel.Moderate => "yellow", RiskLevel.High => "darkorange", _ => "red",
    };

    private static Markup RiskCell(RiskLevel r) => new($"[{RiskColor(r)}]{Markup.Escape(r.Es())}[/]");

    public static void Title(string text) => AnsiConsole.Write(new Rule($"[bold]{Markup.Escape(text)}[/]").LeftJustified());

    public static void ScanSummary(AuditResult r, int top)
    {
        Title("Resumen del análisis");
        var grid = new Grid().AddColumn().AddColumn();
        void Row(string label, string value) => grid.AddRow(T(label), T(value));
        Row("Rutas", string.Join("; ", r.Roots));
        Row("Modo", r.Mode == ScanMode.Deep ? "Profundo" : "Rápido");
        Row("Duración", (r.FinishedUtc - r.StartedUtc).ToString(@"hh\:mm\:ss"));
        foreach (var v in r.Volumes.Where(v => v.TotalBytes > 0)) Row("Unidad " + v.Root, $"{B(v.TotalBytes)} de capacidad, {B(v.FreeBytes)} disponibles ({v.FileSystem})");
        Row("Analizado", $"{r.Storage.FileCount:N0} archivos en {r.Storage.DirectoryCount:N0} carpetas");
        Row("Espacio físico ocupado", B(r.Storage.PhysicalBytes));
        Row("Tamaño lógico", B(r.Storage.LogicalBytes));
        Row("Potencialmente recuperable", B(r.Reclaim.CandidateReclaimableBytes) + " (candidatos de limpieza, sin superposiciones)");
        Row("Podría recuperarse tras revisar", B(r.Reclaim.ReviewReclaimableBytes));
        Row("Efectivamente liberado", "0 B: esta herramienta no borra nada");
        AnsiConsole.Write(grid);
        AnsiConsole.WriteLine();

        Folders(r.Storage.Concentrations.Count > 0 ? r.Storage.Concentrations : r.Storage.TopFolders, Math.Min(top, 10), "Dónde se concentra el espacio");
        Findings(r.Findings.Where(f => f.Recommendation == RecommendationClass.CleanupCandidate).OrderByDescending(f => f.CountedReclaimableBytes), Math.Min(top, 10), "Principales candidatos de limpieza");

        var backups = r.Findings.Where(f => f.Recommendation == RecommendationClass.BackupPriority).ToList();
        if (backups.Count > 0) Findings(backups, Math.Min(top, 10), "Respaldar prioritariamente");

        Coverage(r.Coverage, brief: true);
    }

    public static void Folders(IEnumerable<StorageItem> items, int top, string title)
    {
        var table = NewTable(title).AddColumn("Ruta").AddColumn(new TableColumn("Físico").RightAligned()).AddColumn(new TableColumn("Lógico").RightAligned())
            .AddColumn(new TableColumn("%").RightAligned()).AddColumn("Contenido").AddColumn("Riesgo").AddColumn(new TableColumn("Recuperable").RightAligned());
        foreach (var i in items.Take(top))
        {
            table.AddRow(T(i.Path), Num(B(i.PhysicalBytes)), Num(B(i.LogicalBytes)), Num(i.PercentOfAnalyzed.ToString("0.0")), T(i.ContentType), RiskCell(i.Risk), Num(i.ReclaimableBytes is { } v ? B(v) : "—"));
        }
        AnsiConsole.Write(table);
    }

    public static void Breakdown(IEnumerable<BreakdownEntry> items, int top, string title, Func<string, string> label)
    {
        var table = NewTable(title).AddColumn("Clave").AddColumn(new TableColumn("Físico").RightAligned()).AddColumn(new TableColumn("Lógico").RightAligned()).AddColumn(new TableColumn("Archivos").RightAligned());
        foreach (var i in items.Take(top)) table.AddRow(T(label(i.Key)), Num(B(i.PhysicalBytes)), Num(B(i.LogicalBytes)), Num(i.FileCount.ToString("N0")));
        AnsiConsole.Write(table);
    }

    public static void Findings(IEnumerable<Finding> findings, int top, string title)
    {
        var list = findings.ToList();
        var table = NewTable($"{title} ({list.Count})").AddColumn("Id").AddColumn("Ruta o recurso").AddColumn("Clasificación").AddColumn("Riesgo").AddColumn("Confianza").AddColumn(new TableColumn("Recuperable").RightAligned());
        foreach (var f in list.Take(top))
        {
            table.AddRow(T(f.Id), T(f.PathOrResource), T(f.Recommendation.Es()), RiskCell(f.RiskLevel), T(f.Confidence.Es()), Num(f.EstimatedReclaimableBytes > 0 ? B(f.EstimatedReclaimableBytes) : "—"));
        }
        AnsiConsole.Write(table);
        if (list.Count > top) AnsiConsole.MarkupLine($"[grey]Se muestran {top} de {list.Count}. Use --top o «report --format html».[/]");
    }

    public static void FindingDetail(Finding f)
    {
        var rows = new List<IRenderable>
        {
            Line("Qué se encontró", f.Description),
            Line("Por qué importa", f.Relevance),
            Line("Evidencia", string.Join("\n", f.Evidence.Select(e => "- " + e))),
            Line("Qué puede hacer", f.RecommendedAction),
            Line("Qué podría perder", f.PotentialLoss),
            Line("Espacio", $"Ocupa {B(f.DetectedSizeBytes)}; recuperable estimado {B(f.EstimatedReclaimableBytes)}; suma en totales {B(f.CountedReclaimableBytes)}."),
            Line("Clasificación", $"{f.Recommendation.Es()} · riesgo {f.RiskLevel.Es().ToLowerInvariant()} · confianza {f.Confidence.Es().ToLowerInvariant()} · {f.Reversibility.Es().ToLowerInvariant()}"),
            Line("Regla", f.RuleId),
        };
        if (f.ResourceKind != ResourceKind.None) rows.Insert(1, Line("Tipo de recurso", f.ResourceKind.Es()));
        if (f.RelatedPaths.Count > 0) rows.Add(Line("Rutas relacionadas", string.Join("\n", f.RelatedPaths)));
        if (f.RequiresBackup) rows.Add(Line("Respaldo", "Respalde antes de modificar."));
        AnsiConsole.Write(new Panel(new Rows(rows)) { Header = new PanelHeader(Markup.Escape(f.PathOrResource)), Expand = true });
    }

    private static Markup Line(string label, string value) => new($"[bold]{Markup.Escape(label)}:[/] {Markup.Escape(value)}");

    public static void Git(AuditResult r, int top)
    {
        if (!r.GitAvailable)
        {
            AnsiConsole.MarkupLine("[yellow]Git no está disponible o no se evaluó en este análisis.[/]");
            return;
        }
        var table = NewTable($"Repositorios Git ({r.GitRepositories.Count})").AddColumn("Repositorio").AddColumn(new TableColumn("Tamaño").RightAligned()).AddColumn("Remotos").AddColumn("Estado");
        foreach (var g in r.GitRepositories.Take(top))
        {
            var flags = new List<string>();
            if (g.IsWorktree) flags.Add("worktree");
            if (g.IsSubmodule) flags.Add("submódulo");
            if (g.IsBare) flags.Add("bare");
            if (g.IsNestedInRepository && !g.IsSubmodule) flags.Add("anidado");
            var name = g.Path + (flags.Count > 0 ? $" ({string.Join(", ", flags)})" : "");
            table.AddRow(T(name), Num(B(g.SizeBytes)), T(g.Remotes.Count == 0 ? "Ninguno" : string.Join(", ", g.Remotes.Select(x => x.Name))), T(string.Join("\n", g.States)));
        }
        AnsiConsole.Write(table);
        AnsiConsole.MarkupLine("[grey]No se contactó con ningún servidor: la comparación usa las referencias remotas locales, que pueden estar desactualizadas.[/]");
    }

    public static void Backups(AuditResult r, int top)
    {
        Git(r, top);
        var table = NewTable("Archivos personales").AddColumn("Tipo").AddColumn(new TableColumn("Archivos").RightAligned()).AddColumn(new TableColumn("Tamaño").RightAligned()).AddColumn(new TableColumn("Solo en la nube").RightAligned()).AddColumn("Carpeta principal");
        foreach (var g in r.Backup.PersonalGroups) table.AddRow(T(g.Kind.Es()), Num(g.FileCount.ToString("N0")), Num(B(g.Bytes)), Num(g.OnlineOnlyCount.ToString("N0")), T(g.TopFolders.FirstOrDefault()));
        AnsiConsole.Write(table);

        AnsiConsole.MarkupLine(Markup.Escape(r.Backup.Destinations.Count == 0
            ? "Sin destinos de respaldo configurados: use «config add-backup <ruta>» para comparar."
            : "Destinos: " + string.Join("; ", r.Backup.Destinations)));
        foreach (var (state, count) in r.Backup.StateCounts) AnsiConsole.MarkupLine(Markup.Escape($"  {state.Es()}: {count:N0}"));

        var priorities = NewTable("Prioridades de respaldo").AddColumn("#").AddColumn("Qué respaldar").AddColumn("Por qué").AddColumn(new TableColumn("Tamaño").RightAligned());
        foreach (var p in r.Backup.Priorities.Take(top)) priorities.AddRow(Num(p.Rank.ToString()), T(p.Target), T(p.Reason), Num(B(p.SizeBytes)));
        AnsiConsole.Write(priorities);
    }

    public static void Duplicates(AuditResult r, int top)
    {
        var d = r.Duplicates;
        if (!d.Evaluated)
        {
            AnsiConsole.MarkupLine("[yellow]Los duplicados no se evaluaron. Use «scan --deep» o «analyze duplicates».[/]");
            return;
        }
        var table = NewTable($"Duplicados confirmados ({d.Groups.Count})").AddColumn(new TableColumn("Tamaño").RightAligned()).AddColumn(new TableColumn("Redundante").RightAligned()).AddColumn("Copias").AddColumn("Revisión");
        foreach (var g in d.Groups.OrderByDescending(g => g.RedundantBytes).Take(top))
            table.AddRow(Num(B(g.FileSizeBytes)), Num(B(g.RedundantBytes)), T(string.Join("\n", g.Paths)), T(g.ContainsSensitiveContent ? "Contenido sensible" : "Normal"));
        AnsiConsole.Write(table);
        AnsiConsole.MarkupLine(Markup.Escape($"{d.FilesConsidered:N0} archivos considerados · {d.FilesHashed:N0} con hash completo · {B(d.BytesRead)} leídos · {d.SkippedOnlineOnly:N0} solo en la nube omitidos · {d.SkippedLocked:N0} bloqueados · {d.HardLinkGroupsIgnored:N0} grupos con enlaces duros"));
    }

    public static void Apps(AuditResult r, int top)
    {
        if (!r.Apps.Evaluated)
        {
            AnsiConsole.MarkupLine("[yellow]Las aplicaciones no se evaluaron. Use «scan --deep» o «analyze apps».[/]");
            return;
        }
        var sources = NewTable("Fuentes de evidencia").AddColumn("Fuente").AddColumn("Disponible").AddColumn(new TableColumn("Registros").RightAligned()).AddColumn("Detalle");
        foreach (var s in r.Apps.Sources) sources.AddRow(T(s.Name), T(s.Available ? "Sí" : "No"), Num(s.Records.ToString("N0")), T(s.Detail));
        AnsiConsole.Write(sources);
        foreach (var e in r.Apps.SourceErrors) AnsiConsole.MarkupLine($"[yellow]{Markup.Escape(e)}[/]");

        var table = NewTable($"Aplicaciones ({r.Apps.Apps.Count})").AddColumn("Nombre").AddColumn("Editor").AddColumn(new TableColumn("Tamaño").RightAligned()).AddColumn("Última evidencia").AddColumn("Uso").AddColumn("Confianza");
        foreach (var a in r.Apps.Apps.OrderByDescending(a => a.EstimatedSizeBytes ?? 0).Take(top))
            table.AddRow(T(a.Name), T(a.Publisher), Num(a.EstimatedSizeBytes is { } s ? B(s) : "—"), Num(a.LastRunUtc?.ToString("yyyy-MM-dd") ?? "—"), T(a.Usage.Es()), T(a.UsageConfidence.Es()));
        AnsiConsole.Write(table);
        AnsiConsole.MarkupLine("[grey]Windows no conserva un historial completo. La ausencia de evidencia no significa que una aplicación no se use.[/]");
        var counts = r.Apps.Apps.GroupBy(a => a.Usage).OrderBy(g => g.Key).Select(g => $"{g.Key.Es()}: {g.Count()}");
        foreach (var c in counts) AnsiConsole.MarkupLine(Markup.Escape("  " + c));
    }

    public static void Maintenance(IReadOnlyList<MaintenanceItem> items)
    {
        if (items.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No se evaluó el mantenimiento en este análisis.[/]");
            return;
        }
        foreach (var m in items.OrderBy(m => m.Severity == MaintenanceSeverity.Advanced).ThenByDescending(m => m.Severity == MaintenanceSeverity.Recommended))
        {
            var rows = new List<IRenderable>
            {
                new Text(m.Description),
                Line("Relevancia", m.Relevance),
                Line("Estado detectado", m.DetectedState),
            };
            if (m.EstimatedRecoverableBytes is { } b) rows.Add(Line("Potencial estimado", B(b)));
            if (m.Command != null) rows.Add(Line("Comando (no se ejecuta)", "\n" + m.Command));
            if (m.SettingsPath != null) rows.Add(Line("Configuración", m.SettingsPath));
            rows.Add(Line("Permisos", m.RequiredPermissions));
            rows.Add(Line("Consecuencias", m.Consequences));
            rows.Add(Line("Reversibilidad", m.ReversibilityNote));
            rows.Add(Line("Referencia", m.Reference));
            var color = m.Severity == MaintenanceSeverity.Advanced ? "red" : m.Severity == MaintenanceSeverity.Recommended ? "green" : "grey";
            AnsiConsole.Write(new Panel(new Rows(rows)) { Header = new PanelHeader($"[{color}]{Markup.Escape(m.Title + " · " + m.Severity.Es())}[/]"), Expand = true });
        }
    }

    public static void Coverage(CoverageReport c, bool brief = false)
    {
        Title("Limitaciones de este análisis");
        if (c.WasCancelled) AnsiConsole.MarkupLine("[yellow]Análisis cancelado: los resultados son parciales.[/]");
        foreach (var (kind, count) in c.IssueCounts.OrderByDescending(kv => kv.Value)) AnsiConsole.MarkupLine(Markup.Escape($"{kind.Es()}: {count:N0}"));
        foreach (var n in c.Notes) AnsiConsole.MarkupLine(Markup.Escape("- " + n));
        if (!brief)
            foreach (var s in c.IssueSamples.Take(30)) AnsiConsole.MarkupLine(Markup.Escape($"  [{s.Kind.Es()}] {s.Path} {s.Detail}"));
    }

    public static void History(IReadOnlyList<HistoryEntry> entries)
    {
        if (entries.Count == 0)
        {
            AnsiConsole.MarkupLine("El historial está vacío.");
            return;
        }
        var table = NewTable("Historial de análisis").AddColumn(new TableColumn("Id").RightAligned()).AddColumn("Fecha").AddColumn("Modo").AddColumn("Rutas")
            .AddColumn(new TableColumn("Físico").RightAligned()).AddColumn(new TableColumn("Candidatos").RightAligned()).AddColumn(new TableColumn("Revisión").RightAligned()).AddColumn(new TableColumn("Hallazgos").RightAligned());
        foreach (var e in entries)
        {
            table.AddRow(Num(e.Id.ToString()), Num(e.StartedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm")), T((e.Mode == "Deep" ? "Profundo" : "Rápido") + (e.Cancelled ? " (cancelado)" : "")), T(e.Roots),
                Num(B(e.PhysicalBytes)), Num(B(e.CandidateBytes)), Num(B(e.ReviewBytes)), Num(e.Findings.ToString("N0")));
        }
        AnsiConsole.Write(table);
    }

    public static void Comparison(HistoryComparison c, int top)
    {
        AnsiConsole.MarkupLine(Markup.Escape($"Físico: {B(c.Older.PhysicalBytes)} → {B(c.Newer.PhysicalBytes)} ({Signed(c.Newer.PhysicalBytes - c.Older.PhysicalBytes)})"));
        Delta(c.Categories.Select(d => d with { Key = Enum.TryParse<StorageCategory>(d.Key, out var cat) ? cat.Es() : d.Key }), top, "Cambios por categoría");
        Delta(c.Folders, top, "Cambios en carpetas destacadas");
        AnsiConsole.MarkupLine("[grey]Solo se comparan las carpetas destacadas de cada análisis; una carpeta ausente de uno de ellos no implica que no existiera.[/]");
    }

    private static void Delta(IEnumerable<HistoryDelta> items, int top, string title)
    {
        var table = NewTable(title).AddColumn("Elemento").AddColumn(new TableColumn("Antes").RightAligned()).AddColumn(new TableColumn("Después").RightAligned()).AddColumn(new TableColumn("Cambio").RightAligned());
        foreach (var d in items.Take(top)) table.AddRow(T(d.Key), Num(B(d.Before)), Num(B(d.After)), Num(Signed(d.Change)));
        AnsiConsole.Write(table);
    }

    private static string Signed(long v) => (v > 0 ? "+" : "") + B(v);

    private static Table NewTable(string title) => new Table { Title = new TableTitle(Markup.Escape(title)), Border = TableBorder.Rounded, Expand = false };
}
