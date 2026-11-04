using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Spectre.Console;
using WinStorageAudit.Cli;
using WinStorageAudit.Core;
using WinStorageAudit.Core.Cleanup;
using WinStorageAudit.Core.Model;
using WinStorageAudit.Core.Scanning;
using WinStorageAudit.Infrastructure;
using WinStorageAudit.Infrastructure.Apps;
using WinStorageAudit.Infrastructure.Maintenance;
using WinStorageAudit.Infrastructure.Native;
using WinStorageAudit.Infrastructure.Persistence;
using WinStorageAudit.Reporting;
using TreeNode = WinStorageAudit.Core.Model.TreeNode;

Console.OutputEncoding = Encoding.UTF8;

// Al redirigir la salida, un ancho amplio evita partir rutas y permite filtrarlas con otras herramientas.
if (Console.IsOutputRedirected) AnsiConsole.Profile.Width = 240;
using var cancellation = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    if (cancellation.IsCancellationRequested) return; // Un segundo Ctrl+C termina el proceso.
    e.Cancel = true;
    cancellation.Cancel();
    AnsiConsole.MarkupLine("[yellow]Cancelando; se conservarán los resultados parciales…[/]");
};

try
{
    return await new App(AppPaths.Default()).RunAsync(args, cancellation.Token);
}
catch (UsageException ex)
{
    AnsiConsole.MarkupLine($"[red]{Markup.Escape(ex.Message)}[/]");
    return 2;
}
catch (InvalidDataException ex)
{
    AnsiConsole.MarkupLine($"[red]{Markup.Escape(ex.Message)}[/]");
    return 1;
}

namespace WinStorageAudit.Cli
{
    public sealed class App(AppPaths paths)
    {
        private const string Version = "0.1.0";
        private readonly ConfigStore _config = new(paths);
        private readonly ResultStore _results = new(paths);
        private readonly HistoryStore _history = new(paths);

        public async Task<int> RunAsync(string[] args, CancellationToken ct)
        {
            if (args.Length == 0 || args[0] is "-h" or "--help" or "help" or "/?")
            {
                if (args.Length > 1 && Commands.All.FirstOrDefault(c => c.Name == args[1]) is { } target) PrintHelp(target);
                else PrintGeneralHelp();
                return 0;
            }
            if (args[0] is "--version" or "version")
            {
                AnsiConsole.WriteLine("WinStorageAudit " + Version);
                return 0;
            }

            var spec = Commands.All.FirstOrDefault(c => c.Name.Equals(args[0], StringComparison.OrdinalIgnoreCase))
                ?? throw new UsageException($"Comando desconocido: {args[0]}. Consulte «winstorageaudit --help».");
            var parsed = ArgParser.Parse(args.Skip(1).ToList(), spec);
            if (parsed.Has("help"))
            {
                PrintHelp(spec);
                return 0;
            }

            return spec.Name switch
            {
                "scan" => await ScanAsync(parsed, ct),
                "analyze" => await AnalyzeAsync(parsed, ct),
                "recommendations" => Recommendations(parsed),
                "top" => Top(parsed),
                "browse" => Browse(),
                "maintenance" => ShowMaintenance(),
                "report" => Report(parsed),
                "history" => History(parsed),
                "config" => Config(parsed),
                _ => 2,
            };
        }

        private static void PrintGeneralHelp()
        {
            AnsiConsole.MarkupLine("[bold]WinStorageAudit[/]: auditoría de almacenamiento para Windows. Solo lectura: nunca borra, mueve ni modifica nada.");
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold]Uso:[/] winstorageaudit <comando> [[opciones]]");
            AnsiConsole.WriteLine();
            var table = new Table { Border = TableBorder.None, ShowHeaders = false }.AddColumn("").AddColumn("");
            foreach (var c in Commands.All) table.AddRow(new Text(c.Name), new Text(c.Summary));
            AnsiConsole.Write(table);
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("Primer uso: [bold]winstorageaudit scan --quick[/] y luego [bold]winstorageaudit report --open[/]");
            AnsiConsole.MarkupLine("Ayuda de un comando: winstorageaudit <comando> --help");
        }

        private static void PrintHelp(CommandSpec spec)
        {
            AnsiConsole.MarkupLine(Markup.Escape(spec.Summary));
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold]Uso:[/] winstorageaudit " + Markup.Escape(spec.Usage));
            if (spec.Options.Count > 0)
            {
                AnsiConsole.WriteLine();
                var table = new Table { Border = TableBorder.None, ShowHeaders = false }.AddColumn("").AddColumn("");
                foreach (var o in spec.Options) table.AddRow(new Text("--" + o.Name + (o.TakesValue ? " " + o.ValueName : "")), new Text(o.Description));
                AnsiConsole.Write(table);
            }
            if (spec.Examples is { Count: > 0 })
            {
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("[bold]Ejemplos:[/]");
                foreach (var e in spec.Examples) AnsiConsole.MarkupLine("  winstorageaudit " + Markup.Escape(e));
            }
        }

        private AuditDependencies BuildDependencies()
        {
            var runner = new ProcessRunner();
            var scanner = new Win32FileScanner();

            // Modo de demostración: todas las ubicaciones se confinan a una carpeta y no se consulta el sistema real.
            var sandbox = Environment.GetEnvironmentVariable("WINSTORAGEAUDIT_SANDBOX_ROOT");
            if (!string.IsNullOrWhiteSpace(sandbox))
            {
                return new AuditDependencies
                {
                    Scanner = scanner,
                    Identity = scanner,
                    Processes = runner,
                    Locations = KnownLocations.UnderRoot(Path.GetFullPath(sandbox)),
                    VolumeReader = VolumeInfoProvider.ForRoots,
                };
            }

            return new AuditDependencies
            {
                Scanner = scanner,
                Identity = scanner,
                Processes = runner,
                Locations = KnownLocationsProvider.Detect(),
                VolumeReader = VolumeInfoProvider.ForRoots,
                AppSources = [new RegistryAppSource(), new AppxAppSource(runner)],
                UsageSources = [new UserAssistSource(), new PrefetchSource()],
                MaintenanceProbe = new WindowsMaintenanceProbe(runner),
                SystemReferences = SystemReferenceProvider.Read,
                AppExecutableEnricher = AppExecutableEnricher.Enrich,
            };
        }

        private List<string> ResolveRoots(ParsedArgs args, AppConfig config, KnownLocations locations)
        {
            var roots = new List<string>();
            foreach (var p in args.All("path"))
            {
                if (p.Length == 0) throw new UsageException("--path no puede estar vacío.");
                roots.Add(PathUtil.Normalize(p));
            }
            foreach (var d in args.All("drive"))
            {
                var letter = d.TrimEnd('\\', '/');
                if (letter.Length != 2 || letter[1] != ':' || !char.IsLetter(letter[0])) throw new UsageException($"Unidad no válida: {d}. Ejemplo: --drive C:");
                roots.Add(letter.ToUpperInvariant() + "\\");
            }
            if (args.Has("profile")) roots.Add(locations.UserProfile);
            if (roots.Count == 0) roots.AddRange(config.DefaultPaths.Count > 0 ? config.DefaultPaths.Select(PathUtil.Normalize) : [locations.UserProfile]);
            return roots;
        }

        private async Task<int> ScanAsync(ParsedArgs args, CancellationToken ct)
        {
            if (args.Has("quick") && args.Has("deep")) throw new UsageException("--quick y --deep son incompatibles.");
            var config = _config.Load();
            var deps = BuildDependencies();
            var mode = args.Has("deep") ? ScanMode.Deep : ScanMode.Quick;
            var request = BuildRequest(args, config, deps.Locations, mode);
            var options = AuditOptions.ForMode(request, config.Thresholds, config.BackupDestinations) with { VerifyBackupHashes = args.Has("verify-hashes") };

            var result = await ExecuteAsync(deps, options, ct);
            if (!args.Has("no-save")) Persist(result);
            Views.ScanSummary(result, config.TopItems);
            AnsiConsole.WriteLine();
            if (!args.Has("no-save")) AnsiConsole.MarkupLine("Siguiente paso: [bold]winstorageaudit report --open[/], [bold]recommendations[/], [bold]top folders[/], [bold]maintenance[/] o [bold]browse[/]");
            return result.Coverage.WasCancelled ? 130 : 0;
        }

        private ScanRequest BuildRequest(ParsedArgs args, AppConfig config, KnownLocations locations, ScanMode mode) => new()
        {
            Roots = ResolveRoots(args, config, locations),
            Mode = mode,
            Exclusions = [.. config.Exclusions, .. args.All("exclude")],
            MaxConcurrency = args.Int("concurrency", config.MaxConcurrency, 1, 32),
            AllowNetworkRoots = args.Has("allow-network"),
        };

        private async Task<int> AnalyzeAsync(ParsedArgs args, CancellationToken ct)
        {
            var module = args.Positionals.FirstOrDefault()?.ToLowerInvariant() ?? throw new UsageException("Indique un módulo: storage, git, backups, apps, duplicates o maintenance.");
            var config = _config.Load();
            var deps = BuildDependencies();
            var request = BuildRequest(args, config, deps.Locations, ScanMode.Quick);
            var off = new AuditOptions { Request = request, Thresholds = config.Thresholds, RunGit = false, RunMaintenance = false, RunApps = false, RunDuplicates = false };

            var options = module switch
            {
                "storage" => off,
                "git" => off with { RunGit = true, GitIncludeIgnored = true, Request = request with { HardLinkCheckMinBytes = long.MaxValue } },
                "backups" => off with { RunGit = true, GitIncludeIgnored = true, BackupDestinations = config.BackupDestinations, VerifyBackups = config.BackupDestinations.Count > 0, VerifyBackupHashes = args.Has("verify-hashes") },
                "apps" => off with { RunApps = true, Request = request with { Roots = args.All("path").Count + args.All("drive").Count > 0 || args.Has("profile") ? request.Roots : [] } },
                "duplicates" => off with { RunDuplicates = true },
                "maintenance" => off with { RunMaintenance = true, MaintenanceExpensive = true, Request = request with { Roots = [] } },
                _ => throw new UsageException($"Módulo desconocido: {module}. Use storage, git, backups, apps, duplicates o maintenance."),
            };

            var result = await ExecuteAsync(deps, options, ct);
            if (args.Has("save")) Persist(result);

            var top = config.TopItems;
            switch (module)
            {
                case "storage":
                    Views.Folders(result.Storage.TopFolders, top, "Carpetas con mayor consumo");
                    Views.Folders(result.Storage.TopFiles, top, "Archivos más grandes");
                    Views.Breakdown(result.Storage.ByCategory, 20, "Por categoría", CategoryLabel);
                    break;
                case "git": Views.Git(result, top); break;
                case "backups": Views.Backups(result, top); break;
                case "apps": Views.Apps(result, top); break;
                case "duplicates": Views.Duplicates(result, top); break;
                case "maintenance": Views.Maintenance(result.Maintenance); break;
            }
            Views.Coverage(result.Coverage, brief: true);
            return result.Coverage.WasCancelled ? 130 : 0;
        }

        private static string CategoryLabel(string key) => Enum.TryParse<StorageCategory>(key, out var c) ? c.Es() : key;

        private static async Task<AuditResult> ExecuteAsync(AuditDependencies deps, AuditOptions options, CancellationToken ct)
        {
            var progress = new ScanProgress();
            var pipeline = new AuditPipeline(deps);
            var run = pipeline.RunAsync(options, progress, ct);

            if (!AnsiConsole.Profile.Capabilities.Interactive || Console.IsOutputRedirected)
            {
                var clock = Stopwatch.StartNew();
                while (!run.IsCompleted)
                {
                    await Task.WhenAny(run, Task.Delay(TimeSpan.FromSeconds(5), CancellationToken.None));
                    if (!run.IsCompleted) await Console.Error.WriteLineAsync($"[{clock.Elapsed:hh\\:mm\\:ss}] {progress.Stage}: {progress.Files:N0} archivos, {PathUtil.FormatBytes(progress.PhysicalBytes)}, {progress.Errors:N0} errores");
                }
                return await run;
            }

            var volumes = deps.VolumeReader(options.Request.Roots);
            var isWholeDrive = options.Request.Roots.Count > 0 && options.Request.Roots.All(r => r.Length <= 3);
            var expected = isWholeDrive ? volumes.Sum(v => v.UsedBytes) : 0;

            await AnsiConsole.Progress()
                .AutoClear(true)
                .Columns(new ProgressBarColumn(), new PercentageColumn(), new TaskDescriptionColumn { Alignment = Justify.Left }, new ElapsedTimeColumn())
                .StartAsync(async context =>
                {
                    var task = context.AddTask("Preparando");
                    task.IsIndeterminate = expected <= 0;
                    task.MaxValue = 100;
                    while (!run.IsCompleted)
                    {
                        var current = progress.CurrentPath;
                        if (current.Length > 42) current = "…" + current[^41..];
                        task.Description = Markup.Escape($"{progress.Stage} · {progress.Files:N0} archivos · {PathUtil.FormatBytes(progress.PhysicalBytes)} · {progress.Errors:N0} errores · {current}");
                        if (expected > 0)
                        {
                            task.IsIndeterminate = progress.Stage != "Enumerando archivos";
                            task.Value = Math.Min(99, (double)progress.PhysicalBytes / expected * 100);
                        }
                        await Task.WhenAny(run, Task.Delay(200, CancellationToken.None));
                    }
                    task.Value = 100;
                });
            return await run;
        }

        private void Persist(AuditResult result)
        {
            _results.Save(result);
            var id = _history.Save(result);
            AnsiConsole.MarkupLine(Markup.Escape($"Análisis guardado (id {id}). Datos: {paths.DataDirectory}"));
        }

        private AuditResult LoadLast() => _results.Load()
            ?? throw new InvalidDataException("No hay resultados guardados. Ejecute primero «winstorageaudit scan».");

        private int Recommendations(ParsedArgs args)
        {
            var result = LoadLast();
            var top = args.Int("top", _config.Load().TopItems);

            if (args.Value("id") is { } id)
            {
                var finding = result.Findings.FirstOrDefault(f => f.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
                if (finding == null) throw new UsageException($"No existe el hallazgo {id}.");
                Views.FindingDetail(finding);
                return 0;
            }

            IEnumerable<Finding> query = result.Findings;
            query = FilterBy(query, args.All("risk"), MapRisk, f => f.RiskLevel);
            query = FilterBy(query, args.All("area"), MapArea, f => f.Category);
            query = FilterBy(query, args.All("class"), MapClass, f => f.Recommendation);
            query = args.Value("sort")?.ToLowerInvariant() switch
            {
                null or "size" => query.OrderByDescending(f => f.EstimatedReclaimableBytes).ThenByDescending(f => f.DetectedSizeBytes),
                "risk" => query.OrderByDescending(f => f.RiskLevel),
                "confidence" => query.OrderByDescending(f => f.Confidence),
                "path" => query.OrderBy(f => f.PathOrResource, StringComparer.OrdinalIgnoreCase),
                var other => throw new UsageException($"--sort no admite «{other}». Use size, risk, confidence o path."),
            };
            var list = query.ToList();

            if (args.Has("interactive"))
            {
                RequireInteractive();
                while (true)
                {
                    var choice = AnsiConsole.Prompt(new SelectionPrompt<Finding?>()
                        .Title("Seleccione un hallazgo (Esc no disponible: elija «Salir»)")
                        .PageSize(18)
                        .UseConverter(f => f == null ? "Salir" : Markup.Escape($"{PathUtil.FormatBytes(f.EstimatedReclaimableBytes),10}  {f.RiskLevel.Es(),-8}  {f.Recommendation.Es()}: {f.PathOrResource}"))
                        .AddChoices([null, .. list]));
                    if (choice == null) return 0;
                    Views.FindingDetail(choice);
                }
            }

            Views.Findings(list, top, "Hallazgos");
            AnsiConsole.MarkupLine(Markup.Escape($"Ocupado: {PathUtil.FormatBytes(result.Reclaim.OccupiedPhysicalBytes)} · Potencialmente recuperable: {PathUtil.FormatBytes(result.Reclaim.CandidateReclaimableBytes)} · Tras revisión: {PathUtil.FormatBytes(result.Reclaim.ReviewReclaimableBytes)} · Liberado: 0 B"));
            AnsiConsole.MarkupLine("[grey]Explicación completa: recommendations --id <Id>[/]");
            return 0;
        }

        private static IEnumerable<Finding> FilterBy<T>(IEnumerable<Finding> source, IReadOnlyList<string> values, Func<string, T> map, Func<Finding, T> selector) where T : struct
        {
            if (values.Count == 0) return source;
            var set = values.SelectMany(v => v.Split(',')).Select(map).ToHashSet();
            return source.Where(f => set.Contains(selector(f)));
        }

        private static string Fold(string s)
        {
            var normalized = s.Trim().ToLowerInvariant().Normalize(NormalizationForm.FormD);
            return new string(normalized.Where(c => System.Globalization.CharUnicodeInfo.GetUnicodeCategory(c) != System.Globalization.UnicodeCategory.NonSpacingMark).ToArray());
        }

        private static RiskLevel MapRisk(string v) => Fold(v) switch
        {
            "bajo" => RiskLevel.Low, "moderado" => RiskLevel.Moderate, "alto" => RiskLevel.High, "critico" => RiskLevel.Critical,
            _ => throw new UsageException($"Riesgo desconocido: {v}. Use bajo, moderado, alto o crítico."),
        };

        private static FindingArea MapArea(string v) => Fold(v) switch
        {
            "descargas" => FindingArea.Downloads, "temporales" => FindingArea.Temporary, "desarrollo" => FindingArea.Development, "residuos" => FindingArea.AppResidue,
            "duplicados" => FindingArea.Duplicates, "grandes" => FindingArea.LargeFiles, "discos" => FindingArea.VirtualDisks, "bases" => FindingArea.Databases,
            "git" => FindingArea.GitBackup, "personales" => FindingArea.PersonalBackup, "aplicaciones" => FindingArea.Applications,
            _ => throw new UsageException($"Área desconocida: {v}. Consulte «recommendations --help»."),
        };

        private static RecommendationClass MapClass(string v) => Fold(v) switch
        {
            "limpieza" => RecommendationClass.CleanupCandidate, "revision" => RecommendationClass.ManualReview, "respaldo" => RecommendationClass.BackupPriority,
            "mantener" => RecommendationClass.Keep, "insuficiente" => RecommendationClass.InsufficientInformation,
            _ => throw new UsageException($"Clasificación desconocida: {v}. Use limpieza, revision, respaldo, mantener o insuficiente."),
        };

        private int Top(ParsedArgs args)
        {
            var what = args.Positionals.FirstOrDefault()?.ToLowerInvariant() ?? "folders";
            var result = LoadLast();
            var top = args.Int("top", _config.Load().TopItems);
            var logical = args.Value("sort")?.ToLowerInvariant() switch
            {
                null or "physical" => false,
                "logical" => true,
                var other => throw new UsageException($"--sort no admite «{other}». Use physical o logical."),
            };
            IEnumerable<StorageItem> Sort(IEnumerable<StorageItem> i) => logical ? i.OrderByDescending(x => x.LogicalBytes) : i.OrderByDescending(x => x.PhysicalBytes);
            IEnumerable<BreakdownEntry> SortB(IEnumerable<BreakdownEntry> i) => logical ? i.OrderByDescending(x => x.LogicalBytes) : i.OrderByDescending(x => x.PhysicalBytes);

            switch (what)
            {
                case "folders": Views.Folders(Sort(result.Storage.TopFolders), top, "Carpetas con mayor consumo (pueden estar anidadas)"); break;
                case "files": Views.Folders(Sort(result.Storage.TopFiles), top, "Archivos más grandes"); break;
                case "concentrations": Views.Folders(Sort(result.Storage.Concentrations), top, "Concentraciones de almacenamiento"); break;
                case "extensions": Views.Breakdown(SortB(result.Storage.ByExtension), top, "Por extensión", k => k); break;
                case "categories": Views.Breakdown(SortB(result.Storage.ByCategory), top, "Por categoría", CategoryLabel); break;
                default: throw new UsageException($"No se reconoce «{what}». Use folders, files, extensions, categories o concentrations.");
            }
            return 0;
        }

        private static void RequireInteractive()
        {
            if (!AnsiConsole.Profile.Capabilities.Interactive || Console.IsInputRedirected)
                throw new UsageException("Este modo necesita una terminal interactiva.");
        }

        private int Browse()
        {
            RequireInteractive();
            var result = LoadLast();
            var stack = new Stack<IReadOnlyList<TreeNode>>();
            IReadOnlyList<TreeNode> level = result.Storage.Tree;
            TreeNode exit = new() { Name = "Salir", FullPath = "" }, up = new() { Name = "..", FullPath = "" };

            while (true)
            {
                var choices = new List<TreeNode> { exit };
                if (stack.Count > 0) choices.Add(up);
                choices.AddRange(level.OrderByDescending(n => n.PhysicalBytes));
                var pick = AnsiConsole.Prompt(new SelectionPrompt<TreeNode>()
                    .Title("Carpetas (físico · archivos · categoría). Solo se conservan las de 10 MiB o más.")
                    .PageSize(20)
                    .UseConverter(n => ReferenceEquals(n, exit) || ReferenceEquals(n, up) ? n.Name : Markup.Escape($"{PathUtil.FormatBytes(n.PhysicalBytes),10}  {n.FileCount,10:N0}  {n.Category.Es(),-24} {n.FullPath}"))
                    .AddChoices(choices));
                if (ReferenceEquals(pick, exit)) return 0;
                if (ReferenceEquals(pick, up))
                {
                    level = stack.Pop();
                    continue;
                }
                if (pick.Children.Count == 0)
                {
                    AnsiConsole.MarkupLine("[grey]Sin subcarpetas conservadas en este nivel.[/]");
                    continue;
                }
                stack.Push(level);
                level = pick.Children;
            }
        }

        private int ShowMaintenance()
        {
            Views.Maintenance(LoadLast().Maintenance);
            return 0;
        }

        private int Report(ParsedArgs args)
        {
            var result = LoadLast();
            var format = args.Value("format")?.ToLowerInvariant() ?? "html";
            var extension = format switch
            {
                "html" => "html", "json" => "json", "plan" => "md",
                _ => throw new UsageException($"Formato desconocido: {format}. Use html, json o plan."),
            };
            var output = args.Value("output");
            if (output == null)
            {
                Directory.CreateDirectory(paths.ReportsDirectory);
                output = Path.Combine(paths.ReportsDirectory, $"winstorageaudit-{(format == "plan" ? "plan" : "reporte")}-{result.FinishedUtc:yyyyMMdd-HHmmss}.{extension}");
            }
            output = Path.GetFullPath(output);
            if (File.Exists(output) && !args.Has("force")) throw new UsageException($"El archivo ya existe y no se reemplazará sin --force: {output}");
            if (Path.GetDirectoryName(output) is { } directory) Directory.CreateDirectory(directory);

            var mode = args.Has("force") ? FileMode.Create : FileMode.CreateNew;
            using (var stream = new FileStream(output, mode, FileAccess.Write, FileShare.None))
            {
                switch (format)
                {
                    case "json":
                        JsonReportWriter.Write(result, stream);
                        break;
                    case "plan":
                        stream.Write(new UTF8Encoding(false).GetBytes(CleanupPlanWriter.Render(result)));
                        break;
                    default:
                        stream.Write(new UTF8Encoding(false).GetBytes(HtmlReportWriter.Render(result, _config.Load().ReportRowLimit)));
                        break;
                }
            }

            AnsiConsole.MarkupLine("Reporte generado: " + Markup.Escape(output));
            AnsiConsole.MarkupLine("[grey]Contiene rutas personales: compártalo con cuidado.[/]");
            if (args.Has("open")) Process.Start(new ProcessStartInfo(output) { UseShellExecute = true })?.Dispose();
            return 0;
        }

        private int History(ParsedArgs args)
        {
            var sub = args.Positionals.FirstOrDefault()?.ToLowerInvariant() ?? "list";
            switch (sub)
            {
                case "list":
                    Views.History(_history.List());
                    return 0;
                case "compare":
                    if (args.Positionals.Count != 3 || !long.TryParse(args.Positionals[1], out var a) || !long.TryParse(args.Positionals[2], out var b))
                        throw new UsageException("Uso: history compare <id antiguo> <id nuevo>");
                    var comparison = _history.Compare(a, b) ?? throw new UsageException("Alguno de los identificadores no existe. Consulte «history list».");
                    Views.Comparison(comparison, _config.Load().TopItems);
                    return 0;
                case "clear":
                    if (!Confirm(args, $"¿Eliminar el historial y el último resultado de {paths.DataDirectory}?")) return 0;
                    var history = _history.Clear();
                    var result = _results.Delete();
                    var reports = 0;
                    if (args.Has("include-reports") && Directory.Exists(paths.ReportsDirectory))
                    {
                        foreach (var f in Directory.EnumerateFiles(paths.ReportsDirectory, "winstorageaudit-*"))
                        {
                            File.Delete(f);
                            reports++;
                        }
                    }
                    AnsiConsole.MarkupLine(Markup.Escape($"Historial: {(history ? "eliminado" : "no existía")}. Último resultado: {(result ? "eliminado" : "no existía")}. Reportes eliminados: {reports}."));
                    return 0;
                default:
                    throw new UsageException($"Subcomando desconocido: {sub}. Use list, compare o clear.");
            }
        }

        private static bool Confirm(ParsedArgs args, string question)
        {
            if (args.Has("yes")) return true;
            if (Console.IsInputRedirected) throw new UsageException("Sin terminal interactiva, use --yes para confirmar.");
            return AnsiConsole.Confirm(Markup.Escape(question), false);
        }

        private int Config(ParsedArgs args)
        {
            var sub = args.Positionals.FirstOrDefault()?.ToLowerInvariant() ?? "show";
            var config = _config.Load();
            string Arg() => args.Positionals.Count >= 2 ? args.Positionals[1] : throw new UsageException($"«config {sub}» requiere un valor.");

            AppConfig Add(List<string> list, string v, Func<List<string>, AppConfig> with)
            {
                var copy = new List<string>(list);
                if (!copy.Contains(v, StringComparer.OrdinalIgnoreCase)) copy.Add(v);
                return with(copy);
            }

            AppConfig Remove(List<string> list, string v, Func<List<string>, AppConfig> with)
            {
                var copy = new List<string>(list);
                if (copy.RemoveAll(x => x.Equals(v, StringComparison.OrdinalIgnoreCase)) == 0) throw new UsageException($"No está configurado: {v}");
                return with(copy);
            }

            switch (sub)
            {
                case "show":
                    Console.WriteLine(JsonSerializer.Serialize(config, AuditJson.Options));
                    return 0;
                case "path":
                    AnsiConsole.WriteLine("Configuración: " + paths.ConfigFile);
                    AnsiConsole.WriteLine("Historial: " + paths.HistoryDatabase);
                    AnsiConsole.WriteLine("Último resultado: " + paths.LastResultFile);
                    AnsiConsole.WriteLine("Reportes: " + paths.ReportsDirectory);
                    return 0;
                case "add-path": config = Add(config.DefaultPaths, PathUtil.Normalize(Arg()), l => config with { DefaultPaths = l }); break;
                case "remove-path": config = Remove(config.DefaultPaths, PathUtil.Normalize(Arg()), l => config with { DefaultPaths = l }); break;
                case "add-exclude": config = Add(config.Exclusions, Arg(), l => config with { Exclusions = l }); break;
                case "remove-exclude": config = Remove(config.Exclusions, Arg(), l => config with { Exclusions = l }); break;
                case "add-backup":
                    var destination = PathUtil.Normalize(Arg());
                    if (destination.StartsWith(@"\\", StringComparison.Ordinal)) throw new UsageException("Los destinos de red no se comparan: la herramienta no accede a unidades de red.");
                    config = Add(config.BackupDestinations, destination, l => config with { BackupDestinations = l });
                    break;
                case "remove-backup": config = Remove(config.BackupDestinations, PathUtil.Normalize(Arg()), l => config with { BackupDestinations = l }); break;
                case "set":
                    if (args.Positionals.Count != 3) throw new UsageException("Uso: config set <clave> <valor>");
                    config = Set(config, args.Positionals[1], args.Positionals[2]);
                    break;
                case "export":
                    var target = Path.GetFullPath(Arg());
                    if (File.Exists(target) && !args.Has("force")) throw new UsageException($"El archivo ya existe; use --force: {target}");
                    File.WriteAllText(target, JsonSerializer.Serialize(config, AuditJson.Options));
                    AnsiConsole.WriteLine("Configuración exportada a " + target);
                    return 0;
                case "reset":
                    if (Confirm(args, "¿Restablecer la configuración?"))
                    {
                        _config.Delete();
                        AnsiConsole.WriteLine("Configuración restablecida.");
                    }
                    return 0;
                default:
                    throw new UsageException($"Subcomando desconocido: {sub}. Consulte «config --help».");
            }

            _config.Save(config);
            AnsiConsole.WriteLine("Configuración actualizada.");
            return 0;
        }

        private static AppConfig Set(AppConfig c, string key, string value)
        {
            int I(int min = 1, int max = 100_000) => int.TryParse(value, out var v) && v >= min && v <= max ? v : throw new UsageException($"{key} requiere un número entre {min} y {max}.");
            long Mb() => long.TryParse(value, out var v) && v > 0 ? v * 1024 * 1024 : throw new UsageException($"{key} requiere un número positivo de MiB.");
            var t = c.Thresholds;
            return key.ToLowerInvariant() switch
            {
                "concurrency" => c with { MaxConcurrency = I(1, 32) },
                "top" => c with { TopItems = I(1, 1000) },
                "report-rows" => c with { ReportRowLimit = I(100, 100_000) },
                "old-download-days" => c with { Thresholds = t with { OldDownloadDays = I() } },
                "stale-file-days" => c with { Thresholds = t with { StaleFileDays = I() } },
                "temp-age-days" => c with { Thresholds = t with { TempAgeDays = I() } },
                "log-age-days" => c with { Thresholds = t with { LogAgeDays = I() } },
                "residue-age-days" => c with { Thresholds = t with { ResidueAgeDays = I() } },
                "active-days" => c with { Thresholds = t with { ActiveEnvironmentDays = I() } },
                "large-file-mb" => c with { Thresholds = t with { LargeFileBytes = Mb() } },
                "min-finding-mb" => c with { Thresholds = t with { MinFindingBytes = Mb() } },
                "duplicate-min-mb" => c with { Thresholds = t with { DuplicateMinBytes = Mb() } },
                "usage-recent-days" => c with { Thresholds = t with { UsageRecentDays = I() } },
                "usage-medium-days" => c with { Thresholds = t with { UsageMediumDays = I() } },
                "usage-long-days" => c with { Thresholds = t with { UsageLongDays = I() } },
                _ => throw new UsageException($"Clave desconocida: {key}. Claves: concurrency, top, report-rows, old-download-days, stale-file-days, temp-age-days, log-age-days, residue-age-days, active-days, large-file-mb, min-finding-mb, duplicate-min-mb, usage-recent-days, usage-medium-days, usage-long-days."),
            };
        }
    }
}
