using System.Text.RegularExpressions;
using WinStorageAudit.Core.Model;
using WinStorageAudit.Core.Scanning;

namespace WinStorageAudit.Core.Cleanup;

internal static class Text
{
    public static string Age(double days) =>
        double.IsInfinity(days) ? "sin fecha disponible" : days >= 365 ? $"hace {days / 365:0.#} años" : $"hace {days:0} días";

    public static string Bytes(long b) => PathUtil.FormatBytes(b);
}

public sealed class DevArtifactRule : IRule
{
    public string Id => "DEV-ARTIFACT";

    public IEnumerable<Finding> Evaluate(RuleContext c)
    {
        var small = new Dictionary<string, (long Bytes, long Reclaim, int Count, List<string> Samples, DevArtifactKind Kind)>();

        foreach (var r in c.Scan.DevResources.Where(r => r.Cache == null && r.Artifact != null).OrderByDescending(r => r.Totals.PhysicalBytes))
        {
            var kind = r.Artifact!;
            var age = c.AgeDays(r.Totals.NewestWriteUtc);
            var recent = age < c.Thresholds.ActiveEnvironmentDays;
            var evidence = new List<string> { "Marcador: " + kind.MarkerEvidence, "Última escritura: " + Text.Age(age) };
            var recommendation = RecommendationClass.CleanupCandidate;
            var confidence = Confidence.Medium;
            var risk = RiskLevel.Low;

            if (r.HasTrackedFiles == true)
            {
                evidence.Add("Git informa archivos versionados dentro de la carpeta: no es solo un resultado generado.");
                recommendation = RecommendationClass.ManualReview;
                risk = RiskLevel.Moderate;
            }
            else if (r.HasTrackedFiles == false)
            {
                evidence.Add("Git confirma que no contiene archivos versionados.");
                confidence = Confidence.High;
            }
            else
            {
                evidence.Add(r.RepoRoot == null ? "Fuera de un repositorio Git: no se pudo confirmar que sea solo un resultado generado." : "No se pudo consultar a Git.");
            }

            if (kind.Kind == ResourceKind.ActiveEnvironment)
            {
                recommendation = RecommendationClass.ManualReview;
                risk = RiskLevel.Moderate;
                confidence = Confidence.Medium;
            }

            if (kind.Id == "node-modules" && !r.ParentMarkers.HasFlag(ProjectMarkers.JsLockFile))
            {
                evidence.Add("Sin archivo de bloqueo: reinstalar podría obtener versiones distintas.");
                recommendation = RecommendationClass.ManualReview;
                risk = RiskLevel.Moderate;
                confidence = Confidence.Medium;
            }

            if (kind.Id == "python-venv" && !r.ParentMarkers.HasFlag(ProjectMarkers.Python))
                evidence.Add("No se encontró requirements.txt ni pyproject.toml junto al entorno: puede ser difícil recrearlo.");

            if (recent)
            {
                evidence.Add($"Actividad en los últimos {c.Thresholds.ActiveEnvironmentDays} días: el proyecto parece activo.");
                if (confidence == Confidence.High) confidence = Confidence.Medium;
                if (kind.Kind == ResourceKind.DownloadedDependency) recommendation = RecommendationClass.ManualReview;
            }

            if (r.Totals.HardLinkedPhysicalBytes > 0)
                evidence.Add($"{Text.Bytes(r.Totals.HardLinkedPhysicalBytes)} con enlaces duros no cuentan como recuperables.");

            if (r.Totals.PhysicalBytes < c.Thresholds.MinFindingBytes)
            {
                if (recommendation == RecommendationClass.CleanupCandidate)
                {
                    var e = small.GetValueOrDefault(kind.Id, (0, 0, 0, new List<string>(), kind));
                    if (e.Item4.Count < 5) e.Item4.Add(r.Path);
                    small[kind.Id] = (e.Item1 + r.Totals.PhysicalBytes, e.Item2 + r.Totals.ReclaimablePhysicalBytes, e.Item3 + 1, e.Item4, kind);
                }
                continue;
            }

            yield return new Finding
            {
                RuleId = Id + ":" + kind.Id,
                Category = FindingArea.Development,
                PathOrResource = r.Path,
                Description = $"{kind.Kind.Es()} de {kind.Tool} con {r.Totals.FileCount:N0} archivos.",
                Relevance = "Ocupa espacio y normalmente se puede reconstruir desde el código del proyecto.",
                Evidence = evidence,
                Recommendation = recommendation,
                Confidence = confidence,
                RiskLevel = risk,
                Reversibility = kind.Reversibility,
                RecommendedAction = kind.RegenerateHint,
                PotentialLoss = kind.Kind == ResourceKind.ActiveEnvironment
                    ? "Paquetes instalados a mano y estado local del entorno."
                    : "Tiempo de reconstrucción; si el proyecto depende de versiones ya no publicadas, podría no reconstruirse igual.",
                DetectedSizeBytes = r.Totals.PhysicalBytes,
                EstimatedReclaimableBytes = r.Totals.ReclaimablePhysicalBytes,
                ResourceKind = kind.Kind,
            };
        }

        foreach (var (id, v) in small.Where(kv => kv.Value.Bytes > 0))
        {
            yield return new Finding
            {
                RuleId = Id + ":" + id + ":aggregate",
                Category = FindingArea.Development,
                PathOrResource = $"({v.Count} carpetas pequeñas de {v.Kind.Tool}: {id})",
                IsAggregate = true,
                RelatedPaths = v.Samples,
                Description = $"{v.Count} carpetas de {v.Kind.Kind.Es().ToLowerInvariant()}, cada una menor que el umbral de reporte individual.",
                Relevance = "Por separado son pequeñas, pero en conjunto pueden sumar espacio.",
                Evidence = ["Marcador: " + v.Kind.MarkerEvidence, "Se muestran solo ejemplos de rutas"],
                Recommendation = RecommendationClass.CleanupCandidate,
                Confidence = Confidence.Medium,
                RiskLevel = RiskLevel.Low,
                Reversibility = v.Kind.Reversibility,
                RecommendedAction = v.Kind.RegenerateHint,
                PotentialLoss = "Tiempo de reconstrucción.",
                DetectedSizeBytes = v.Bytes,
                EstimatedReclaimableBytes = v.Reclaim,
                ResourceKind = v.Kind.Kind,
            };
        }
    }
}

public sealed class DevCacheRule : IRule
{
    public string Id => "DEV-CACHE";

    public IEnumerable<Finding> Evaluate(RuleContext c)
    {
        foreach (var r in c.Scan.DevResources.Where(r => r.Cache != null && r.Totals.PhysicalBytes >= c.Thresholds.MinFindingBytes))
        {
            var def = r.Cache!;
            var evidence = new List<string>
            {
                "Ubicación exacta de la caché de " + def.Tool,
                "Última escritura: " + Text.Age(c.AgeDays(r.Totals.NewestWriteUtc)),
            };
            var recommendation = def.Risk == RiskLevel.Low ? RecommendationClass.CleanupCandidate : RecommendationClass.ManualReview;
            var confidence = def.MaxConfidence;
            if (def.Markers.Length > 0)
            {
                if (r.MarkerSatisfied) evidence.Add("Estructura interna esperada presente: " + string.Join(" o ", def.Markers));
                else
                {
                    evidence.Add("No se halló la estructura interna esperada: " + string.Join(" o ", def.Markers));
                    recommendation = RecommendationClass.ManualReview;
                    confidence = Confidence.Low;
                }
            }

            yield return new Finding
            {
                RuleId = Id + ":" + def.Id,
                Category = FindingArea.Development,
                PathOrResource = r.Path,
                Description = $"{def.Kind.Es()} de {def.Tool} con {r.Totals.FileCount:N0} archivos.",
                Relevance = "La herramienta la mantiene para evitar descargas o cálculos repetidos.",
                Evidence = evidence,
                Recommendation = recommendation,
                Confidence = confidence,
                RiskLevel = def.Risk,
                Reversibility = def.Reversibility,
                RecommendedAction = def.Action,
                PotentialLoss = def.Loss,
                DetectedSizeBytes = r.Totals.PhysicalBytes,
                EstimatedReclaimableBytes = r.Totals.ReclaimablePhysicalBytes,
                ResourceKind = def.Kind,
            };
        }
    }
}

public sealed class UserTempRule : IRule
{
    public string Id => "TMP-USER";

    public IEnumerable<Finding> Evaluate(RuleContext c)
    {
        var limit = c.Thresholds.TempAgeDays;
        long smallBytes = 0, smallReclaim = 0;
        var smallCount = 0;
        var samples = new List<string>();

        foreach (var d in c.Scan.TempChildren.OrderByDescending(d => d.Totals.PhysicalBytes))
        {
            var age = c.AgeDays(d.Totals.NewestWriteUtc);
            if (age < limit || d.Totals.PhysicalBytes == 0) continue;
            if (d.Totals.InaccessibleDirectories > 0) continue;

            if (d.Totals.PhysicalBytes < c.Thresholds.MinFindingBytes)
            {
                smallBytes += d.Totals.PhysicalBytes;
                smallReclaim += d.Totals.ReclaimablePhysicalBytes;
                smallCount++;
                if (samples.Count < 5) samples.Add(d.Path);
                continue;
            }

            yield return Build(d.Path, d.Totals.PhysicalBytes, d.Totals.ReclaimablePhysicalBytes, age, limit, false, []);
        }

        if (smallCount > 0)
            yield return Build($"({smallCount} carpetas temporales pequeñas)", smallBytes, smallReclaim, limit, limit, true, samples);

        var loose = c.Scan.TempLooseFiles;
        if (loose.PhysicalBytes >= c.Thresholds.MinFindingBytes && c.Scan.TempRootScanned is { } tempRoot)
        {
            var age = c.AgeDays(loose.NewestWriteUtc);
            if (age >= limit)
                yield return Build($"({loose.FileCount:N0} archivos sueltos en {tempRoot})", loose.PhysicalBytes, loose.PhysicalBytes, age, limit, true, []);
        }
    }

    private Finding Build(string path, long bytes, long reclaim, double age, int limit, bool aggregate, IReadOnlyList<string> samples) => new()
    {
        RuleId = Id,
        Category = FindingArea.Temporary,
        PathOrResource = path,
        IsAggregate = aggregate,
        RelatedPaths = samples,
        Description = "Contenido del directorio temporal del usuario sin escrituras recientes.",
        Relevance = "Los temporales abandonados no se eliminan solos si la aplicación que los creó no los limpia.",
        Evidence =
        [
            "Ubicado en el directorio TEMP real del usuario (no solo por el nombre)",
            $"Escritura más reciente: {Text.Age(age)} (umbral: {limit} días)",
        ],
        Recommendation = RecommendationClass.CleanupCandidate,
        Confidence = Confidence.Medium,
        RiskLevel = RiskLevel.Low,
        Reversibility = Reversibility.Unknown,
        RecommendedAction = "Usar Configuración > Sistema > Almacenamiento > Archivos temporales, con las aplicaciones cerradas.",
        PotentialLoss = "Algunos programas guardan datos temporales de una instalación o documento sin guardar.",
        DetectedSizeBytes = bytes,
        EstimatedReclaimableBytes = reclaim,
        ResourceKind = ResourceKind.None,
    };
}

public sealed class NamedTempRule : IRule
{
    public string Id => "TMP-NAMED";

    public IEnumerable<Finding> Evaluate(RuleContext c)
    {
        foreach (var d in c.Scan.NamedTempDirectories.Where(d => d.Totals.PhysicalBytes >= c.Thresholds.NamedTempMinBytes))
        {
            yield return new Finding
            {
                RuleId = Id,
                Category = FindingArea.Temporary,
                PathOrResource = d.Path,
                Description = "Carpeta llamada «temp» fuera del directorio temporal del sistema.",
                Relevance = "Un nombre no prueba que el contenido sea desechable; los usuarios también guardan trabajo aquí.",
                Evidence = ["Solo se basa en el nombre de la carpeta", "Última escritura: " + Text.Age(c.AgeDays(d.Totals.NewestWriteUtc))],
                Recommendation = RecommendationClass.ManualReview,
                Confidence = Confidence.Low,
                RiskLevel = RiskLevel.Moderate,
                Reversibility = Reversibility.Unknown,
                RecommendedAction = "Revise el contenido antes de decidir.",
                PotentialLoss = "Cualquier cosa guardada aquí a propósito.",
                DetectedSizeBytes = d.Totals.PhysicalBytes,
                EstimatedReclaimableBytes = d.Totals.ReclaimablePhysicalBytes,
                ResourceKind = ResourceKind.None,
            };
        }
    }
}

public sealed class OldLogRule : IRule
{
    public string Id => "LOG-OLD";

    public IEnumerable<Finding> Evaluate(RuleContext c)
    {
        foreach (var f in c.Scan.LogFiles.Where(f => c.AgeDays(f.LastWriteUtc) >= c.Thresholds.LogAgeDays && !f.IsOnlineOnly).OrderByDescending(f => f.PhysicalBytes))
        {
            yield return new Finding
            {
                RuleId = Id,
                Category = FindingArea.Temporary,
                PathOrResource = f.Path,
                Description = "Registro grande de aplicación sin escrituras recientes.",
                Relevance = "Los registros antiguos suelen tener poco valor, salvo que se investigue un problema.",
                Evidence = ["Extensión .log en datos de aplicación", "Última escritura: " + Text.Age(c.AgeDays(f.LastWriteUtc))],
                Recommendation = RecommendationClass.ManualReview,
                Confidence = Confidence.Medium,
                RiskLevel = RiskLevel.Low,
                Reversibility = Reversibility.Irreversible,
                RecommendedAction = "Si no investiga un problema de esa aplicación, puede eliminarlo con la aplicación cerrada.",
                PotentialLoss = "Información de diagnóstico histórica.",
                DetectedSizeBytes = f.PhysicalBytes,
                EstimatedReclaimableBytes = f.LinkCount > 1 ? 0 : f.PhysicalBytes,
                ResourceKind = ResourceKind.None,
            };
        }
    }
}

public sealed partial class DownloadsRule : IRule
{
    public string Id => "DL";

    [GeneratedRegex(@"^(?<base>.+?)(\s*\(\d+\)|\s*-\s*(copia|copy)(\s*\(\d+\))?)(?<ext>\.[^.]+)?$", RegexOptions.IgnoreCase)]
    private static partial Regex CopyPattern();

    public IEnumerable<Finding> Evaluate(RuleContext c)
    {
        var bySize = c.Scan.DownloadFiles.ToLookup(f => f.LogicalBytes);
        var names = new HashSet<string>(c.Scan.DownloadFiles.Select(f => f.Path), StringComparer.OrdinalIgnoreCase);
        long smallBytes = 0, smallReclaim = 0;
        var smallCount = 0;
        var samples = new List<string>();

        foreach (var f in c.Scan.DownloadFiles.OrderByDescending(f => f.PhysicalBytes))
        {
            if (f.IsOnlineOnly) continue;
            var age = c.AgeDays(f.LastWriteUtc);
            var ext = Path.GetExtension(f.Path);
            var name = Path.GetFileName(f.Path);
            var reclaim = f.LinkCount > 1 ? 0 : f.PhysicalBytes;
            var ageEvidence = $"Modificado por última vez: {Text.Age(age)}";

            var copy = CopyPattern().Match(name);
            if (copy.Success)
            {
                var original = Path.Combine(Path.GetDirectoryName(f.Path)!, copy.Groups["base"].Value + copy.Groups["ext"].Value);
                if (names.Contains(original) && bySize[f.LogicalBytes].Any(o => o.Path.Equals(original, StringComparison.OrdinalIgnoreCase)))
                {
                    yield return Make("DL-COPY", f.Path, f.PhysicalBytes, reclaim,
                        "Posible copia de otra descarga: mismo nombre base y mismo tamaño.",
                        "Las descargas repetidas ocupan espacio sin aportar contenido nuevo.",
                        ["Patrón de nombre de copia", "Mismo tamaño que: " + Path.GetFileName(original), ageEvidence, "El análisis profundo confirma el contenido con hash"],
                        Confidence.Medium, RiskLevel.Low, Reversibility.Unknown,
                        "Compare ambos archivos o ejecute «scan --deep», y conserve al menos una copia.",
                        "Si el contenido fuera distinto, se perdería esa versión.");
                    continue;
                }
            }

            var isInstaller = FileClassifier.IsInstaller(ext);
            var isArchive = FileClassifier.IsArchive(ext);
            if ((isInstaller || isArchive) && age >= c.Thresholds.OldDownloadDays)
            {
                if (f.PhysicalBytes < c.Thresholds.MinFindingBytes)
                {
                    smallBytes += f.PhysicalBytes;
                    smallReclaim += reclaim;
                    smallCount++;
                    if (samples.Count < 5) samples.Add(f.Path);
                    continue;
                }

                var evidence = new List<string> { "Extensión: " + ext.ToLowerInvariant(), ageEvidence };
                if (Math.Abs((f.CreationUtc - f.LastWriteUtc).TotalMinutes) < 10)
                    evidence.Add("Heurística de baja confianza: no parece modificado tras la descarga; quizá fue de un solo uso.");

                if (isArchive)
                {
                    var extracted = Path.Combine(Path.GetDirectoryName(f.Path)!, Path.GetFileNameWithoutExtension(f.Path));
                    if (Directory.Exists(extracted)) evidence.Add("Existe una carpeta con el mismo nombre: quizá ya se extrajo.");
                }

                yield return Make(isInstaller ? "DL-INSTALLER" : "DL-ARCHIVE", f.Path, f.PhysicalBytes, reclaim,
                    isInstaller ? "Instalador descargado hace tiempo." : "Archivo comprimido descargado hace tiempo.",
                    "Antigüedad no significa basura: puede ser una versión o un contenido difícil de volver a obtener.",
                    evidence, Confidence.Low, RiskLevel.Moderate, Reversibility.Unknown,
                    isInstaller ? "Si la aplicación se puede volver a descargar del fabricante, considere eliminarlo." : "Compruebe si lo extrajo o respaldó antes de decidir.",
                    isInstaller ? "Una versión específica que el fabricante ya no publique." : "Contenido que quizá solo exista dentro del archivo.");
                continue;
            }

            if (f.LogicalBytes >= c.Thresholds.LargeDownloadBytes && age >= c.Thresholds.StaleFileDays)
            {
                var personal = FileClassifier.IsSensitiveForDuplicates(ext);
                yield return Make("DL-LARGE", f.Path, f.PhysicalBytes, reclaim,
                    "Descarga grande sin modificaciones recientes.",
                    "Es uno de los mayores consumidores de la carpeta Descargas.",
                    ["Tamaño: " + Text.Bytes(f.LogicalBytes), ageEvidence, "El tamaño y la antigüedad no indican que se pueda eliminar"],
                    Confidence.Low, personal ? RiskLevel.High : RiskLevel.Moderate, Reversibility.Unknown,
                    "Decida si la necesita o si debe moverla a un respaldo.",
                    "El contenido, si no existe otra copia.", personal);
            }
        }

        if (smallCount > 0)
        {
            yield return Make("DL-SMALL", $"({smallCount} instaladores y comprimidos antiguos pequeños)", smallBytes, smallReclaim,
                "Instaladores y archivos comprimidos antiguos, menores que el umbral individual.",
                "En conjunto pueden sumar espacio.",
                [$"Más antiguos que {c.Thresholds.OldDownloadDays} días", "Se muestran solo ejemplos de rutas"],
                Confidence.Low, RiskLevel.Moderate, Reversibility.Unknown, "Revise la carpeta Descargas ordenando por fecha.", "Contenido que no exista en otro lugar.")
                with { IsAggregate = true, RelatedPaths = samples };
        }
    }

    private static Finding Make(string rule, string path, long size, long reclaim, string description, string relevance, IReadOnlyList<string> evidence,
        Confidence confidence, RiskLevel risk, Reversibility reversibility, string action, string loss, bool backup = false) => new()
    {
        RuleId = rule,
        Category = FindingArea.Downloads,
        PathOrResource = path,
        Description = description,
        Relevance = relevance,
        Evidence = evidence,
        Recommendation = RecommendationClass.ManualReview,
        Confidence = confidence,
        RiskLevel = risk,
        Reversibility = reversibility,
        RecommendedAction = action,
        PotentialLoss = loss,
        DetectedSizeBytes = size,
        EstimatedReclaimableBytes = reclaim,
        RequiresBackup = backup,
        ResourceKind = backup ? ResourceKind.IrreplaceableUserData : ResourceKind.None,
    };
}

public sealed class LargeStaleFileRule : IRule
{
    public string Id => "LARGE-STALE";

    public IEnumerable<Finding> Evaluate(RuleContext c)
    {
        foreach (var f in c.Storage.TopFiles.Where(f => f.PhysicalBytes >= c.Thresholds.LargeFileBytes))
        {
            if (f.Category is StorageCategory.OperatingSystem or StorageCategory.Applications or StorageCategory.Downloads
                or StorageCategory.DevCaches or StorageCategory.TemporaryFiles or StorageCategory.DatabasesAndBackups) continue;
            if (FileClassifier.IsVirtualDisk(Path.GetExtension(f.Path))) continue;
            var age = c.AgeDays(f.LastWriteUtc);
            if (age < c.Thresholds.StaleFileDays) continue;

            yield return new Finding
            {
                RuleId = Id,
                Category = FindingArea.LargeFiles,
                PathOrResource = f.Path,
                Description = "Archivo grande sin modificaciones recientes.",
                Relevance = "Identifica dónde se concentra el espacio; no indica que sea prescindible.",
                Evidence = [$"Tamaño: {Text.Bytes(f.PhysicalBytes)}", "Modificado: " + Text.Age(age), "Tipo: " + f.ContentType],
                Recommendation = RecommendationClass.ManualReview,
                Confidence = Confidence.Low,
                RiskLevel = FileClassifier.DefaultRisk(f.Category),
                Reversibility = Reversibility.Unknown,
                RecommendedAction = "Revise si aún lo necesita; si es valioso, respáldelo antes de moverlo o borrarlo.",
                PotentialLoss = "El contenido, si no existe otra copia.",
                DetectedSizeBytes = f.PhysicalBytes,
                EstimatedReclaimableBytes = f.PhysicalBytes,
                RequiresBackup = true,
                ResourceKind = ResourceKind.IrreplaceableUserData,
            };
        }
    }
}

public sealed class VirtualDiskRule : IRule
{
    public string Id => "VD-KEEP";

    public IEnumerable<Finding> Evaluate(RuleContext c)
    {
        foreach (var f in c.Scan.VirtualDisks.Where(f => f.PhysicalBytes >= c.Thresholds.MinFindingBytes).OrderByDescending(f => f.PhysicalBytes))
        {
            var isDocker = f.Path.Contains(@"\Docker\", StringComparison.OrdinalIgnoreCase) || Path.GetFileName(f.Path).StartsWith("docker_data", StringComparison.OrdinalIgnoreCase);
            var isWsl = !isDocker && (f.Path.Contains(@"\Packages\", StringComparison.OrdinalIgnoreCase) || Path.GetFileName(f.Path).Equals("ext4.vhdx", StringComparison.OrdinalIgnoreCase));
            var action = isDocker
                ? "Vea el detalle con «docker system df» y use Docker Desktop o la limpieza oficial de recursos que realmente no use."
                : isWsl
                    ? "Libere espacio dentro de la distribución y considere «wsl --manage <distribución> --set-sparse true»; respalde antes con «wsl --export»."
                    : "Administre este disco con la herramienta de virtualización que lo creó.";

            yield return new Finding
            {
                RuleId = Id,
                Category = FindingArea.VirtualDisks,
                PathOrResource = f.Path,
                Description = isDocker ? "Disco virtual de Docker Desktop." : isWsl ? "Disco virtual de una distribución WSL." : "Imagen de disco de una máquina virtual.",
                Relevance = "Un disco virtual contiene un sistema de archivos completo. No es basura aunque parezca muy grande.",
                Evidence = ["Extensión de disco virtual: " + Path.GetExtension(f.Path).ToLowerInvariant(), "Última escritura: " + Text.Age(c.AgeDays(f.LastWriteUtc))],
                Recommendation = RecommendationClass.Keep,
                Confidence = Confidence.High,
                RiskLevel = RiskLevel.Critical,
                Reversibility = Reversibility.Irreversible,
                RecommendedAction = action,
                PotentialLoss = "Eliminar el archivo destruye todo lo que contiene: imágenes, volúmenes, bases de datos y datos de usuario.",
                DetectedSizeBytes = f.PhysicalBytes,
                EstimatedReclaimableBytes = 0,
                RequiresBackup = true,
                ResourceKind = ResourceKind.PersistentAppData,
            };
        }
    }
}

public sealed class DatabaseRule : IRule
{
    public string Id => "DB-KEEP";

    public IEnumerable<Finding> Evaluate(RuleContext c)
    {
        foreach (var f in c.Scan.Databases.Where(f => f.PhysicalBytes >= c.Thresholds.MinFindingBytes).OrderByDescending(f => f.PhysicalBytes))
        {
            yield return new Finding
            {
                RuleId = Id,
                Category = FindingArea.Databases,
                PathOrResource = f.Path,
                Description = "Base de datos o archivo de respaldo.",
                Relevance = "Puede contener información que no se puede regenerar. Su contenido no se ha leído.",
                Evidence = ["Extensión: " + Path.GetExtension(f.Path).ToLowerInvariant(), "Última escritura: " + Text.Age(c.AgeDays(f.LastWriteUtc))],
                Recommendation = RecommendationClass.Keep,
                Confidence = Confidence.Medium,
                RiskLevel = RiskLevel.High,
                Reversibility = Reversibility.Irreversible,
                RecommendedAction = "Consérvelo. Si necesita espacio, use las herramientas de la aplicación propietaria y respalde primero.",
                PotentialLoss = "Datos persistentes de la aplicación o del usuario.",
                DetectedSizeBytes = f.PhysicalBytes,
                EstimatedReclaimableBytes = 0,
                RequiresBackup = true,
                ResourceKind = ResourceKind.PersistentAppData,
            };
        }
    }
}

public sealed partial class AppResidueRule : IRule
{
    public string Id => "RES-ORPHAN";

    private static readonly HashSet<string> SharedFolders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft", "Windows", "Packages", "Temp", "Programs", "Common Files", "Microsoft.NET", "WindowsApps", "dotnet",
        "NuGet", "npm", "npm-cache", "pip", "pnpm", "Yarn", "Docker", "DockerDesktop", "JetBrains", "Code", "Comms",
        "ConnectedDevicesPlatform", "D3DSCache", "CrashDumps", "Publishers", "Package Cache", "Application Data",
        "USOShared", "USOPrivate", "ssh", "regid.1991-06.com.microsoft", "PeerDistRepub", "Pub", "Python", "Git",
        "Windows Defender", "Windows NT", "Windows Mail", "Windows Media Player", "Windows Photo Viewer", "Windows Sidebar",
        "WindowsPowerShell", "ModifiableWindowsApps", "Reference Assemblies", "MSBuild", "Internet Explorer", "Uninstall Information",
        "History", "IconCache", "Claude", "SoftwareDistribution", "Application Verifier", "Adobe", "Google", "Mozilla", "Nvidia", "NVIDIA Corporation", "Intel",
    };

    [GeneratedRegex("[^a-z0-9]+")]
    private static partial Regex NonAlnum();

    private static string Key(string? s) => s == null ? "" : NonAlnum().Replace(s.ToLowerInvariant(), "");

    public IEnumerable<Finding> Evaluate(RuleContext c)
    {
        if (c.Apps is not { Evaluated: true } apps || apps.Apps.Count == 0) yield break;

        var names = apps.Apps.SelectMany(a => new[] { Key(a.Name), Key(a.Publisher), Key(Path.GetFileName(a.InstallLocation?.TrimEnd('\\') ?? "")) })
            .Where(k => k.Length >= 3).Distinct().ToList();
        var locations = apps.Apps.Select(a => a.InstallLocation?.TrimEnd('\\')).Where(l => !string.IsNullOrEmpty(l)).Select(l => l!).ToList();

        foreach (var f in c.Scan.AppDataFolders.Where(f => f.Totals.PhysicalBytes >= c.Thresholds.ResidueMinBytes).OrderByDescending(f => f.Totals.PhysicalBytes))
        {
            var folder = Path.GetFileName(f.Path);
            if (SharedFolders.Contains(folder) || folder.StartsWith('.') || f.Totals.InaccessibleDirectories > 0) continue;
            var age = c.AgeDays(f.Totals.NewestWriteUtc);
            if (age < c.Thresholds.ResidueAgeDays) continue;
            if (locations.Any(l => PathUtil.IsSameOrUnder(l, f.Path) || PathUtil.IsSameOrUnder(f.Path, l))) continue;
            if (c.SystemReferences.Any(r => r.Contains(f.Path, StringComparison.OrdinalIgnoreCase))) continue;

            var key = Key(folder);
            if (key.Length < 3 || names.Any(n => n.Contains(key) || (n.Length >= 4 && key.Contains(n)))) continue;

            var hasExecutables = f.Totals.ExecutableCount > 0;
            yield return new Finding
            {
                RuleId = Id,
                Category = FindingArea.AppResidue,
                PathOrResource = f.Path,
                Description = "Carpeta de aplicación sin relación aparente con el software instalado.",
                Relevance = "Podría ser un resto de una aplicación desinstalada. El nombre no basta para afirmarlo; por eso se combinan varias evidencias.",
                Evidence =
                [
                    $"Sin coincidencia con {apps.Apps.Count} aplicaciones inventariadas (nombre, editor, ubicación)",
                    "Sin referencias en PATH ni en servicios de Windows",
                    "Escritura más reciente: " + Text.Age(age),
                    hasExecutables ? $"Contiene {f.Totals.ExecutableCount} ejecutables: podría ser una aplicación portable" : "No contiene ejecutables",
                ],
                Recommendation = RecommendationClass.ManualReview,
                Confidence = hasExecutables ? Confidence.Low : Confidence.Medium,
                RiskLevel = RiskLevel.Moderate,
                Reversibility = Reversibility.Irreversible,
                RecommendedAction = "Identifique a qué aplicación pertenece; respalde o mueva la carpeta temporalmente antes de borrarla definitivamente.",
                PotentialLoss = "Ajustes, licencias o datos guardados por una aplicación que quizá siga en uso.",
                DetectedSizeBytes = f.Totals.PhysicalBytes,
                EstimatedReclaimableBytes = f.Totals.ReclaimablePhysicalBytes,
                RequiresBackup = true,
                ResourceKind = ResourceKind.PersistentAppData,
            };
        }
    }
}

public sealed class DuplicateRule : IRule
{
    public string Id => "DUP-CONFIRMED";

    public IEnumerable<Finding> Evaluate(RuleContext c)
    {
        foreach (var g in c.Duplicates.Groups.OrderByDescending(g => g.RedundantBytes))
        {
            var allInDownloads = g.Paths.All(p => PathUtil.IsSameOrUnder(p, c.Locations.Downloads));
            var candidate = !g.ContainsSensitiveContent && allInDownloads;
            var keep = g.Paths.OrderBy(p => p.Length).First();
            yield return new Finding
            {
                RuleId = Id,
                Category = FindingArea.Duplicates,
                PathOrResource = g.Paths[0],
                RelatedPaths = g.Paths,
                Description = $"{g.Paths.Count} copias idénticas de {Text.Bytes(g.FileSizeBytes)} cada una.",
                Relevance = "Mantener varias copias en el mismo disco ocupa espacio y no protege contra su fallo.",
                Evidence =
                [
                    "Mismo tamaño, misma firma parcial y mismo hash SHA-256 completo",
                    "Son archivos físicos distintos (no enlaces duros)",
                ],
                Recommendation = candidate ? RecommendationClass.CleanupCandidate : RecommendationClass.ManualReview,
                Confidence = candidate ? Confidence.Medium : Confidence.Low,
                RiskLevel = g.ContainsSensitiveContent ? RiskLevel.High : RiskLevel.Low,
                Reversibility = Reversibility.Unknown,
                RecommendedAction = $"Conserve al menos una copia (por ejemplo, {keep}). Nunca elimine todas.",
                PotentialLoss = g.ContainsSensitiveContent
                    ? "Contenido personal: la organización en carpetas puede ser intencional."
                    : "Una aplicación podría esperar el archivo en esa ruta concreta.",
                DetectedSizeBytes = g.FileSizeBytes * g.Paths.Count,
                EstimatedReclaimableBytes = g.RedundantBytes,
                RequiresBackup = g.ContainsSensitiveContent,
                ResourceKind = g.ContainsSensitiveContent ? ResourceKind.IrreplaceableUserData : ResourceKind.None,
            };
        }
    }
}
