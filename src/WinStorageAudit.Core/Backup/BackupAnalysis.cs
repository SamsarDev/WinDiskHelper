using System.Security.Cryptography;
using WinStorageAudit.Core.Cleanup;
using WinStorageAudit.Core.Model;
using WinStorageAudit.Core.Scanning;

namespace WinStorageAudit.Core.Backup;

/// <summary>
/// Compara archivos personales con destinos locales de respaldo configurados por el usuario.
/// Solo «Copia verificada» implica contenido comprobado, y solo tras una comparación por hash solicitada.
/// </summary>
public sealed class BackupVerifier(IFileScanner scanner)
{
    private sealed class DestinationIndexer : IScanObserver
    {
        private readonly Lock _lock = new();
        public Dictionary<string, List<(string Path, long Bytes, DateTime Write, bool Online)>> ByName { get; } = new(StringComparer.OrdinalIgnoreCase);
        public DirectoryContext EnterDirectory(DirectorySnapshot s, DirectoryContext? p) => new() { Path = s.FullPath, Depth = (p?.Depth ?? -1) + 1 };

        public void ExitDirectory(DirectorySnapshot s, DirectoryContext c, DirectoryTotals t)
        {
            lock (_lock)
            {
                foreach (var f in s.Files)
                {
                    if (!ByName.TryGetValue(f.Name, out var list)) ByName[f.Name] = list = [];
                    list.Add((Path.Combine(s.FullPath, f.Name), f.LogicalBytes, f.LastWriteUtc, f.IsOnlineOnly));
                }
            }
        }
    }

    public async Task VerifyAsync(IReadOnlyList<PersonalFileRecord> files, IReadOnlyList<string> destinations, bool verifyHashes,
        KnownLocations locations, CoverageTracker coverage, CancellationToken ct)
    {
        var indexer = new DestinationIndexer();
        var usable = destinations.Where(Directory.Exists).ToList();
        foreach (var missing in destinations.Except(usable, StringComparer.OrdinalIgnoreCase))
            coverage.Report(ScanIssueKind.NotFound, missing, "Destino de respaldo no disponible.");

        if (usable.Count > 0)
            await scanner.ScanAsync(new ScanRequest { Roots = usable, Mode = ScanMode.Quick, AllowNetworkRoots = false }, indexer, new ScanProgress(), coverage, ct);

        foreach (var file in files)
        {
            ct.ThrowIfCancellationRequested();
            if (usable.Any(d => PathUtil.IsSameOrUnder(file.Path, d))) continue;
            await EvaluateAsync(file, indexer, usable.Count > 0, verifyHashes, locations, ct);
        }
    }

    private static async Task EvaluateAsync(PersonalFileRecord file, DestinationIndexer index, bool hasDestinations, bool verifyHashes, KnownLocations loc, CancellationToken ct)
    {
        var inSync = loc.CloudSyncRoots.Any(r => PathUtil.IsSameOrUnder(file.Path, r));
        if (!hasDestinations)
        {
            if (inSync)
            {
                file.BackupState = BackupState.NotVerifiable;
                file.BackupDetail = "Está en una carpeta sincronizada: eso no garantiza un respaldo remoto válido ni que se conserven versiones.";
            }
            else file.BackupState = BackupState.NotEvaluated;
            return;
        }

        var name = Path.GetFileName(file.Path);
        var matches = index.ByName.GetValueOrDefault(name)?.Where(m => m.Bytes == file.Bytes).ToList() ?? [];
        if (matches.Count == 0)
        {
            file.BackupState = inSync ? BackupState.NotVerifiable : BackupState.NoCopyFound;
            file.BackupDetail = inSync ? "Sin copia en los destinos; la carpeta sincronizada no se puede verificar." : null;
            return;
        }

        var local = matches.Where(m => !m.Online).ToList();
        if (local.Count == 0 || file.IsOnlineOnly)
        {
            file.BackupState = BackupState.NotVerifiable;
            file.BackupDetail = "Hay una coincidencia, pero el contenido no está disponible localmente y no se descargará para comprobarlo.";
            return;
        }

        var sameDate = local.Where(m => Math.Abs((m.Write - file.LastWriteUtc).TotalSeconds) <= 2).ToList();
        file.BackupState = BackupState.PossibleCopy;
        file.BackupDetail = (sameDate.Count > 0 ? "Mismo nombre, tamaño y fecha en: " : "Mismo nombre y tamaño, distinta fecha, en: ") + (sameDate.Count > 0 ? sameDate : local)[0].Path;

        if (!verifyHashes) return;
        var source = await HashOrNullAsync(file.Path, ct);
        if (source == null) return;
        foreach (var candidate in sameDate.Concat(local).DistinctBy(m => m.Path).Take(3))
        {
            if (await HashOrNullAsync(candidate.Path, ct) is { } h && h.SequenceEqual(source))
            {
                file.BackupState = BackupState.VerifiedCopy;
                file.BackupDetail = "Contenido idéntico (SHA-256) en: " + candidate.Path;
                return;
            }
        }
        file.BackupDetail = "Mismo nombre y tamaño, pero contenido distinto o ilegible.";
    }

    private static async Task<byte[]?> HashOrNullAsync(string path, CancellationToken ct)
    {
        try
        {
            await using var s = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            return await SHA256.HashDataAsync(s, ct);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }
}

public static class BackupReportBuilder
{
    public static BackupReport Build(ScanCollector scan, IReadOnlyList<GitRepositoryStatus> repositories, IReadOnlyList<string> destinations, bool hashesVerified)
    {
        var groups = scan.PersonalTotals.Select(kv =>
        {
            var folders = scan.PersonalFolderBytes.Where(f => f.Key.Kind == kv.Key).OrderByDescending(f => f.Value).Take(5).Select(f => f.Key.Folder).ToList();
            var largest = scan.PersonalFiles.Where(f => f.Kind == kv.Key).OrderByDescending(f => f.Bytes).Take(20).ToList();
            return new PersonalFileGroup
            {
                Kind = kv.Key,
                Bytes = kv.Value.Bytes,
                FileCount = kv.Value.Count,
                OnlineOnlyCount = kv.Value.Online,
                TopFolders = folders,
                Largest = largest,
            };
        }).OrderByDescending(g => g.Bytes).ToList();

        return new BackupReport
        {
            PersonalGroups = groups,
            StateCounts = scan.PersonalFiles.GroupBy(f => f.BackupState).ToDictionary(g => g.Key, g => (long)g.Count()),
            Destinations = destinations,
            Priorities = BuildPriorities(scan, repositories),
            Unprotected = [.. scan.PersonalFiles.Where(f => f.BackupState is BackupState.NoCopyFound or BackupState.NotVerifiable or BackupState.NotEvaluated).OrderByDescending(f => f.Bytes).Take(500)],
            HashesVerified = hashesVerified,
        };
    }

    public static int GitPriorityScore(GitRepositoryStatus r)
    {
        if (r.Error != null) return 3;
        var score = 0;
        if (r.Remotes.Count == 0) score += 100;
        if (r.HasUncommittedWork) score += 30;
        if (r.UntrackedFiles > 0) score += 15;
        if (r.StashCount > 0) score += 20;
        if (r.Remotes.Count > 0 && r.UnpublishedCommitsTotal > 0) score += 25;
        if (r.SensitiveIgnored.Count > 0) score += 10;
        return score;
    }

    private static List<BackupPriority> BuildPriorities(ScanCollector scan, IReadOnlyList<GitRepositoryStatus> repositories)
    {
        var entries = new List<(int Score, string Target, string Reason, long Size)>();
        foreach (var r in repositories)
        {
            var score = GitPriorityScore(r);
            if (score > 0) entries.Add((score, r.Path, string.Join("; ", r.States.Where(s => !s.StartsWith("Estado remoto", StringComparison.Ordinal))), r.SizeBytes));
        }

        foreach (var g in scan.PersonalTotals.OrderByDescending(kv => kv.Value.Bytes))
        {
            var unprotected = scan.PersonalFiles.Where(f => f.Kind == g.Key && f.BackupState != BackupState.VerifiedCopy).ToList();
            if (unprotected.Count == 0) continue;
            var score = g.Key switch
            {
                PersonalKind.Database or PersonalKind.Configuration => 40,
                PersonalKind.Photo or PersonalKind.Video or PersonalKind.Creative or PersonalKind.Design => 35,
                PersonalKind.Office or PersonalKind.Pdf => 30,
                _ => 10,
            };
            var states = unprotected.GroupBy(f => f.BackupState).OrderByDescending(s => s.Count()).Select(s => $"{s.Count():N0}: {s.Key.Es().ToLowerInvariant()}");
            var folder = scan.PersonalFolderBytes.Where(f => f.Key.Kind == g.Key).OrderByDescending(f => f.Value).Select(f => f.Key.Folder).FirstOrDefault();
            entries.Add((score, g.Key.Es() + (folder == null ? "" : " (principal: " + folder + ")"), string.Join(", ", states) + ". No se pueden regenerar si se pierde el equipo.", unprotected.Sum(f => f.Bytes)));
        }

        var rank = 1;
        return [.. entries.OrderByDescending(e => e.Score).ThenByDescending(e => e.Size).Take(50).Select(e => new BackupPriority(rank++, e.Target, e.Reason, e.Size))];
    }
}
