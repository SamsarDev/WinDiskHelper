using WinStorageAudit.Core.Model;

namespace WinStorageAudit.Core.Scanning;

public sealed record DevResourceRecord
{
    public required string Path { get; init; }
    public DevArtifactKind? Artifact { get; init; }
    public KnownCacheDefinition? Cache { get; init; }
    public bool MarkerSatisfied { get; init; }
    public string? RepoRoot { get; init; }
    public ProjectMarkers ParentMarkers { get; init; }
    public required DirectoryTotals Totals { get; init; }

    /// <summary>Resultado de consultar a Git si contiene archivos versionados. Null: sin repositorio o sin consultar.</summary>
    public bool? HasTrackedFiles { get; set; }
}

public sealed record RetainedFile(string Path, long LogicalBytes, long PhysicalBytes, DateTime CreationUtc, DateTime LastWriteUtc, int LinkCount, bool IsOnlineOnly, bool IsRepeatedHardLink);

public sealed record RepoCandidate(string Path, bool IsBare, bool GitIsFile, string? ParentRepo, DirectoryTotals Totals);

public sealed record AppDataFolderRecord(string Path, string ParentZoneName, DirectoryTotals Totals);

public sealed record DirectoryCandidate(string Path, DirectoryTotals Totals);

/// <summary>Límites de memoria: el recorrido nunca retiene todos los archivos del disco.</summary>
public sealed record CollectorLimits
{
    public int TopFiles { get; init; } = 200;
    public int TopFolders { get; init; } = 300;
    public int MaxTreeDepth { get; init; } = 6;
    public long MinTreeNodeBytes { get; init; } = 10 * 1024 * 1024;
    public int MaxExtensions { get; init; } = 5000;
    public int MaxPersonalFiles { get; init; } = 200_000;
    public int MaxDownloadFiles { get; init; } = 20_000;
    public int MaxDuplicateCandidates { get; init; } = 500_000;
    public long DuplicateMinBytes { get; init; } = 1024 * 1024;
    public long LogMinBytes { get; init; } = 10 * 1024 * 1024;
}

/// <summary>Agrega los lotes del recorrido en estructuras acotadas. Es seguro para llamadas concurrentes.</summary>
public sealed class ScanCollector : IScanObserver
{
    private sealed class Bucket { public long Logical, Physical, Count; }

    private readonly Lock _lock = new();
    private readonly KnownLocations _loc;
    private readonly CollectorLimits _limits;
    private readonly bool _collectDuplicates;
    private readonly KnownCacheCatalog _caches;
    private readonly Dictionary<string, DirectoryZone> _zoneRoots = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _appDataParents = new(StringComparer.OrdinalIgnoreCase);
    private readonly PriorityQueue<RetainedFile, long> _topFiles = new();
    private readonly PriorityQueue<(string Path, DirectoryTotals Totals, StorageCategory Cat, string Label, RiskLevel Risk, string? Evidence), long> _topFolders = new();
    private readonly Dictionary<string, Bucket> _byExtension = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<StorageCategory, Bucket> _byCategory = [];
    private readonly List<TreeNode> _rootNodes = [];
    private readonly DirectoryTotals _grand = new();
    private long _repeatedHardLinkLogical;

    public List<DevResourceRecord> DevResources { get; } = [];
    public List<RepoCandidate> Repositories { get; } = [];
    public List<RetainedFile> DownloadFiles { get; } = [];
    public List<DirectoryCandidate> TempChildren { get; } = [];
    public DirectoryTotals TempLooseFiles { get; } = new();
    public string? TempRootScanned { get; private set; }
    public List<DirectoryCandidate> NamedTempDirectories { get; } = [];
    public List<RetainedFile> LogFiles { get; } = [];
    public List<AppDataFolderRecord> AppDataFolders { get; } = [];
    public List<RetainedFile> VirtualDisks { get; } = [];
    public List<RetainedFile> Databases { get; } = [];
    public List<PersonalFileRecord> PersonalFiles { get; } = [];
    public long PersonalFilesDropped { get; private set; }
    public long DownloadFilesDropped { get; private set; }
    public Dictionary<PersonalKind, (long Bytes, long Count, long Online)> PersonalTotals { get; } = [];
    public Dictionary<(PersonalKind Kind, string Folder), long> PersonalFolderBytes { get; } = [];
    public List<RetainedFile> DuplicateCandidates { get; } = [];
    public long DuplicateCandidatesDropped { get; private set; }

    public ScanCollector(KnownLocations locations, CollectorLimits? limits = null, bool collectDuplicates = false)
    {
        _loc = locations;
        _limits = limits ?? new CollectorLimits();
        _collectDuplicates = collectDuplicates;
        _caches = new KnownCacheCatalog(locations);
        void Zone(string path, DirectoryZone zone) { if (!string.IsNullOrEmpty(path)) _zoneRoots[path.TrimEnd('\\')] = zone; }
        Zone(locations.WindowsDirectory, DirectoryZone.System);
        Zone(locations.ProgramFiles, DirectoryZone.ProgramFiles);
        Zone(locations.ProgramFilesX86, DirectoryZone.ProgramFiles);
        Zone(locations.ProgramData, DirectoryZone.AppData);
        Zone(locations.LocalAppData, DirectoryZone.AppData);
        Zone(locations.RoamingAppData, DirectoryZone.AppData);
        Zone(locations.Temp, DirectoryZone.Temp);
        Zone(locations.Downloads, DirectoryZone.Downloads);
        foreach (var p in new[] { locations.ProgramFiles, locations.ProgramFilesX86, locations.ProgramData, locations.LocalAppData, locations.RoamingAppData })
            if (!string.IsNullOrEmpty(p)) _appDataParents.Add(p.TrimEnd('\\'));
    }

    private DirectoryZone ZoneFor(string path, DirectoryContext? parent)
    {
        if (_zoneRoots.TryGetValue(path, out var exact)) return exact;
        if (parent != null) return parent.Zone;

        // Raíz del análisis: puede estar dentro de cualquier zona conocida. Gana la más específica.
        var best = DirectoryZone.Normal;
        var bestLength = -1;
        foreach (var (root, zone) in _zoneRoots)
        {
            if (root.Length > bestLength && PathUtil.IsSameOrUnder(path, root)) { best = zone; bestLength = root.Length; }
        }
        return best;
    }

    public DirectoryContext EnterDirectory(DirectorySnapshot s, DirectoryContext? parent)
    {
        var zone = ZoneFor(s.FullPath, parent);
        var inGit = parent?.InGitInternals == true || s.Name.Equals(".git", StringComparison.OrdinalIgnoreCase);
        var repo = parent == null ? FindEnclosingRepository(s.FullPath) : parent.RepoRoot;
        var insideDev = parent?.InsideDevResource == true;
        DevArtifactKind? artifact = null;
        KnownCacheDefinition? cache = null;
        var satisfied = false;
        var isDevRoot = false;

        if (!inGit && !insideDev)
        {
            cache = _caches.Match(s.FullPath, s.Name);
            if (cache != null)
            {
                satisfied = cache.Markers.Length == 0 || cache.Markers.Any(s.HasSubdirectory);
                isDevRoot = true;
            }
            else if (zone is DirectoryZone.Normal or DirectoryZone.Downloads && parent?.SuppressArtifacts != true)
            {
                artifact = DevArtifactCatalog.Detect(s.Name, parent?.Markers ?? ProjectMarkers.None, s);
                if (artifact != null) { isDevRoot = true; satisfied = true; }
            }
        }

        // Lo instalado por herramientas no es un proyecto: el «dist» de una extensión o paquete es su código en uso.
        var suppress = parent?.SuppressArtifacts == true || (artifact == null && IsToolManaged(s, parent));

        var gitDirExists = s.HasSubdirectory(".git");
        var gitFileExists = !gitDirExists && !inGit && !insideDev && !isDevRoot && HasValidGitFile(s);
        var bare = !gitDirExists && !gitFileExists && !inGit && s.Name.EndsWith(".git", StringComparison.OrdinalIgnoreCase)
            && s.HasFile("HEAD") && s.HasFile("config") && s.HasSubdirectory("objects") && s.HasSubdirectory("refs");
        var isRepoRoot = !inGit && !insideDev && !isDevRoot && (gitDirExists || gitFileExists || bare);
        if (isRepoRoot) repo = s.FullPath;

        return new DirectoryContext
        {
            Path = s.FullPath,
            Depth = (parent?.Depth ?? -1) + 1,
            Parent = parent,
            Zone = zone,
            InGitInternals = inGit,
            RepoRoot = repo,
            Artifact = artifact ?? parent?.Artifact,
            Cache = cache ?? parent?.Cache,
            InsideDevResource = insideDev || isDevRoot,
            IsDevResourceRoot = isDevRoot,
            SuppressArtifacts = suppress,
            MarkerSatisfied = satisfied,
            Markers = inGit ? ProjectMarkers.None : MarkerDetector.Detect(s.Files),
        };
    }

    /// <summary>
    /// Un archivo .git de un worktree o submódulo empieza por «gitdir:». Otras herramientas (la caché de uv)
    /// dejan un .git vacío como marcador. Solo se leen los primeros bytes de este archivo de metadatos.
    /// </summary>
    private static bool HasValidGitFile(DirectorySnapshot s)
    {
        var file = s.Files.FirstOrDefault(f => f.Name.Equals(".git", StringComparison.OrdinalIgnoreCase));
        if (file == null || file.LogicalBytes == 0 || file.IsOnlineOnly) return false;
        try
        {
            using var stream = new FileStream(Path.Combine(s.FullPath, ".git"), FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            Span<byte> head = stackalloc byte[7];
            return stream.Read(head) == 7 && head.SequenceEqual("gitdir:"u8);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return true; // Si no se puede leer, se informará como repositorio no verificable.
        }
    }

    /// <summary>Una raíz de análisis puede estar dentro de un repositorio: sus artefactos también se comprueban con Git.</summary>
    private static string? FindEnclosingRepository(string path)
    {
        foreach (var ancestor in PathUtil.Ancestors(path))
        {
            var marker = Path.Combine(ancestor, ".git");
            if (Directory.Exists(marker) || File.Exists(marker)) return ancestor;
        }
        return null;
    }

    private bool IsToolManaged(DirectorySnapshot s, DirectoryContext? parent)
    {
        if (s.Name.Equals("node_modules", StringComparison.OrdinalIgnoreCase) || s.Name.Equals("site-packages", StringComparison.OrdinalIgnoreCase)
            || s.Name.Equals(".pnpm", StringComparison.OrdinalIgnoreCase) || s.Name.Equals("extensions", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Carpetas ocultas del perfil (.vscode, .cursor, .claude…): pertenecen a herramientas, no a proyectos del usuario.
        var parentPath = parent?.Path ?? Path.GetDirectoryName(s.FullPath);
        return s.Name.StartsWith('.') && parentPath != null && parentPath.Equals(_loc.UserProfile.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
    }

    public void ExitDirectory(DirectorySnapshot s, DirectoryContext ctx, DirectoryTotals totals)
    {
        lock (_lock)
        {
            ProcessFiles(s, ctx);
            RecordDirectory(s, ctx, totals);
        }
    }

    private void ProcessFiles(DirectorySnapshot s, DirectoryContext ctx)
    {
        foreach (var f in s.Files)
        {
            var ext = Path.GetExtension(f.Name);
            var category = FileClassifier.ForFile(ctx, ext);
            AddBucket(_byCategory, category, f);
            ctx.CategoryBytes[(int)category] += f.PhysicalBytes;
            var extKey = ext.Length == 0 ? "(sin extensión)" : ext.ToLowerInvariant();
            if (_byExtension.Count < _limits.MaxExtensions || _byExtension.ContainsKey(extKey))
                AddToBucket(GetOrAdd(_byExtension, extKey), f);
            else
                AddToBucket(GetOrAdd(_byExtension, "(otras extensiones)"), f);

            if (f.IsRepeatedHardLink) { _repeatedHardLinkLogical += f.LogicalBytes; continue; }
            if (f.IsLink) continue;

            var retained = new Lazy<RetainedFile>(() => Retain(s, f));
            OfferTopFile(f, retained);

            var systemLike = ctx.Zone is DirectoryZone.System or DirectoryZone.ProgramFiles;
            var free = !ctx.InGitInternals && !ctx.InsideDevResource;

            if (FileClassifier.IsVirtualDisk(ext) && !systemLike) VirtualDisks.Add(retained.Value);

            if (ctx.Zone == DirectoryZone.Downloads && free && f.LogicalBytes >= 1024 * 1024)
            {
                if (DownloadFiles.Count < _limits.MaxDownloadFiles) DownloadFiles.Add(retained.Value);
                else DownloadFilesDropped++;
            }

            if (ctx.Zone is DirectoryZone.AppData or DirectoryZone.Temp && ext.Equals(".log", StringComparison.OrdinalIgnoreCase) && f.LogicalBytes >= _limits.LogMinBytes)
                LogFiles.Add(retained.Value);

            if (ctx.Zone == DirectoryZone.Temp && PathUtil.IsSameOrUnder(ctx.Path, _loc.Temp) && ctx.Path.Length == _loc.Temp.TrimEnd('\\').Length)
                AddLooseTemp(f);

            if (FileClassifier.IsDatabaseOrBackup(ext) && free && ctx.Zone is DirectoryZone.Normal or DirectoryZone.Downloads or DirectoryZone.AppData && f.LogicalBytes >= 1024 * 1024)
                Databases.Add(retained.Value);

            if (free && ctx.Zone is DirectoryZone.Normal or DirectoryZone.Downloads && ctx.RepoRoot == null)
            {
                var kind = FileClassifier.ClassifyPersonal(f.Name, ext, s.Name);
                if (kind is { } k) AddPersonal(s, f, k);

                if (_collectDuplicates && f.LogicalBytes >= _limits.DuplicateMinBytes && !f.IsOnlineOnly)
                {
                    if (DuplicateCandidates.Count < _limits.MaxDuplicateCandidates) DuplicateCandidates.Add(retained.Value);
                    else DuplicateCandidatesDropped++;
                }
            }
        }
    }

    private void AddLooseTemp(FileEntry f)
    {
        var fileOnly = new DirectoryTotals
        {
            LogicalBytes = f.LogicalBytes,
            PhysicalBytes = f.PhysicalBytes,
            FileCount = 1,
            NewestWriteUtc = f.LastWriteUtc,
        };
        var dirCount = TempLooseFiles.DirectoryCount;
        TempLooseFiles.Add(fileOnly);
        TempLooseFiles.DirectoryCount = dirCount;
    }

    private void AddPersonal(DirectorySnapshot s, FileEntry f, PersonalKind kind)
    {
        var t = PersonalTotals.GetValueOrDefault(kind);
        PersonalTotals[kind] = (t.Bytes + f.LogicalBytes, t.Count + 1, t.Online + (f.IsOnlineOnly ? 1 : 0));
        var key = (kind, s.FullPath);
        PersonalFolderBytes[key] = PersonalFolderBytes.GetValueOrDefault(key) + f.LogicalBytes;
        if (PersonalFiles.Count < _limits.MaxPersonalFiles)
        {
            PersonalFiles.Add(new PersonalFileRecord
            {
                Path = Path.Combine(s.FullPath, f.Name),
                Kind = kind,
                Bytes = f.LogicalBytes,
                LastWriteUtc = f.LastWriteUtc,
                IsOnlineOnly = f.IsOnlineOnly,
            });
        }
        else PersonalFilesDropped++;
    }

    private void RecordDirectory(DirectorySnapshot s, DirectoryContext ctx, DirectoryTotals totals)
    {
        if (ctx.IsDevResourceRoot)
        {
            DevResources.Add(new DevResourceRecord
            {
                Path = s.FullPath,
                Artifact = ctx.Artifact,
                Cache = ctx.Cache,
                MarkerSatisfied = ctx.MarkerSatisfied,
                RepoRoot = ctx.RepoRoot,
                ParentMarkers = ctx.Parent?.Markers ?? ProjectMarkers.None,
                Totals = totals,
            });
        }

        if (ctx.RepoRoot == s.FullPath)
        {
            var hasGitDir = s.HasSubdirectory(".git");
            var hasGitFile = !hasGitDir && s.HasFile(".git") && HasValidGitFile(s);
            Repositories.Add(new RepoCandidate(s.FullPath, !hasGitDir && !hasGitFile, hasGitFile, ctx.Parent?.RepoRoot, totals));
        }

        var parentPath = ctx.Parent?.Path ?? Path.GetDirectoryName(s.FullPath);
        if (parentPath != null)
        {
            if (parentPath.Equals(_loc.Temp.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                TempChildren.Add(new DirectoryCandidate(s.FullPath, totals));
            else if (_appDataParents.Contains(parentPath) && !s.FullPath.Equals(_loc.Temp.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
                AppDataFolders.Add(new AppDataFolderRecord(s.FullPath, Path.GetFileName(parentPath), totals));
        }

        if (s.FullPath.Equals(_loc.Temp.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase)) TempRootScanned = s.FullPath;

        if (ctx.Zone == DirectoryZone.Normal && !ctx.InsideDevResource && !ctx.InGitInternals && ctx.Parent?.Zone == DirectoryZone.Normal
            && s.Name is "temp" or "tmp" or "Temp" or "TEMP" or "Tmp")
        {
            NamedTempDirectories.Add(new DirectoryCandidate(s.FullPath, totals));
        }

        var category = ResolveFolderCategory(ctx, out var label);
        var risk = ctx.HighestContentRisk();
        if (ctx.Parent != null)
        {
            for (var i = 0; i < ctx.CategoryBytes.Length; i++) ctx.Parent.CategoryBytes[i] += ctx.CategoryBytes[i];
        }

        if (ctx.Parent != null || totals.PhysicalBytes > 0) OfferTopFolder(s, ctx, totals, category, label, risk);

        if (ctx.Depth <= _limits.MaxTreeDepth && (totals.PhysicalBytes >= _limits.MinTreeNodeBytes || ctx.Parent == null))
        {
            var node = new TreeNode
            {
                Name = s.Name,
                FullPath = s.FullPath,
                LogicalBytes = totals.LogicalBytes,
                PhysicalBytes = totals.PhysicalBytes,
                FileCount = totals.FileCount,
                Category = category,
                Risk = risk,
                ContentLabel = label,
                Children = [.. ctx.ChildNodes.OrderByDescending(n => n.PhysicalBytes)],
            };
            if (ctx.Parent != null) ctx.Parent.ChildNodes.Add(node);
            else _rootNodes.Add(node);
        }

        if (ctx.Parent == null)
        {
            var d = _grand.DirectoryCount;
            _grand.Add(totals);
            _grand.DirectoryCount = d + totals.DirectoryCount + 1;
        }
    }

    private void OfferTopFile(FileEntry f, Lazy<RetainedFile> retained)
    {
        if (_topFiles.Count < _limits.TopFiles) _topFiles.Enqueue(retained.Value, f.PhysicalBytes);
        else if (_topFiles.TryPeek(out _, out var min) && f.PhysicalBytes > min) _topFiles.EnqueueDequeue(retained.Value, f.PhysicalBytes);
    }

    private static StorageCategory ResolveFolderCategory(DirectoryContext ctx, out string label)
    {
        var byLocation = FileClassifier.ForDirectory(ctx);
        if (byLocation != StorageCategory.Other)
        {
            label = byLocation.Es();
            return byLocation;
        }
        var dominant = ctx.DominantFileCategory();
        label = dominant?.Es() ?? "Contenido mixto";
        return dominant ?? StorageCategory.Other;
    }

    private void OfferTopFolder(DirectorySnapshot s, DirectoryContext ctx, DirectoryTotals totals, StorageCategory category, string label, RiskLevel risk)
    {
        string? evidence = ctx.IsDevResourceRoot
            ? ctx.Artifact?.MarkerEvidence ?? (ctx.Cache != null ? "ubicación conocida de " + ctx.Cache.Tool : null)
            : ctx.RepoRoot == s.FullPath ? "repositorio Git" : null;
        var item = (s.FullPath, totals, category, label, risk, evidence);
        if (_topFolders.Count < _limits.TopFolders) _topFolders.Enqueue(item, totals.PhysicalBytes);
        else if (_topFolders.TryPeek(out _, out var min) && totals.PhysicalBytes > min) _topFolders.EnqueueDequeue(item, totals.PhysicalBytes);
    }

    private static RetainedFile Retain(DirectorySnapshot s, FileEntry f) =>
        new(Path.Combine(s.FullPath, f.Name), f.LogicalBytes, f.PhysicalBytes, f.CreationUtc, f.LastWriteUtc, f.LinkCount, f.IsOnlineOnly, f.IsRepeatedHardLink);

    private static void AddBucket<TKey>(Dictionary<TKey, Bucket> dict, TKey key, FileEntry f) where TKey : notnull =>
        AddToBucket(GetOrAdd(dict, key), f);

    private static Bucket GetOrAdd<TKey>(Dictionary<TKey, Bucket> dict, TKey key) where TKey : notnull
    {
        if (!dict.TryGetValue(key, out var b)) dict[key] = b = new Bucket();
        return b;
    }

    private static void AddToBucket(Bucket b, FileEntry f)
    {
        b.Logical += f.LogicalBytes;
        b.Physical += f.PhysicalBytes;
        b.Count++;
    }

    public StorageSummary BuildSummary()
    {
        lock (_lock)
        {
            double analyzed = Math.Max(1, _grand.PhysicalBytes);
            // Una cadena de carpetas casi idénticas (C:\Users\yo\...) no aporta información: se conserva el nivel más profundo.
            var entries = _topFolders.UnorderedItems.Select(i => i.Element).ToList();
            var redundantParents = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var folderBytes = entries.GroupBy(e => e.Path, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First().Totals.PhysicalBytes, StringComparer.OrdinalIgnoreCase);
            foreach (var e in entries)
            {
                var parent = Path.GetDirectoryName(e.Path);
                if (parent != null && folderBytes.TryGetValue(parent, out var parentBytes) && e.Totals.PhysicalBytes >= parentBytes * 0.98) redundantParents.Add(parent);
            }

            var folders = entries.Where(e => !redundantParents.Contains(e.Path)).OrderByDescending(e => e.Totals.PhysicalBytes).Select(e => new StorageItem
            {
                Path = e.Path,
                LogicalBytes = e.Totals.LogicalBytes,
                PhysicalBytes = e.Totals.PhysicalBytes,
                PercentOfAnalyzed = e.Totals.PhysicalBytes / analyzed * 100,
                ContentType = "Carpeta · " + e.Label,
                Category = e.Cat,
                Risk = e.Risk,
                Evidence = BuildFolderEvidence(e.Totals, e.Evidence),
                LastWriteUtc = e.Totals.NewestWriteUtc,
            }).ToList();

            var files = _topFiles.UnorderedItems.OrderByDescending(i => i.Priority).Select(i => i.Element).Select(f =>
            {
                var ext = Path.GetExtension(f.Path);
                var cat = CategoryForRetained(f.Path, ext);
                return new StorageItem
                {
                    Path = f.Path,
                    LogicalBytes = f.LogicalBytes,
                    PhysicalBytes = f.PhysicalBytes,
                    PercentOfAnalyzed = f.PhysicalBytes / analyzed * 100,
                    ContentType = (ext.Length == 0 ? "Sin extensión" : ext.ToLowerInvariant()) + " · " + cat.Es(),
                    Category = cat,
                    Risk = FileClassifier.DefaultRisk(cat),
                    Evidence = BuildFileEvidence(f),
                    LastWriteUtc = f.LastWriteUtc,
                };
            }).ToList();

            return new StorageSummary
            {
                LogicalBytes = _grand.LogicalBytes,
                PhysicalBytes = _grand.PhysicalBytes,
                OnlineOnlyLogicalBytes = _grand.OnlineOnlyLogicalBytes,
                FileCount = _grand.FileCount,
                DirectoryCount = _grand.DirectoryCount,
                RepeatedHardLinkLogicalBytes = _repeatedHardLinkLogical,
                TopFolders = folders,
                TopFiles = files,
                Concentrations = FindConcentrations(analyzed),
                ByCategory = [.. _byCategory.Select(kv => new BreakdownEntry(kv.Key.ToString(), kv.Value.Logical, kv.Value.Physical, kv.Value.Count)).OrderByDescending(b => b.PhysicalBytes)],
                ByExtension = [.. _byExtension.Select(kv => new BreakdownEntry(kv.Key, kv.Value.Logical, kv.Value.Physical, kv.Value.Count)).OrderByDescending(b => b.PhysicalBytes).Take(200)],
                Tree = [.. _rootNodes],
            };
        }
    }

    private StorageCategory CategoryForRetained(string path, string ext)
    {
        if (PathUtil.IsSameOrUnder(path, _loc.WindowsDirectory)) return StorageCategory.OperatingSystem;
        if (PathUtil.IsSameOrUnder(path, _loc.Temp)) return StorageCategory.TemporaryFiles;
        if (PathUtil.IsSameOrUnder(path, _loc.ProgramFiles) || PathUtil.IsSameOrUnder(path, _loc.ProgramFilesX86)
            || PathUtil.IsSameOrUnder(path, _loc.ProgramData) || PathUtil.IsSameOrUnder(path, _loc.LocalAppData)
            || PathUtil.IsSameOrUnder(path, _loc.RoamingAppData))
        {
            return FileClassifier.IsVirtualDisk(ext) ? StorageCategory.DatabasesAndBackups : StorageCategory.Applications;
        }
        if (FileClassifier.IsVirtualDisk(ext)) return StorageCategory.DatabasesAndBackups;
        if (PathUtil.IsSameOrUnder(path, _loc.Downloads)) return StorageCategory.Downloads;
        var pseudo = new DirectoryContext { Path = path, Depth = 0 };
        return FileClassifier.ForFile(pseudo, ext);
    }

    private static List<string> BuildFolderEvidence(DirectoryTotals t, string? extra)
    {
        var e = new List<string> { $"{t.FileCount:N0} archivos en {t.DirectoryCount:N0} subcarpetas" };
        if (extra != null) e.Add(extra);
        if (t.HardLinkedPhysicalBytes > 0) e.Add($"{PathUtil.FormatBytes(t.HardLinkedPhysicalBytes)} con enlaces duros: borrar esta ruta quizá no los libere");
        if (t.OnlineOnlyLogicalBytes > 0) e.Add($"{PathUtil.FormatBytes(t.OnlineOnlyLogicalBytes)} solo en la nube (sin leer)");
        if (t.InaccessibleDirectories > 0) e.Add($"{t.InaccessibleDirectories} subcarpetas inaccesibles: tamaño incompleto");
        return e;
    }

    private static List<string> BuildFileEvidence(RetainedFile f)
    {
        var e = new List<string> { $"Modificado por última vez: {f.LastWriteUtc:yyyy-MM-dd}" };
        if (f.LinkCount > 1) e.Add($"{f.LinkCount} enlaces duros: borrar una ruta no libera el espacio");
        if (f.LogicalBytes != f.PhysicalBytes) e.Add($"Tamaño lógico {PathUtil.FormatBytes(f.LogicalBytes)}, físico {PathUtil.FormatBytes(f.PhysicalBytes)}");
        return e;
    }

    /// <summary>Baja por el árbol mientras un hijo domine; el nodo final es donde realmente se concentra el espacio.</summary>
    private List<StorageItem> FindConcentrations(double analyzed)
    {
        var minimum = analyzed * 0.02;
        var results = new List<StorageItem>();
        void Visit(TreeNode n)
        {
            var significant = n.Children.Where(c => c.PhysicalBytes >= minimum).ToList();
            foreach (var c in significant) Visit(c);

            // Una carpeta es concentración si, tras quitar sus hijos relevantes, aún queda volumen propio.
            var remainder = n.PhysicalBytes - significant.Sum(c => c.PhysicalBytes);
            if (remainder < minimum || remainder < n.PhysicalBytes * 0.5) return;
            results.Add(new StorageItem
            {
                Path = n.FullPath,
                LogicalBytes = n.LogicalBytes,
                PhysicalBytes = n.PhysicalBytes,
                PercentOfAnalyzed = n.PhysicalBytes / analyzed * 100,
                ContentType = "Concentración · " + n.ContentLabel,
                Category = n.Category,
                Risk = n.Risk,
                Evidence = [$"{n.FileCount:N0} archivos; {PathUtil.FormatBytes((long)remainder)} no pertenecen a una subcarpeta destacada"],
            });
        }
        foreach (var r in _rootNodes) Visit(r);
        return [.. results.OrderByDescending(r => r.PhysicalBytes).Take(25)];
    }
}
