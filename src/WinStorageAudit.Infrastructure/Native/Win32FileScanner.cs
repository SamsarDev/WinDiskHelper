using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using WinStorageAudit.Core;
using WinStorageAudit.Core.Model;
using WinStorageAudit.Core.Scanning;

namespace WinStorageAudit.Infrastructure.Native;

/// <summary>
/// Enumerador basado en FindFirstFileExW. Solo consulta metadatos, no sigue enlaces simbólicos ni
/// junctions, y abre los archivos con FILE_READ_ATTRIBUTES y FILE_FLAG_OPEN_NO_RECALL para contar enlaces duros,
/// de modo que nunca hidrata contenido en la nube.
/// </summary>
public sealed class Win32FileScanner : IFileScanner, IFileIdentityProvider
{
    private sealed class Session
    {
        public required ScanRequest Request { get; init; }
        public required IScanObserver Observer { get; init; }
        public required ScanProgress Progress { get; init; }
        public required CoverageTracker Coverage { get; init; }
        public required ExclusionMatcher Exclusions { get; init; }
        public required SemaphoreSlim Slots { get; init; }
        public required string WindowsDirectory { get; init; }
        public required CancellationToken Token { get; init; }
        public long ClusterBytes { get; set; } = 4096;
        public ConcurrentDictionary<(ulong, ulong), byte> SeenHardLinks { get; } = new();
    }

    public async Task ScanAsync(ScanRequest request, IScanObserver observer, ScanProgress progress, CoverageTracker coverage, CancellationToken ct)
    {
        var session = new Session
        {
            Request = request,
            Observer = observer,
            Progress = progress,
            Coverage = coverage,
            Exclusions = new ExclusionMatcher(request.Exclusions),
            Slots = new SemaphoreSlim(Math.Max(0, request.MaxConcurrency - 1)),
            WindowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Token = ct,
        };

        foreach (var root in NormalizeRoots(request.Roots))
        {
            if (ct.IsCancellationRequested) break;
            if (!IsRootAllowed(root, request.AllowNetworkRoots))
            {
                coverage.Report(ScanIssueKind.Other, root, "Ruta de red no analizada: requiere autorización explícita (--allow-network).");
                progress.AddError();
                continue;
            }
            if (!Directory.Exists(ToExistsPath(root)))
            {
                coverage.Report(ScanIssueKind.NotFound, root, "La ruta no existe o no está disponible.");
                progress.AddError();
                continue;
            }
            session.ClusterBytes = GetClusterBytes(root);
            var name = Path.GetFileName(root);
            await Task.Run(() => Walk(session, root, name.Length == 0 ? root : name, null, 0), CancellationToken.None);
        }
    }

    private static string ToExistsPath(string p) => p.Length == 2 ? p + "\\" : p;

    /// <summary>Evita analizar dos veces una ruta contenida en otra.</summary>
    public static IReadOnlyList<string> NormalizeRoots(IEnumerable<string> roots)
    {
        var normalized = roots.Select(PathUtil.Normalize).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(p => p.Length).ToList();
        var result = new List<string>();
        foreach (var r in normalized)
            if (!result.Any(existing => PathUtil.IsSameOrUnder(r, existing))) result.Add(r);
        return result;
    }

    private static bool IsRootAllowed(string root, bool allowNetwork)
    {
        if (allowNetwork) return true;
        if (root.StartsWith(@"\\", StringComparison.Ordinal)) return false;
        try { return new DriveInfo(root[..1]).DriveType != DriveType.Network; }
        catch { return true; }
    }

    private static long GetClusterBytes(string root)
    {
        var drive = Path.GetPathRoot(root);
        if (drive != null && NativeMethods.GetDiskFreeSpace(drive, out var spc, out var bps, out _, out _)) return Math.Max(1, (long)spc * bps);
        return 4096;
    }

    private DirectoryTotals Walk(Session s, string path, string name, DirectoryContext? parent, int depth)
    {
        var totals = new DirectoryTotals();
        if (s.Token.IsCancellationRequested) return totals;

        var files = new List<FileEntry>();
        var subdirs = new List<string>();
        if (!ReadDirectory(s, path, files, subdirs, totals)) totals.InaccessibleDirectories = 1;

        var snapshot = new DirectorySnapshot { FullPath = path, Name = name, Files = files, Subdirectories = subdirs };
        var ctx = s.Observer.EnterDirectory(snapshot, parent);

        if (depth >= s.Request.MaxDepth)
        {
            if (subdirs.Count > 0) s.Coverage.Report(ScanIssueKind.PathTooLong, path, "Profundidad máxima alcanzada; subcarpetas sin analizar.");
            subdirs = [];
        }

        var tasks = new List<Task<DirectoryTotals>>();
        foreach (var sub in subdirs)
        {
            if (s.Token.IsCancellationRequested) break;
            var childPath = path.EndsWith('\\') ? path + sub : path + "\\" + sub;
            if (s.Slots.Wait(0))
            {
                tasks.Add(Task.Run(() =>
                {
                    try { return Walk(s, childPath, sub, ctx, depth + 1); }
                    finally { s.Slots.Release(); }
                }, CancellationToken.None));
            }
            else
            {
                totals.Add(Walk(s, childPath, sub, ctx, depth + 1));
            }
        }

        foreach (var t in tasks) totals.Add(t.GetAwaiter().GetResult());

        s.Observer.ExitDirectory(snapshot, ctx, totals);
        return totals;
    }

    private bool ReadDirectory(Session s, string path, List<FileEntry> files, List<string> subdirs, DirectoryTotals totals)
    {
        var search = NativeMethods.ToLongPath(path.EndsWith('\\') ? path + "*" : path + "\\*");
        using var handle = NativeMethods.FindFirstFileEx(search, NativeMethods.FindExInfoBasic, out var data,
            NativeMethods.FindExSearchNameMatch, IntPtr.Zero, NativeMethods.FindFirstExLargeFetch);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            var kind = error switch
            {
                NativeMethods.ErrorAccessDenied => ScanIssueKind.AccessDenied,
                NativeMethods.ErrorFileNotFound or NativeMethods.ErrorPathNotFound => ScanIssueKind.NotFound,
                NativeMethods.ErrorFilenameExcedRange => ScanIssueKind.PathTooLong,
                _ => ScanIssueKind.Other,
            };
            s.Coverage.Report(kind, path, $"Error de Windows {error}");
            s.Progress.AddError();
            return false;
        }

        long batchPhysical = 0;
        do
        {
            var name = data.FileName;
            if (name is "." or "..") continue;
            var full = path.EndsWith('\\') ? path + name : path + "\\" + name;

            if (s.Exclusions.IsExcluded(full, name))
            {
                s.Coverage.Report(ScanIssueKind.Excluded, full);
                continue;
            }

            var attrs = data.FileAttributes;
            var reparse = (attrs & NativeMethods.FileAttributeReparsePoint) != 0;
            var tag = reparse ? data.Reserved0 : 0;
            var isCloudTag = reparse && (tag & NativeMethods.ReparseTagCloudMask) == NativeMethods.ReparseTagCloudBase;
            var nameSurrogate = reparse && (tag & NativeMethods.ReparseTagNameSurrogateBit) != 0;

            if ((attrs & NativeMethods.FileAttributeDirectory) != 0)
            {
                if ((attrs & (NativeMethods.FileAttributeRecallOnOpen | NativeMethods.FileAttributeRecallOnDataAccess)) != 0)
                {
                    s.Coverage.Report(ScanIssueKind.CloudSkipped, full, "Carpeta remota sin copia local completa: no se recorre para no descargarla.");
                    continue;
                }
                if (reparse && !isCloudTag)
                {
                    s.Coverage.Report(ScanIssueKind.LinkSkipped, full, DescribeTag(tag));
                    continue;
                }
                subdirs.Add(name);
                continue;
            }

            var entry = BuildFileEntry(s, full, name, data, attrs, nameSurrogate, tag);
            files.Add(entry);
            batchPhysical += entry.PhysicalBytes;

            totals.LogicalBytes += entry.IsLink ? 0 : entry.LogicalBytes;
            totals.PhysicalBytes += entry.PhysicalBytes;
            totals.FileCount++;
            if (entry.IsOnlineOnly) totals.OnlineOnlyLogicalBytes += entry.LogicalBytes;
            if (entry.LinkCount > 1) totals.HardLinkedPhysicalBytes += entry.PhysicalBytes;
            if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) totals.ExecutableCount++;
            if (entry.LastWriteUtc > totals.NewestWriteUtc) totals.NewestWriteUtc = entry.LastWriteUtc;
        }
        while (NativeMethods.FindNextFile(handle, out data));

        var last = Marshal.GetLastPInvokeError();
        if (last != NativeMethods.ErrorNoMoreFiles)
        {
            s.Coverage.Report(ScanIssueKind.Other, path, $"Enumeración interrumpida: error de Windows {last}");
            s.Progress.AddError();
        }

        s.Progress.AddDirectory(files.Count, batchPhysical, path);
        return true;
    }

    private FileEntry BuildFileEntry(Session s, string full, string name, in NativeMethods.Win32FindData data, uint attrs, bool isLink, uint tag)
    {
        var logical = ((long)data.FileSizeHigh << 32) | data.FileSizeLow;
        var online = (attrs & NativeMethods.OnlineOnlyMask) != 0;
        var created = NativeMethods.ToUtc(data.CreationTime);
        var written = NativeMethods.ToUtc(data.LastWriteTime);

        if (isLink)
        {
            s.Coverage.Report(ScanIssueKind.LinkSkipped, full, DescribeTag(tag));
            return new FileEntry
            {
                Name = name, LogicalBytes = logical, PhysicalBytes = 0, Attributes = (FileAttributes)attrs,
                CreationUtc = created, LastWriteUtc = written, IsLink = true,
            };
        }

        var special = (attrs & (NativeMethods.FileAttributeSparse | NativeMethods.FileAttributeCompressed)) != 0;
        long allocated = logical;

        // El análisis profundo consulta todos los archivos: también detecta compresión WOF (CompactOS), invisible en los atributos.
        if (special || online || s.Request.Mode == ScanMode.Deep)
        {
            var low = NativeMethods.GetCompressedFileSize(NativeMethods.ToLongPath(full), out var high);
            if (low != uint.MaxValue || Marshal.GetLastPInvokeError() == 0) allocated = ((long)high << 32) | low;
            else if (online) allocated = 0;
        }

        var physical = RoundToCluster(allocated, s.ClusterBytes);
        var links = 0;
        var repeated = false;

        var checkLinks = !online && logical > 0 && (s.Request.Mode == ScanMode.Deep || logical >= s.Request.HardLinkCheckMinBytes || PathUtil.IsSameOrUnder(full, s.WindowsDirectory));
        if (checkLinks)
        {
            var identity = ReadIdentity(full);
            if (identity is { } id)
            {
                links = id.Links;
                if (links > 1 && !s.SeenHardLinks.TryAdd((id.Volume, id.FileId), 0))
                {
                    repeated = true;
                    physical = 0;
                }
            }
        }

        return new FileEntry
        {
            Name = name,
            LogicalBytes = logical,
            PhysicalBytes = physical,
            Attributes = (FileAttributes)attrs,
            CreationUtc = created,
            LastWriteUtc = written,
            LinkCount = links,
            IsOnlineOnly = online,
            IsSparseOrCompressed = special,
            IsRepeatedHardLink = repeated,
        };
    }

    public (ulong Volume, ulong FileId, int Links)? TryGetIdentity(string path) => ReadIdentity(path);

    private static (ulong Volume, ulong FileId, int Links)? ReadIdentity(string path)
    {
        using var h = NativeMethods.CreateFile(NativeMethods.ToLongPath(path), NativeMethods.FileReadAttributes, NativeMethods.FileShareAll, IntPtr.Zero,
            NativeMethods.OpenExisting, NativeMethods.FileFlagBackupSemantics | NativeMethods.FileFlagOpenReparsePoint | NativeMethods.FileFlagOpenNoRecall, IntPtr.Zero);
        if (h.IsInvalid) return null;
        if (!NativeMethods.GetFileInformationByHandle(h, out var info)) return null;
        return (info.VolumeSerialNumber, ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow, (int)info.NumberOfLinks);
    }

    private static long RoundToCluster(long bytes, long cluster) =>
        bytes <= 0 ? 0 : (bytes + cluster - 1) / cluster * cluster;

    private static string DescribeTag(uint tag) => tag switch
    {
        NativeMethods.ReparseTagMountPoint => "Junction o punto de montaje",
        NativeMethods.ReparseTagSymlink => "Enlace simbólico",
        _ => $"Punto de reanálisis 0x{tag:X8}",
    };
}
