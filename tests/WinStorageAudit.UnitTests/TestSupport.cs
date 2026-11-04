using WinStorageAudit.Core;
using WinStorageAudit.Core.Cleanup;
using WinStorageAudit.Core.Model;
using WinStorageAudit.Core.Scanning;

namespace WinStorageAudit.UnitTests;

public sealed record FF(string Name, long Size = 1000, DateTime? Written = null, int Links = 1, bool Online = false);

public sealed record DD(string Name, FF[]? Files = null, DD[]? Subs = null);

/// <summary>Recorre un árbol en memoria con el mismo contrato que el escáner real.</summary>
public sealed class FakeScanner(string root, DD tree) : IFileScanner
{
    public Task ScanAsync(ScanRequest request, IScanObserver observer, ScanProgress progress, CoverageTracker coverage, CancellationToken ct)
    {
        Walk(root, tree, null, observer);
        return Task.CompletedTask;
    }

    private static DirectoryTotals Walk(string path, DD dir, DirectoryContext? parent, IScanObserver observer)
    {
        var totals = new DirectoryTotals();
        var files = (dir.Files ?? []).Select(f => new FileEntry
        {
            Name = f.Name,
            LogicalBytes = f.Size,
            PhysicalBytes = f.Online ? 0 : f.Size,
            CreationUtc = f.Written ?? Fixtures.Now,
            LastWriteUtc = f.Written ?? Fixtures.Now,
            LinkCount = f.Links,
            IsOnlineOnly = f.Online,
        }).ToList();
        foreach (var f in files)
        {
            totals.LogicalBytes += f.LogicalBytes;
            totals.PhysicalBytes += f.PhysicalBytes;
            totals.FileCount++;
            if (f.LinkCount > 1) totals.HardLinkedPhysicalBytes += f.PhysicalBytes;
            if (f.IsOnlineOnly) totals.OnlineOnlyLogicalBytes += f.LogicalBytes;
            if (f.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) totals.ExecutableCount++;
            if (f.LastWriteUtc > totals.NewestWriteUtc) totals.NewestWriteUtc = f.LastWriteUtc;
        }
        var subs = dir.Subs ?? [];
        var snapshot = new DirectorySnapshot { FullPath = path, Name = dir.Name, Files = files, Subdirectories = [.. subs.Select(s => s.Name)] };
        var ctx = observer.EnterDirectory(snapshot, parent);
        foreach (var s in subs) totals.Add(Walk(path + "\\" + s.Name, s, ctx, observer));
        observer.ExitDirectory(snapshot, ctx, totals);
        return totals;
    }
}

public static class Fixtures
{
    public const string Root = @"C:\Sandbox";
    public static readonly DateTime Now = new(2026, 6, 1, 12, 0, 0, DateTimeKind.Utc);
    public static readonly KnownLocations Locations = KnownLocations.UnderRoot(Root);
    public const long MiB = 1024 * 1024;

    public static DateTime DaysAgo(int days) => Now.AddDays(-days);

    public static (RuleContext Context, ScanCollector Collector) Scan(DD tree, Func<RuleContext, RuleContext>? customize = null, string root = Root, bool duplicates = false)
    {
        var collector = new ScanCollector(Locations, new CollectorLimits { MinTreeNodeBytes = 1 }, duplicates);
        new FakeScanner(root, tree).ScanAsync(new ScanRequest { Roots = [root] }, collector, new ScanProgress(), new CoverageTracker(), default).GetAwaiter().GetResult();
        var context = new RuleContext { Scan = collector, Storage = collector.BuildSummary(), Locations = Locations, Thresholds = new AuditThresholds(), NowUtc = Now };
        return (customize?.Invoke(context) ?? context, collector);
    }

    /// <summary>Construye un árbol desde rutas relativas a la raíz, para no anidar a mano.</summary>
    public static DD Tree(params (string Path, FF File)[] items)
    {
        var root = new Node("Sandbox");
        foreach (var (path, file) in items)
        {
            var node = root;
            foreach (var part in path.Split('\\', StringSplitOptions.RemoveEmptyEntries)) node = node.Child(part);
            node.Files.Add(file);
        }
        return root.ToDd();
    }

    public static Finding Finding(string path, long reclaimable, RecommendationClass cls = RecommendationClass.CleanupCandidate, FindingArea area = FindingArea.Development) => new()
    {
        RuleId = "TEST",
        Category = area,
        PathOrResource = path,
        Description = "d",
        Relevance = "r",
        Evidence = ["a", "b"],
        Recommendation = cls,
        Confidence = Confidence.Medium,
        RiskLevel = RiskLevel.Low,
        Reversibility = Reversibility.Regenerable,
        RecommendedAction = "x",
        PotentialLoss = "y",
        DetectedSizeBytes = reclaimable,
        EstimatedReclaimableBytes = reclaimable,
    };

    private sealed class Node(string name)
    {
        public List<FF> Files { get; } = [];
        private readonly Dictionary<string, Node> _children = new(StringComparer.OrdinalIgnoreCase);
        public Node Child(string n)
        {
            if (!_children.TryGetValue(n, out var c)) _children[n] = c = new Node(n);
            return c;
        }
        public DD ToDd() => new(name, [.. Files], [.. _children.Values.Select(c => c.ToDd())]);
    }
}
