using System.Diagnostics;
using WinStorageAudit.Core.Model;
using WinStorageAudit.Core.Scanning;
using WinStorageAudit.Infrastructure.Native;

namespace WinStorageAudit.IntegrationTests;

public sealed class TempTree : IDisposable
{
    public string Root { get; } = Path.Combine(Path.GetTempPath(), "wsa-tests-" + Guid.NewGuid().ToString("N")[..10]);
    public TempTree() => Directory.CreateDirectory(Root);

    public string File(string relative, int bytes = 16, DateTime? lastWrite = null, byte fill = 65)
    {
        var path = System.IO.Path.Combine(Root, relative);
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path)!);
        var content = new byte[bytes];
        Array.Fill(content, fill);
        System.IO.File.WriteAllBytes(path, content);
        if (lastWrite is { } w) System.IO.File.SetLastWriteTimeUtc(path, w);
        return path;
    }

    public string Dir(string relative)
    {
        var path = System.IO.Path.Combine(Root, relative);
        Directory.CreateDirectory(path);
        return path;
    }

    public void Dispose()
    {
        try
        {
            foreach (var f in Directory.EnumerateFiles(Root, "*", SearchOption.AllDirectories))
            {
                try { System.IO.File.SetAttributes(f, FileAttributes.Normal); } catch (IOException) { } catch (UnauthorizedAccessException) { }
            }
            Directory.Delete(Root, true);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}

public static class Scan
{
    public static async Task<(ScanCollector Collector, CoverageReport Coverage, ScanProgress Progress)> RunAsync(
        string root, ScanMode mode = ScanMode.Deep, IReadOnlyList<string>? exclusions = null, CancellationToken ct = default,
        KnownLocations? locations = null, bool duplicates = true)
    {
        var scanner = new Win32FileScanner();
        var loc = locations ?? KnownLocations.UnderRoot(root);
        var collector = new ScanCollector(loc, new CollectorLimits { MinTreeNodeBytes = 1 }, duplicates);
        var progress = new ScanProgress();
        var coverage = new CoverageTracker();
        await scanner.ScanAsync(new ScanRequest { Roots = [root], Mode = mode, Exclusions = exclusions ?? [] }, collector, progress, coverage, ct);
        return (collector, coverage.ToReport([], ct.IsCancellationRequested), progress);
    }

    /// <summary>Instantánea de cada archivo: tamaño, fecha, atributos y hash de contenido.</summary>
    public static Dictionary<string, string> Fingerprint(string root)
    {
        var result = new Dictionary<string, string>();
        foreach (var f in Directory.EnumerateFiles(root, "*", new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = 0 }))
        {
            var info = new FileInfo(f);
            var hash = "n/a";
            try { hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.IO.File.ReadAllBytes(f))); }
            catch (IOException) { }
            result[f] = $"{info.Length}|{info.LastWriteTimeUtc.Ticks}|{info.CreationTimeUtc.Ticks}|{info.Attributes}|{hash}";
        }
        return result;
    }
}

public class ScannerTests
{
    [Fact]
    public async Task Enumerates_tree_and_aggregates_sizes()
    {
        using var t = new TempTree();
        t.File(@"a\one.bin", 1000);
        t.File(@"a\b\two.bin", 3000);
        t.File("three.txt", 500);

        var (c, _, progress) = await Scan.RunAsync(t.Root);
        var s = c.BuildSummary();

        Assert.Equal(4500, s.LogicalBytes);
        Assert.Equal(3, s.FileCount);
        Assert.Equal(3, s.DirectoryCount); // raíz, a y a\b
        Assert.True(s.PhysicalBytes >= 4500);
        Assert.Equal(3, progress.Files);
        Assert.Contains(s.TopFiles, f => f.Path.EndsWith("two.bin") && f.LogicalBytes == 3000);
        Assert.Contains(s.ByExtension, e => e.Key == ".bin" && e.LogicalBytes == 4000);
    }

    [Fact]
    public async Task Excluded_directories_are_not_counted_and_are_reported()
    {
        using var t = new TempTree();
        t.File(@"keep\a.bin", 100);
        t.File(@"skipme\b.bin", 200);
        t.File(@"deep\skipme\c.bin", 300);

        var (c, coverage, _) = await Scan.RunAsync(t.Root, exclusions: ["skipme"]);

        Assert.Equal(100, c.BuildSummary().LogicalBytes);
        Assert.Equal(2, coverage.IssueCounts[ScanIssueKind.Excluded]);
    }

    [Fact]
    public async Task Full_path_exclusion_only_affects_that_path()
    {
        using var t = new TempTree();
        t.File(@"x\skip\a.bin", 100);
        t.File(@"y\skip\b.bin", 200);

        var (c, _, _) = await Scan.RunAsync(t.Root, exclusions: [Path.Combine(t.Root, "x", "skip")]);

        Assert.Equal(200, c.BuildSummary().LogicalBytes);
    }

    [Fact]
    public async Task Junctions_are_not_followed_even_if_they_form_a_cycle()
    {
        using var t = new TempTree();
        t.File(@"real\data.bin", 1000);
        var junction = Path.Combine(t.Root, "real", "loop");
        CreateJunction(junction, t.Root);
        Assert.True(Directory.Exists(junction));

        var (c, coverage, _) = await Scan.RunAsync(t.Root);

        Assert.Equal(1000, c.BuildSummary().LogicalBytes);
        Assert.Equal(1, coverage.IssueCounts[ScanIssueKind.LinkSkipped]);
        Assert.Contains(coverage.IssueSamples, i => i.Detail.Contains("Junction"));
    }

    [Fact]
    public async Task Symbolic_links_do_not_add_target_size_when_they_can_be_created()
    {
        using var t = new TempTree();
        var target = t.File(@"data\big.bin", 5000);
        try { File.CreateSymbolicLink(Path.Combine(t.Root, "link.bin"), target); }
        catch (IOException) { return; } // Requiere modo desarrollador o privilegio; se documenta en docs/security.md.
        catch (UnauthorizedAccessException) { return; }

        var (c, coverage, _) = await Scan.RunAsync(t.Root);

        Assert.Equal(5000, c.BuildSummary().LogicalBytes);
        Assert.True(coverage.IssueCounts[ScanIssueKind.LinkSkipped] >= 1);
    }

    [Fact]
    public async Task Hard_links_are_physically_counted_once()
    {
        using var t = new TempTree();
        var original = t.File(@"a\file.bin", 100_000);
        CreateHardLink(Path.Combine(t.Root, "a", "link.bin"), original);

        var (c, _, _) = await Scan.RunAsync(t.Root);
        var s = c.BuildSummary();

        Assert.Equal(200_000, s.LogicalBytes);
        Assert.InRange(s.PhysicalBytes, 100_000, 110_000);
        Assert.Equal(100_000, s.RepeatedHardLinkLogicalBytes);
    }

    [Fact]
    public async Task Compressed_files_report_smaller_physical_size()
    {
        using var t = new TempTree();
        var path = t.File("compressible.bin", 2_000_000);
        var result = Process.Start(new ProcessStartInfo("compact.exe", ["/c", path]) { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true })!;
        await result.WaitForExitAsync();

        var (c, _, _) = await Scan.RunAsync(t.Root);
        var s = c.BuildSummary();

        Assert.Equal(2_000_000, s.LogicalBytes);
        Assert.True(s.PhysicalBytes < 2_000_000, $"físico: {s.PhysicalBytes}");
    }

    [Fact]
    public async Task Sparse_files_report_allocated_size_not_logical()
    {
        using var t = new TempTree();
        var path = Path.Combine(t.Root, "sparse.bin");
        using (var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write))
        {
            stream.WriteByte(1);
        }
        await RunTool("fsutil.exe", "sparse", "setflag", path);
        await RunTool("fsutil.exe", "file", "seteof", path, "50000000");

        var (c, _, _) = await Scan.RunAsync(t.Root);
        var s = c.BuildSummary();

        Assert.Equal(50_000_000, s.LogicalBytes);
        Assert.True(s.PhysicalBytes < 1_000_000, $"físico: {s.PhysicalBytes}");
    }

    [Fact]
    public async Task Inaccessible_directory_is_reported_without_aborting()
    {
        using var t = new TempTree();
        t.File(@"ok\a.bin", 100);
        var denied = t.Dir("denied");
        t.File(@"denied\secret.bin", 999);
        await RunTool("icacls.exe", denied, "/deny", Environment.UserName + ":(OI)(CI)(RX)");
        try
        {
            var (c, coverage, progress) = await Scan.RunAsync(t.Root);

            Assert.Equal(100, c.BuildSummary().LogicalBytes);
            Assert.Equal(1, coverage.IssueCounts[ScanIssueKind.AccessDenied]);
            Assert.True(progress.Errors >= 1);
        }
        finally
        {
            await RunTool("icacls.exe", denied, "/remove:d", Environment.UserName);
        }
    }

    [Fact]
    public async Task Locked_files_are_still_measured()
    {
        using var t = new TempTree();
        var path = t.File("locked.bin", 4096);
        using var exclusive = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);

        var (c, coverage, _) = await Scan.RunAsync(t.Root);

        Assert.Equal(4096, c.BuildSummary().LogicalBytes);
        Assert.False(coverage.IssueCounts.ContainsKey(ScanIssueKind.AccessDenied));
    }

    [Fact]
    public async Task Offline_attribute_is_treated_as_online_only()
    {
        using var t = new TempTree();
        var path = t.File("cloud.bin", 8192);
        File.SetAttributes(path, FileAttributes.Offline);

        var (c, _, _) = await Scan.RunAsync(t.Root);

        Assert.Equal(8192, c.BuildSummary().OnlineOnlyLogicalBytes);
        Assert.DoesNotContain(c.DuplicateCandidates, f => f.Path == path);
    }

    [Fact]
    public async Task Pre_cancelled_scan_stops_immediately()
    {
        using var t = new TempTree();
        t.File(@"a\b\c.bin", 100);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var (c, coverage, _) = await Scan.RunAsync(t.Root, ct: cts.Token);

        Assert.True(coverage.WasCancelled);
        Assert.Equal(0, c.BuildSummary().FileCount);
    }

    [Fact]
    public async Task Cancellation_during_scan_returns_partial_result()
    {
        using var t = new TempTree();
        for (var i = 0; i < 400; i++) t.File($@"d{i}\f.bin", 10);
        using var cts = new CancellationTokenSource();
        var collector = new CancelAfterObserver(new ScanCollector(KnownLocations.UnderRoot(t.Root)), 20, cts);

        await new Win32FileScanner().ScanAsync(new ScanRequest { Roots = [t.Root], MaxConcurrency = 1 }, collector, new ScanProgress(), new CoverageTracker(), cts.Token);

        Assert.True(cts.IsCancellationRequested);
        Assert.InRange(collector.Exits, 20, 399);
    }

    [Fact]
    public async Task Missing_root_is_reported_not_thrown()
    {
        using var t = new TempTree();
        var coverage = new CoverageTracker();
        var collector = new ScanCollector(KnownLocations.UnderRoot(t.Root));

        await new Win32FileScanner().ScanAsync(new ScanRequest { Roots = [Path.Combine(t.Root, "nope")] }, collector, new ScanProgress(), coverage, default);

        Assert.Equal(1, coverage.ToReport([], false).IssueCounts[ScanIssueKind.NotFound]);
    }

    [Fact]
    public async Task Network_roots_require_explicit_authorization()
    {
        var coverage = new CoverageTracker();
        var collector = new ScanCollector(KnownLocations.UnderRoot(Path.GetTempPath()));

        await new Win32FileScanner().ScanAsync(new ScanRequest { Roots = [@"\\no-such-server\share"] }, collector, new ScanProgress(), coverage, default);

        var report = coverage.ToReport([], false);
        Assert.Contains(report.IssueSamples, i => i.Detail.Contains("--allow-network"));
    }

    [Fact]
    public void Nested_roots_are_deduplicated()
    {
        var roots = Win32FileScanner.NormalizeRoots([@"C:\Data\Sub", @"C:\Data", @"C:\Other\", @"c:\data"]);
        Assert.Equal(2, roots.Count);
        Assert.Contains(@"C:\Data", roots, StringComparer.OrdinalIgnoreCase);
        Assert.Contains(@"C:\Other", roots, StringComparer.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Scanning_does_not_modify_any_file()
    {
        using var t = new TempTree();
        t.File(@"proj\package.json", 20);
        t.File(@"proj\node_modules\x\index.js", 100);
        t.File(@"docs\report.docx", 300, DateTime.UtcNow.AddYears(-3));
        t.File(@"docs\copy.docx", 300, DateTime.UtcNow.AddYears(-3));
        var before = Scan.Fingerprint(t.Root);

        await Scan.RunAsync(t.Root);

        Assert.Equal(before, Scan.Fingerprint(t.Root));
    }

    private sealed class CancelAfterObserver(ScanCollector inner, int limit, CancellationTokenSource cts) : WinStorageAudit.Core.IScanObserver
    {
        public int Exits;
        public DirectoryContext EnterDirectory(DirectorySnapshot s, DirectoryContext? p) => inner.EnterDirectory(s, p);
        public void ExitDirectory(DirectorySnapshot s, DirectoryContext c, DirectoryTotals t)
        {
            inner.ExitDirectory(s, c, t);
            if (Interlocked.Increment(ref Exits) == limit) cts.Cancel();
        }
    }

    private static void CreateJunction(string link, string target)
    {
        var p = Process.Start(new ProcessStartInfo("cmd.exe", ["/c", "mklink", "/J", link, target]) { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true })!;
        p.WaitForExit();
        Assert.Equal(0, p.ExitCode);
    }

    private static void CreateHardLink(string link, string target)
    {
        var p = Process.Start(new ProcessStartInfo("cmd.exe", ["/c", "mklink", "/H", link, target]) { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true })!;
        p.WaitForExit();
        Assert.Equal(0, p.ExitCode);
    }

    private static async Task RunTool(string tool, params string[] args)
    {
        var p = Process.Start(new ProcessStartInfo(tool, args) { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true })!;
        await p.WaitForExitAsync();
    }
}
