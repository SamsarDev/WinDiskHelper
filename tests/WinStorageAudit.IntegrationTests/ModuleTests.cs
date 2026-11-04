using System.Diagnostics;
using System.Text;
using System.Text.Json;
using WinStorageAudit.Core;
using WinStorageAudit.Core.Backup;
using WinStorageAudit.Core.Cleanup;
using WinStorageAudit.Core.Git;
using WinStorageAudit.Core.Model;
using WinStorageAudit.Core.Scanning;
using WinStorageAudit.Infrastructure;
using WinStorageAudit.Infrastructure.Apps;
using WinStorageAudit.Infrastructure.Native;
using WinStorageAudit.Infrastructure.Persistence;

namespace WinStorageAudit.IntegrationTests;

/// <summary>Requiere Git en PATH. Todo ocurre en carpetas temporales propias.</summary>
public sealed class GitFixture : IDisposable
{
    private readonly TempTree _tree = new();
    public string Root => _tree.Root;
    public GitAnalyzer Analyzer { get; } = new(new ProcessRunner());

    public string Repo(string name)
    {
        var path = Path.Combine(Root, name);
        Directory.CreateDirectory(path);
        Git(path, "init", "-q", "-b", "main");
        Git(path, "config", "user.email", "t@example.invalid");
        Git(path, "config", "user.name", "Test");
        Git(path, "config", "commit.gpgsign", "false");
        return path;
    }

    public void Commit(string repo, string file = "a.txt", string text = "x")
    {
        File.WriteAllText(Path.Combine(repo, file), text);
        Git(repo, "add", "-A");
        Git(repo, "commit", "-q", "-m", "c");
    }

    public string Git(string repo, params string[] args)
    {
        var psi = new ProcessStartInfo("git") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = repo };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var output = p.StandardOutput.ReadToEnd();
        var error = p.StandardError.ReadToEnd();
        p.WaitForExit();
        Assert.True(p.ExitCode == 0, $"git {string.Join(' ', args)}: {error}");
        return output;
    }

    public Task<GitRepositoryStatus> Analyze(string repo, bool gitIsFile = false, bool ignored = true) =>
        Analyzer.AnalyzeAsync(new RepoCandidate(repo, false, gitIsFile, null, new DirectoryTotals()), ignored, default);

    public void Dispose() => _tree.Dispose();
}

public class GitTests
{
    [Fact]
    public async Task Repo_without_remote_is_reported_and_commits_count_as_local_only()
    {
        using var g = new GitFixture();
        var repo = g.Repo("solo");
        g.Commit(repo);

        var s = await g.Analyze(repo);

        Assert.Empty(s.Remotes);
        Assert.Contains("Repositorio sin remoto conocido", s.States);
        Assert.Equal(100, BackupReportBuilder.GitPriorityScore(s));
        Assert.Equal(1, s.Branches.Single().CommitsNotOnAnyRemoteRef);
    }

    [Fact]
    public async Task Uncommitted_changes_are_detected()
    {
        using var g = new GitFixture();
        var repo = g.Repo("dirty");
        g.Commit(repo);
        File.WriteAllText(Path.Combine(repo, "a.txt"), "changed");
        File.WriteAllText(Path.Combine(repo, "b.txt"), "staged");
        g.Git(repo, "add", "b.txt");

        var s = await g.Analyze(repo);

        Assert.Equal(1, s.UnstagedChanges);
        Assert.Equal(1, s.StagedChanges);
        Assert.True(s.HasUncommittedWork);
        Assert.Contains(s.States, x => x.StartsWith("Modificaciones locales"));
    }

    [Fact]
    public async Task Untracked_files_are_detected()
    {
        using var g = new GitFixture();
        var repo = g.Repo("untracked");
        g.Commit(repo);
        File.WriteAllText(Path.Combine(repo, "new.txt"), "n");

        var s = await g.Analyze(repo);

        Assert.Equal(1, s.UntrackedFiles);
        Assert.Contains(s.States, x => x.StartsWith("Archivos no versionados"));
    }

    private static string CloneOf(GitFixture g, string origin, string name)
    {
        var path = Path.Combine(g.Root, name);
        g.Git(g.Root, "clone", "-q", origin, name);
        g.Git(path, "config", "user.email", "t@example.invalid");
        g.Git(path, "config", "user.name", "Test");
        g.Git(path, "config", "commit.gpgsign", "false");
        return path;
    }

    [Fact]
    public async Task Clean_clone_says_no_local_changes_but_remote_not_verifiable()
    {
        using var g = new GitFixture();
        var origin = g.Repo("origin");
        g.Commit(origin);
        var clone = CloneOf(g, origin, "clone");

        var s = await g.Analyze(clone);

        Assert.Equal("Repositorio sin cambios locales detectados", s.States[0]);
        Assert.Contains(s.States, x => x.StartsWith("Estado remoto no verificable"));
        Assert.Equal(0, BackupReportBuilder.GitPriorityScore(s));
    }

    [Fact]
    public async Task Commits_ahead_of_local_upstream_are_detected()
    {
        using var g = new GitFixture();
        var origin = g.Repo("origin");
        g.Commit(origin);
        var clone = CloneOf(g, origin, "clone");
        g.Commit(clone, "b.txt");
        g.Commit(clone, "c.txt");

        var s = await g.Analyze(clone);

        Assert.Equal(2, s.Ahead);
        Assert.Equal(2, s.UnpublishedCommitsTotal);
        Assert.Contains(s.States, x => x.StartsWith("Commits aparentemente pendientes"));
    }

    [Fact]
    public async Task Local_branch_without_upstream_is_counted()
    {
        using var g = new GitFixture();
        var origin = g.Repo("origin");
        g.Commit(origin);
        var clone = CloneOf(g, origin, "clone");
        g.Git(clone, "switch", "-q", "-c", "feature");
        g.Commit(clone, "f.txt");

        var s = await g.Analyze(clone);

        var feature = s.Branches.Single(b => b.Name == "feature");
        Assert.Null(feature.Upstream);
        Assert.Equal(1, feature.CommitsNotOnAnyRemoteRef);
        Assert.Contains("Rama actual sin upstream configurado", s.States);
    }

    [Fact]
    public async Task Stashes_are_counted_without_being_applied()
    {
        using var g = new GitFixture();
        var repo = g.Repo("stashed");
        g.Commit(repo);
        File.WriteAllText(Path.Combine(repo, "a.txt"), "wip");
        g.Git(repo, "stash", "push", "-q");

        var s = await g.Analyze(repo);

        Assert.Equal(1, s.StashCount);
        Assert.Equal("x", File.ReadAllText(Path.Combine(repo, "a.txt")));
        Assert.Contains(s.States, x => x.StartsWith("Stashes existentes"));
    }

    [Fact]
    public async Task Worktree_with_git_file_is_recognized_by_scan_and_analyzer()
    {
        using var g = new GitFixture();
        var repo = g.Repo("main");
        g.Commit(repo);
        var worktree = Path.Combine(g.Root, "wt");
        g.Git(repo, "worktree", "add", "-q", "-b", "wt-branch", worktree);
        Assert.True(File.Exists(Path.Combine(worktree, ".git")));

        var (c, _, _) = await Scan.RunAsync(g.Root);
        var candidate = c.Repositories.Single(r => r.Path == worktree);
        Assert.True(candidate.GitIsFile);

        var s = await g.Analyzer.AnalyzeAsync(candidate, false, default);
        Assert.True(s.IsWorktree);
        Assert.Equal("wt-branch", s.CurrentBranch);
    }

    [Fact]
    public async Task Nested_repositories_and_submodules_are_discovered()
    {
        using var g = new GitFixture();
        var outer = g.Repo("outer");
        g.Commit(outer);
        var nested = Path.Combine(outer, "vendor", "inner");
        Directory.CreateDirectory(nested);
        g.Git(nested, "init", "-q");

        var lib = g.Repo("lib");
        g.Commit(lib);
        g.Git(outer, "-c", "protocol.file.allow=always", "submodule", "add", "-q", lib, "sub");

        var (c, _, _) = await Scan.RunAsync(g.Root);

        Assert.Equal(outer, c.Repositories.Single(r => r.Path == nested).ParentRepo);
        var sub = c.Repositories.Single(r => r.Path == Path.Combine(outer, "sub"));
        var subStatus = await g.Analyzer.AnalyzeAsync(sub, false, default);
        Assert.True(subStatus.IsSubmodule);
        var outerStatus = await g.Analyzer.AnalyzeAsync(c.Repositories.Single(r => r.Path == outer), false, default);
        Assert.Equal(1, outerStatus.Submodules);
    }

    [Fact]
    public async Task Ignored_sensitive_files_are_listed_by_name_without_reading_secrets()
    {
        using var g = new GitFixture();
        var repo = g.Repo("secrets");
        File.WriteAllText(Path.Combine(repo, ".gitignore"), ".env\nlocal.sqlite\nbuild/\n");
        g.Commit(repo, "a.txt");
        File.WriteAllText(Path.Combine(repo, ".env"), "API_KEY=super-secret-value");
        File.WriteAllText(Path.Combine(repo, "local.sqlite"), "db");
        Directory.CreateDirectory(Path.Combine(repo, "build"));
        File.WriteAllText(Path.Combine(repo, "build", "o.js"), "x");

        var s = await g.Analyze(repo);

        Assert.Contains(".env", s.SensitiveIgnored);
        Assert.Contains("local.sqlite", s.SensitiveIgnored);
        Assert.DoesNotContain(s.SensitiveIgnored, i => i.Contains("build"));
        Assert.DoesNotContain("super-secret-value", JsonSerializer.Serialize(s, AuditJson.Options));
    }

    [Fact]
    public async Task Remote_token_never_reaches_results()
    {
        using var g = new GitFixture();
        var repo = g.Repo("token");
        g.Git(repo, "remote", "add", "origin", "https://user:ghp_verysecret@example.invalid/a.git");

        var s = await g.Analyze(repo);

        Assert.Equal("https://example.invalid/a.git", s.Remotes.Single().SanitizedUrl);
        Assert.DoesNotContain("ghp_verysecret", JsonSerializer.Serialize(s, AuditJson.Options));
    }

    [Fact]
    public async Task Analysis_does_not_modify_repository_including_index_and_refs()
    {
        using var g = new GitFixture();
        var repo = g.Repo("readonly");
        g.Commit(repo);
        File.WriteAllText(Path.Combine(repo, "a.txt"), "modified without staging");
        File.WriteAllText(Path.Combine(repo, "b.txt"), "untracked");
        g.Git(repo, "stash", "push", "-q", "--include-untracked");
        File.WriteAllText(Path.Combine(repo, "a.txt"), "again");
        File.SetLastWriteTimeUtc(Path.Combine(repo, "a.txt"), DateTime.UtcNow.AddHours(-1));
        var before = Scan.Fingerprint(repo);

        await g.Analyze(repo);

        Assert.Equal(before, Scan.Fingerprint(repo));
    }

    [Fact]
    public async Task Corrupt_repository_is_reported_as_not_verifiable()
    {
        using var t = new TempTree();
        t.File(@"broken\.git\HEAD", 5);
        var s = await new GitAnalyzer(new ProcessRunner()).AnalyzeAsync(
            new RepoCandidate(Path.Combine(t.Root, "broken"), false, false, null, new DirectoryTotals()), false, default);
        Assert.NotNull(s.Error);
        Assert.Contains(s.States, x => x.StartsWith("Estado no verificable"));
    }

    [Fact]
    public async Task Tracked_check_distinguishes_committed_artifacts()
    {
        using var g = new GitFixture();
        var repo = g.Repo("tracked");
        Directory.CreateDirectory(Path.Combine(repo, "dist"));
        g.Commit(repo, @"dist\bundle.js");
        Directory.CreateDirectory(Path.Combine(repo, "obj"));
        File.WriteAllText(Path.Combine(repo, "obj", "x.o"), "x");

        Assert.True(await g.Analyzer.HasTrackedFilesAsync(repo, Path.Combine(repo, "dist"), default));
        Assert.False(await g.Analyzer.HasTrackedFilesAsync(repo, Path.Combine(repo, "obj"), default));
    }

    [Fact]
    public async Task Missing_git_is_handled()
    {
        var analyzer = new GitAnalyzer(new ProcessRunner(), "git-does-not-exist-" + Guid.NewGuid().ToString("N"));
        Assert.False(await analyzer.IsAvailableAsync(default));
    }
}

public class DuplicateTests
{
    private static async Task<DuplicateReport> Detect(TempTree t, long min = 1)
    {
        var loc = KnownLocations.UnderRoot(Path.Combine(t.Root, "none"));
        var scanner = new Win32FileScanner();
        var collector = new ScanCollector(loc, new CollectorLimits { DuplicateMinBytes = min }, true);
        await scanner.ScanAsync(new ScanRequest { Roots = [t.Root], Mode = ScanMode.Deep }, collector, new ScanProgress(), new CoverageTracker(), default);
        return await new DuplicateDetector(scanner).DetectAsync(collector.DuplicateCandidates, null, default);
    }

    [Fact]
    public async Task True_duplicates_are_confirmed()
    {
        using var t = new TempTree();
        t.File(@"a\x.bin", 300_000);
        t.File(@"b\y.bin", 300_000);
        t.File(@"c\z.bin", 300_000);

        var r = await Detect(t);

        var g = Assert.Single(r.Groups);
        Assert.Equal(3, g.Paths.Count);
        Assert.Equal(600_000, g.RedundantBytes);
        Assert.False(g.ContainsSensitiveContent);
    }

    [Fact]
    public async Task Same_size_different_content_is_not_duplicate()
    {
        using var t = new TempTree();
        t.File("a.bin", 300_000, fill: 1);
        t.File("b.bin", 300_000, fill: 2);

        var r = await Detect(t);

        Assert.Empty(r.Groups);
        Assert.Equal(0, r.FilesHashed); // La firma parcial evitó el hash completo.
    }

    [Fact]
    public async Task Difference_in_the_middle_requires_full_hash_and_is_not_duplicate()
    {
        using var t = new TempTree();
        var a = t.File("a.bin", 500_000);
        var b = t.File("b.bin", 500_000);
        var content = File.ReadAllBytes(b);
        content[250_000] = 9;
        File.WriteAllBytes(b, content);

        var r = await Detect(t);

        Assert.Empty(r.Groups);
        Assert.Equal(2, r.FilesHashed);
    }

    [Fact]
    public async Task Unique_sizes_are_never_read()
    {
        using var t = new TempTree();
        t.File("a.bin", 100_000);
        t.File("b.bin", 200_000);

        var r = await Detect(t);

        Assert.Equal(0, r.BytesRead);
    }

    [Fact]
    public async Task Hard_links_are_not_duplicates()
    {
        using var t = new TempTree();
        var original = t.File("a.bin", 300_000);
        Process.Start(new ProcessStartInfo("cmd.exe", ["/c", "mklink", "/H", Path.Combine(t.Root, "b.bin"), original]) { UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true })!.WaitForExit();
        Assert.True(File.Exists(Path.Combine(t.Root, "b.bin")));

        var r = await Detect(t);

        Assert.Empty(r.Groups);
        Assert.Equal(0, r.BytesRead);
    }

    [Fact]
    public async Task Online_only_files_are_not_read()
    {
        using var t = new TempTree();
        var a = t.File("a.bin", 300_000);
        var b = t.File("b.bin", 300_000);
        File.SetAttributes(a, FileAttributes.Offline);

        var r = await Detect(t);

        Assert.Empty(r.Groups);
        Assert.Equal(0, r.BytesRead);
    }

    [Fact]
    public async Task Candidate_that_becomes_online_only_after_scan_is_skipped()
    {
        using var t = new TempTree();
        var a = t.File("a.bin", 300_000);
        var b = t.File("b.bin", 300_000);
        var retained = new[] { new RetainedFile(a, 300_000, 300_000, default, File.GetLastWriteTimeUtc(a), 1, false, false), new RetainedFile(b, 300_000, 300_000, default, File.GetLastWriteTimeUtc(b), 1, false, false) };
        File.SetAttributes(a, FileAttributes.Offline);

        var r = await new DuplicateDetector(new Win32FileScanner()).DetectAsync(retained, null, default);

        Assert.Empty(r.Groups);
        Assert.Equal(1, r.SkippedOnlineOnly);
    }

    [Fact]
    public async Task Locked_files_are_skipped_and_counted()
    {
        using var t = new TempTree();
        var a = t.File("a.bin", 300_000);
        t.File("b.bin", 300_000);
        using var exclusive = new FileStream(a, FileMode.Open, FileAccess.Read, FileShare.None);

        var r = await Detect(t);

        Assert.Empty(r.Groups);
        Assert.True(r.SkippedLocked >= 1);
    }

    [Fact]
    public async Task Personal_duplicates_are_marked_sensitive()
    {
        using var t = new TempTree();
        t.File("a.jpg", 300_000);
        t.File("b.jpg", 300_000);

        Assert.True(Assert.Single((await Detect(t)).Groups).ContainsSensitiveContent);
    }

    [Fact]
    public async Task Cancellation_propagates()
    {
        using var t = new TempTree();
        t.File("a.bin", 300_000);
        t.File("b.bin", 300_000);
        var scanner = new Win32FileScanner();
        var collector = new ScanCollector(KnownLocations.UnderRoot(Path.Combine(t.Root, "n")), new CollectorLimits { DuplicateMinBytes = 1 }, true);
        await scanner.ScanAsync(new ScanRequest { Roots = [t.Root] }, collector, new ScanProgress(), new CoverageTracker(), default);
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new DuplicateDetector(scanner).DetectAsync(collector.DuplicateCandidates, null, cts.Token));
    }

    [Fact]
    public async Task Hashing_does_not_modify_files()
    {
        using var t = new TempTree();
        t.File("a.bin", 300_000);
        t.File("b.bin", 300_000);
        var before = Scan.Fingerprint(t.Root);

        await Detect(t);

        Assert.Equal(before, Scan.Fingerprint(t.Root));
    }
}

public class BackupVerifierTests
{
    private static KnownLocations Loc(TempTree t, params string[] cloud) => KnownLocations.UnderRoot(Path.Combine(t.Root, "n")) with { CloudSyncRoots = cloud };

    private static PersonalFileRecord Record(string path, bool online = false) =>
        new() { Path = path, Kind = PersonalKind.Office, Bytes = new FileInfo(path).Length, LastWriteUtc = File.GetLastWriteTimeUtc(path), IsOnlineOnly = online };

    private static Task Verify(TempTree t, PersonalFileRecord r, bool hashes = false, KnownLocations? loc = null, params string[] destinations) =>
        new BackupVerifier(new Win32FileScanner()).VerifyAsync([r], destinations, hashes, loc ?? Loc(t), new CoverageTracker(), default);

    [Fact]
    public async Task No_destination_means_not_evaluated()
    {
        using var t = new TempTree();
        var r = Record(t.File(@"docs\a.docx"));
        await Verify(t, r);
        Assert.Equal(BackupState.NotEvaluated, r.BackupState);
    }

    [Fact]
    public async Task No_match_means_no_copy_found()
    {
        using var t = new TempTree();
        t.Dir("bk");
        var r = Record(t.File(@"docs\a.docx"));
        await Verify(t, r, false, null, Path.Combine(t.Root, "bk"));
        Assert.Equal(BackupState.NoCopyFound, r.BackupState);
    }

    [Fact]
    public async Task Metadata_match_is_only_possible_copy()
    {
        using var t = new TempTree();
        var r = Record(t.File(@"docs\a.docx", 100, new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc)));
        t.File(@"bk\deep\a.docx", 100, new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc));
        await Verify(t, r, false, null, Path.Combine(t.Root, "bk"));
        Assert.Equal(BackupState.PossibleCopy, r.BackupState);
    }

    [Fact]
    public async Task Hash_match_is_verified_copy()
    {
        using var t = new TempTree();
        var r = Record(t.File(@"docs\a.docx", 100));
        t.File(@"bk\a.docx", 100);
        await Verify(t, r, true, null, Path.Combine(t.Root, "bk"));
        Assert.Equal(BackupState.VerifiedCopy, r.BackupState);
    }

    [Fact]
    public async Task Same_metadata_different_content_is_never_verified()
    {
        using var t = new TempTree();
        var r = Record(t.File(@"docs\a.docx", 100, fill: 1));
        t.File(@"bk\a.docx", 100, fill: 2);
        await Verify(t, r, true, null, Path.Combine(t.Root, "bk"));
        Assert.Equal(BackupState.PossibleCopy, r.BackupState);
        Assert.Contains("distinto", r.BackupDetail);
    }

    [Fact]
    public async Task Online_only_copy_is_not_verifiable_and_not_downloaded()
    {
        using var t = new TempTree();
        var r = Record(t.File(@"docs\a.docx", 100));
        var copy = t.File(@"bk\a.docx", 100);
        File.SetAttributes(copy, FileAttributes.Offline);
        await Verify(t, r, true, null, Path.Combine(t.Root, "bk"));
        Assert.Equal(BackupState.NotVerifiable, r.BackupState);
    }

    [Fact]
    public async Task Synced_folder_is_not_treated_as_backup()
    {
        using var t = new TempTree();
        var cloud = t.Dir("OneDrive");
        var r = Record(t.File(@"OneDrive\a.docx"));
        await Verify(t, r, false, Loc(t, cloud));
        Assert.Equal(BackupState.NotVerifiable, r.BackupState);
        Assert.Contains("no garantiza", r.BackupDetail);
    }

    [Fact]
    public async Task Missing_destination_is_reported()
    {
        using var t = new TempTree();
        var coverage = new CoverageTracker();
        var r = Record(t.File("a.docx"));
        await new BackupVerifier(new Win32FileScanner()).VerifyAsync([r], [Path.Combine(t.Root, "gone")], false, Loc(t), coverage, default);
        Assert.Equal(1, coverage.ToReport([], false).IssueCounts[ScanIssueKind.NotFound]);
    }
}

public class AppSourceTests
{
    [Fact]
    public void Registry_entry_is_parsed()
    {
        var values = new Dictionary<string, object> { ["DisplayName"] = " VLC ", ["Publisher"] = "VideoLAN", ["DisplayVersion"] = "3.0", ["InstallLocation"] = "\"C:\\VLC\"", ["EstimatedSize"] = 2048, ["InstallDate"] = "20240315" };
        var a = RegistryAppSource.Parse(k => values.GetValueOrDefault(k), "HKLM")!;
        Assert.Equal("VLC", a.Name);
        Assert.Equal(@"C:\VLC", a.InstallLocation);
        Assert.Equal(2048 * 1024, a.EstimatedSizeBytes);
        Assert.Equal(new DateTime(2024, 3, 15), a.InstallDate);
    }

    [Theory]
    [InlineData("SystemComponent", 1)]
    [InlineData("ParentKeyName", "KB123")]
    public void Hidden_and_child_entries_are_skipped(string key, object value)
    {
        var values = new Dictionary<string, object> { ["DisplayName"] = "x", [key] = value };
        Assert.Null(RegistryAppSource.Parse(k => values.GetValueOrDefault(k), "HKLM"));
    }

    [Fact]
    public void Entry_without_name_or_bad_date_is_tolerated()
    {
        Assert.Null(RegistryAppSource.Parse(_ => null, "HKLM"));
        var values = new Dictionary<string, object> { ["DisplayName"] = "x", ["InstallDate"] = "ayer", ["EstimatedSize"] = 0 };
        var a = RegistryAppSource.Parse(k => values.GetValueOrDefault(k), "HKLM")!;
        Assert.Null(a.InstallDate);
        Assert.Null(a.EstimatedSizeBytes);
    }

    [Fact]
    public async Task Real_registry_inventory_returns_named_entries()
    {
        var apps = await new RegistryAppSource().ReadAsync(default);
        Assert.All(apps, a => Assert.False(string.IsNullOrWhiteSpace(a.Name)));
    }

    [Fact]
    public void Appx_json_handles_object_and_array()
    {
        Assert.Single(AppxAppSource.Parse("""{"Name":"A","PackageFamilyName":"A_1"}"""));
        Assert.Equal(2, AppxAppSource.Parse("""[{"Name":"A"},{"Name":"B"}]""").Count);
        Assert.Empty(AppxAppSource.Parse(""));
    }

    [Fact]
    public async Task Real_appx_query_is_read_only_and_parses()
    {
        var apps = await new AppxAppSource(new ProcessRunner()).ReadAsync(default);
        Assert.All(apps, a => Assert.Equal("MSIX/AppX", a.Source));
    }

    [Fact]
    public void UserAssist_value_is_decoded()
    {
        var data = new byte[72];
        BitConverter.TryWriteBytes(data.AsSpan(4), 7);
        var when = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc);
        BitConverter.TryWriteBytes(data.AsSpan(60), when.ToFileTimeUtc());
        var name = UserAssistSource.Rot13(@"C:\Apps\Tool\tool.exe");

        var r = UserAssistSource.TryParse(name, data)!;

        Assert.Equal(@"C:\Apps\Tool\tool.exe", r.ExecutablePathOrId);
        Assert.Equal(7, r.RunCount);
        Assert.Equal(when, r.LastRunUtc);
    }

    [Fact]
    public void UserAssist_rejects_unexpected_format()
    {
        Assert.Null(UserAssistSource.TryParse("x", new byte[16]));
        Assert.Null(UserAssistSource.TryParse(UserAssistSource.Rot13("UEME_CTLSESSION"), new byte[72]));
    }

    [Fact]
    public void UserAssist_known_folder_is_resolved()
    {
        var r = UserAssistSource.TryParse(UserAssistSource.Rot13(@"{6D809377-6AF0-444B-8957-A3773F02200E}\App\a.exe"), new byte[72])!;
        Assert.Equal(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "App", "a.exe"), r.ExecutablePathOrId);
        Assert.Null(r.LastRunUtc);
    }

    [Fact]
    public async Task Prefetch_reads_names_from_a_controlled_directory()
    {
        using var t = new TempTree();
        var when = new DateTime(2026, 2, 2, 0, 0, 0, DateTimeKind.Utc);
        t.File(@"pf\TOOL.EXE-ABCDEF12.pf", 10, when);
        var data = await new PrefetchSource(Path.Combine(t.Root, "pf")).ReadAsync(default);
        var record = Assert.Single(data.Records);
        Assert.Equal("TOOL.EXE", record.ExecutablePathOrId);
        Assert.Equal(when, record.LastRunUtc);
    }

    [Fact]
    public async Task Missing_prefetch_is_reported_as_unavailable_not_as_no_usage()
    {
        using var t = new TempTree();
        var data = await new PrefetchSource(Path.Combine(t.Root, "none")).ReadAsync(default);
        Assert.False(data.Status.Available);
        Assert.Empty(data.Records);
    }

    [Fact]
    public async Task Real_system_prefetch_never_throws()
    {
        var data = await new PrefetchSource().ReadAsync(default);
        if (!data.Status.Available) Assert.Contains("administrador", data.Status.Detail);
    }
}

public class PersistenceTests
{
    private static AuditResult Result(long physical, string category = "Other", string folder = @"C:\a") => new()
    {
        StartedUtc = DateTime.UtcNow,
        FinishedUtc = DateTime.UtcNow,
        Roots = [@"C:\a"],
        Storage = new StorageSummary
        {
            PhysicalBytes = physical,
            ByCategory = [new BreakdownEntry(category, physical, physical, 1)],
            TopFolders = [new StorageItem { Path = folder, ContentType = "x", PhysicalBytes = physical }],
        },
        Reclaim = new ReclaimSummary { CandidateReclaimableBytes = 5 },
        Coverage = new CoverageReport(),
    };

    [Fact]
    public void History_saves_lists_compares_and_clears()
    {
        using var t = new TempTree();
        var store = new HistoryStore(new AppPaths(t.Root, t.Root));
        var a = store.Save(Result(100));
        var b = store.Save(Result(350));

        Assert.Equal(2, store.List().Count);
        var cmp = store.Compare(a, b)!;
        Assert.Equal(250, cmp.Categories.Single().Change);
        Assert.Equal(250, cmp.Folders.Single().Change);
        Assert.Null(store.Compare(a, 999));

        Assert.True(store.Clear());
        Assert.False(File.Exists(Path.Combine(t.Root, "history.db")));
        Assert.Empty(store.List());
        Assert.False(store.Clear());
    }

    [Fact]
    public void Sql_special_characters_are_data()
    {
        using var t = new TempTree();
        var store = new HistoryStore(new AppPaths(t.Root, t.Root));
        var id = store.Save(Result(1, folder: @"C:\x'); DROP TABLE scans;--"));
        Assert.Contains(store.List(), e => e.Id == id);
    }

    [Fact]
    public void History_database_never_contains_file_content_or_hashes()
    {
        using var t = new TempTree();
        var store = new HistoryStore(new AppPaths(t.Root, t.Root));
        store.Save(Result(1));
        var bytes = File.ReadAllBytes(Path.Combine(t.Root, "history.db"));
        var text = Encoding.UTF8.GetString(bytes);
        Assert.DoesNotContain("sha256", text, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("hash", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Config_round_trips_and_defaults_when_missing()
    {
        using var t = new TempTree();
        var store = new ConfigStore(new AppPaths(t.Root, t.Root));
        Assert.Empty(store.Load().Exclusions);
        store.Save(new AppConfig { Exclusions = ["x"], Thresholds = new AuditThresholds { TempAgeDays = 5 } });
        var loaded = store.Load();
        Assert.Equal("x", loaded.Exclusions.Single());
        Assert.Equal(5, loaded.Thresholds.TempAgeDays);
        store.Delete();
        Assert.Empty(store.Load().Exclusions);
    }

    [Fact]
    public void Corrupt_config_gives_clear_error()
    {
        using var t = new TempTree();
        File.WriteAllText(Path.Combine(t.Root, "config.json"), "{not json");
        Assert.Throws<InvalidDataException>(() => new ConfigStore(new AppPaths(t.Root, t.Root)).Load());
    }

    [Fact]
    public void Result_round_trips()
    {
        using var t = new TempTree();
        var store = new ResultStore(new AppPaths(t.Root, t.Root));
        Assert.Null(store.Load());
        store.Save(Result(42));
        Assert.Equal(42, store.Load()!.Storage.PhysicalBytes);
        Assert.True(store.Delete());
        Assert.False(store.Delete());
    }
}

public class ProcessRunnerTests
{
    [Fact]
    public async Task Arguments_are_not_interpreted_by_a_shell()
    {
        using var t = new TempTree();
        var marker = Path.Combine(t.Root, "pwned.txt");
        var hostile = $"x & echo y > \"{marker}\"";
        var r = await new ProcessRunner().RunAsync("git", ["--version", hostile], null, TimeSpan.FromSeconds(20), null, default);
        Assert.False(File.Exists(marker));
        Assert.False(r.StartFailed);
    }

    [Fact]
    public async Task Timeout_kills_process()
    {
        var clock = Stopwatch.StartNew();
        var r = await new ProcessRunner().RunAsync("powershell.exe", ["-NoProfile", "-Command", "Start-Sleep 30"], null, TimeSpan.FromSeconds(1), null, default);
        Assert.True(r.TimedOut);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(20));
    }

    [Fact]
    public async Task Missing_executable_reports_start_failure()
    {
        var r = await new ProcessRunner().RunAsync("no-such-tool-" + Guid.NewGuid().ToString("N"), [], null, TimeSpan.FromSeconds(5), null, default);
        Assert.True(r.StartFailed);
    }
}

public class MaintenanceProbeTests
{
    [Fact]
    public async Task Real_probe_reads_state_without_elevation_or_failure()
    {
        var probe = new WinStorageAudit.Infrastructure.Maintenance.WindowsMaintenanceProbe(new ProcessRunner());
        var s = await probe.ProbeAsync(false, default);
        Assert.False(string.IsNullOrEmpty(s.SystemDrive));
        Assert.NotNull(s.RecycleBinBytes); // Falla si SHQUERYRBINFO tuviera un empaquetado incorrecto.
    }
}

/// <summary>Ejercita el ejecutable real en una carpeta confinada con WINSTORAGEAUDIT_SANDBOX_ROOT.</summary>
public class CliEndToEndTests
{
    private static (int Code, string Out, string Err) Cli(string sandbox, string home, params string[] args)
    {
        var exe = Path.Combine(AppContext.BaseDirectory, "winstorageaudit.exe");
        var psi = new ProcessStartInfo(exe) { RedirectStandardOutput = true, RedirectStandardError = true, RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true, StandardOutputEncoding = Encoding.UTF8 };
        psi.Environment["WINSTORAGEAUDIT_HOME"] = home;
        psi.Environment["WINSTORAGEAUDIT_SANDBOX_ROOT"] = sandbox;
        psi.Environment["COLUMNS"] = "240";
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        p.StandardInput.Close();
        var stderr = p.StandardError.ReadToEndAsync();
        var stdout = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        return (p.ExitCode, stdout, stderr.Result);
    }

    private static void BuildSandbox(TempTree t)
    {
        var old = DateTime.UtcNow.AddYears(-2);
        t.File(@"sb\Users\demo\Downloads\setup.exe", 200_000, old);
        t.File(@"sb\Users\demo\AppData\Local\Temp\job\x.bin", 12 * 1024 * 1024, old);
        t.File(@"sb\Users\demo\Documents\tesis.docx", 2000, old);
        t.File(@"sb\Users\demo\Documents\copia\tesis.docx", 2000, old);
        t.File(@"sb\Users\demo\Dev\app\package.json", 10, old);
        t.File(@"sb\Users\demo\Dev\app\package-lock.json", 10, old);
        t.File(@"sb\Users\demo\Dev\app\node_modules\dep\i.js", 11 * 1024 * 1024, old);
        t.File(@"sb\Users\demo\weird[bold]\[red]name.txt", 5, old);
    }

    [Fact]
    public void Full_flow_scan_report_history_config()
    {
        using var t = new TempTree();
        BuildSandbox(t);
        var sandbox = Path.Combine(t.Root, "sb");
        var home = Path.Combine(t.Root, "home");
        var before = Scan.Fingerprint(sandbox);

        var scan = Cli(sandbox, home, "scan", "--quick", "--path", sandbox);
        Assert.True(scan.Code == 0, scan.Out + scan.Err);
        Assert.Contains("Efectivamente liberado", scan.Out);
        Assert.Equal(before, Scan.Fingerprint(sandbox));

        var recs = Cli(sandbox, home, "recommendations", "--class", "limpieza", "--top", "50");
        Assert.Equal(0, recs.Code);
        Assert.Contains("node_modules", recs.Out);

        var filtered = Cli(sandbox, home, "recommendations", "--risk", "crítico", "--class", "limpieza");
        Assert.Equal(0, filtered.Code);
        Assert.DoesNotContain("node_modules", filtered.Out);

        Assert.Equal(0, Cli(sandbox, home, "top", "folders").Code);
        Assert.Equal(0, Cli(sandbox, home, "top", "extensions", "--sort", "logical").Code);

        var html = Path.Combine(t.Root, "r.html");
        Assert.Equal(0, Cli(sandbox, home, "report", "--format", "html", "--output", html).Code);
        Assert.Contains("weird[bold]", File.ReadAllText(html));
        var existing = Cli(sandbox, home, "report", "--format", "html", "--output", html);
        Assert.Equal(2, existing.Code);
        Assert.Equal(0, Cli(sandbox, home, "report", "--format", "html", "--output", html, "--force").Code);

        var json = Path.Combine(t.Root, "r.json");
        Assert.Equal(0, Cli(sandbox, home, "report", "--format", "json", "--output", json).Code);
        using (var doc = JsonDocument.Parse(File.ReadAllText(json)))
            Assert.True(doc.RootElement.GetProperty("Findings").GetArrayLength() > 0);

        var plan = Path.Combine(t.Root, "p.md");
        Assert.Equal(0, Cli(sandbox, home, "report", "--format", "plan", "--output", plan).Code);
        Assert.Contains("no es un script", File.ReadAllText(plan));

        Assert.Equal(0, Cli(sandbox, home, "scan", "--path", sandbox).Code);
        var history = Cli(sandbox, home, "history");
        Assert.Contains("Historial", history.Out);
        Assert.Equal(0, Cli(sandbox, home, "history", "compare", "1", "2").Code);

        Assert.Equal(0, Cli(sandbox, home, "config", "add-exclude", "node_modules").Code);
        Assert.Contains("node_modules", Cli(sandbox, home, "config", "show").Out);
        Assert.Equal(0, Cli(sandbox, home, "config", "set", "temp-age-days", "7").Code);
        Assert.Equal(2, Cli(sandbox, home, "config", "set", "temp-age-days", "abc").Code);
        Assert.Equal(2, Cli(sandbox, home, "config", "add-backup", @"\\server\share").Code);

        Assert.Equal(2, Cli(sandbox, home, "history", "clear").Code); // Sin terminal y sin --yes no borra.
        Assert.Equal(0, Cli(sandbox, home, "history", "clear", "--yes").Code);
        Assert.Equal(1, Cli(sandbox, home, "recommendations").Code);

        Assert.Equal(before, Scan.Fingerprint(sandbox));
    }

    [Fact]
    public void Deep_scan_finds_duplicates_and_repositories()
    {
        using var t = new TempTree();
        BuildSandbox(t);
        t.File(@"sb\Users\demo\Media\v1.mp4", 2 * 1024 * 1024);
        t.File(@"sb\Users\demo\Media\v2.mp4", 2 * 1024 * 1024);
        var sandbox = Path.Combine(t.Root, "sb");
        var home = Path.Combine(t.Root, "home");
        using var g = new GitFixture();
        var repo = Path.Combine(sandbox, "Users", "demo", "Dev", "solo");
        Directory.CreateDirectory(repo);
        g.Git(repo, "init", "-q");

        var scan = Cli(sandbox, home, "scan", "--deep", "--path", sandbox);
        Assert.True(scan.Code == 0, scan.Out + scan.Err);

        var dup = Cli(sandbox, home, "recommendations", "--area", "duplicados", "--top", "50");
        Assert.Contains("v1.mp4", dup.Out);
        var git = Cli(sandbox, home, "recommendations", "--area", "git", "--top", "50");
        Assert.Contains("solo", git.Out);
    }

    [Fact]
    public void Usage_errors_are_reported_in_spanish_with_exit_code_2()
    {
        using var t = new TempTree();
        var home = t.Dir("h");
        Assert.Contains("Comando desconocido", Cli(t.Root, home, "nope").Out);
        var opt = Cli(t.Root, home, "scan", "--pat", "x");
        Assert.Equal(2, opt.Code);
        Assert.Contains("--path", opt.Out);
        Assert.Equal(2, Cli(t.Root, home, "scan", "--quick", "--deep").Code);
        Assert.Equal(2, Cli(t.Root, home, "scan", "--concurrency", "0").Code);
        Assert.Equal(2, Cli(t.Root, home, "scan", "--drive", "nada").Code);
        Assert.Equal(2, Cli(t.Root, home, "analyze", "nada").Code);
    }

    [Fact]
    public void Help_is_available_for_every_command()
    {
        using var t = new TempTree();
        var home = t.Dir("h");
        Assert.Contains("Uso:", Cli(t.Root, home, "--help").Out);
        foreach (var c in WinStorageAudit.Cli.Commands.All)
            Assert.Contains("Uso:", Cli(t.Root, home, c.Name, "--help").Out);
    }

    [Fact]
    public void Scan_without_saved_result_commands_explain_what_to_do()
    {
        using var t = new TempTree();
        var r = Cli(t.Root, t.Dir("h"), "report");
        Assert.Equal(1, r.Code);
        Assert.Contains("scan", r.Out);
    }

    [Fact]
    public void Parser_handles_values_and_repetition()
    {
        var parsed = WinStorageAudit.Cli.ArgParser.Parse(["--path", @"C:\a b", "--path=C:\\c", "--deep"], WinStorageAudit.Cli.Commands.Scan);
        Assert.Equal(2, parsed.All("path").Count);
        Assert.True(parsed.Has("deep"));
    }
}

/// <summary>Una ruta con caracteres extremos no debe romper el análisis ni el reporte.</summary>
public class PipelineTests
{
    [Fact]
    public async Task Pipeline_produces_consistent_totals_on_controlled_tree()
    {
        using var t = new TempTree();
        var loc = KnownLocations.UnderRoot(t.Root);
        var old = DateTime.UtcNow.AddYears(-1);
        t.File(@"Users\demo\AppData\Local\Temp\j\x.bin", 11 * 1024 * 1024, old);
        t.File(@"Users\demo\Dev\a\package.json", 10, old);
        t.File(@"Users\demo\Dev\a\package-lock.json", 10, old);
        t.File(@"Users\demo\Dev\a\node_modules\d\i.js", 12 * 1024 * 1024, old);
        t.File(@"Users\demo\AppData\Local\Docker\wsl\disk\docker_data.vhdx", 13 * 1024 * 1024, old);
        var scanner = new Win32FileScanner();
        var deps = new AuditDependencies { Scanner = scanner, Identity = scanner, Processes = new ProcessRunner(), Locations = loc, VolumeReader = VolumeInfoProvider.ForRoots };
        var before = Scan.Fingerprint(t.Root);

        var r = await new AuditPipeline(deps).RunAsync(new AuditOptions { Request = new ScanRequest { Roots = [t.Root] } }, new ScanProgress(), default);

        Assert.Equal(before, Scan.Fingerprint(t.Root));
        Assert.Contains(r.Findings, f => f.Recommendation == RecommendationClass.Keep && f.PathOrResource.EndsWith("docker_data.vhdx"));
        Assert.Contains(r.Findings, f => f.Recommendation == RecommendationClass.CleanupCandidate && f.PathOrResource.EndsWith("node_modules"));
        Assert.True(r.Reclaim.CandidateReclaimableBytes + r.Reclaim.ReviewReclaimableBytes <= r.Storage.PhysicalBytes);
        Assert.Equal(r.Reclaim.CandidateReclaimableBytes, r.Findings.Where(f => f.Recommendation == RecommendationClass.CleanupCandidate).Sum(f => f.CountedReclaimableBytes));
        Assert.Equal(r.Storage.PhysicalBytes, r.Storage.ByCategory.Sum(c => c.PhysicalBytes));
        Assert.Equal(r.Storage.LogicalBytes, r.Storage.ByCategory.Sum(c => c.LogicalBytes));
        Assert.Contains(r.Storage.TopFolders, f => f.ReclaimableBytes > 0);
        Assert.NotEmpty(r.Coverage.Notes);
    }

    [Fact]
    public async Task Cancelled_pipeline_returns_flagged_partial_result()
    {
        using var t = new TempTree();
        t.File(@"a\b.bin", 10);
        var scanner = new Win32FileScanner();
        var deps = new AuditDependencies { Scanner = scanner, Identity = scanner, Processes = new ProcessRunner(), Locations = KnownLocations.UnderRoot(t.Root) };
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var r = await new AuditPipeline(deps).RunAsync(new AuditOptions { Request = new ScanRequest { Roots = [t.Root] }, RunDuplicates = true }, new ScanProgress(), cts.Token);

        Assert.True(r.Coverage.WasCancelled);
        Assert.Contains(r.Coverage.Notes, n => n.Contains("cancelado"));
    }

    [Fact]
    public async Task Failing_module_is_noted_and_does_not_abort()
    {
        using var t = new TempTree();
        t.File("a.txt", 10);
        var scanner = new Win32FileScanner();
        var deps = new AuditDependencies { Scanner = scanner, Identity = scanner, Processes = new ProcessRunner(), Locations = KnownLocations.UnderRoot(t.Root), MaintenanceProbe = new ThrowingProbe() };

        var r = await new AuditPipeline(deps).RunAsync(new AuditOptions { Request = new ScanRequest { Roots = [t.Root] } }, new ScanProgress(), default);

        Assert.Contains(r.Coverage.Notes, n => n.Contains("Mantenimiento") && n.Contains("fallo simulado"));
        Assert.Equal(10, r.Storage.LogicalBytes);
    }

    [Fact]
    public async Task Without_git_the_scan_continues_and_notes_it()
    {
        using var t = new TempTree();
        t.File(@"r\.git\HEAD", 10);
        var scanner = new Win32FileScanner();
        var deps = new AuditDependencies { Scanner = scanner, Identity = scanner, Processes = new ProcessRunner(), Locations = KnownLocations.UnderRoot(t.Root), GitExecutable = "no-git-" + Guid.NewGuid().ToString("N") };

        var r = await new AuditPipeline(deps).RunAsync(new AuditOptions { Request = new ScanRequest { Roots = [t.Root] } }, new ScanProgress(), default);

        Assert.False(r.GitAvailable);
        Assert.Contains(r.Coverage.Notes, n => n.Contains("Git no está disponible"));
    }

    private sealed class ThrowingProbe : IMaintenanceProbe
    {
        public Task<MaintenanceSnapshot> ProbeAsync(bool includeExpensive, CancellationToken ct) => throw new InvalidOperationException("fallo simulado");
    }
}
