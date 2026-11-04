using System.Text.Json;
using WinStorageAudit.Core;
using WinStorageAudit.Core.Apps;
using WinStorageAudit.Core.Backup;
using WinStorageAudit.Core.Cleanup;
using WinStorageAudit.Core.Git;
using WinStorageAudit.Core.Maintenance;
using WinStorageAudit.Core.Model;
using WinStorageAudit.Core.Scanning;
using WinStorageAudit.Reporting;
using static WinStorageAudit.UnitTests.Fixtures;

namespace WinStorageAudit.UnitTests;

public class GitParsingTests
{
    [Fact]
    public void Parses_porcelain_v2_with_all_change_kinds()
    {
        var output = string.Join('\0',
            "# branch.oid abc", "# branch.head main", "# branch.upstream origin/main", "# branch.ab +3 -2", "# stash 4",
            "1 .M N... 100644 100644 100644 a a f1.txt", "1 A. N... 000000 100644 100644 0 a f2.txt", "1 MM N... 100644 100644 100644 a a f3.txt",
            "2 R. N... 100644 100644 100644 a a R100 new.txt", "old.txt", "u UU N... 1 2 3 4 a b c conflict.txt", "? untracked.txt", "! ignored.txt", "");
        var s = GitParsing.ParsePorcelainV2(output);

        Assert.Equal("main", s.Head);
        Assert.Equal("origin/main", s.Upstream);
        Assert.Equal(3, s.Ahead);
        Assert.Equal(2, s.Behind);
        Assert.Equal(4, s.Stash);
        Assert.Equal(3, s.Staged);
        Assert.Equal(2, s.Unstaged);
        Assert.Equal(1, s.Untracked);
        Assert.Equal(1, s.Conflicted);
    }

    [Fact]
    public void Detached_head_and_no_upstream()
    {
        var s = GitParsing.ParsePorcelainV2("# branch.oid abc\0# branch.head (detached)\0");
        Assert.True(s.IsDetached);
        Assert.Null(s.Upstream);
        Assert.Null(s.Ahead);
    }

    [Theory]
    [InlineData("https://user:ghp_secret@github.com/a/b.git", "https://github.com/a/b.git")]
    [InlineData("https://ghp_secret@github.com/a/b.git", "https://github.com/a/b.git")]
    [InlineData("ssh://git@github.com/a/b.git", "ssh://git@github.com/a/b.git")]
    [InlineData("ssh://git:pw@github.com/a/b.git", "ssh://github.com/a/b.git")]
    [InlineData("git@github.com:a/b.git", "git@github.com:a/b.git")]
    [InlineData(@"C:\repos\b.git", @"C:\repos\b.git")]
    public void Remote_urls_never_expose_credentials(string input, string expected)
    {
        Assert.Equal(expected, GitParsing.SanitizeRemoteUrl(input));
    }

    [Fact]
    public void Parses_remote_config_records()
    {
        var r = GitParsing.ParseRemoteConfig("remote.origin.url\nhttps://t:x@host/a.git\0remote.back.up.url\nC:\\b\0");
        Assert.Equal(2, r.Count);
        Assert.Equal("origin", r[0].Name);
        Assert.Equal("https://host/a.git", r[0].SanitizedUrl);
        Assert.Equal("back.up", r[1].Name);
    }

    [Theory]
    [InlineData(".env", true)]
    [InlineData(".env.local", true)]
    [InlineData("config/appsettings.Development.json", true)]
    [InlineData("data/app.sqlite", true)]
    [InlineData("certs/server.pfx", true)]
    [InlineData("secrets.yaml", true)]
    [InlineData("bin/", false)]
    [InlineData("node_modules/", false)]
    [InlineData("build/out.js", false)]
    public void Sensitive_ignored_names(string path, bool expected)
    {
        Assert.Equal(expected, SensitiveIgnoredPatterns.IsPotentiallyImportant(path));
    }
}

public class BackupPriorityTests
{
    private static GitRepositoryStatus Repo(string name, bool remote = false, int unstaged = 0, int untracked = 0, int stash = 0, int unpublished = 0, string? error = null) => new()
    {
        Path = @"C:\r\" + name,
        Remotes = remote ? [new GitRemoteInfo("origin", "u")] : [],
        UnstagedChanges = unstaged,
        UntrackedFiles = untracked,
        StashCount = stash,
        Branches = unpublished > 0 ? [new GitBranchInfo { Name = "m", CommitsNotOnAnyRemoteRef = unpublished }] : [],
        Error = error,
    };

    [Fact]
    public void No_remote_outranks_everything_and_clean_remote_scores_zero()
    {
        var withWork = BackupReportBuilder.GitPriorityScore(Repo("a", true, 5, 5, 5, 5));
        var noRemote = BackupReportBuilder.GitPriorityScore(Repo("b"));
        Assert.True(noRemote > withWork);
        Assert.True(BackupReportBuilder.GitPriorityScore(Repo("c", unstaged: 1)) > noRemote);
        Assert.Equal(0, BackupReportBuilder.GitPriorityScore(Repo("d", true)));
    }

    [Fact]
    public void Git_rule_never_claims_remote_repo_is_backed_up()
    {
        var f = new GitBackupRule().Evaluate(Scan(Tree()).Context with { Repositories = [Repo("a", true, unstaged: 1)] }).Single();
        Assert.Equal(RecommendationClass.BackupPriority, f.Recommendation);
        Assert.Contains("no equivale", f.Relevance);
    }

    [Fact]
    public void Unreadable_repository_is_reported_as_insufficient_information()
    {
        var f = new GitBackupRule().Evaluate(Scan(Tree()).Context with { Repositories = [Repo("a", error: "x")] }).Single();
        Assert.Equal(RecommendationClass.InsufficientInformation, f.Recommendation);
    }

    [Fact]
    public void Personal_files_are_detected_by_kind_and_exclude_repos_and_system()
    {
        var (_, c) = Scan(Tree(
            (@"Users\demo\Docs", new FF("a.docx")), (@"Users\demo\Docs", new FF("b.pdf")), (@"Users\demo\Pics", new FF("c.jpg")),
            (@"Users\demo\.ssh", new FF("id_ed25519")), (@"Users\demo\Art", new FF("d.psd")), (@"Users\demo\Backups", new FF("e.bak")),
            (@"proj\.git", new FF("HEAD")), (@"proj", new FF("inrepo.jpg")), (@"Windows", new FF("sys.pdf")), (@"Program Files\App", new FF("manual.pdf"))));
        Assert.Equal(6, c.PersonalFiles.Count);
        Assert.DoesNotContain(c.PersonalFiles, f => f.Path.Contains("inrepo") || f.Path.Contains("sys.pdf") || f.Path.Contains("manual"));
        Assert.Contains(c.PersonalFiles, f => f.Kind == PersonalKind.Configuration);
    }
}

public class UsageClassifierTests
{
    private static InstalledApp App(string name = "Mi App", string? loc = @"C:\Apps\MyApp", bool system = false) =>
        new() { Name = name, InstallLocation = loc, Source = "t", IsSystemLike = system };

    private static UsageSourceData Source(bool available, params RawUsageRecord[] r) =>
        new(new UsageSourceStatus("UA", available, r.Length, ""), r);

    private static RawUsageRecord Run(string id, int daysAgo) => new("UA", id, DaysAgo(daysAgo), 3);

    private static InstalledApp Classify(InstalledApp app, params UsageSourceData[] sources)
    {
        UsageClassifier.Classify([app], sources, new AuditThresholds(), Now);
        return app;
    }

    [Theory]
    [InlineData(5, UsageClass.RecentExecution)]
    [InlineData(45, UsageClass.NoEvidence30Days)]
    [InlineData(75, UsageClass.NoEvidence60Days)]
    [InlineData(200, UsageClass.NoEvidence90Days)]
    public void Windows_are_classified(int days, UsageClass expected)
    {
        var a = Classify(App(), Source(true, Run(@"C:\Apps\MyApp\my.exe", days)));
        Assert.Equal(expected, a.Usage);
        Assert.Equal(DaysAgo(days), a.LastRunUtc);
    }

    [Fact]
    public void Thresholds_are_configurable()
    {
        var a = App();
        UsageClassifier.Classify([a], [Source(true, Run(@"C:\Apps\MyApp\my.exe", 20))], new AuditThresholds { UsageRecentDays = 10, UsageMediumDays = 15, UsageLongDays = 18 }, Now);
        Assert.Equal(UsageClass.NoEvidence90Days, a.Usage);
    }

    [Fact]
    public void App_without_evidence_is_no_historical_evidence_low_confidence()
    {
        var a = Classify(App(), Source(true, Run(@"C:\Other\x.exe", 1)));
        Assert.Equal(UsageClass.NoHistoricalEvidence, a.Usage);
        Assert.Equal(Confidence.Low, a.UsageConfidence);
        Assert.Null(a.LastRunUtc);
        Assert.DoesNotContain("nunca", a.Suggestion!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Absence_of_all_sources_means_unknown()
    {
        var a = Classify(App(), Source(false));
        Assert.Equal(UsageClass.Unknown, a.Usage);
        Assert.Equal(Confidence.Unknown, a.UsageConfidence);
    }

    [Fact]
    public void App_without_location_cannot_be_evaluated()
    {
        Assert.Equal(UsageClass.Unknown, Classify(App(loc: null), Source(true, Run(@"C:\x.exe", 1))).Usage);
    }

    [Fact]
    public void Matching_does_not_confuse_sibling_folders()
    {
        Assert.Equal(UsageClass.NoHistoricalEvidence, Classify(App(), Source(true, Run(@"C:\Apps\MyApp2\x.exe", 1))).Usage);
    }

    [Fact]
    public void Packaged_app_matches_family_name()
    {
        var a = new InstalledApp { Name = "Calc", PackageFamilyName = "Microsoft.Calc_abc", Source = "t" };
        Assert.Equal(UsageClass.RecentExecution, Classify(a, Source(true, Run("Microsoft.Calc_abc!App", 1))).Usage);
    }

    [Fact]
    public void Prefetch_style_name_uses_executable_list()
    {
        var a = App();
        a.ExecutableNames = ["MYAPP.EXE"];
        Assert.Equal(UsageClass.RecentExecution, Classify(a, Source(true, Run("myapp.exe", 1))).Usage);
    }

    [Fact]
    public void Latest_evidence_wins_across_sources()
    {
        var a = Classify(App(), Source(true, Run(@"C:\Apps\MyApp\a.exe", 300), Run(@"C:\Apps\MyApp\b.exe", 3)));
        Assert.Equal(UsageClass.RecentExecution, a.Usage);
    }

    [Fact]
    public void Unused_rule_only_flags_old_evidence_and_never_system_components()
    {
        var old = App("Viejo");
        var sys = App("Visual C++ Redistributable", loc: @"C:\Apps\Red", system: true);
        var none = App("Sin datos", loc: @"C:\Apps\None");
        UsageClassifier.Classify([old, sys, none], [Source(true, Run(@"C:\Apps\MyApp\a.exe", 300), Run(@"C:\Apps\Red\a.exe", 300))], new AuditThresholds(), Now);

        var ctx = Scan(Tree()).Context with { Apps = new AppReport { Evaluated = true, Apps = [old, sys, none] } };
        var f = new UnusedAppRule().Evaluate(ctx).Single();

        Assert.Equal("Viejo", f.PathOrResource);
        Assert.Equal(RecommendationClass.ManualReview, f.Recommendation);
        Assert.Equal(Confidence.Low, f.Confidence);
        Assert.Contains("nunca desinstala", f.RecommendedAction);
    }

    [Theory]
    [InlineData("Microsoft Visual C++ 2022 Redistributable", true)]
    [InlineData(".NET Runtime 10", true)]
    [InlineData("NVIDIA Graphics Driver", true)]
    [InlineData("VLC media player", false)]
    public void System_like_names(string name, bool expected) => Assert.Equal(expected, UsageClassifier.LooksLikeSystemComponent(name));
}

public class MaintenanceAdvisorTests
{
    private static IReadOnlyList<MaintenanceItem> All() => MaintenanceAdvisor.Build(new MaintenanceSnapshot
    {
        StorageSenseEnabled = false, RecycleBinBytes = 5 * MiB, RecycleBinItems = 3, HiberfilBytes = 8000 * MiB, PagefileBytes = 4000 * MiB, UpdateDownloadBytes = 200 * MiB,
        WindowsOldBytes = 9000 * MiB, MemoryDumpBytes = 100 * MiB, WindowsInstallerBytes = 1000 * MiB, DockerInstalled = true,
        WslInstalled = true, WslDistributions = [("Ubuntu", @"C:\x\ext4.vhdx", 1000 * MiB)],
    });

    [Fact]
    public void Dangerous_actions_appear_only_as_advanced()
    {
        foreach (var item in All().Where(i => i.Severity != MaintenanceSeverity.Advanced))
        {
            Assert.DoesNotContain("ResetBase", item.Command ?? "");
            Assert.DoesNotContain("--volumes", item.Command ?? "");
            Assert.DoesNotContain("Set-ReservedStorageState", item.Command ?? "");
        }
        Assert.Contains(All(), i => i.Severity == MaintenanceSeverity.Advanced && (i.Command ?? "").Contains("ResetBase"));
        Assert.Contains(All(), i => i.Severity == MaintenanceSeverity.Advanced && (i.Command ?? "").Contains("--volumes"));
    }

    [Fact]
    public void Advice_never_suggests_manual_deletion_commands()
    {
        foreach (var item in All())
        {
            var cmd = item.Command ?? "";
            Assert.DoesNotContain("del ", cmd, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("rmdir", cmd, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Remove-Item", cmd, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("--unregister", cmd, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void Every_item_has_the_mandatory_fields()
    {
        Assert.All(All(), i =>
        {
            Assert.False(string.IsNullOrWhiteSpace(i.Description));
            Assert.False(string.IsNullOrWhiteSpace(i.Relevance));
            Assert.False(string.IsNullOrWhiteSpace(i.DetectedState));
            Assert.False(string.IsNullOrWhiteSpace(i.RequiredPermissions));
            Assert.False(string.IsNullOrWhiteSpace(i.Consequences));
            Assert.False(string.IsNullOrWhiteSpace(i.ReversibilityNote));
            Assert.StartsWith("https://", i.Reference);
        });
    }

    [Fact]
    public void Absent_features_are_not_recommended()
    {
        var items = MaintenanceAdvisor.Build(new MaintenanceSnapshot());
        Assert.DoesNotContain(items, i => i.Id is "MNT-DOCKER" or "MNT-WSL" or "MNT-WINDOWS-OLD" or "MNT-UPDATE-CACHE");
        Assert.Contains(items, i => i.Id == "MNT-HIBERNATION" && i.EstimatedRecoverableBytes == null);
    }

    [Fact]
    public void Docker_df_excludes_volumes_from_reclaimable()
    {
        const string json = """
            {"Active":"1","Reclaimable":"1.5GB (50%)","Size":"3GB","TotalCount":"5","Type":"Images"}
            {"Active":"0","Reclaimable":"10MB (100%)","Size":"10MB","TotalCount":"1","Type":"Containers"}
            {"Active":"0","Reclaimable":"100GB (100%)","Size":"100GB","TotalCount":"9","Type":"Local Volumes"}
            {"Active":"0","Reclaimable":"500MB","Size":"500MB","TotalCount":"9","Type":"Build Cache"}
            """;
        var (summary, reclaimable) = MaintenanceAdvisor.ParseDockerDf(json);
        Assert.Contains("Local Volumes", summary);
        Assert.Equal(2_010_000_000, reclaimable);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("error during connect")]
    public void Docker_df_tolerates_bad_output(string? input)
    {
        Assert.Null(MaintenanceAdvisor.ParseDockerDf(input).Summary);
    }
}

public class ReportTests
{
    private const string Evil = "C:\\x\\</script><script>alert(1)</script><img src=x onerror=alert(2)>&\u2028.txt";

    private static AuditResult Sample(string path = Evil) => new()
    {
        StartedUtc = Now,
        FinishedUtc = Now.AddMinutes(2),
        Roots = [path],
        Storage = new StorageSummary
        {
            PhysicalBytes = 2000,
            LogicalBytes = 3000,
            FileCount = 2,
            TopFiles = [new StorageItem { Path = path, ContentType = path, PhysicalBytes = 1000, Evidence = [path] }],
            TopFolders = [new StorageItem { Path = path, ContentType = "x", PhysicalBytes = 1000 }],
            ByExtension = [new BreakdownEntry(path, 1, 1, 1)],
        },
        Findings = [Finding(path, 100) with { Evidence = [path, "b"], RecommendedAction = path }],
        Reclaim = new ReclaimSummary { OccupiedPhysicalBytes = 2000, CandidateReclaimableBytes = 100, ReviewReclaimableBytes = 7 },
        Coverage = new CoverageReport { Notes = [path], IssueSamples = [new ScanIssue(ScanIssueKind.AccessDenied, path, path)] },
        GitRepositories = [new GitRepositoryStatus { Path = path, States = [path] }],
    };

    [Fact]
    public void Html_escapes_every_dynamic_value()
    {
        var html = HtmlReportWriter.Render(Sample());

        Assert.DoesNotContain("<script>alert", html);
        Assert.DoesNotContain("<img src=x", html);
        Assert.DoesNotContain("\u2028", html);
        Assert.Equal(2, html.Split("</script>").Length - 1); // Solo el cierre del bloque de datos y del script propio.
    }

    [Fact]
    public void Html_embedded_data_round_trips_to_original_path()
    {
        var html = HtmlReportWriter.Render(Sample());
        var start = html.IndexOf("id=\"report-data\">", StringComparison.Ordinal) + "id=\"report-data\">".Length;
        var json = html[start..html.IndexOf("</script>", start, StringComparison.Ordinal)];
        using var doc = JsonDocument.Parse(json);
        Assert.Equal(Evil, doc.RootElement.GetProperty("roots")[0].GetString());
    }

    [Fact]
    public void Html_is_self_contained_and_only_inserts_text()
    {
        var html = HtmlReportWriter.Render(Sample("C:\\ok.txt"));
        Assert.DoesNotContain("src=\"http", html);
        Assert.DoesNotContain("href=\"http", html);
        Assert.DoesNotContain("<link", html);
        Assert.DoesNotContain("innerHTML", html);
        Assert.DoesNotContain("document.write", html);
        Assert.Contains("default-src 'none'", html);
    }

    [Fact]
    public void Html_includes_required_sections()
    {
        var html = HtmlReportWriter.Render(Sample("C:\\ok.txt"));
        foreach (var id in new[] { "resumen", "distribucion", "limpieza", "respaldo", "aplicaciones", "mantenimiento", "limitaciones" })
            Assert.Contains($"id: \"{id}\"", html.Replace("{ id: ", "id: ").Replace("h(\"section\", ", ""));
        Assert.Contains("Efectivamente liberado", html);
    }

    [Fact]
    public void Html_row_limit_reports_truncation()
    {
        var r = Sample("C:\\ok.txt") with { Findings = [.. Enumerable.Range(0, 300).Select(i => Finding($@"C:\f{i}", i))] };
        var html = HtmlReportWriter.Render(r, rowLimit: 100);
        Assert.Contains("hallazgos: 100 de 300", html);
    }

    [Fact]
    public void Json_report_round_trips()
    {
        using var stream = new MemoryStream();
        JsonReportWriter.Write(Sample("C:\\ok.txt"), stream);
        stream.Position = 0;
        var parsed = JsonSerializer.Deserialize<AuditResult>(stream, AuditJson.Options)!;
        Assert.Equal(100, parsed.Reclaim.CandidateReclaimableBytes);
        Assert.Equal(0, parsed.Reclaim.EffectivelyFreedBytes);
        Assert.Equal("C:\\ok.txt", parsed.Findings[0].PathOrResource);
        Assert.Contains("\"Recommendation\": \"CleanupCandidate\"", System.Text.Encoding.UTF8.GetString(stream.ToArray()));
    }

    [Fact]
    public void Plan_is_not_executable_and_neutralizes_backticks()
    {
        var plan = CleanupPlanWriter.Render(Sample("C:\\x`rm -rf`\r\nfoo"));
        Assert.Contains("no es un script", plan);
        Assert.Contains("x'rm -rf' ", plan);
        Assert.Contains("Efectivamente liberado: 0 B", plan);
    }
}
