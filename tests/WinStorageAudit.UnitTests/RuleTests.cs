using WinStorageAudit.Core.Cleanup;
using WinStorageAudit.Core.Model;
using WinStorageAudit.Core.Scanning;
using static WinStorageAudit.UnitTests.Fixtures;

namespace WinStorageAudit.UnitTests;

public class ClassificationTests
{
    private static List<DevResourceRecord> Dev(params (string, FF)[] items) => Scan(Tree(items)).Collector.DevResources;

    [Fact]
    public void Node_modules_requires_package_json_next_to_it()
    {
        Assert.Empty(Dev((@"data\node_modules", new FF("a.js"))));
        var found = Dev((@"app\node_modules", new FF("a.js")), (@"app", new FF("package.json")));
        Assert.Equal("node-modules", Assert.Single(found).Artifact!.Id);
    }

    [Fact]
    public void Bin_without_a_dotnet_project_is_not_an_artifact()
    {
        Assert.Empty(Dev((@"tools\bin", new FF("custom.exe"))));
        Assert.Equal("dotnet-bin", Assert.Single(Dev((@"app\bin", new FF("x.dll")), (@"app", new FF("app.csproj")))).Artifact!.Id);
    }

    [Fact]
    public void Build_folder_needs_the_matching_project_type()
    {
        Assert.Empty(Dev((@"p\build", new FF("thesis.pdf"))));
        Assert.Equal("flutter-build", Assert.Single(Dev((@"p\build", new FF("x")), (@"p", new FF("pubspec.yaml")))).Artifact!.Id);
        Assert.Equal("gradle-build", Assert.Single(Dev((@"p\build", new FF("x")), (@"p", new FF("build.gradle.kts")))).Artifact!.Id);
    }

    [Fact]
    public void Pycache_with_unexpected_files_is_not_classified()
    {
        Assert.Empty(Dev((@"x\__pycache__", new FF("notes.txt"))));
        Assert.Single(Dev((@"x\__pycache__", new FF("m.cpython-312.pyc"))));
    }

    [Fact]
    public void Virtual_environment_is_active_environment_not_a_cache()
    {
        var r = Assert.Single(Dev((@"p\.venv", new FF("pyvenv.cfg")), (@"p\.venv\Lib", new FF("x.py"))));
        Assert.Equal(ResourceKind.ActiveEnvironment, r.Artifact!.Kind);
    }

    [Fact]
    public void Known_cache_requires_exact_location_not_just_the_name()
    {
        Assert.Empty(Dev((@"Other\npm-cache\_cacache", new FF("x"))));
        var path = @"Users\demo\AppData\Local\npm-cache\_cacache";
        var r = Assert.Single(Dev((path, new FF("x", 20 * MiB))));
        Assert.Equal("npm-cache", r.Cache!.Id);
        Assert.True(r.MarkerSatisfied);
    }

    [Fact]
    public void Artifact_nested_in_artifact_is_not_reported_twice()
    {
        var found = Dev((@"a\node_modules\dep\node_modules", new FF("x")), (@"a\node_modules\dep", new FF("package.json")), (@"a", new FF("package.json")));
        Assert.Equal(@"C:\Sandbox\a\node_modules", Assert.Single(found).Path);
    }

    [Theory]
    [InlineData(@"Users\demo\.vscode\extensions\pub.ext")]
    [InlineData(@"Users\demo\.cursor\tool")]
    [InlineData(@"Users\demo\Dev\orphan\node_modules\pkg")]
    [InlineData(@"Users\demo\Dev\venv\Lib\site-packages\pkg")]
    public void Dist_of_installed_tool_is_never_an_artifact(string package)
    {
        // Falso positivo hallado en un equipo real: el «dist» de una extensión es su código en uso.
        Assert.Empty(Dev((package, new FF("package.json")), (package + @"\dist", new FF("main.js", 20 * MiB))));
    }

    [Fact]
    public void Dist_without_repo_or_lockfile_needs_review_with_low_confidence()
    {
        var f = new DevArtifactRule().Evaluate(Scan(Tree((@"p\dist", new FF("a.js", 30 * MiB, DaysAgo(100))), (@"p", new FF("package.json", 1, DaysAgo(100))))).Context).Single();
        Assert.Equal(RecommendationClass.ManualReview, f.Recommendation);
        Assert.Equal(Confidence.Low, f.Confidence);
    }

    [Fact]
    public void Concentrations_cover_every_significant_branch()
    {
        var s = Scan(Tree((@"a\big", new FF("x", 500 * MiB)), (@"b\other", new FF("y", 300 * MiB)), (@"c", new FF("z", 1)))).Context.Storage;
        Assert.Contains(s.Concentrations, c => c.Path.EndsWith(@"a\big"));
        Assert.Contains(s.Concentrations, c => c.Path.EndsWith(@"b\other"));
        Assert.DoesNotContain(s.Concentrations, c => c.Path == Root);
    }

    [Theory]
    [InlineData(@"Users\demo\AppData\Local\Temp", "x.bin", StorageCategory.TemporaryFiles)]
    [InlineData(@"Windows\System32", "x.dll", StorageCategory.OperatingSystem)]
    [InlineData(@"Program Files\App", "x.dll", StorageCategory.Applications)]
    [InlineData(@"Users\demo\Downloads", "x.zip", StorageCategory.Downloads)]
    [InlineData(@"Users\demo\Pictures", "x.jpg", StorageCategory.Images)]
    [InlineData(@"Users\demo\Videos", "x.mkv", StorageCategory.Videos)]
    [InlineData(@"Users\demo\Music", "x.flac", StorageCategory.Music)]
    [InlineData(@"Users\demo\Docs", "x.docx", StorageCategory.PersonalDocuments)]
    [InlineData(@"Users\demo\Archive", "x.7z", StorageCategory.Archives)]
    [InlineData(@"Users\demo\Data", "x.sqlite", StorageCategory.DatabasesAndBackups)]
    [InlineData(@"Users\demo\Misc", "x.xyz", StorageCategory.Other)]
    public void Categories_are_assigned(string dir, string file, StorageCategory expected)
    {
        var s = Scan(Tree((dir, new FF(file)))).Context.Storage;
        Assert.Contains(s.ByCategory, c => c.Key == expected.ToString() && c.FileCount == 1);
    }

    [Fact]
    public void Files_in_repo_are_categorized_as_code()
    {
        var s = Scan(Tree((@"proj\.git", new FF("HEAD")), (@"proj", new FF("photo.jpg")))).Context.Storage;
        Assert.Contains(s.ByCategory, c => c.Key == nameof(StorageCategory.CodeRepositories) && c.FileCount == 2);
    }
}

public class CleanupRuleTests
{
    private const string Downloads = @"Users\demo\Downloads";
    private const string Temp = @"Users\demo\AppData\Local\Temp";

    private static List<Finding> Run<T>((string, FF)[] items, Func<RuleContext, RuleContext>? customize = null) where T : IRule, new() =>
        [.. new T().Evaluate(Scan(Tree(items), customize).Context)];

    [Fact]
    public void Old_download_is_never_a_cleanup_candidate_by_age_alone()
    {
        var old = DaysAgo(2000);
        var findings = Run<DownloadsRule>([(Downloads, new FF("setup.exe", 50 * MiB, old)), (Downloads, new FF("data.zip", 50 * MiB, old)), (Downloads, new FF("big.iso", 800 * MiB, old))]);
        Assert.Equal(3, findings.Count);
        Assert.All(findings, f => Assert.Equal(RecommendationClass.ManualReview, f.Recommendation));
        Assert.All(findings, f => Assert.NotEqual(Confidence.High, f.Confidence));
    }

    [Fact]
    public void Single_use_heuristic_stays_low_confidence()
    {
        var f = Assert.Single(Run<DownloadsRule>([(Downloads, new FF("tool.msi", 20 * MiB, DaysAgo(400)))]));
        Assert.Equal(Confidence.Low, f.Confidence);
        Assert.Contains(f.Evidence, e => e.Contains("baja confianza"));
    }

    [Fact]
    public void Recent_download_is_not_flagged()
    {
        Assert.Empty(Run<DownloadsRule>([(Downloads, new FF("setup.exe", 50 * MiB, DaysAgo(3)))]));
    }

    [Fact]
    public void Copy_requires_matching_original_with_same_size()
    {
        var both = Run<DownloadsRule>([(Downloads, new FF("a.zip", 5 * MiB, DaysAgo(1))), (Downloads, new FF("a (1).zip", 5 * MiB, DaysAgo(1)))]);
        Assert.Equal("DL-COPY", Assert.Single(both).RuleId);
        Assert.Empty(Run<DownloadsRule>([(Downloads, new FF("a.zip", 6 * MiB, DaysAgo(1))), (Downloads, new FF("a (1).zip", 5 * MiB, DaysAgo(1)))]));
    }

    [Fact]
    public void Online_only_download_is_skipped()
    {
        Assert.Empty(Run<DownloadsRule>([(Downloads, new FF("x.exe", 50 * MiB, DaysAgo(400), Online: true))]));
    }

    [Fact]
    public void Old_personal_files_are_not_cleanup_candidates()
    {
        var (ctx, _) = Scan(Tree((@"Users\demo\Docs", new FF("tesis.docx", 2048 * MiB, DaysAgo(3000)))));
        var f = new LargeStaleFileRule().Evaluate(ctx).Single();
        Assert.Equal(RecommendationClass.ManualReview, f.Recommendation);
        Assert.Equal(Confidence.Low, f.Confidence);
        Assert.True(f.RequiresBackup);
    }

    [Fact]
    public void Folder_named_temp_outside_system_temp_is_only_manual_review()
    {
        var f = Assert.Single(Run<NamedTempRule>([(@"Users\demo\Work\temp", new FF("x.bin", 200 * MiB, DaysAgo(500)))]));
        Assert.Equal(RecommendationClass.ManualReview, f.Recommendation);
        Assert.Equal(Confidence.Low, f.Confidence);
        Assert.Empty(Run<UserTempRule>([(@"Users\demo\Work\temp\sub", new FF("x.bin", 200 * MiB, DaysAgo(500)))]));
    }

    [Fact]
    public void Real_temp_requires_age_and_never_gets_high_confidence()
    {
        var old = Assert.Single(Run<UserTempRule>([(Temp + @"\oldjob", new FF("x.bin", 20 * MiB, DaysAgo(90)))]));
        Assert.Equal(RecommendationClass.CleanupCandidate, old.Recommendation);
        Assert.Equal(Confidence.Medium, old.Confidence);
        Assert.Empty(Run<UserTempRule>([(Temp + @"\running", new FF("x.bin", 20 * MiB, DaysAgo(2)))]));
    }

    [Fact]
    public void Temp_folder_with_one_recent_file_is_not_flagged()
    {
        Assert.Empty(Run<UserTempRule>([(Temp + @"\job", new FF("old.bin", 20 * MiB, DaysAgo(90))), (Temp + @"\job\sub", new FF("new.bin", 1, DaysAgo(1)))]));
    }

    [Fact]
    public void Virtual_disks_are_kept_and_reclaim_nothing()
    {
        var f = Assert.Single(Run<VirtualDiskRule>([(@"Users\demo\AppData\Local\Docker\wsl\disk", new FF("docker_data.vhdx", 50_000 * MiB)) ]));
        Assert.Equal(RecommendationClass.Keep, f.Recommendation);
        Assert.Equal(0, f.EstimatedReclaimableBytes);
        Assert.Contains("docker system df", f.RecommendedAction);
    }

    [Fact]
    public void Databases_are_kept()
    {
        var f = Assert.Single(Run<DatabaseRule>([(@"Users\demo\Data", new FF("app.sqlite", 40 * MiB, DaysAgo(900)))]));
        Assert.Equal(RecommendationClass.Keep, f.Recommendation);
        Assert.True(f.RequiresBackup);
    }

    [Fact]
    public void Tracked_artifact_is_downgraded_and_untracked_confirmed()
    {
        var items = new[] { (@"app\dist", new FF("a.js", 30 * MiB, DaysAgo(100))), (@"app", new FF("package.json", 1, DaysAgo(100))), (@"app\.git", new FF("HEAD", 1, DaysAgo(100))) };
        var (ctx, collector) = Scan(Tree(items));
        var record = Assert.Single(collector.DevResources);

        record.HasTrackedFiles = true;
        var tracked = new DevArtifactRule().Evaluate(ctx).Single();
        Assert.Equal(RecommendationClass.ManualReview, tracked.Recommendation);

        record.HasTrackedFiles = false;
        var clean = new DevArtifactRule().Evaluate(ctx).Single();
        Assert.Equal(RecommendationClass.CleanupCandidate, clean.Recommendation);
        Assert.Equal(Confidence.High, clean.Confidence);
    }

    [Fact]
    public void Artifact_outside_repository_cannot_reach_high_confidence()
    {
        var f = new DevArtifactRule().Evaluate(Scan(Tree((@"app\bin", new FF("x", 30 * MiB, DaysAgo(200))), (@"app", new FF("a.csproj", 1, DaysAgo(200))))).Context).Single();
        Assert.Equal(Confidence.Medium, f.Confidence);
    }

    [Fact]
    public void Active_project_is_marked_and_dependencies_need_review()
    {
        var f = new DevArtifactRule().Evaluate(Scan(Tree((@"a\node_modules", new FF("x", 30 * MiB, DaysAgo(1))), (@"a", new FF("package.json")), (@"a", new FF("package-lock.json")))).Context).Single();
        Assert.Equal(RecommendationClass.ManualReview, f.Recommendation);
        Assert.Contains(f.Evidence, e => e.Contains("activo"));
    }

    [Fact]
    public void Node_modules_without_lockfile_needs_review()
    {
        var f = new DevArtifactRule().Evaluate(Scan(Tree((@"a\node_modules", new FF("x", 30 * MiB, DaysAgo(100))), (@"a", new FF("package.json", 1, DaysAgo(100))))).Context).Single();
        Assert.Equal(RecommendationClass.ManualReview, f.Recommendation);
        Assert.Contains(f.Evidence, e => e.Contains("bloqueo"));
    }

    [Fact]
    public void Hard_linked_bytes_are_not_reclaimable()
    {
        var f = new DevArtifactRule().Evaluate(Scan(Tree((@"a\dist", new FF("x", 30 * MiB, DaysAgo(100), Links: 2)), (@"a\dist", new FF("y", 20 * MiB, DaysAgo(100))), (@"a", new FF("package.json", 1, DaysAgo(100))))).Context).Single();
        Assert.Equal(50 * MiB, f.DetectedSizeBytes);
        Assert.Equal(20 * MiB, f.EstimatedReclaimableBytes);
    }

    [Fact]
    public void Small_artifacts_are_aggregated()
    {
        var items = Enumerable.Range(0, 5).SelectMany(i => new[] { ($@"p{i}\__pycache__", new FF("m.pyc", 1000, DaysAgo(100))) }).ToArray();
        var f = Assert.Single(Run<DevArtifactRule>(items));
        Assert.True(f.IsAggregate);
        Assert.Equal(5000, f.DetectedSizeBytes);
    }

    private static AppReport Apps(params string[] names) => new()
    {
        Evaluated = true,
        Apps = [.. names.Select(n => new InstalledApp { Name = n, Source = "test" })],
    };

    private const string Roaming = @"Users\demo\AppData\Roaming";

    [Fact]
    public void Residue_requires_all_evidence_and_is_never_high_confidence()
    {
        var f = Assert.Single(Run<AppResidueRule>([(Roaming + @"\OldTool", new FF("cache.dat", 100 * MiB, DaysAgo(800)))], c => c with { Apps = Apps("Something Else") }));
        Assert.Equal(RecommendationClass.ManualReview, f.Recommendation);
        Assert.Equal(Confidence.Medium, f.Confidence);
        Assert.True(f.Evidence.Count >= 3);
    }

    [Fact]
    public void Residue_is_not_reported_without_inventory()
    {
        Assert.Empty(Run<AppResidueRule>([(Roaming + @"\OldTool", new FF("x", 100 * MiB, DaysAgo(800)))]));
    }

    [Fact]
    public void Residue_ignores_installed_recent_shared_and_referenced_folders()
    {
        (string, FF)[] item = [(Roaming + @"\OldTool", new FF("x", 100 * MiB, DaysAgo(800)))];
        Assert.Empty(Run<AppResidueRule>(item, c => c with { Apps = Apps("OldTool Pro 3") }));
        Assert.Empty(Run<AppResidueRule>([(Roaming + @"\OldTool", new FF("x", 100 * MiB, DaysAgo(5)))], c => c with { Apps = Apps("Other") }));
        Assert.Empty(Run<AppResidueRule>([(Roaming + @"\Microsoft", new FF("x", 100 * MiB, DaysAgo(800)))], c => c with { Apps = Apps("Other") }));
        Assert.Empty(Run<AppResidueRule>(item, c => c with { Apps = Apps("Other"), SystemReferences = [@"C:\Sandbox\Users\demo\AppData\Roaming\OldTool\svc.exe"] }));
    }

    [Fact]
    public void Portable_looking_folder_stays_low_confidence()
    {
        var f = Assert.Single(Run<AppResidueRule>([(Roaming + @"\Portable", new FF("tool.exe", 100 * MiB, DaysAgo(800)))], c => c with { Apps = Apps("Other") }));
        Assert.Equal(Confidence.Low, f.Confidence);
    }

    [Fact]
    public void Duplicates_of_personal_content_stay_in_manual_review_and_keep_one_copy()
    {
        var group = new DuplicateGroup { FileSizeBytes = 10, Paths = [@"C:\Sandbox\Users\demo\Downloads\a.jpg", @"C:\Sandbox\Users\demo\Downloads\b.jpg"], ContainsSensitiveContent = true };
        var f = new DuplicateRule().Evaluate(Scan(Tree()).Context with { Duplicates = new DuplicateReport { Evaluated = true, Groups = [group] } }).Single();
        Assert.Equal(RecommendationClass.ManualReview, f.Recommendation);
        Assert.Equal(10, f.EstimatedReclaimableBytes);
        Assert.Contains("Nunca elimine todas", f.RecommendedAction);
    }

    [Fact]
    public void Duplicates_outside_downloads_are_not_candidates()
    {
        var group = new DuplicateGroup { FileSizeBytes = 10, Paths = [@"C:\Sandbox\Work\a.bin", @"C:\Sandbox\Users\demo\Downloads\a.bin"] };
        var f = new DuplicateRule().Evaluate(Scan(Tree()).Context with { Duplicates = new DuplicateReport { Evaluated = true, Groups = [group] } }).Single();
        Assert.Equal(RecommendationClass.ManualReview, f.Recommendation);
    }
}

public class RecommendationEngineTests
{
    private static readonly ProtectedPaths Protected = new(Locations);

    [Theory]
    [InlineData(@"C:\Sandbox\Windows\WinSxS")]
    [InlineData(@"C:\Sandbox\Windows\Installer\x.msi")]
    [InlineData(@"C:\Sandbox\ProgramData\Package Cache\x")]
    [InlineData(@"C:\System Volume Information\x")]
    [InlineData(@"C:\")]
    [InlineData(@"C:\Sandbox\Users\demo")]
    public void Protected_paths_can_never_be_candidates(string path)
    {
        var f = RecommendationEngine.Enforce(Finding(path, 1000), Protected);
        Assert.Equal(RecommendationClass.Keep, f.Recommendation);
        Assert.Equal(0, f.EstimatedReclaimableBytes);
        Assert.Equal(RiskLevel.Critical, f.RiskLevel);
    }

    [Fact]
    public void High_confidence_needs_at_least_two_evidences()
    {
        var f = RecommendationEngine.Enforce(Finding(@"C:\x\y", 1) with { Confidence = Confidence.High, Evidence = ["solo una"] }, Protected);
        Assert.Equal(Confidence.Medium, f.Confidence);
    }

    [Theory]
    [InlineData(ResourceKind.IrreplaceableUserData)]
    [InlineData(ResourceKind.PersistentAppData)]
    [InlineData(ResourceKind.ActiveEnvironment)]
    public void Valuable_resources_cannot_be_candidates(ResourceKind kind)
    {
        var f = RecommendationEngine.Enforce(Finding(@"C:\x\y", 1) with { ResourceKind = kind }, Protected);
        Assert.Equal(RecommendationClass.ManualReview, f.Recommendation);
    }

    [Fact]
    public void Failing_rule_does_not_stop_others()
    {
        var engine = new RecommendationEngine([new ThrowingRule(), new VirtualDiskRule()]);
        var result = engine.Run(Scan(Tree((@"VMs", new FF("a.vhdx", 50 * MiB)))).Context);
        Assert.Single(result.Findings);
        Assert.Contains(result.Notes, n => n.Contains("BOOM"));
    }

    private sealed class ThrowingRule : IRule
    {
        public string Id => "BOOM";
        public IEnumerable<Finding> Evaluate(RuleContext context) => throw new InvalidOperationException("fallo");
    }

    [Fact]
    public void Ids_are_stable_and_distinct()
    {
        Assert.Equal(Finding(@"C:\a", 1).Id, Finding(@"c:\A", 2).Id);
        Assert.NotEqual(Finding(@"C:\a", 1).Id, Finding(@"C:\b", 1).Id);
    }

    [Fact]
    public void Nested_findings_are_counted_once()
    {
        var r = ReclaimCalculator.Apply([Finding(@"C:\a\b", 100), Finding(@"C:\a", 500)]);
        Assert.Equal(500, r.Sum(f => f.CountedReclaimableBytes));
        Assert.Equal(0, r[0].CountedReclaimableBytes);
    }

    [Fact]
    public void Same_path_from_two_rules_is_counted_once()
    {
        var r = ReclaimCalculator.Apply([Finding(@"C:\a", 100), Finding(@"C:\a", 100) with { RuleId = "OTHER" }]);
        Assert.Equal(100, r.Sum(f => f.CountedReclaimableBytes));
    }

    [Fact]
    public void Sibling_with_shared_prefix_is_not_treated_as_nested()
    {
        var r = ReclaimCalculator.Apply([Finding(@"C:\app", 100), Finding(@"C:\app2", 100)]);
        Assert.Equal(200, r.Sum(f => f.CountedReclaimableBytes));
    }

    [Fact]
    public void Review_folder_does_not_double_count_contained_candidate()
    {
        var r = ReclaimCalculator.Apply([Finding(@"C:\p", 500, RecommendationClass.ManualReview), Finding(@"C:\p\bin", 200)]);
        Assert.Equal(200, r[1].CountedReclaimableBytes);
        Assert.Equal(300, r[0].CountedReclaimableBytes);
    }

    [Fact]
    public void Duplicate_copy_inside_counted_folder_does_not_add_again()
    {
        var dup = Finding(@"C:\keep\a.bin", 100, RecommendationClass.ManualReview, FindingArea.Duplicates) with { RelatedPaths = [@"C:\keep\a.bin", @"C:\cache\a.bin"], DetectedSizeBytes = 200 };
        var r = ReclaimCalculator.Apply([Finding(@"C:\cache", 1000), dup]);
        Assert.Equal(1000, r[0].CountedReclaimableBytes);
        Assert.Equal(0, r[1].CountedReclaimableBytes);
    }

    [Fact]
    public void Candidate_duplicate_counts_and_removable_copy_is_not_counted_again_in_review()
    {
        var dup = Finding(@"C:\d\a.zip", 100, RecommendationClass.CleanupCandidate, FindingArea.Duplicates) with { RelatedPaths = [@"C:\d\a.zip", @"C:\d\a-copy.zip"] };
        var review = Finding(@"C:\d\a-copy.zip", 100, RecommendationClass.ManualReview, FindingArea.Downloads);
        var r = ReclaimCalculator.Apply([dup, review]);
        Assert.Equal(100, r[0].CountedReclaimableBytes);
        Assert.Equal(0, r[1].CountedReclaimableBytes);
    }

    [Fact]
    public void Confirmed_duplicate_replaces_name_based_copy_finding()
    {
        var d = @"Users\demo\Downloads";
        var (ctx, _) = Scan(Tree((d, new FF("a.zip", 5 * MiB, DaysAgo(1))), (d, new FF("a (1).zip", 5 * MiB, DaysAgo(1)))));
        var dup = new DuplicateReport { Evaluated = true, Groups = [new DuplicateGroup { FileSizeBytes = 5 * MiB, Paths = [$@"{Root}\{d}\a.zip", $@"{Root}\{d}\a (1).zip"] }] };
        Assert.Empty(new DownloadsRule().Evaluate(ctx with { Duplicates = dup }));
    }

    [Fact]
    public void Mixed_folder_takes_highest_risk_of_its_content_not_the_majority()
    {
        // Falso «riesgo bajo» detectado al revisar el reporte: la mayoría era caché, pero contenía documentos.
        var s = Scan(Tree((@"Users\demo\Mix\app\node_modules", new FF("x", 900 * MiB)), (@"Users\demo\Mix\app", new FF("package.json")), (@"Users\demo\Mix\docs", new FF("tesis.docx", 100 * MiB)))).Context.Storage;
        var mix = s.TopFolders.Single(f => f.Path.EndsWith("Mix"));
        Assert.Equal(RiskLevel.High, mix.Risk);
        Assert.Contains("Cachés", mix.ContentType);
    }

    [Fact]
    public void Virtual_disk_in_appdata_is_critical_at_every_level()
    {
        var s = Scan(Tree((@"Users\demo\AppData\Local\Docker\wsl\disk", new FF("docker_data.vhdx", 900 * MiB)), (@"Users\demo\Otros", new FF("x.bin", 100 * MiB)))).Context.Storage;
        Assert.Equal(RiskLevel.Critical, s.TopFiles.Single(f => f.Path.EndsWith(".vhdx")).Risk);
        Assert.Equal(RiskLevel.Critical, s.TopFolders.Single(f => f.Path.EndsWith(@"wsl\disk")).Risk);
        Assert.Equal(RiskLevel.Critical, s.Concentrations.Single(f => f.Path.Contains("Docker")).Risk);
    }

    [Fact]
    public void Chain_of_nearly_identical_parents_is_collapsed_in_top_folders()
    {
        var s = Scan(Tree((@"a\b\c", new FF("x", 500 * MiB)))).Context.Storage;
        Assert.Contains(s.TopFolders, f => f.Path.EndsWith(@"a\b\c"));
        Assert.DoesNotContain(s.TopFolders, f => f.Path.EndsWith(@"a\b") || f.Path == Root);
    }

    [Fact]
    public void Generic_folder_takes_its_dominant_content_type()
    {
        var s = Scan(Tree((@"Users\demo\Peliculas", new FF("a.mkv", 900 * MiB)), (@"Users\demo\Peliculas", new FF("n.txt", 1)))).Context.Storage;
        Assert.Contains(s.TopFolders, f => f.Path.EndsWith("Peliculas") && f.Category == StorageCategory.Videos);
    }

    [Fact]
    public void Duplicate_with_all_copies_outside_counts_all_but_one()
    {
        var dup = Finding(@"C:\a\x", 200, RecommendationClass.ManualReview, FindingArea.Duplicates) with { RelatedPaths = [@"C:\a\x", @"C:\b\x", @"C:\c\x"] };
        Assert.Equal(200, ReclaimCalculator.Apply([dup])[0].CountedReclaimableBytes);
    }

    [Fact]
    public void Keep_findings_never_add_to_totals()
    {
        var r = ReclaimCalculator.Apply([Finding(@"C:\a", 100, RecommendationClass.Keep), Finding(@"C:\b", 100, RecommendationClass.BackupPriority)]);
        Assert.Equal(0, r.Sum(f => f.CountedReclaimableBytes));
    }

    [Fact]
    public void Summary_separates_occupied_candidates_review_and_freed()
    {
        var (ctx, _) = Scan(Tree(
            (@"Users\demo\AppData\Local\Temp\job", new FF("x", 20 * MiB, DaysAgo(100))),
            (@"Users\demo\Downloads", new FF("s.exe", 30 * MiB, DaysAgo(200))),
            (@"VMs", new FF("v.vhdx", 500 * MiB, DaysAgo(200)))));
        var result = new RecommendationEngine(RecommendationEngine.DefaultRules()).Run(ctx);

        Assert.Equal(550 * MiB, result.Reclaim.OccupiedPhysicalBytes);
        Assert.Equal(20 * MiB, result.Reclaim.CandidateReclaimableBytes);
        Assert.Equal(30 * MiB, result.Reclaim.ReviewReclaimableBytes);
        Assert.Equal(0, result.Reclaim.EffectivelyFreedBytes);
        Assert.True(result.Reclaim.CandidateReclaimableBytes + result.Reclaim.ReviewReclaimableBytes <= result.Reclaim.OccupiedPhysicalBytes);
    }

    [Fact]
    public void Every_finding_of_default_rules_explains_itself()
    {
        var (ctx, _) = Scan(Tree(
            (@"Users\demo\AppData\Local\Temp\job", new FF("x", 20 * MiB, DaysAgo(100))),
            (@"Users\demo\Downloads", new FF("s.exe", 30 * MiB, DaysAgo(200))),
            (@"a\node_modules", new FF("x", 30 * MiB, DaysAgo(200))), (@"a", new FF("package.json")),
            (@"VMs", new FF("v.vhdx", 500 * MiB))));
        var findings = new RecommendationEngine(RecommendationEngine.DefaultRules()).Run(ctx).Findings;

        Assert.True(findings.Count >= 4);
        Assert.All(findings, f =>
        {
            Assert.False(string.IsNullOrWhiteSpace(f.Description));
            Assert.False(string.IsNullOrWhiteSpace(f.Relevance));
            Assert.NotEmpty(f.Evidence);
            Assert.False(string.IsNullOrWhiteSpace(f.RecommendedAction));
            Assert.False(string.IsNullOrWhiteSpace(f.PotentialLoss));
            Assert.InRange(f.CountedReclaimableBytes, 0, f.EstimatedReclaimableBytes);
        });
    }
}

public class ExclusionMatcherTests
{
    [Theory]
    [InlineData("node_modules", @"C:\a\node_modules", "node_modules", true)]
    [InlineData("NODE_MODULES", @"C:\a\node_modules", "node_modules", true)]
    [InlineData("node_modules", @"C:\a\node_modules2", "node_modules2", false)]
    [InlineData("*.tmp", @"C:\a\x.tmp", "x.tmp", true)]
    [InlineData(@"C:\Data", @"C:\Data", "Data", true)]
    [InlineData(@"C:\Data", @"C:\Data\sub", "sub", true)]
    [InlineData(@"C:\Data", @"C:\Database", "Database", false)]
    [InlineData(@"C:\Data\*\cache", @"C:\Data\a\cache", "cache", true)]
    [InlineData(@"C:\Data\*\cache", @"C:\Data\a\b\cache", "cache", false)]
    [InlineData(@"C:\Data\**\cache", @"C:\Data\a\b\cache", "cache", true)]
    public void Patterns(string pattern, string path, string name, bool expected)
    {
        Assert.Equal(expected, new ExclusionMatcher([pattern]).IsExcluded(path, name));
    }

    [Fact]
    public void Regex_metacharacters_in_paths_are_literal()
    {
        var m = new ExclusionMatcher([@"C:\Prog (x86)\a+b"]);
        Assert.True(m.IsExcluded(@"C:\Prog (x86)\a+b", "a+b"));
        Assert.False(m.IsExcluded(@"C:\Prog x86\aab", "aab"));
    }
}
