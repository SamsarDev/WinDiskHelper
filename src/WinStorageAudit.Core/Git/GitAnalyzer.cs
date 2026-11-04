using System.Text.RegularExpressions;
using WinStorageAudit.Core.Model;
using WinStorageAudit.Core.Scanning;

namespace WinStorageAudit.Core.Git;

/// <summary>Resultado de «git status --porcelain=v2 --branch».</summary>
public sealed record PorcelainStatus
{
    public string? Oid { get; init; }
    public string? Head { get; init; }
    public string? Upstream { get; init; }
    public int? Ahead { get; init; }
    public int? Behind { get; init; }
    public int Staged { get; init; }
    public int Unstaged { get; init; }
    public int Untracked { get; init; }
    public int Conflicted { get; init; }
    public int Stash { get; init; }
    public bool IsDetached => Head == "(detached)";
}

public static partial class GitParsing
{
    /// <summary>Interpreta el formato estable porcelain v2 (registros separados por NUL con -z).</summary>
    public static PorcelainStatus ParsePorcelainV2(string output)
    {
        string? oid = null, head = null, upstream = null;
        int? ahead = null, behind = null;
        int staged = 0, unstaged = 0, untracked = 0, conflicted = 0, stash = 0;

        var records = output.Split('\0');
        for (var i = 0; i < records.Length; i++)
        {
            var line = records[i];
            if (line.Length == 0) continue;
            if (line[0] == '#')
            {
                var parts = line.Split(' ', 3);
                if (parts.Length < 3) continue;
                switch (parts[1])
                {
                    case "branch.oid": oid = parts[2]; break;
                    case "branch.head": head = parts[2]; break;
                    case "branch.upstream": upstream = parts[2]; break;
                    case "branch.ab":
                        var ab = parts[2].Split(' ');
                        if (ab.Length == 2 && int.TryParse(ab[0].TrimStart('+'), out var a) && int.TryParse(ab[1].TrimStart('-'), out var b))
                        {
                            ahead = a;
                            behind = b;
                        }
                        break;
                    case "stash":
                        _ = int.TryParse(parts[2], out stash);
                        break;
                }
                continue;
            }

            switch (line[0])
            {
                case '1':
                case '2':
                    var xy = line.Length > 3 ? line.Substring(2, 2) : "..";
                    if (xy[0] != '.') staged++;
                    if (xy[1] != '.') unstaged++;
                    if (line[0] == '2') i++; // El registro de renombrado incluye una ruta adicional.
                    break;
                case 'u': conflicted++; break;
                case '?': untracked++; break;
            }
        }

        return new PorcelainStatus
        {
            Oid = oid, Head = head, Upstream = upstream, Ahead = ahead, Behind = behind,
            Staged = staged, Unstaged = unstaged, Untracked = untracked, Conflicted = conflicted, Stash = stash,
        };
    }

    [GeneratedRegex(@"^(?<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)(?<userinfo>[^/@]+@)?(?<rest>.*)$")]
    private static partial Regex UrlWithScheme();

    /// <summary>Quita credenciales incrustadas: una URL remota puede contener tokens que no deben llegar al reporte.</summary>
    public static string SanitizeRemoteUrl(string url)
    {
        var match = UrlWithScheme().Match(url.Trim());
        if (!match.Success) return url.Trim();
        var user = match.Groups["userinfo"].Value;
        var keep = user.Length > 0 && match.Groups["scheme"].Value.StartsWith("ssh", StringComparison.OrdinalIgnoreCase) && !user.Contains(':');
        return match.Groups["scheme"].Value + (keep ? user : "") + match.Groups["rest"].Value;
    }

    public static IReadOnlyList<GitRemoteInfo> ParseRemoteConfig(string output)
    {
        // Formato de «git config --null --get-regexp»: clave\nvalor\0
        var result = new List<GitRemoteInfo>();
        foreach (var record in output.Split('\0', StringSplitOptions.RemoveEmptyEntries))
        {
            var nl = record.IndexOf('\n');
            if (nl <= 0) continue;
            var key = record[..nl];
            if (!key.StartsWith("remote.", StringComparison.OrdinalIgnoreCase) || !key.EndsWith(".url", StringComparison.OrdinalIgnoreCase)) continue;
            result.Add(new GitRemoteInfo(key["remote.".Length..^".url".Length], SanitizeRemoteUrl(record[(nl + 1)..])));
        }
        return result;
    }
}

/// <summary>
/// Consulta repositorios exclusivamente con comandos de lectura. Nunca ejecuta fetch, commit,
/// stash apply ni push. El estado siempre es local: no se contacta con ningún servidor.
/// </summary>
public sealed class GitAnalyzer(IProcessRunner runner, string gitExecutable = "git")
{
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(60);

    private static readonly Dictionary<string, string> SafeEnvironment = new()
    {
        ["GIT_OPTIONAL_LOCKS"] = "0",
        ["GIT_TERMINAL_PROMPT"] = "0",
        ["GCM_INTERACTIVE"] = "never",
        ["LC_ALL"] = "C",
    };

    // --no-optional-locks evita reescribir el índice. fsmonitor se desactiva: es una opción de un
    // repositorio que puede ejecutar un programa arbitrario durante «git status».
    private static readonly string[] SafePrefix = ["--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "core.quotePath=false"];

    public async Task<bool> IsAvailableAsync(CancellationToken ct)
    {
        var r = await runner.RunAsync(gitExecutable, ["--version"], null, TimeSpan.FromSeconds(10), SafeEnvironment, ct);
        return !r.StartFailed && r.ExitCode == 0;
    }

    private Task<ProcessResult> GitAsync(string repo, CancellationToken ct, params string[] args) =>
        runner.RunAsync(gitExecutable, [.. SafePrefix, "-C", repo, .. args], null, CommandTimeout, SafeEnvironment, ct);

    public async Task<GitRepositoryStatus> AnalyzeAsync(RepoCandidate candidate, bool includeIgnored, CancellationToken ct)
    {
        var path = candidate.Path;
        var size = candidate.Totals.PhysicalBytes;
        var nested = candidate.ParentRepo != null;

        var remotesResult = await GitAsync(path, ct, "config", "--null", "--get-regexp", @"^remote\..*\.url$");
        if (remotesResult.StartFailed) return Failure(candidate, "No se pudo ejecutar Git.");
        var remotes = remotesResult.ExitCode == 0 ? GitParsing.ParseRemoteConfig(remotesResult.StandardOutput) : [];

        var branches = await ReadBranchesAsync(path, remotes.Count > 0, ct);

        if (candidate.IsBare)
        {
            return Finish(new GitRepositoryStatus
            {
                Path = path, IsBare = true, SizeBytes = size, GitDirBytes = size, Remotes = remotes, Branches = branches, IsNestedInRepository = nested,
            });
        }

        var status = await GitAsync(path, ct, "status", "--porcelain=v2", "--branch", "--show-stash", "--untracked-files=normal", "-z");
        if (status.ExitCode != 0)
        {
            var reason = status.TimedOut ? "Git excedió el tiempo límite."
                : status.StandardError.Contains("dubious ownership", StringComparison.OrdinalIgnoreCase)
                    ? "Git rechaza el repositorio porque pertenece a otro usuario (safe.directory)."
                    : "Git no pudo leer el repositorio.";
            return Failure(candidate, reason, remotes);
        }

        var parsed = GitParsing.ParsePorcelainV2(status.StandardOutput);
        var superproject = await GitAsync(path, ct, "rev-parse", "--show-superproject-working-tree");
        var modules = await GitAsync(path, ct, "config", "--file", ".gitmodules", "--null", "--get-regexp", @"^submodule\..*\.path$");
        var ignored = includeIgnored ? await ReadSensitiveIgnoredAsync(path, ct) : [];

        return Finish(new GitRepositoryStatus
        {
            Path = path,
            IsWorktree = candidate.GitIsFile && string.IsNullOrWhiteSpace(superproject.StandardOutput),
            IsSubmodule = !string.IsNullOrWhiteSpace(superproject.StandardOutput),
            IsNestedInRepository = nested,
            SizeBytes = size,
            CurrentBranch = parsed.IsDetached ? null : parsed.Head,
            IsDetached = parsed.IsDetached,
            Upstream = parsed.Upstream,
            Remotes = remotes,
            Branches = branches,
            StagedChanges = parsed.Staged,
            UnstagedChanges = parsed.Unstaged,
            UntrackedFiles = parsed.Untracked,
            ConflictedFiles = parsed.Conflicted,
            Ahead = parsed.Ahead ?? 0,
            Behind = parsed.Behind ?? 0,
            StashCount = parsed.Stash,
            Submodules = modules.ExitCode == 0 ? modules.StandardOutput.Split('\0', StringSplitOptions.RemoveEmptyEntries).Length : 0,
            SensitiveIgnored = ignored,
        });
    }

    private async Task<IReadOnlyList<GitBranchInfo>> ReadBranchesAsync(string repo, bool hasRemotes, CancellationToken ct)
    {
        var refs = await GitAsync(repo, ct, "for-each-ref", "--format=%(refname:short)%00%(upstream:short)%00%(upstream:track)", "refs/heads");
        if (refs.ExitCode != 0) return [];

        var result = new List<GitBranchInfo>();
        foreach (var line in refs.StandardOutput.Split('\n', StringSplitOptions.RemoveEmptyEntries).Take(200))
        {
            var parts = line.TrimEnd('\r').Split('\0');
            if (parts.Length < 3) continue;
            var track = parts[2];
            int? ahead = MatchInt(track, "ahead "), behind = MatchInt(track, "behind ");

            int? notOnRemote = null;
            if (hasRemotes)
            {
                var count = await GitAsync(repo, ct, "rev-list", "--count", "refs/heads/" + parts[0], "--not", "--remotes");
                if (count.ExitCode == 0 && int.TryParse(count.StandardOutput.Trim(), out var n)) notOnRemote = n;
            }
            else
            {
                var count = await GitAsync(repo, ct, "rev-list", "--count", "refs/heads/" + parts[0]);
                if (count.ExitCode == 0 && int.TryParse(count.StandardOutput.Trim(), out var n)) notOnRemote = n;
            }

            result.Add(new GitBranchInfo
            {
                Name = parts[0],
                Upstream = parts[1].Length == 0 ? null : parts[1],
                UpstreamGone = track.Contains("gone", StringComparison.Ordinal),
                Ahead = ahead,
                Behind = behind,
                CommitsNotOnAnyRemoteRef = notOnRemote,
            });
        }
        return result;
    }

    private static int? MatchInt(string track, string label)
    {
        var i = track.IndexOf(label, StringComparison.Ordinal);
        if (i < 0) return null;
        var digits = new string(track[(i + label.Length)..].TakeWhile(char.IsDigit).ToArray());
        return int.TryParse(digits, out var value) ? value : null;
    }

    /// <summary>Solo se evalúan nombres de archivo. El contenido nunca se abre.</summary>
    private async Task<IReadOnlyList<string>> ReadSensitiveIgnoredAsync(string repo, CancellationToken ct)
    {
        var r = await GitAsync(repo, ct, "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z");
        if (r.ExitCode != 0) return [];
        return [.. r.StandardOutput.Split('\0', StringSplitOptions.RemoveEmptyEntries).Where(SensitiveIgnoredPatterns.IsPotentiallyImportant).Take(50)];
    }

    /// <summary>Confirma si un artefacto contiene archivos versionados.</summary>
    public async Task<bool?> HasTrackedFilesAsync(string repo, string directory, CancellationToken ct)
    {
        var relative = Path.GetRelativePath(repo, directory);
        var r = await GitAsync(repo, ct, "ls-files", "-z", "--", relative);
        if (r.ExitCode != 0) return null;
        return r.StandardOutput.Length > 0;
    }

    private static GitRepositoryStatus Failure(RepoCandidate c, string error, IReadOnlyList<GitRemoteInfo>? remotes = null) =>
        Finish(new GitRepositoryStatus { Path = c.Path, SizeBytes = c.Totals.PhysicalBytes, Error = error, Remotes = remotes ?? [], IsNestedInRepository = c.ParentRepo != null });

    /// <summary>Traduce a estados honestos: tener un remoto no significa estar respaldado.</summary>
    private static GitRepositoryStatus Finish(GitRepositoryStatus r)
    {
        var states = new List<string>();
        if (r.Error != null)
        {
            states.Add("Estado no verificable: " + r.Error);
            return r with { States = states };
        }

        if (r.Remotes.Count == 0) states.Add("Repositorio sin remoto conocido");
        if (r.HasUncommittedWork) states.Add($"Modificaciones locales sin confirmar ({r.StagedChanges + r.UnstagedChanges + r.ConflictedFiles})");
        if (r.UntrackedFiles > 0) states.Add($"Archivos no versionados ({r.UntrackedFiles})");
        if (r.StashCount > 0) states.Add($"Stashes existentes ({r.StashCount})");
        if (r.Remotes.Count > 0)
        {
            var pending = r.UnpublishedCommitsTotal;
            if (pending > 0) states.Add($"Commits aparentemente pendientes de publicación ({pending}, comparando con referencias remotas locales)");
            if (r.CurrentBranch != null && r.Upstream == null) states.Add("Rama actual sin upstream configurado");
            if (r.IsDetached) states.Add("HEAD separado: los commits nuevos no pertenecen a ninguna rama");
            states.Add("Estado remoto no verificable sin consultar al servidor (no se ejecuta fetch)");
        }

        if (r.SensitiveIgnored.Count > 0) states.Add($"Contenido ignorado potencialmente importante ({r.SensitiveIgnored.Count})");

        var clean = !r.HasUncommittedWork && r.UntrackedFiles == 0 && r.StashCount == 0 && r.Remotes.Count > 0 && r.UnpublishedCommitsTotal == 0 && r.SensitiveIgnored.Count == 0;
        if (clean) states.Insert(0, "Repositorio sin cambios locales detectados");
        return r with { States = states };
    }
}
