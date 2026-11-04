using System.Text.Json;
using Microsoft.Data.Sqlite;
using WinStorageAudit.Core;
using WinStorageAudit.Core.Cleanup;
using WinStorageAudit.Core.Model;

namespace WinStorageAudit.Infrastructure.Persistence;

public sealed record AppPaths(string ConfigDirectory, string DataDirectory)
{
    public string ConfigFile => Path.Combine(ConfigDirectory, "config.json");
    public string HistoryDatabase => Path.Combine(DataDirectory, "history.db");
    public string LastResultFile => Path.Combine(DataDirectory, "last-result.json");
    public string ReportsDirectory => Path.Combine(DataDirectory, "reports");

    /// <summary>WINSTORAGEAUDIT_HOME concentra todos los datos en una carpeta: útil para pruebas y uso portable.</summary>
    public static AppPaths Default()
    {
        var home = Environment.GetEnvironmentVariable("WINSTORAGEAUDIT_HOME");
        if (!string.IsNullOrWhiteSpace(home)) return new AppPaths(Path.GetFullPath(home), Path.GetFullPath(home));
        return new AppPaths(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "WinStorageAudit"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinStorageAudit"));
    }
}

public sealed record AppConfig
{
    public List<string> DefaultPaths { get; init; } = [];
    public List<string> Exclusions { get; init; } = [];
    public List<string> BackupDestinations { get; init; } = [];
    public AuditThresholds Thresholds { get; init; } = new();
    public int MaxConcurrency { get; init; } = 4;
    public int TopItems { get; init; } = 20;
    public int ReportRowLimit { get; init; } = 2000;
}

public sealed class ConfigStore(AppPaths paths)
{
    public AppConfig Load()
    {
        if (!File.Exists(paths.ConfigFile)) return new AppConfig();
        try
        {
            return JsonSerializer.Deserialize<AppConfig>(File.ReadAllText(paths.ConfigFile), AuditJson.Options) ?? new AppConfig();
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"El archivo de configuración no es válido ({paths.ConfigFile}): {ex.Message}", ex);
        }
    }

    public void Save(AppConfig config)
    {
        Directory.CreateDirectory(paths.ConfigDirectory);
        var temp = paths.ConfigFile + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(config, AuditJson.Options));
        File.Move(temp, paths.ConfigFile, true);
    }

    public void Delete()
    {
        if (File.Exists(paths.ConfigFile)) File.Delete(paths.ConfigFile);
    }
}

/// <summary>Último resultado completo, para generar reportes sin repetir el análisis.</summary>
public sealed class ResultStore(AppPaths paths)
{
    public void Save(AuditResult result)
    {
        Directory.CreateDirectory(paths.DataDirectory);
        var temp = paths.LastResultFile + ".tmp";
        using (var stream = File.Create(temp)) JsonSerializer.Serialize(stream, result, AuditJson.Options);
        File.Move(temp, paths.LastResultFile, true);
    }

    public AuditResult? Load()
    {
        if (!File.Exists(paths.LastResultFile)) return null;
        using var stream = File.OpenRead(paths.LastResultFile);
        return JsonSerializer.Deserialize<AuditResult>(stream, AuditJson.Options);
    }

    public bool Delete()
    {
        if (!File.Exists(paths.LastResultFile)) return false;
        File.Delete(paths.LastResultFile);
        return true;
    }
}

public sealed record HistoryEntry(long Id, DateTime StartedUtc, DateTime FinishedUtc, string Mode, string Roots, long PhysicalBytes, long LogicalBytes, long Files, long CandidateBytes, long ReviewBytes, int Findings, bool Cancelled);

public sealed record HistoryDelta(string Key, long Before, long After)
{
    public long Change => After - Before;
}

public sealed record HistoryComparison(HistoryEntry Older, HistoryEntry Newer, IReadOnlyList<HistoryDelta> Categories, IReadOnlyList<HistoryDelta> Folders);

/// <summary>
/// Historial de resúmenes. Guarda rutas y tamaños, nunca contenido de archivos ni hashes.
/// </summary>
public sealed class HistoryStore(AppPaths paths)
{
    private SqliteConnection Open()
    {
        Directory.CreateDirectory(paths.DataDirectory);
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = paths.HistoryDatabase, Pooling = false }.ToString());
        connection.Open();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS scans (
              id INTEGER PRIMARY KEY AUTOINCREMENT, started_utc TEXT NOT NULL, finished_utc TEXT NOT NULL, mode TEXT NOT NULL,
              roots TEXT NOT NULL, physical_bytes INTEGER NOT NULL, logical_bytes INTEGER NOT NULL, files INTEGER NOT NULL,
              candidate_bytes INTEGER NOT NULL, review_bytes INTEGER NOT NULL, findings INTEGER NOT NULL, cancelled INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS scan_categories (scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE, category TEXT NOT NULL, physical_bytes INTEGER NOT NULL, PRIMARY KEY (scan_id, category));
            CREATE TABLE IF NOT EXISTS scan_folders (scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE, path TEXT NOT NULL, physical_bytes INTEGER NOT NULL, PRIMARY KEY (scan_id, path));
            CREATE TABLE IF NOT EXISTS scan_rule_summary (scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE, rule_id TEXT NOT NULL, findings INTEGER NOT NULL, reclaimable_bytes INTEGER NOT NULL, PRIMARY KEY (scan_id, rule_id));
            PRAGMA foreign_keys = ON;
            """;
        cmd.ExecuteNonQuery();
        return connection;
    }

    public long Save(AuditResult r)
    {
        using var c = Open();
        using var tx = c.BeginTransaction();
        using var insert = c.CreateCommand();
        insert.Transaction = tx;
        insert.CommandText = """
            INSERT INTO scans (started_utc, finished_utc, mode, roots, physical_bytes, logical_bytes, files, candidate_bytes, review_bytes, findings, cancelled)
            VALUES ($s, $f, $m, $r, $p, $l, $n, $cb, $rb, $fi, $ca); SELECT last_insert_rowid();
            """;
        insert.Parameters.AddWithValue("$s", r.StartedUtc.ToString("O"));
        insert.Parameters.AddWithValue("$f", r.FinishedUtc.ToString("O"));
        insert.Parameters.AddWithValue("$m", r.Mode.ToString());
        insert.Parameters.AddWithValue("$r", string.Join("; ", r.Roots));
        insert.Parameters.AddWithValue("$p", r.Storage.PhysicalBytes);
        insert.Parameters.AddWithValue("$l", r.Storage.LogicalBytes);
        insert.Parameters.AddWithValue("$n", r.Storage.FileCount);
        insert.Parameters.AddWithValue("$cb", r.Reclaim.CandidateReclaimableBytes);
        insert.Parameters.AddWithValue("$rb", r.Reclaim.ReviewReclaimableBytes);
        insert.Parameters.AddWithValue("$fi", r.Findings.Count);
        insert.Parameters.AddWithValue("$ca", r.Coverage.WasCancelled ? 1 : 0);
        var id = (long)insert.ExecuteScalar()!;

        foreach (var cat in r.Storage.ByCategory) Exec(c, tx, "INSERT INTO scan_categories VALUES ($i, $k, $v)", id, cat.Key, cat.PhysicalBytes);
        foreach (var folder in r.Storage.TopFolders.DistinctBy(f => f.Path, StringComparer.OrdinalIgnoreCase)) Exec(c, tx, "INSERT INTO scan_folders VALUES ($i, $k, $v)", id, folder.Path, folder.PhysicalBytes);
        foreach (var group in r.Findings.GroupBy(f => f.RuleId))
        {
            using var cmd = c.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = "INSERT INTO scan_rule_summary VALUES ($i, $k, $n, $v)";
            cmd.Parameters.AddWithValue("$i", id);
            cmd.Parameters.AddWithValue("$k", group.Key);
            cmd.Parameters.AddWithValue("$n", group.Count());
            cmd.Parameters.AddWithValue("$v", group.Sum(f => f.CountedReclaimableBytes));
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
        return id;
    }

    private static void Exec(SqliteConnection c, SqliteTransaction tx, string sql, long id, string key, long value)
    {
        using var cmd = c.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        cmd.Parameters.AddWithValue("$i", id);
        cmd.Parameters.AddWithValue("$k", key);
        cmd.Parameters.AddWithValue("$v", value);
        cmd.ExecuteNonQuery();
    }

    public IReadOnlyList<HistoryEntry> List()
    {
        if (!File.Exists(paths.HistoryDatabase)) return [];
        using var c = Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT id, started_utc, finished_utc, mode, roots, physical_bytes, logical_bytes, files, candidate_bytes, review_bytes, findings, cancelled FROM scans ORDER BY id DESC";
        using var reader = cmd.ExecuteReader();
        var list = new List<HistoryEntry>();
        while (reader.Read())
        {
            list.Add(new HistoryEntry(reader.GetInt64(0), DateTime.Parse(reader.GetString(1), null, System.Globalization.DateTimeStyles.RoundtripKind),
                DateTime.Parse(reader.GetString(2), null, System.Globalization.DateTimeStyles.RoundtripKind), reader.GetString(3), reader.GetString(4), reader.GetInt64(5), reader.GetInt64(6),
                reader.GetInt64(7), reader.GetInt64(8), reader.GetInt64(9), reader.GetInt32(10), reader.GetInt64(11) != 0));
        }
        return list;
    }

    public HistoryComparison? Compare(long olderId, long newerId)
    {
        var all = List();
        var older = all.FirstOrDefault(e => e.Id == olderId);
        var newer = all.FirstOrDefault(e => e.Id == newerId);
        if (older == null || newer == null) return null;
        using var c = Open();
        return new HistoryComparison(older, newer,
            Diff(Read(c, "SELECT category, physical_bytes FROM scan_categories WHERE scan_id = $i", olderId), Read(c, "SELECT category, physical_bytes FROM scan_categories WHERE scan_id = $i", newerId)),
            Diff(Read(c, "SELECT path, physical_bytes FROM scan_folders WHERE scan_id = $i", olderId), Read(c, "SELECT path, physical_bytes FROM scan_folders WHERE scan_id = $i", newerId)));
    }

    private static Dictionary<string, long> Read(SqliteConnection c, string sql, long id)
    {
        using var cmd = c.CreateCommand();
        cmd.CommandText = sql;
        cmd.Parameters.AddWithValue("$i", id);
        using var r = cmd.ExecuteReader();
        var result = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        while (r.Read()) result[r.GetString(0)] = r.GetInt64(1);
        return result;
    }

    private static List<HistoryDelta> Diff(Dictionary<string, long> before, Dictionary<string, long> after) =>
        [.. before.Keys.Union(after.Keys, StringComparer.OrdinalIgnoreCase)
            .Select(k => new HistoryDelta(k, before.GetValueOrDefault(k), after.GetValueOrDefault(k)))
            .Where(d => d.Change != 0)
            .OrderByDescending(d => Math.Abs(d.Change))];

    /// <summary>Elimina solo los archivos propios de la herramienta.</summary>
    public bool Clear()
    {
        if (!File.Exists(paths.HistoryDatabase)) return false;
        SqliteConnection.ClearAllPools();
        File.Delete(paths.HistoryDatabase);
        return true;
    }
}
