using WinStorageAudit.Core.Model;

namespace WinStorageAudit.Core.Scanning;

public enum DirectoryZone { Normal, System, ProgramFiles, AppData, Temp, Downloads }

/// <summary>Contexto heredado durante el recorrido: permite clasificar cada archivo sin rutas repetidas.</summary>
public sealed class DirectoryContext
{
    public required string Path { get; init; }
    public required int Depth { get; init; }
    public DirectoryContext? Parent { get; init; }
    public DirectoryZone Zone { get; init; }
    public bool InGitInternals { get; init; }
    public string? RepoRoot { get; init; }
    public DevArtifactKind? Artifact { get; init; }
    public KnownCacheDefinition? Cache { get; init; }
    public bool InsideDevResource { get; init; }
    public bool IsDevResourceRoot { get; init; }
    public bool SuppressArtifacts { get; init; }
    public ProjectMarkers Markers { get; init; }
    public bool MarkerSatisfied { get; init; }
    public List<TreeNode> ChildNodes { get; } = [];

    /// <summary>Espacio físico por categoría de todo el subárbol; da nombre al contenido de una carpeta genérica.</summary>
    public long[] CategoryBytes { get; } = new long[Enum.GetValues<StorageCategory>().Length];

    /// <summary>La categoría que ocupa al menos el 60 % del subárbol; si no la hay, el contenido es mixto.</summary>
    public StorageCategory? DominantFileCategory()
    {
        var total = CategoryBytes.Sum();
        if (total == 0) return null;
        for (var i = 0; i < CategoryBytes.Length; i++)
            if (CategoryBytes[i] >= total * 0.6) return (StorageCategory)i;
        return null;
    }

    /// <summary>El riesgo de una carpeta es el de su contenido más delicado, no el de su contenido mayoritario.</summary>
    public RiskLevel HighestContentRisk()
    {
        var total = CategoryBytes.Sum();
        var risk = RiskLevel.Low;
        for (var i = 0; i < CategoryBytes.Length; i++)
        {
            if (CategoryBytes[i] == 0 || CategoryBytes[i] < total * 0.01) continue;
            var r = FileClassifier.DefaultRisk((StorageCategory)i);
            if (r > risk) risk = r;
        }
        return risk;
    }
}

public static class FileClassifier
{
    private static readonly HashSet<string> ImageExt = Set(".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff", ".heic", ".heif", ".raw", ".cr2", ".cr3", ".nef", ".arw", ".dng", ".svg");
    private static readonly HashSet<string> PhotoExt = Set(".jpg", ".jpeg", ".heic", ".heif", ".raw", ".cr2", ".cr3", ".nef", ".arw", ".dng", ".tif", ".tiff");
    private static readonly HashSet<string> VideoExt = Set(".mp4", ".mkv", ".mov", ".avi", ".wmv", ".webm", ".m4v", ".mpg", ".mpeg", ".mts", ".m2ts");
    private static readonly HashSet<string> MusicExt = Set(".mp3", ".flac", ".wav", ".aac", ".m4a", ".ogg", ".wma", ".opus");
    private static readonly HashSet<string> ArchiveExt = Set(".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".zst", ".iso");
    private static readonly HashSet<string> OfficeExt = Set(".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".rtf", ".one", ".pages", ".numbers", ".key");
    private static readonly HashSet<string> DocumentExt = Set(".pdf", ".txt", ".md", ".epub", ".csv");
    private static readonly HashSet<string> DatabaseExt = Set(".db", ".sqlite", ".sqlite3", ".mdf", ".ldf", ".ndf", ".accdb", ".mdb", ".dump", ".dbf");
    private static readonly HashSet<string> BackupExt = Set(".bak", ".backup", ".wbcat", ".tib", ".old", ".bkf", ".pst", ".ost");
    private static readonly HashSet<string> DesignExt = Set(".psd", ".ai", ".indd", ".sketch", ".fig", ".xd", ".xcf", ".kra", ".cdr", ".afdesign", ".afphoto");
    private static readonly HashSet<string> CreativeExt = Set(".blend", ".prproj", ".aep", ".drp", ".veg", ".flp", ".als", ".logicx", ".kdenlive", ".ptx", ".reapr", ".rpp", ".c4d", ".max", ".ma");
    private static readonly HashSet<string> VirtualDiskExt = Set(".vhd", ".vhdx", ".vmdk", ".vdi", ".qcow2", ".avhdx");
    private static readonly HashSet<string> InstallerExt = Set(".exe", ".msi", ".msix", ".msixbundle", ".appx", ".appxbundle");
    private static readonly HashSet<string> SensitiveConfigNames = Set(".gitconfig", ".npmrc", ".pypirc", ".wslconfig", ".netrc", "id_rsa", "id_ed25519", "known_hosts", "authorized_keys");
    private static readonly HashSet<string> SensitiveConfigDirs = Set(".ssh", ".aws", ".kube", ".gnupg", ".azure", ".docker");

    private static HashSet<string> Set(params string[] v) => new(v, StringComparer.OrdinalIgnoreCase);

    public static bool IsInstaller(string ext) => InstallerExt.Contains(ext);
    public static bool IsArchive(string ext) => ArchiveExt.Contains(ext);
    public static bool IsVirtualDisk(string ext) => VirtualDiskExt.Contains(ext);
    public static bool IsDatabaseOrBackup(string ext) => DatabaseExt.Contains(ext) || BackupExt.Contains(ext);

    public static StorageCategory ForDirectory(DirectoryContext ctx)
    {
        if (ctx.InsideDevResource) return StorageCategory.DevCaches;
        return ctx.Zone switch
        {
            DirectoryZone.Temp => StorageCategory.TemporaryFiles,
            DirectoryZone.System => StorageCategory.OperatingSystem,
            DirectoryZone.ProgramFiles => StorageCategory.Applications,
            DirectoryZone.AppData => StorageCategory.Applications,
            _ when ctx.RepoRoot != null || ctx.InGitInternals => StorageCategory.CodeRepositories,
            DirectoryZone.Downloads => StorageCategory.Downloads,
            _ => StorageCategory.Other,
        };
    }

    public static StorageCategory ForFile(DirectoryContext ctx, string extension)
    {
        // Un disco virtual nunca se trata como archivo de aplicación corriente, aunque esté en AppData.
        if (VirtualDiskExt.Contains(extension) && ctx.Zone != DirectoryZone.System) return StorageCategory.DatabasesAndBackups;
        var dir = ForDirectory(ctx);
        if (dir != StorageCategory.Other) return dir;
        if (ImageExt.Contains(extension)) return StorageCategory.Images;
        if (VideoExt.Contains(extension)) return StorageCategory.Videos;
        if (MusicExt.Contains(extension)) return StorageCategory.Music;
        if (ArchiveExt.Contains(extension)) return StorageCategory.Archives;
        if (OfficeExt.Contains(extension) || DocumentExt.Contains(extension) || DesignExt.Contains(extension) || CreativeExt.Contains(extension)) return StorageCategory.PersonalDocuments;
        if (DatabaseExt.Contains(extension) || BackupExt.Contains(extension) || VirtualDiskExt.Contains(extension)) return StorageCategory.DatabasesAndBackups;
        return StorageCategory.Other;
    }

    /// <summary>Clasifica por metadatos (nombre y extensión). Nunca abre el archivo.</summary>
    public static PersonalKind? ClassifyPersonal(string fileName, string extension, string directoryName)
    {
        if (OfficeExt.Contains(extension)) return PersonalKind.Office;
        if (extension.Equals(".pdf", StringComparison.OrdinalIgnoreCase)) return PersonalKind.Pdf;
        if (PhotoExt.Contains(extension)) return PersonalKind.Photo;
        if (VideoExt.Contains(extension)) return PersonalKind.Video;
        if (DesignExt.Contains(extension)) return PersonalKind.Design;
        if (CreativeExt.Contains(extension)) return PersonalKind.Creative;
        if (DatabaseExt.Contains(extension)) return PersonalKind.Database;
        if (BackupExt.Contains(extension)) return PersonalKind.ExistingBackup;
        if (SensitiveConfigNames.Contains(fileName) || SensitiveConfigDirs.Contains(directoryName)) return PersonalKind.Configuration;
        return null;
    }

    /// <summary>Contenido que nunca debe tratarse como prescindible en un duplicado.</summary>
    public static bool IsSensitiveForDuplicates(string extension) =>
        OfficeExt.Contains(extension) || DocumentExt.Contains(extension) || ImageExt.Contains(extension) || VideoExt.Contains(extension)
        || MusicExt.Contains(extension) || DesignExt.Contains(extension) || CreativeExt.Contains(extension)
        || DatabaseExt.Contains(extension) || BackupExt.Contains(extension);

    public static string DescribeContent(StorageCategory category) => category.Es();

    public static RiskLevel DefaultRisk(StorageCategory category) => category switch
    {
        StorageCategory.OperatingSystem => RiskLevel.Critical,
        StorageCategory.Applications => RiskLevel.High,
        StorageCategory.PersonalDocuments or StorageCategory.Images or StorageCategory.Videos or StorageCategory.Music => RiskLevel.High,
        StorageCategory.CodeRepositories or StorageCategory.DatabasesAndBackups => RiskLevel.Critical,
        StorageCategory.DevCaches or StorageCategory.TemporaryFiles => RiskLevel.Low,
        _ => RiskLevel.Moderate,
    };
}

/// <summary>Patrones de nombres ignorados por Git que pueden contener información valiosa. Solo se evalúa el nombre.</summary>
public static class SensitiveIgnoredPatterns
{
    private static readonly HashSet<string> Extensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".db", ".sqlite", ".sqlite3", ".mdf", ".ldf", ".accdb", ".mdb", ".dump", ".bak", ".backup", ".sql",
        ".pem", ".key", ".pfx", ".p12", ".jks", ".keystore", ".env", ".tfstate", ".kdbx",
    };

    public static bool IsPotentiallyImportant(string relativePath)
    {
        var name = System.IO.Path.GetFileName(relativePath.TrimEnd('/', '\\'));
        if (name.Length == 0) return false;
        if (name.StartsWith(".env", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.StartsWith("appsettings.", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".json", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.StartsWith("secrets", StringComparison.OrdinalIgnoreCase) || name.StartsWith("credentials", StringComparison.OrdinalIgnoreCase)) return true;
        if (name.Equals("local.properties", StringComparison.OrdinalIgnoreCase)) return true;
        return Extensions.Contains(System.IO.Path.GetExtension(name));
    }
}
