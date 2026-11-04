namespace WinStorageAudit.Core.Model;

public enum Confidence { Unknown, Low, Medium, High }

public enum RiskLevel { Low, Moderate, High, Critical }

public enum RecommendationClass { CleanupCandidate, ManualReview, BackupPriority, Keep, InsufficientInformation }

public enum Reversibility { Regenerable, Redownloadable, RecoverableWithEffort, Irreversible, Unknown }

public enum StorageCategory
{
    OperatingSystem, Applications, PersonalDocuments, Images, Videos, Music, Downloads, Archives,
    CodeRepositories, DevCaches, TemporaryFiles, DatabasesAndBackups, Other,
}

/// <summary>Distinción obligatoria entre tipos de recursos de desarrollo y datos.</summary>
public enum ResourceKind
{
    None, RegenerableCache, BuildArtifact, DownloadedDependency, ActiveEnvironment,
    PersistentAppData, IrreplaceableUserData,
}

public enum FindingArea
{
    Downloads, Temporary, Development, AppResidue, Duplicates, LargeFiles, VirtualDisks,
    Databases, GitBackup, PersonalBackup, Applications,
}

public enum ScanMode { Quick, Deep }

public enum UsageClass
{
    RecentExecution, NoEvidence30Days, NoEvidence60Days, NoEvidence90Days, NoHistoricalEvidence, Unknown,
}

public enum BackupState { VerifiedCopy, PossibleCopy, NoCopyFound, NotVerifiable, NotEvaluated }

public enum GitRemoteState { NoRemote, RemoteWithoutUpstream, UpstreamTracked, Detached, NotVerifiable }

public enum ScanIssueKind { AccessDenied, NotFound, Locked, PathTooLong, CloudSkipped, LinkSkipped, Excluded, Other }

public enum PersonalKind { Office, Pdf, Photo, Video, Design, Creative, Database, Configuration, ExistingBackup }

public enum MaintenanceSeverity { Informational, Recommended, Advanced }

public static class Labels
{
    public static string Es(this Confidence v) => v switch
    {
        Confidence.High => "Alta", Confidence.Medium => "Media", Confidence.Low => "Baja", _ => "Desconocida",
    };

    public static string Es(this RiskLevel v) => v switch
    {
        RiskLevel.Low => "Bajo", RiskLevel.Moderate => "Moderado", RiskLevel.High => "Alto", _ => "Crítico",
    };

    public static string Es(this RecommendationClass v) => v switch
    {
        RecommendationClass.CleanupCandidate => "Candidato de limpieza",
        RecommendationClass.ManualReview => "Revisión manual",
        RecommendationClass.BackupPriority => "Respaldar prioritariamente",
        RecommendationClass.Keep => "Mantener",
        _ => "Información insuficiente",
    };

    public static string Es(this Reversibility v) => v switch
    {
        Reversibility.Regenerable => "Regenerable",
        Reversibility.Redownloadable => "Se puede volver a descargar",
        Reversibility.RecoverableWithEffort => "Recuperable con esfuerzo",
        Reversibility.Irreversible => "Irreversible",
        _ => "Desconocida",
    };

    public static string Es(this StorageCategory v) => v switch
    {
        StorageCategory.OperatingSystem => "Sistema operativo",
        StorageCategory.Applications => "Aplicaciones",
        StorageCategory.PersonalDocuments => "Documentos personales",
        StorageCategory.Images => "Imágenes",
        StorageCategory.Videos => "Vídeos",
        StorageCategory.Music => "Música",
        StorageCategory.Downloads => "Descargas",
        StorageCategory.Archives => "Archivos comprimidos",
        StorageCategory.CodeRepositories => "Repositorios de código",
        StorageCategory.DevCaches => "Cachés de desarrollo",
        StorageCategory.TemporaryFiles => "Archivos temporales",
        StorageCategory.DatabasesAndBackups => "Bases de datos y respaldos",
        _ => "Otros",
    };

    public static string Es(this ResourceKind v) => v switch
    {
        ResourceKind.RegenerableCache => "Caché regenerable",
        ResourceKind.BuildArtifact => "Artefacto de compilación",
        ResourceKind.DownloadedDependency => "Dependencia descargada",
        ResourceKind.ActiveEnvironment => "Entorno de desarrollo activo",
        ResourceKind.PersistentAppData => "Datos persistentes de aplicaciones",
        ResourceKind.IrreplaceableUserData => "Información de usuario potencialmente irremplazable",
        _ => "No aplica",
    };

    public static string Es(this FindingArea v) => v switch
    {
        FindingArea.Downloads => "Descargas",
        FindingArea.Temporary => "Temporales y registros",
        FindingArea.Development => "Desarrollo",
        FindingArea.AppResidue => "Residuos de aplicaciones",
        FindingArea.Duplicates => "Duplicados",
        FindingArea.LargeFiles => "Archivos grandes",
        FindingArea.VirtualDisks => "Discos virtuales",
        FindingArea.Databases => "Bases de datos",
        FindingArea.GitBackup => "Repositorios Git",
        FindingArea.PersonalBackup => "Archivos personales",
        _ => "Aplicaciones",
    };

    public static string Es(this UsageClass v) => v switch
    {
        UsageClass.RecentExecution => "Evidencia de ejecución reciente",
        UsageClass.NoEvidence30Days => "Sin evidencia de ejecución en los últimos 30 días",
        UsageClass.NoEvidence60Days => "Sin evidencia de ejecución en los últimos 60 días",
        UsageClass.NoEvidence90Days => "Sin evidencia de ejecución en los últimos 90 días",
        UsageClass.NoHistoricalEvidence => "Sin evidencia histórica disponible",
        _ => "Uso desconocido",
    };

    public static string Es(this BackupState v) => v switch
    {
        BackupState.VerifiedCopy => "Copia verificada",
        BackupState.PossibleCopy => "Posible copia encontrada",
        BackupState.NoCopyFound => "Sin copia encontrada en destinos configurados",
        BackupState.NotVerifiable => "Respaldo no verificable",
        _ => "No evaluado",
    };

    public static string Es(this PersonalKind v) => v switch
    {
        PersonalKind.Office => "Documentos Office",
        PersonalKind.Pdf => "PDF",
        PersonalKind.Photo => "Fotografías",
        PersonalKind.Video => "Vídeos personales",
        PersonalKind.Design => "Archivos de diseño",
        PersonalKind.Creative => "Proyectos creativos",
        PersonalKind.Database => "Bases de datos personales",
        PersonalKind.Configuration => "Configuraciones importantes",
        _ => "Copias de seguridad existentes",
    };

    public static string Es(this ScanIssueKind v) => v switch
    {
        ScanIssueKind.AccessDenied => "Acceso denegado",
        ScanIssueKind.NotFound => "Ruta no encontrada",
        ScanIssueKind.Locked => "Archivo bloqueado",
        ScanIssueKind.PathTooLong => "Profundidad o ruta excesiva",
        ScanIssueKind.CloudSkipped => "Contenido en la nube no leído",
        ScanIssueKind.LinkSkipped => "Enlace no seguido",
        ScanIssueKind.Excluded => "Excluido por regla",
        _ => "Otro error",
    };

    public static string Es(this MaintenanceSeverity v) => v switch
    {
        MaintenanceSeverity.Recommended => "Recomendada",
        MaintenanceSeverity.Advanced => "Avanzada de riesgo elevado",
        _ => "Informativa",
    };
}
