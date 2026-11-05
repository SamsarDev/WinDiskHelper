using WinStorageAudit.Core.Backup;
using WinStorageAudit.Core.Model;

namespace WinStorageAudit.Core.Cleanup;

public sealed class GitBackupRule : IRule
{
    public string Id => "BKP-GIT";

    public IEnumerable<Finding> Evaluate(RuleContext c)
    {
        foreach (var r in c.Repositories.OrderByDescending(BackupReportBuilder.GitPriorityScore))
        {
            var score = BackupReportBuilder.GitPriorityScore(r);
            if (score == 0) continue;

            if (r.Error != null)
            {
                yield return new Finding
                {
                    RuleId = Id + ":unreadable",
                    Category = FindingArea.GitBackup,
                    PathOrResource = r.Path,
                    Description = "Repositorio cuyo estado no se pudo determinar.",
                    Relevance = "Sin leer su estado no se puede afirmar que esté respaldado.",
                    Evidence = [r.Error],
                    Recommendation = RecommendationClass.InsufficientInformation,
                    Confidence = Confidence.Unknown,
                    RiskLevel = RiskLevel.Moderate,
                    Reversibility = Reversibility.Unknown,
                    RecommendedAction = "Compruebe el repositorio manualmente con «git status».",
                    PotentialLoss = "Trabajo no publicado, si lo hubiera.",
                    DetectedSizeBytes = r.SizeBytes,
                    RequiresBackup = true,
                    ResourceKind = ResourceKind.IrreplaceableUserData,
                };
                continue;
            }

            var noRemote = r.Remotes.Count == 0;
            yield return new Finding
            {
                RuleId = Id + (noRemote ? ":no-remote" : ":local-work"),
                Category = FindingArea.GitBackup,
                PathOrResource = r.Path,
                Description = noRemote ? "Repositorio sin remoto: esta es la única copia conocida de su historial." : "Repositorio con trabajo local que quizá no esté publicado.",
                Relevance = "Si el disco falla o se formatea, este trabajo se perdería. Tener un remoto no equivale a estar respaldado.",
                Evidence = [.. r.States, .. r.SensitiveIgnored.Take(10).Select(i => "Ignorado por Git: " + i)],
                Recommendation = RecommendationClass.BackupPriority,
                Confidence = noRemote ? Confidence.High : Confidence.Medium,
                RiskLevel = noRemote ? RiskLevel.Critical : RiskLevel.High,
                Reversibility = Reversibility.Irreversible,
                RecommendedAction = noRemote
                    ? "Agregue un remoto y publique, o copie la carpeta completa (incluida .git) a un destino de respaldo."
                    : "Revise, confirme y publique el trabajo pendiente. La herramienta no ejecuta ninguno de estos pasos.",
                PotentialLoss = "Historial, cambios sin confirmar, stashes y archivos ignorados como .env o bases de datos locales.",
                DetectedSizeBytes = r.SizeBytes,
                RequiresBackup = true,
                ResourceKind = ResourceKind.IrreplaceableUserData,
            };
        }
    }
}

public sealed class PersonalBackupRule : IRule
{
    public string Id => "BKP-PERSONAL";

    public IEnumerable<Finding> Evaluate(RuleContext c)
    {
        if (c.Backup == null) yield break;
        foreach (var g in c.Backup.PersonalGroups.Where(g => g.Kind != PersonalKind.ExistingBackup))
        {
            var unverified = c.Scan.PersonalFiles.Count(f => f.Kind == g.Kind && f.BackupState != BackupState.VerifiedCopy);
            if (unverified == 0) continue;
            yield return new Finding
            {
                RuleId = Id + ":" + g.Kind,
                Category = FindingArea.PersonalBackup,
                PathOrResource = $"({g.Kind.Es()}: {g.FileCount:N0} archivo(s))",
                IsAggregate = true,
                RelatedPaths = g.TopFolders,
                Description = $"{g.Kind.Es()} sin copia verificada en los destinos configurados.",
                Relevance = "Clasificado por extensión y ubicación; el contenido no se ha leído. Su antigüedad no los hace prescindibles.",
                Evidence =
                [
                    $"{unverified:N0} de {g.FileCount:N0} archivos sin copia verificada",
                    c.Backup.Destinations.Count == 0 ? "No hay destinos de respaldo configurados" : $"{c.Backup.Destinations.Count} destinos comparados",
                ],
                Recommendation = RecommendationClass.BackupPriority,
                Confidence = Confidence.Medium,
                RiskLevel = RiskLevel.High,
                Reversibility = Reversibility.Irreversible,
                RecommendedAction = "Copie estas carpetas a otro dispositivo y configure el destino con «config add-backup».",
                PotentialLoss = "Archivos personales que no se pueden regenerar.",
                DetectedSizeBytes = g.Bytes,
                RequiresBackup = true,
                ResourceKind = ResourceKind.IrreplaceableUserData,
            };
        }
    }
}
