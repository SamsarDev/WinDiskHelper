using System.Security.Cryptography;
using System.Text;

namespace WinStorageAudit.Core.Model;

/// <summary>
/// Hallazgo explicable. Responde: qué se encontró (Description), por qué importa (Relevance),
/// con qué evidencia (Evidence), qué puede hacer el usuario (RecommendedAction),
/// qué podría perder (PotentialLoss) y cuánto podría recuperar (EstimatedReclaimableBytes).
/// </summary>
public sealed record Finding
{
    public required string RuleId { get; init; }
    public required FindingArea Category { get; init; }
    public required string PathOrResource { get; init; }
    public required string Description { get; init; }
    public required string Relevance { get; init; }
    public required IReadOnlyList<string> Evidence { get; init; }
    public required RecommendationClass Recommendation { get; init; }
    public required Confidence Confidence { get; init; }
    public required RiskLevel RiskLevel { get; init; }
    public required Reversibility Reversibility { get; init; }
    public required string RecommendedAction { get; init; }
    public required string PotentialLoss { get; init; }
    public long DetectedSizeBytes { get; init; }
    public long EstimatedReclaimableBytes { get; init; }
    public bool RequiresBackup { get; init; }
    public bool RequiresElevation { get; init; }
    public ResourceKind ResourceKind { get; init; }

    /// <summary>Rutas adicionales (copias de un duplicado, ejemplos de un agregado).</summary>
    public IReadOnlyList<string> RelatedPaths { get; init; } = [];

    /// <summary>Indica que la ruta es un agregado y no una ubicación concreta.</summary>
    public bool IsAggregate { get; init; }

    /// <summary>Espacio que suma en los totales una vez eliminadas las superposiciones.</summary>
    public long CountedReclaimableBytes { get; init; }

    /// <summary>Identificador estable: la misma regla y ruta generan el mismo Id entre análisis.</summary>
    public string Id => StableId(RuleId, PathOrResource);

    public static string StableId(string ruleId, string path)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(ruleId + "|" + path.ToUpperInvariant()));
        return Convert.ToHexString(bytes, 0, 6).ToLowerInvariant();
    }
}

public sealed record ReclaimSummary
{
    /// <summary>Espacio físico que ocupan los elementos analizados.</summary>
    public long OccupiedPhysicalBytes { get; init; }

    /// <summary>Candidatos de limpieza, sin superposiciones.</summary>
    public long CandidateReclaimableBytes { get; init; }

    /// <summary>Elementos que exigen revisión manual; no se debe asumir que son eliminables.</summary>
    public long ReviewReclaimableBytes { get; init; }

    /// <summary>Esta versión es de solo lectura: siempre es cero.</summary>
    public long EffectivelyFreedBytes => 0;
}
