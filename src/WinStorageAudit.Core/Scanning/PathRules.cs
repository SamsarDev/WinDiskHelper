using System.Text;
using System.Text.RegularExpressions;
using WinStorageAudit.Core.Model;

namespace WinStorageAudit.Core.Scanning;

public static class PathUtil
{
    public static string Normalize(string path)
    {
        var full = Path.GetFullPath(path);
        var root = Path.GetPathRoot(full);
        return full.Length > (root?.Length ?? 0) ? full.TrimEnd('\\', '/') : full;
    }

    public static bool IsSameOrUnder(string path, string ancestor)
    {
        if (string.IsNullOrEmpty(ancestor)) return false;
        var a = ancestor.TrimEnd('\\', '/');
        if (!path.StartsWith(a, StringComparison.OrdinalIgnoreCase)) return false;
        return path.Length == a.Length || path[a.Length] is '\\' or '/';
    }

    public static IEnumerable<string> Ancestors(string path)
    {
        var current = Path.GetDirectoryName(path);
        while (!string.IsNullOrEmpty(current))
        {
            yield return current;
            current = Path.GetDirectoryName(current);
        }
    }

    public static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
        double value = Math.Abs((double)bytes);
        var unit = 0;
        while (value >= 1024 && unit < units.Length - 1) { value /= 1024; unit++; }
        var sign = bytes < 0 ? "-" : "";
        return unit == 0 ? $"{sign}{value:0} {units[unit]}" : $"{sign}{value:0.##} {units[unit]}";
    }
}

/// <summary>
/// Reglas de exclusión: un patrón sin separadores coincide con cualquier segmento de nombre
/// (<c>node_modules</c>); un patrón con separadores se compara con la ruta completa y admite
/// <c>*</c>, <c>?</c> y <c>**</c> (<c>C:\Datos\**\tmp</c>). Un patrón de ruta también excluye sus hijos.
/// </summary>
public sealed class ExclusionMatcher
{
    private readonly List<Regex> _pathPatterns = [];
    private readonly List<Regex> _namePatterns = [];

    public ExclusionMatcher(IEnumerable<string> patterns)
    {
        foreach (var raw in patterns)
        {
            var pattern = raw.Trim().TrimEnd('\\', '/');
            if (pattern.Length == 0) continue;
            if (pattern.Contains('\\') || pattern.Contains('/'))
                _pathPatterns.Add(new Regex("^" + GlobToRegex(pattern) + "(\\\\.*)?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)));
            else
                _namePatterns.Add(new Regex("^" + GlobToRegex(pattern) + "$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1)));
        }
    }

    public bool IsExcluded(string fullPath, string name)
    {
        foreach (var r in _namePatterns) if (r.IsMatch(name)) return true;
        foreach (var r in _pathPatterns) if (r.IsMatch(fullPath)) return true;
        return false;
    }

    private static string GlobToRegex(string glob)
    {
        var sb = new StringBuilder();
        for (var i = 0; i < glob.Length; i++)
        {
            var c = glob[i];
            if (c == '*')
            {
                if (i + 1 < glob.Length && glob[i + 1] == '*')
                {
                    sb.Append(".*");
                    i++;
                    if (i + 1 < glob.Length && glob[i + 1] is '\\' or '/') { i++; sb.Append(@"\\?"); }
                }
                else sb.Append(@"[^\\]*");
            }
            else if (c == '?') sb.Append(@"[^\\]");
            else if (c is '\\' or '/') sb.Append(@"\\");
            else sb.Append(Regex.Escape(c.ToString()));
        }
        return sb.ToString();
    }
}

/// <summary>
/// Rutas que nunca pueden ser candidatas de limpieza. Es la última barrera del motor: cualquier regla
/// que proponga una de ellas es degradada a «Mantener».
/// </summary>
public sealed class ProtectedPaths(KnownLocations loc)
{
    private readonly string[] _roots =
    [
        loc.WindowsDirectory,
        Path.Combine(loc.ProgramData, "Package Cache"),
        Path.Combine(loc.ProgramData, "Microsoft"),
        Path.Combine(loc.LocalAppData, "Docker"),
        Path.Combine(loc.LocalAppData, "Packages"),
    ];

    private static readonly string[] ProtectedSegments = ["System Volume Information", "$Recycle.Bin", "$WinREAgent", "Recovery", "Boot"];

    public bool IsProtected(string path)
    {
        foreach (var r in _roots) if (PathUtil.IsSameOrUnder(path, r)) return true;
        var root = Path.GetPathRoot(path) ?? "";
        var rest = path.Length > root.Length ? path[root.Length..] : "";
        var first = rest.Split('\\', 2)[0];
        if (ProtectedSegments.Any(s => s.Equals(first, StringComparison.OrdinalIgnoreCase))) return true;

        // La raíz de una unidad o del perfil nunca es un objetivo válido.
        return rest.Length == 0 || path.Equals(loc.UserProfile.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
    }
}
