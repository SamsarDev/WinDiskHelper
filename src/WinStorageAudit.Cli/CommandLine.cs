namespace WinStorageAudit.Cli;

public sealed record OptionSpec(string Name, string Description, string? ValueName = null, bool Repeatable = false)
{
    public bool TakesValue => ValueName != null;
}

public sealed record CommandSpec(string Name, string Summary, string Usage, IReadOnlyList<OptionSpec> Options, IReadOnlyList<string>? Examples = null);

public sealed class UsageException(string message) : Exception(message);

public sealed class ParsedArgs
{
    public List<string> Positionals { get; } = [];
    public Dictionary<string, List<string>> Values { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<string> Flags { get; } = new(StringComparer.OrdinalIgnoreCase);

    public bool Has(string name) => Flags.Contains(name);
    public string? Value(string name) => Values.TryGetValue(name, out var v) ? v[^1] : null;
    public IReadOnlyList<string> All(string name) => Values.TryGetValue(name, out var v) ? v : [];

    public int Int(string name, int fallback, int min = 1, int max = int.MaxValue)
    {
        var raw = Value(name);
        if (raw == null) return fallback;
        if (!int.TryParse(raw, out var value) || value < min || value > max)
            throw new UsageException($"--{name} requiere un número entre {min} y {max}.");
        return value;
    }
}

/// <summary>Analizador mínimo con mensajes en español. Las rutas nunca se interpretan como comandos.</summary>
public static class ArgParser
{
    public static ParsedArgs Parse(IReadOnlyList<string> args, CommandSpec spec)
    {
        var parsed = new ParsedArgs();
        var byName = spec.Options.ToDictionary(o => o.Name, StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < args.Count; i++)
        {
            var arg = args[i];
            if (arg is "-h" or "--help" or "/?")
            {
                parsed.Flags.Add("help");
                continue;
            }
            if (!arg.StartsWith("--", StringComparison.Ordinal))
            {
                parsed.Positionals.Add(arg);
                continue;
            }

            var name = arg[2..];
            string? inline = null;
            var eq = name.IndexOf('=');
            if (eq > 0)
            {
                inline = name[(eq + 1)..];
                name = name[..eq];
            }

            if (!byName.TryGetValue(name, out var option))
            {
                var hint = spec.Options.FirstOrDefault(o => o.Name.StartsWith(name, StringComparison.OrdinalIgnoreCase));
                throw new UsageException($"Opción desconocida: --{name}." + (hint != null ? $" ¿Quiso decir --{hint.Name}?" : "") + $" Consulte «winstorageaudit {spec.Name} --help».");
            }

            if (!option.TakesValue)
            {
                if (inline != null) throw new UsageException($"--{name} no admite un valor.");
                parsed.Flags.Add(option.Name);
                continue;
            }

            var value = inline;
            if (value == null)
            {
                if (i + 1 >= args.Count) throw new UsageException($"--{name} requiere un valor: {option.ValueName}.");
                value = args[++i];
            }

            if (!parsed.Values.TryGetValue(option.Name, out var list)) parsed.Values[option.Name] = list = [];
            if (list.Count > 0 && !option.Repeatable) throw new UsageException($"--{name} solo se puede indicar una vez.");
            list.Add(value);
        }
        return parsed;
    }
}

public static class Commands
{
    private static readonly OptionSpec[] ScanInputs =
    [
        new("path", "Ruta a analizar. Se puede repetir.", "RUTA", true),
        new("drive", "Unidad completa, por ejemplo C:. Se puede repetir.", "UNIDAD", true),
        new("profile", "Analiza solo el perfil del usuario."),
        new("exclude", "Excluye un nombre (node_modules) o una ruta con comodines. Se puede repetir.", "PATRÓN", true),
        new("concurrency", "Hilos de análisis (1-32).", "N"),
        new("allow-network", "Autoriza analizar rutas de red indicadas expresamente."),
    ];

    public static readonly CommandSpec Scan = new("scan", "Analiza el almacenamiento y genera recomendaciones.", "scan [--quick | --deep] [--path RUTA]... [--drive C:]... [--profile]",
    [
        new("quick", "Análisis rápido (predeterminado): sin hash de duplicados ni inventario de aplicaciones."),
        new("deep", "Análisis profundo: duplicados, aplicaciones, Docker, tamaño físico exacto y archivos ignorados por Git."),
        .. ScanInputs,
        new("verify-hashes", "Compara con los destinos de respaldo por contenido (SHA-256). Puede tardar mucho."),
        new("no-save", "No guarda el resultado ni el historial."),
    ],
    ["scan --quick", "scan --deep --drive C:", "scan --path \"D:\\Projects\" --exclude node_modules"]);

    public static readonly CommandSpec Analyze = new("analyze", "Ejecuta un solo módulo y muestra su resultado.", "analyze <storage|git|backups|apps|duplicates|maintenance> [opciones]",
    [
        .. ScanInputs,
        new("verify-hashes", "backups: compara con los destinos por contenido (SHA-256)."),
        new("save", "Guarda el resultado como el último análisis (reemplaza al anterior)."),
    ],
    ["analyze git --path \"D:\\Projects\"", "analyze apps", "analyze duplicates --path \"D:\\Fotos\"", "analyze backups --verify-hashes"]);

    public static readonly CommandSpec Recommendations = new("recommendations", "Muestra los hallazgos del último análisis, con filtros.", "recommendations [--risk R] [--area A] [--class C] [--sort CAMPO] [--top N] [--id ID] [--interactive]",
    [
        new("risk", "Filtra por riesgo: bajo, moderado, alto, critico. Se puede repetir.", "RIESGO", true),
        new("area", "Filtra por área: descargas, temporales, desarrollo, residuos, duplicados, grandes, discos, bases, git, personales, aplicaciones.", "ÁREA", true),
        new("class", "Filtra por clasificación: limpieza, revision, respaldo, mantener, insuficiente.", "CLASE", true),
        new("sort", "Ordena por: size (predeterminado), risk, confidence, path.", "CAMPO"),
        new("top", "Número máximo de filas.", "N"),
        new("id", "Muestra la explicación completa de un hallazgo.", "ID"),
        new("interactive", "Navega por los hallazgos de forma interactiva."),
    ]);

    public static readonly CommandSpec Maintenance = new("maintenance", "Muestra recomendaciones de mantenimiento de Windows del último análisis.", "maintenance", []);

    public static readonly CommandSpec Top = new("top", "Muestra los mayores consumidores del último análisis.", "top <folders|files|extensions|categories|concentrations> [--top N] [--sort physical|logical]",
    [
        new("top", "Número máximo de filas.", "N"),
        new("sort", "Ordena por tamaño: physical (predeterminado) o logical.", "CAMPO"),
    ]);

    public static readonly CommandSpec Browse = new("browse", "Navega de forma interactiva por el árbol de carpetas del último análisis.", "browse", []);

    public static readonly CommandSpec Report = new("report", "Exporta el último análisis.", "report --format <html|json|plan> [--output ARCHIVO] [--force] [--open]",
    [
        new("format", "html (predeterminado), json o plan (plan de limpieza revisable en Markdown).", "FORMATO"),
        new("output", "Archivo de salida. Por defecto, la carpeta de reportes de la aplicación.", "ARCHIVO"),
        new("force", "Permite reemplazar un archivo de salida existente."),
        new("open", "Abre el reporte al terminar."),
    ]);

    public static readonly CommandSpec History = new("history", "Consulta, compara o elimina el historial.", "history [list | compare <ID antiguo> <ID nuevo> | clear [--yes] [--include-reports]]",
    [
        new("yes", "No pide confirmación al eliminar."),
        new("include-reports", "clear: elimina también los reportes generados en la carpeta de la aplicación."),
    ]);

    public static readonly CommandSpec Config = new("config", "Consulta y modifica la configuración.", "config [show | path | set <clave> <valor> | add-path|remove-path <ruta> | add-exclude|remove-exclude <patrón> | add-backup|remove-backup <ruta> | export <archivo> | reset [--yes]]",
    [
        new("yes", "reset: no pide confirmación."),
        new("force", "export: permite reemplazar el archivo."),
    ]);

    public static readonly IReadOnlyList<CommandSpec> All = [Scan, Analyze, Recommendations, Top, Browse, Maintenance, Report, History, Config];
}
