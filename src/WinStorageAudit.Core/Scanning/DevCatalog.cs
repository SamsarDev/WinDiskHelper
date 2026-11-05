using WinStorageAudit.Core.Model;

namespace WinStorageAudit.Core.Scanning;

[Flags]
public enum ProjectMarkers
{
    None = 0,
    DotNet = 1 << 0,
    PackageJson = 1 << 1,
    JsLockFile = 1 << 2,
    Python = 1 << 3,
    Pubspec = 1 << 4,
    Gradle = 1 << 5,
    Maven = 1 << 6,
    Solution = 1 << 7,
}

public static class MarkerDetector
{
    public static ProjectMarkers Detect(IReadOnlyList<FileEntry> files)
    {
        var m = ProjectMarkers.None;
        foreach (var f in files)
        {
            var n = f.Name.ToLowerInvariant();
            switch (n)
            {
                case "package.json": m |= ProjectMarkers.PackageJson; break;
                case "package-lock.json" or "pnpm-lock.yaml" or "yarn.lock" or "bun.lockb" or "bun.lock": m |= ProjectMarkers.JsLockFile; break;
                case "requirements.txt" or "pyproject.toml" or "setup.py" or "pipfile" or "poetry.lock" or "uv.lock": m |= ProjectMarkers.Python; break;
                case "pubspec.yaml": m |= ProjectMarkers.Pubspec; break;
                case "build.gradle" or "build.gradle.kts" or "settings.gradle" or "settings.gradle.kts": m |= ProjectMarkers.Gradle; break;
                case "pom.xml": m |= ProjectMarkers.Maven; break;
                default:
                    if (n.EndsWith(".csproj") || n.EndsWith(".fsproj") || n.EndsWith(".vbproj")) m |= ProjectMarkers.DotNet;
                    else if (n.EndsWith(".sln") || n.EndsWith(".slnx")) m |= ProjectMarkers.Solution;
                    break;
            }
        }
        return m;
    }
}

public sealed record DevArtifactKind(
    string Id, string Tool, ResourceKind Kind, Reversibility Reversibility, string RegenerateHint, string MarkerEvidence);

public static class DevArtifactCatalog
{
    private static DevArtifactKind Build(string id, string tool, string hint, string marker) =>
        new(id, tool, ResourceKind.BuildArtifact, Reversibility.Regenerable, hint, marker);

    private static DevArtifactKind Cache(string id, string tool, string hint, string marker) =>
        new(id, tool, ResourceKind.RegenerableCache, Reversibility.Regenerable, hint, marker);

    /// <summary>Un nombre genérico como «bin» o «build» solo cuenta si el directorio padre demuestra el tipo de proyecto.</summary>
    public static DevArtifactKind? Detect(string name, ProjectMarkers parent, DirectorySnapshot dir)
    {
        var n = name.ToLowerInvariant();
        if (dir.HasFile("pyvenv.cfg"))
        {
            return new DevArtifactKind("python-venv", "Python", ResourceKind.ActiveEnvironment, Reversibility.RecoverableWithEffort,
                "Recrear con «python -m venv» e instalar las dependencias declaradas.", "contiene pyvenv.cfg");
        }

        switch (n)
        {
            case "node_modules" when parent.HasFlag(ProjectMarkers.PackageJson):
                return new DevArtifactKind("node-modules", "Node.js", ResourceKind.DownloadedDependency, Reversibility.Redownloadable,
                    "Reinstalar con «npm ci», «pnpm install» o «yarn install».", "package.json junto a la carpeta");
            case "dist" when parent.HasFlag(ProjectMarkers.PackageJson):
                return Build("node-dist", "Node.js", "Regenerar con el script de compilación del proyecto.", "package.json junto a la carpeta");
            case ".next" or ".nuxt" or ".output" or ".turbo" or ".parcel-cache" or ".svelte-kit" when parent.HasFlag(ProjectMarkers.PackageJson):
                return Cache("node-framework-cache", "Node.js", "Se regenera al compilar el proyecto.", "package.json junto a la carpeta");
            case "bin" or "obj" when parent.HasFlag(ProjectMarkers.DotNet):
                return Build("dotnet-" + n, ".NET", "Regenerar con «dotnet build».", "archivo de proyecto .NET junto a la carpeta");
            case "testresults" when parent.HasFlag(ProjectMarkers.DotNet) || parent.HasFlag(ProjectMarkers.Solution):
                return Build("dotnet-testresults", ".NET", "Se regenera al ejecutar pruebas; se pierden resultados históricos.", "proyecto o solución .NET junto a la carpeta");
            case ".vs" when parent.HasFlag(ProjectMarkers.Solution) || parent.HasFlag(ProjectMarkers.DotNet):
                return new DevArtifactKind("visualstudio-vs", "Visual Studio", ResourceKind.ActiveEnvironment, Reversibility.RecoverableWithEffort,
                    "Cerrar Visual Studio antes; se perderá el estado local de la solución.", "solución .NET junto a la carpeta");
            case "__pycache__" when dir.Files.Count > 0 && dir.Files.All(f => f.Name.EndsWith(".pyc", StringComparison.OrdinalIgnoreCase)):
                return Cache("python-pycache", "Python", "Python lo regenera al importar módulos.", "solo contiene archivos .pyc");
            case ".pytest_cache" or ".mypy_cache" or ".ruff_cache" or ".tox" when dir.HasFile("CACHEDIR.TAG") || dir.HasFile("README.md") || parent.HasFlag(ProjectMarkers.Python):
                return Cache("python-tool-cache", "Python", "La herramienta lo regenera en su siguiente ejecución.", "marcador de caché o proyecto Python");
            case "htmlcov" when parent.HasFlag(ProjectMarkers.Python):
                return Build("python-coverage", "Python", "Regenerar ejecutando las pruebas con cobertura.", "proyecto Python junto a la carpeta");
            case "build" when parent.HasFlag(ProjectMarkers.Pubspec):
                return Build("flutter-build", "Flutter", "Regenerar con «flutter build»; también «flutter clean».", "pubspec.yaml junto a la carpeta");
            case ".dart_tool" when parent.HasFlag(ProjectMarkers.Pubspec):
                return Cache("dart-tool", "Dart", "Regenerar con «dart pub get».", "pubspec.yaml junto a la carpeta");
            case "build" or ".gradle" when parent.HasFlag(ProjectMarkers.Gradle):
                return Build("gradle-" + n.TrimStart('.'), "Gradle", "Regenerar con «gradle build»; también «gradle clean».", "script Gradle junto a la carpeta");
            case "target" when parent.HasFlag(ProjectMarkers.Maven):
                return Build("maven-target", "Maven", "Regenerar con «mvn package»; también «mvn clean».", "pom.xml junto a la carpeta");
            default:
                return null;
        }
    }
}

public sealed record KnownCacheDefinition(
    string Id, string Tool, string PathPattern, string[] Markers, ResourceKind Kind, Reversibility Reversibility,
    Confidence MaxConfidence, RiskLevel Risk, string Action, string Loss);

/// <summary>Cachés reconocidas por ubicación exacta más un marcador estructural; un nombre parecido no basta.</summary>
public sealed class KnownCacheCatalog
{
    private readonly List<(KnownCacheDefinition Def, string[] Segments)> _definitions = [];
    private readonly HashSet<string> _leafNames = new(StringComparer.OrdinalIgnoreCase);

    public KnownCacheCatalog(KnownLocations loc)
    {
        const string offline = "Sin red o sin acceso a repositorios privados, no se podrá restaurar lo eliminado.";
        var defs = new[]
        {
            new KnownCacheDefinition("nuget-packages", "NuGet", Path.Combine(loc.UserProfile, ".nuget", "packages"), [], ResourceKind.DownloadedDependency, Reversibility.Redownloadable, Confidence.High, RiskLevel.Low,
                "dotnet nuget locals global-packages --clear", offline),
            new KnownCacheDefinition("npm-cache", "npm", Path.Combine(loc.LocalAppData, "npm-cache"), ["_cacache"], ResourceKind.RegenerableCache, Reversibility.Redownloadable, Confidence.High, RiskLevel.Low,
                "npm cache verify  (o «npm cache clean --force» para vaciarla)", offline),
            new KnownCacheDefinition("pnpm-store", "pnpm", Path.Combine(loc.LocalAppData, "pnpm", "store"), [], ResourceKind.DownloadedDependency, Reversibility.Redownloadable, Confidence.Medium, RiskLevel.Moderate,
                "pnpm store prune", "pnpm enlaza este almacén con los node_modules: borrarlo a mano puede romper proyectos. Use solo el comando oficial."),
            new KnownCacheDefinition("yarn-cache", "Yarn", Path.Combine(loc.LocalAppData, "Yarn", "Cache"), [], ResourceKind.RegenerableCache, Reversibility.Redownloadable, Confidence.Medium, RiskLevel.Low,
                "yarn cache clean", offline),
            new KnownCacheDefinition("pip-cache", "pip", Path.Combine(loc.LocalAppData, "pip", "Cache"), ["http", "http-v2", "wheels"], ResourceKind.RegenerableCache, Reversibility.Redownloadable, Confidence.High, RiskLevel.Low,
                "pip cache purge", offline),
            new KnownCacheDefinition("uv-cache", "uv", Path.Combine(loc.LocalAppData, "uv", "cache"), [], ResourceKind.RegenerableCache, Reversibility.Redownloadable, Confidence.Medium, RiskLevel.Low,
                "uv cache clean", offline),
            new KnownCacheDefinition("gradle-caches", "Gradle", Path.Combine(loc.UserProfile, ".gradle", "caches"), ["modules-2"], ResourceKind.DownloadedDependency, Reversibility.Redownloadable, Confidence.Medium, RiskLevel.Low,
                "Detener con «gradle --stop» y revisar la documentación de Gradle antes de borrar", offline),
            new KnownCacheDefinition("maven-repository", "Maven", Path.Combine(loc.UserProfile, ".m2", "repository"), [], ResourceKind.DownloadedDependency, Reversibility.RecoverableWithEffort, Confidence.Medium, RiskLevel.Moderate,
                "mvn dependency:purge-local-repository (por proyecto)", "Puede contener artefactos instalados con «mvn install» que no existen en ningún servidor."),
            new KnownCacheDefinition("pub-cache", "Dart/Flutter", Path.Combine(loc.LocalAppData, "Pub", "Cache"), ["hosted"], ResourceKind.DownloadedDependency, Reversibility.Redownloadable, Confidence.Medium, RiskLevel.Low,
                "dart pub cache clean", "Se perderán paquetes activados globalmente. " + offline),
            new KnownCacheDefinition("vscode-cache", "VS Code", Path.Combine(loc.RoamingAppData, "Code", "Cache"), [], ResourceKind.RegenerableCache, Reversibility.Regenerable, Confidence.Medium, RiskLevel.Low,
                "Cerrar VS Code y eliminar solo esta carpeta", "VS Code tardará más en su próximo arranque."),
            new KnownCacheDefinition("vscode-cacheddata", "VS Code", Path.Combine(loc.RoamingAppData, "Code", "CachedData"), [], ResourceKind.RegenerableCache, Reversibility.Regenerable, Confidence.Medium, RiskLevel.Low,
                "Cerrar VS Code y eliminar solo esta carpeta", "VS Code tardará más en su próximo arranque."),
            new KnownCacheDefinition("vscode-codecache", "VS Code", Path.Combine(loc.RoamingAppData, "Code", "Code Cache"), [], ResourceKind.RegenerableCache, Reversibility.Regenerable, Confidence.Medium, RiskLevel.Low,
                "Cerrar VS Code y eliminar solo esta carpeta", "VS Code tardará más en su próximo arranque."),
            new KnownCacheDefinition("vscode-vsix", "VS Code", Path.Combine(loc.RoamingAppData, "Code", "CachedExtensionVSIXs"), [], ResourceKind.RegenerableCache, Reversibility.Redownloadable, Confidence.Medium, RiskLevel.Low,
                "Cerrar VS Code y eliminar solo esta carpeta", "Las extensiones instaladas no se ven afectadas; las versiones en caché se volverán a descargar."),
            new KnownCacheDefinition("jetbrains-caches", "JetBrains", Path.Combine(loc.LocalAppData, "JetBrains", "*", "caches"), [], ResourceKind.RegenerableCache, Reversibility.Regenerable, Confidence.Medium, RiskLevel.Low,
                "En el IDE: File > Invalidate Caches", "El IDE volverá a indexar los proyectos."),
            new KnownCacheDefinition("visualstudio-mefcache", "Visual Studio", Path.Combine(loc.LocalAppData, "Microsoft", "VisualStudio", "*", "ComponentModelCache"), [], ResourceKind.RegenerableCache, Reversibility.Regenerable, Confidence.Medium, RiskLevel.Low,
                "Cerrar Visual Studio y eliminar solo esta carpeta", "Visual Studio tardará más en su próximo arranque."),
        };

        foreach (var d in defs)
        {
            _definitions.Add((d, d.PathPattern.Split('\\', StringSplitOptions.RemoveEmptyEntries)));
            _leafNames.Add(Path.GetFileName(d.PathPattern));
        }
    }

    public KnownCacheDefinition? Match(string fullPath, string name)
    {
        if (!_leafNames.Contains(name)) return null;
        var segments = fullPath.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        foreach (var (def, pattern) in _definitions)
        {
            if (pattern.Length != segments.Length) continue;
            var ok = true;
            for (var i = 0; i < pattern.Length && ok; i++)
                ok = pattern[i] == "*" || pattern[i].Equals(segments[i], StringComparison.OrdinalIgnoreCase);
            if (ok) return def;
        }
        return null;
    }
}
