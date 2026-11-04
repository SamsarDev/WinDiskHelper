using System.Security.Principal;
using Microsoft.Win32;
using WinStorageAudit.Core;
using WinStorageAudit.Infrastructure.Native;

namespace WinStorageAudit.Infrastructure.Maintenance;

/// <summary>Obtiene el estado del sistema con consultas de solo lectura. Nunca altera la configuración.</summary>
public sealed class WindowsMaintenanceProbe(IProcessRunner runner) : IMaintenanceProbe
{
    public async Task<MaintenanceSnapshot> ProbeAsync(bool includeExpensive, CancellationToken ct)
    {
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var systemDrive = Path.GetPathRoot(windows) ?? @"C:\";
        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var (sense, policy) = ReadStorageSense();
        var (binBytes, binItems) = ReadRecycleBin(systemDrive);

        var snapshot = new MaintenanceSnapshot
        {
            SystemDrive = systemDrive,
            IsElevated = IsElevated(),
            StorageSenseEnabled = sense,
            StorageSenseManagedByPolicy = policy,
            RecycleBinBytes = binBytes,
            RecycleBinItems = binItems,
            HiberfilBytes = FileBytes(Path.Combine(systemDrive, "hiberfil.sys")),
            PagefileBytes = FileBytes(Path.Combine(systemDrive, "pagefile.sys")),
            SwapfileBytes = FileBytes(Path.Combine(systemDrive, "swapfile.sys")),
            UpdateDownloadBytes = DirectoryBytes(Path.Combine(windows, "SoftwareDistribution", "Download"), ct),
            WindowsOldBytes = DirectoryBytes(Path.Combine(systemDrive, "Windows.old"), ct),
            MemoryDumpBytes = FileBytes(Path.Combine(windows, "MEMORY.DMP")),
            MiniDumpBytes = DirectoryBytes(Path.Combine(windows, "Minidump"), ct),
            UserCrashDumpBytes = DirectoryBytes(Path.Combine(local, "CrashDumps"), ct),
            WindowsLogsBytes = DirectoryBytes(Path.Combine(windows, "Logs"), ct),
            WindowsInstallerBytes = includeExpensive ? DirectoryBytes(Path.Combine(windows, "Installer"), ct) : null,
            WinSxsApparentBytes = includeExpensive ? DirectoryBytes(Path.Combine(windows, "WinSxS"), ct) : null,
            WslDistributions = ReadWslDistributions(),
            WslInstalled = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Lxss", false) != null,
            DockerVirtualDisks = ReadDockerDisks(local),
        };

        var dockerPath = FindOnPath("docker.exe");
        snapshot = snapshot with { DockerInstalled = dockerPath != null || snapshot.DockerVirtualDisks.Count > 0 };
        if (includeExpensive && dockerPath != null)
        {
            var df = await runner.RunAsync(dockerPath, ["system", "df", "--format", "json"], null, TimeSpan.FromSeconds(30), null, ct);
            snapshot = df.ExitCode == 0
                ? snapshot with { DockerDfJson = df.StandardOutput }
                : snapshot with { DockerError = df.TimedOut ? "tiempo límite excedido" : "el motor de Docker no respondió; ¿Docker Desktop está en ejecución?" };
        }

        var sleep = await runner.RunAsync("powercfg.exe", ["/a"], null, TimeSpan.FromSeconds(15), null, ct);
        if (sleep.ExitCode == 0) snapshot = snapshot with { SleepStatesOutput = sleep.StandardOutput };
        return snapshot;
    }

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static (bool? Enabled, bool Policy) ReadStorageSense()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy", false);
        bool? enabled = key?.GetValue("01") is int v ? v != 0 : null;
        using var policy = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\StorageSense", false);
        return (enabled, policy?.GetValue("AllowStorageSenseGlobal") != null);
    }

    private static (long? Bytes, long? Items) ReadRecycleBin(string drive)
    {
        var info = new NativeMethods.ShQueryRbInfo { Size = System.Runtime.InteropServices.Marshal.SizeOf<NativeMethods.ShQueryRbInfo>() };
        return NativeMethods.SHQueryRecycleBin(drive, ref info) == 0 ? (info.SizeBytes, info.NumItems) : (null, null);
    }

    private static long? FileBytes(string path)
    {
        try
        {
            var f = new FileInfo(path);
            return f.Exists ? f.Length : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    private static long? DirectoryBytes(string path, CancellationToken ct)
    {
        if (!Directory.Exists(path)) return null;
        try
        {
            var options = new EnumerationOptions
            {
                RecurseSubdirectories = true,
                IgnoreInaccessible = true,
                AttributesToSkip = FileAttributes.ReparsePoint,
            };
            long total = 0;
            foreach (var f in new DirectoryInfo(path).EnumerateFiles("*", options))
            {
                ct.ThrowIfCancellationRequested();
                total += f.Length;
            }
            return total;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    private static IReadOnlyList<(string, string, long?)> ReadWslDistributions()
    {
        var result = new List<(string, string, long?)>();
        using var lxss = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Lxss", false);
        if (lxss == null) return result;
        foreach (var id in lxss.GetSubKeyNames())
        {
            using var d = lxss.OpenSubKey(id, false);
            if (d?.GetValue("DistributionName") is not string name || d.GetValue("BasePath") is not string basePath) continue;
            var cleaned = basePath.StartsWith(@"\\?\", StringComparison.Ordinal) ? basePath[4..] : basePath;
            var fileName = d.GetValue("VhdFileName") as string ?? "ext4.vhdx";
            var vhd = Path.Combine(cleaned, fileName);
            result.Add((name, vhd, FileBytes(vhd)));
        }
        return result;
    }

    private static IReadOnlyList<(string, long)> ReadDockerDisks(string local)
    {
        var result = new List<(string, long)>();
        foreach (var relative in new[] { @"Docker\wsl\disk\docker_data.vhdx", @"Docker\wsl\data\ext4.vhdx", @"Docker\wsl\main\ext4.vhdx" })
        {
            var path = Path.Combine(local, relative);
            if (FileBytes(path) is { } size) result.Add((path, size));
        }
        return result;
    }

    private static string? FindOnPath(string exe) =>
        (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => { try { return Path.Combine(p.Trim(), exe); } catch (ArgumentException) { return null; } })
            .FirstOrDefault(p => p != null && File.Exists(p));
}
