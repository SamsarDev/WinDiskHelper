using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using WinStorageAudit.Core;
using WinStorageAudit.Core.Model;
using WinStorageAudit.Infrastructure.Native;

namespace WinStorageAudit.Infrastructure;

public static class KnownLocationsProvider
{
    private static readonly Guid DownloadsFolder = new("374DE290-123F-4565-9164-39C4925E467B");

    public static KnownLocations Detect()
    {
        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var cloud = new[] { "OneDrive", "OneDriveConsumer", "OneDriveCommercial" }
            .Select(Environment.GetEnvironmentVariable)
            .Where(v => !string.IsNullOrWhiteSpace(v))
            .Select(v => v!.TrimEnd('\\'))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new KnownLocations
        {
            UserProfile = profile,
            Downloads = GetDownloads() ?? Path.Combine(profile, "Downloads"),
            Temp = Path.GetFullPath(Path.GetTempPath()).TrimEnd('\\'),
            LocalAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            RoamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            ProgramData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            ProgramFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            ProgramFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            WindowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            CloudSyncRoots = cloud,
        };
    }

    private static string? GetDownloads()
    {
        if (NativeMethods.SHGetKnownFolderPath(DownloadsFolder, 0, IntPtr.Zero, out var ptr) != 0) return null;
        try { return Marshal.PtrToStringUni(ptr); }
        finally { Marshal.FreeCoTaskMem(ptr); }
    }
}

public static class VolumeInfoProvider
{
    public static IReadOnlyList<VolumeSummary> ForRoots(IEnumerable<string> roots)
    {
        var result = new List<VolumeSummary>();
        foreach (var drive in roots.Select(Path.GetPathRoot).Where(r => !string.IsNullOrEmpty(r)).Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var info = new DriveInfo(drive!);
                long cluster = 0;
                if (NativeMethods.GetDiskFreeSpace(drive!, out var spc, out var bps, out _, out _)) cluster = (long)spc * bps;
                result.Add(new VolumeSummary
                {
                    Root = info.Name,
                    Label = info.VolumeLabel,
                    FileSystem = info.DriveFormat,
                    DriveType = info.DriveType.ToString(),
                    TotalBytes = info.TotalSize,
                    FreeBytes = info.TotalFreeSpace,
                    ClusterBytes = cluster,
                });
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                result.Add(new VolumeSummary { Root = drive!, DriveType = "No disponible" });
            }
        }
        return result;
    }

    public static IReadOnlyList<string> LocalFixedDrives() =>
        [.. DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady).Select(d => d.Name)];
}

/// <summary>Lanza procesos con ArgumentList, sin shell, con límite de tiempo y sin ventana.</summary>
public sealed class ProcessRunner : IProcessRunner
{
    public async Task<ProcessResult> RunAsync(string executable, IReadOnlyList<string> arguments, string? workingDirectory,
        TimeSpan timeout, IReadOnlyDictionary<string, string>? environment, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in arguments) psi.ArgumentList.Add(a);
        if (workingDirectory != null) psi.WorkingDirectory = workingDirectory;
        if (environment != null) foreach (var (k, v) in environment) psi.Environment[k] = v;

        using var process = new Process { StartInfo = psi };
        try { process.Start(); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return new ProcessResult(-1, "", ex.Message, false, true);
        }
        process.StandardInput.Close();

        var stdout = process.StandardOutput.ReadToEndAsync(CancellationToken.None);
        var stderr = process.StandardError.ReadToEndAsync(CancellationToken.None);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);
        var timedOut = false;
        try { await process.WaitForExitAsync(timeoutCts.Token); }
        catch (OperationCanceledException)
        {
            timedOut = !ct.IsCancellationRequested;
            try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { } catch (System.ComponentModel.Win32Exception) { }
        }

        var finished = await Task.WhenAny(Task.WhenAll(stdout, stderr), Task.Delay(TimeSpan.FromSeconds(5), CancellationToken.None));
        var outText = finished is Task<string[]> || stdout.IsCompletedSuccessfully ? await stdout : "";
        var errText = stderr.IsCompletedSuccessfully ? await stderr : "";
        ct.ThrowIfCancellationRequested();
        return new ProcessResult(timedOut ? -1 : process.ExitCode, outText, errText, timedOut, false);
    }
}
