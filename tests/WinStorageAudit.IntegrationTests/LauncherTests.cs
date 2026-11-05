using Spectre.Console.Testing;
using WinStorageAudit.Cli;

namespace WinStorageAudit.IntegrationTests;

public class LauncherTests
{
    [Theory]
    [InlineData(1u, false, false, true)]   // Doble clic: la ventana es solo de este proceso.
    [InlineData(2u, false, false, false)]  // Terminal: el shell sigue abierto, no hace falta pausar.
    [InlineData(1u, true, false, false)]   // Sin teclado disponible nunca se debe esperar.
    [InlineData(1u, false, true, false)]   // Salida redirigida a un archivo o a otro proceso.
    [InlineData(0u, false, false, false)]  // Sin consola.
    public void Own_console_is_detected_only_when_someone_can_answer(uint processes, bool input, bool output, bool expected)
    {
        Assert.Equal(expected, Launcher.IsOwnConsole(processes, input, output));
    }

    [Fact]
    public void Report_option_only_appears_with_a_saved_result()
    {
        Assert.Contains(LauncherAction.OpenReport, Launcher.Options(true));
        Assert.DoesNotContain(LauncherAction.OpenReport, Launcher.Options(false));
    }

    [Fact]
    public void First_option_never_runs_anything_heavier_than_a_quick_scan()
    {
        Assert.Equal(LauncherAction.QuickScan, Launcher.Options(true)[0]);
        Assert.Equal(LauncherAction.Exit, Launcher.Options(true)[^1]);
    }

    [Theory]
    [InlineData(0, LauncherAction.QuickScan)]
    [InlineData(1, LauncherAction.DeepScan)]
    [InlineData(3, LauncherAction.Exit)]
    public async Task Menu_returns_the_selected_action(int downPresses, LauncherAction expected)
    {
        using var console = new TestConsole().Interactive();
        for (var i = 0; i < downPresses; i++) console.Input.PushKey(ConsoleKey.DownArrow);
        console.Input.PushKey(ConsoleKey.Enter);

        Assert.Equal(expected, await Launcher.AskAsync(console, false, default));
    }

    [Theory]
    [InlineData("s", true)]
    [InlineData("n", false)]
    [InlineData("", false)]
    public async Task Confirmation_accepts_spanish_answers_and_defaults_to_no(string answer, bool expected)
    {
        using var console = new TestConsole().Interactive();
        console.Input.PushTextWithEnter(answer);

        Assert.Equal(expected, await Launcher.ConfirmAsync(console, "¿Continuar?", default));
    }

    [Fact]
    public void Without_a_keyboard_no_arguments_prints_help_and_never_waits()
    {
        using var t = new TempTree();
        var exe = Path.Combine(AppContext.BaseDirectory, "winstorageaudit.exe");
        var psi = new System.Diagnostics.ProcessStartInfo(exe) { RedirectStandardOutput = true, RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true };
        psi.Environment["WINSTORAGEAUDIT_HOME"] = t.Root;
        using var p = System.Diagnostics.Process.Start(psi)!;
        p.StandardInput.Close();
        var output = p.StandardOutput.ReadToEnd();

        Assert.True(p.WaitForExit(30_000));
        Assert.Equal(0, p.ExitCode);
        Assert.Contains("Uso:", output);
        Assert.Empty(Directory.GetFileSystemEntries(t.Root));
    }
}
