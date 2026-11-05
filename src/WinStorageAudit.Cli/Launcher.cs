using System.Runtime.InteropServices;
using Spectre.Console;

namespace WinStorageAudit.Cli;

public enum LauncherAction { QuickScan, DeepScan, OpenReport, Help, Exit }

/// <summary>
/// Experiencia al abrir el ejecutable con doble clic: la ventana pertenece solo a este proceso y se
/// cerraría al terminar. Nunca se inicia un análisis sin que el usuario lo elija.
/// </summary>
public static class Launcher
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetConsoleProcessList([Out] uint[] processList, uint count);

    /// <summary>Si este es el único proceso de la consola, nadie la abrió antes: al salir, se cerrará.</summary>
    public static bool OwnsConsole()
    {
        var count = GetConsoleProcessList(new uint[4], 4);
        return IsOwnConsole(count, Console.IsInputRedirected, Console.IsOutputRedirected);
    }

    public static bool IsOwnConsole(uint attachedProcesses, bool inputRedirected, bool outputRedirected) =>
        attachedProcesses == 1 && !inputRedirected && !outputRedirected;

    public static IReadOnlyList<LauncherAction> Options(bool hasSavedResult) => hasSavedResult
        ? [LauncherAction.QuickScan, LauncherAction.DeepScan, LauncherAction.OpenReport, LauncherAction.Help, LauncherAction.Exit]
        : [LauncherAction.QuickScan, LauncherAction.DeepScan, LauncherAction.Help, LauncherAction.Exit];

    public static string Describe(LauncherAction action) => action switch
    {
        LauncherAction.QuickScan => "Análisis rápido del perfil de usuario",
        LauncherAction.DeepScan => "Análisis profundo del perfil de usuario",
        LauncherAction.OpenReport => "Abrir el reporte del último análisis",
        LauncherAction.Help => "Ver la ayuda y los comandos",
        _ => "Salir",
    };

    public static Task<LauncherAction> AskAsync(IAnsiConsole console, bool hasSavedResult, CancellationToken ct) =>
        new SelectionPrompt<LauncherAction>()
            .Title("¿Qué desea hacer? Nada se borra ni se modifica.")
            .UseConverter(a => Markup.Escape(Describe(a)))
            .AddChoices(Options(hasSavedResult))
            .ShowAsync(console, ct);

    public static Task<bool> ConfirmAsync(IAnsiConsole console, string question, CancellationToken ct) =>
        new ConfirmationPrompt(Markup.Escape(question)) { DefaultValue = false, Yes = 's', No = 'n', InvalidChoiceMessage = "[red]Responda s o n.[/]" }.ShowAsync(console, ct);

    /// <summary>Evita que la ventana se cierre antes de poder leer el resultado.</summary>
    public static void WaitForKey()
    {
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[grey]Pulse una tecla para cerrar esta ventana.[/]");
        Console.ReadKey(intercept: true);
    }
}
