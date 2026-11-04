using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace WinStorageAudit.Infrastructure.Native;

internal static class NativeMethods
{
    public const int ErrorFileNotFound = 2;
    public const int ErrorPathNotFound = 3;
    public const int ErrorAccessDenied = 5;
    public const int ErrorNoMoreFiles = 18;
    public const int ErrorSharingViolation = 32;
    public const int ErrorFilenameExcedRange = 206;

    public const uint FileAttributeDirectory = 0x10;
    public const uint FileAttributeReparsePoint = 0x400;
    public const uint FileAttributeSparse = 0x200;
    public const uint FileAttributeCompressed = 0x800;
    public const uint FileAttributeOffline = 0x1000;
    public const uint FileAttributeRecallOnOpen = 0x40000;
    public const uint FileAttributeRecallOnDataAccess = 0x400000;

    public const uint OnlineOnlyMask = FileAttributeOffline | FileAttributeRecallOnOpen | FileAttributeRecallOnDataAccess;

    public const uint ReparseTagMountPoint = 0xA0000003;
    public const uint ReparseTagSymlink = 0xA000000C;
    public const uint ReparseTagNameSurrogateBit = 0x20000000;
    public const uint ReparseTagCloudBase = 0x9000001A;
    public const uint ReparseTagCloudMask = 0xFFFF0FFF;

    public const int FindExInfoBasic = 1;
    public const int FindExSearchNameMatch = 0;
    public const int FindFirstExLargeFetch = 2;

    public const uint FileReadAttributes = 0x80;
    public const uint FileShareAll = 0x7;
    public const uint OpenExisting = 3;
    public const uint FileFlagBackupSemantics = 0x02000000;
    public const uint FileFlagOpenReparsePoint = 0x00200000;
    public const uint FileFlagOpenNoRecall = 0x00100000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct Win32FindData
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint Reserved0;
        public uint Reserved1;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string FileName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string AlternateFileName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct ShQueryRbInfo
    {
        public int Size;
        public long SizeBytes;
        public long NumItems;
    }

    public sealed class SafeFindHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeFindHandle() : base(true) { }
        protected override bool ReleaseHandle() => FindClose(handle);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "FindFirstFileExW")]
    public static extern SafeFindHandle FindFirstFileEx(string fileName, int infoLevel, out Win32FindData data, int searchOp, IntPtr searchFilter, int additionalFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "FindNextFileW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool FindNextFile(SafeFindHandle handle, out Win32FindData data);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool FindClose(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetCompressedFileSizeW")]
    public static extern uint GetCompressedFileSize(string fileName, out uint fileSizeHigh);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    public static extern SafeFileHandle CreateFile(string fileName, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetFileInformationByHandle(SafeFileHandle handle, out ByHandleFileInformation info);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetDiskFreeSpaceW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetDiskFreeSpace(string root, out uint sectorsPerCluster, out uint bytesPerSector, out uint freeClusters, out uint totalClusters);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, EntryPoint = "SHQueryRecycleBinW")]
    public static extern int SHQueryRecycleBin(string? rootPath, ref ShQueryRbInfo info);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    public static extern int SHGetKnownFolderPath([MarshalAs(UnmanagedType.LPStruct)] Guid folderId, uint flags, IntPtr token, out IntPtr path);

    public static string ToLongPath(string path)
    {
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) return path;
        if (path.StartsWith(@"\\", StringComparison.Ordinal)) return @"\\?\UNC\" + path[2..];
        return @"\\?\" + path;
    }

    public static DateTime ToUtc(System.Runtime.InteropServices.ComTypes.FILETIME ft)
    {
        var ticks = ((long)(uint)ft.dwHighDateTime << 32) | (uint)ft.dwLowDateTime;
        if (ticks <= 0 || ticks >= DateTime.MaxValue.Ticks - 504911232000000000L) return DateTime.MinValue;
        return DateTime.FromFileTimeUtc(ticks);
    }
}
