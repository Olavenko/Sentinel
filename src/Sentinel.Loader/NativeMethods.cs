using System.Runtime.InteropServices;

namespace Sentinel.Loader;

/// <summary>
/// P/Invoke declarations for process creation and DLL injection.
/// </summary>
internal static partial class NativeMethods
{
    internal const uint PROCESS_ALL_ACCESS = 0x001FFFFF;
    internal const uint CREATE_SUSPENDED = 0x00000004;
    internal const uint MEM_COMMIT = 0x00001000;
    internal const uint MEM_RESERVE = 0x00002000;
    internal const uint MEM_RELEASE = 0x00008000;
    internal const uint PAGE_READWRITE = 0x04;
    internal const uint INFINITE = 0xFFFFFFFF;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct STARTUPINFO
    {
        public int cb;
        public nint lpReserved;
        public nint lpDesktop;
        public nint lpTitle;
        public int dwX, dwY, dwXSize, dwYSize;
        public int dwXCountChars, dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public nint lpReserved2;
        public nint hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public nint hProcess;
        public nint hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateProcessW(
        string? lpApplicationName,
        string lpCommandLine,
        nint lpProcessAttributes,
        nint lpThreadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
        uint dwCreationFlags,
        nint lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial nint VirtualAllocEx(
        nint hProcess, nint lpAddress,
        uint dwSize, uint flAllocationType, uint flProtect);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool VirtualFreeEx(
        nint hProcess, nint lpAddress,
        uint dwSize, uint dwFreeType);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool WriteProcessMemory(
        nint hProcess, nint lpBaseAddress,
        byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial nint CreateRemoteThread(
        nint hProcess, nint lpThreadAttributes,
        uint dwStackSize, nint lpStartAddress,
        nint lpParameter, uint dwCreationFlags,
        out uint lpThreadId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial uint WaitForSingleObject(nint hHandle, uint dwMilliseconds);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetExitCodeThread(nint hThread, out uint lpExitCode);

    [LibraryImport("kernel32.dll")]
    internal static partial uint ResumeThread(nint hThread);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool CloseHandle(nint hObject);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial nint OpenProcess(uint dwDesiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial nint GetModuleHandleA(string lpModuleName);

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial nint GetProcAddress(nint hModule, string lpProcName);
}
