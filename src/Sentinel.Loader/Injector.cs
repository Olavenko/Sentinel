using System.Runtime.InteropServices;
using System.Text;
using static Sentinel.Loader.NativeMethods;

namespace Sentinel.Loader;

/// <summary>
/// Injects a DLL into a target process using CreateRemoteThread + LoadLibraryA.
/// </summary>
internal static class Injector
{
    /// <summary>
    /// Inject <paramref name="dllPath"/> into the process identified by <paramref name="hProcess"/>.
    /// The DLL path must be an absolute path.
    /// </summary>
    /// <returns>true if injection succeeded.</returns>
    public static bool InjectDll(nint hProcess, string dllPath)
    {
        byte[] pathBytes = Encoding.ASCII.GetBytes(dllPath + '\0');

        // Allocate memory in the target process for the DLL path string
        nint remoteMem = VirtualAllocEx(
            hProcess, 0,
            (uint)pathBytes.Length,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        if (remoteMem == 0)
        {
            Console.Error.WriteLine($"  VirtualAllocEx failed (0x{Marshal.GetLastWin32Error():X8})");
            return false;
        }

        try
        {
            // Write the DLL path into the target process
            if (!WriteProcessMemory(hProcess, remoteMem, pathBytes, (uint)pathBytes.Length, out _))
            {
                Console.Error.WriteLine($"  WriteProcessMemory failed (0x{Marshal.GetLastWin32Error():X8})");
                return false;
            }

            // Resolve LoadLibraryA in kernel32.dll (same address in all processes)
            nint hKernel32 = GetModuleHandleA("kernel32.dll");
            nint pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");

            if (pLoadLibrary == 0)
            {
                Console.Error.WriteLine("  Could not resolve LoadLibraryA");
                return false;
            }

            // Create a remote thread that calls LoadLibraryA(remoteMem)
            nint hThread = CreateRemoteThread(
                hProcess, 0, 0,
                pLoadLibrary, remoteMem,
                0, out _);

            if (hThread == 0)
            {
                Console.Error.WriteLine($"  CreateRemoteThread failed (0x{Marshal.GetLastWin32Error():X8})");
                return false;
            }

            // Wait for LoadLibraryA to complete (10 second timeout)
            WaitForSingleObject(hThread, 10_000);

            GetExitCodeThread(hThread, out uint exitCode);
            CloseHandle(hThread);

            if (exitCode == 0)
            {
                Console.Error.WriteLine("  LoadLibraryA returned NULL — DLL load failed in target process");
                return false;
            }

            return true;
        }
        finally
        {
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        }
    }
}
