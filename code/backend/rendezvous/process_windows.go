//go:build windows

package rendezvous

import "golang.org/x/sys/windows"

func processAlive(pid int) bool {
	const stillActive = 259
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	var exitCode uint32
	return windows.GetExitCodeProcess(handle, &exitCode) == nil && exitCode == stillActive
}
