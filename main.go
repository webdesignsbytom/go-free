package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// List of known adware filenames to search for
var threatActors = []string{
	"adwarefile1.exe", // Replace with actual known adware filenames
	"adwarefile2.dll", // Placeholder, change to real filenames
	"unwanted_toolbar.exe",
}

// Whitelist of good files or directories to ignore
var whitelistFiles = []string{
	"C:\\Windows",                         // Whitelist the entire Windows directory
	"C:\\Program Files",                   // Whitelist Program Files
	"C:\\Program Files (x86)",             // Whitelist Program Files (x86)
	"C:\\Windows\\System32",               // Whitelist the System32 folder
	"C:\\Windows\\SysWOW64",               // Whitelist SysWOW64 on 64-bit systems
	"C:\\Windows\\explorer.exe",           // Whitelist critical executables
	"C:\\Windows\\System32\\svchost.exe",  // Critical service host process
	"C:\\Windows\\System32\\lsass.exe",    // Security subsystem service
	"C:\\Windows\\System32\\csrss.exe",    // Client/Server runtime process
	"C:\\Windows\\System32\\cmd.exe",      // Command prompt
	"C:\\Windows\\System32\\taskmgr.exe",  // Task Manager
	"C:\\Windows\\System32\\dwm.exe",      // Desktop Window Manager
	"C:\\Windows\\System32\\services.exe", // Services management
	"C:\\Windows\\System32\\winlogon.exe", // Login process manager
	"C:\\Windows\\System32\\kernel32.dll", // Core Windows API
	"C:\\Windows\\System32\\user32.dll",   // User interface elements
	"C:\\Windows\\System32\\gdi32.dll",    // Graphics interface DLL
	"C:\\Windows\\System32\\ntdll.dll",    // NT Kernel
	"C:\\Windows\\System32\\shell32.dll",  // Windows shell API
	"C:\\Windows\\System32\\advapi32.dll", // Advanced Windows API
}

// isAdwareFile checks whether a file's name matches any of the known adware filenames
func isAdwareFile(filename string) bool {
	for _, threatActor := range threatActors {
		if filepath.Base(filename) == threatActor {
			return true
		}
	}
	return false
}

// isWhitelisted checks if a file or directory is part of the whitelist
func isWhitelisted(path string) bool {
	for _, whitelistPath := range whitelistFiles {
		if filepath.HasPrefix(path, whitelistPath) {
			return true
		}
	}
	return false
}

func getWhitelist() []string {
	return whitelistFiles
}

func getKnownThreatActors() []string {
	return threatActors
}

// isHiddenFile checks if a file is hidden based on its attributes on Windows
func isHiddenFile(info os.FileInfo) bool {
	attr := info.Sys().(*syscall.Win32FileAttributeData).FileAttributes
	return attr&syscall.FILE_ATTRIBUTE_HIDDEN != 0
}

// scanDirectory searches a directory for hidden files that match the known adware files
func scanDirectory(directoryPath string, onlyHidden bool) string {
	var result string

	err := filepath.Walk(directoryPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			result += fmt.Sprintf("Error accessing path %q: %v\n", path, err)
			return err
		}

		// Skip whitelisted paths
		if isWhitelisted(path) {
			result += fmt.Sprintf("Skipping whitelisted path: %s\n", path)
			return nil
		}

		// If we are searching only hidden files, skip files that aren't hidden
		if onlyHidden && !isHiddenFile(info) {
			return nil
		}

		// Check if it's not a directory and if it's a known adware file
		if !info.IsDir() && isAdwareFile(info.Name()) {
			result += fmt.Sprintf("Adware found: %s\n", path)
		}

		return nil
	})

	if err != nil {
		result += fmt.Sprintf("Error scanning directory %s: %v\n", directoryPath, err)
	}

	return result
}

// startScan is the function that gets called when the "Start Scan" button is pressed
func startScan() string {
	directoriesToScan := []string{
		`C:\Program Files (x86)`,
		`C:\ProgramData`,
		`C:\Users\<your_username>\AppData\Local`,   // Replace <your_username> with your actual Windows username
		`C:\Users\<your_username>\AppData\Roaming`, // Replace <your_username> with your actual Windows username
	}

	onlyHidden := true // Set to true to search for hidden files, false to search all files
	var scanResults string

	// Scan each directory and collect results
	for _, directory := range directoriesToScan {
		scanResults += fmt.Sprintf("Scanning directory: %s\n", directory)
		scanResults += scanDirectory(directory, onlyHidden)
	}

	scanResults += "Scan complete.\n"
	return scanResults
}

func main() {
	// Create the Fyne app
	myApp := app.New()
	myWindow := myApp.NewWindow("Simple Adware Scanner")

	// Create a label to display scan results
	scanResultsLabel := widget.NewLabel("")

	// Create a button to start the scan
	startButton := widget.NewButton("Start Scan", func() {
		// When the button is pressed, start the scan and display results in the label
		scanResultsLabel.SetText(startScan())
	})

	whiteListButton := widget.NewButton("Whitelist", func() {
		scanResultsLabel.SetText("ello")
	})

	// Create a simple layout with the button and the label
	content := container.NewVBox(
		startButton,
		scanResultsLabel,
		whiteListButton,
	)

	// Set the content and show the window
	myWindow.SetContent(content)
	myWindow.Resize(fyne.NewSize(400, 300)) // Set window size
	myWindow.ShowAndRun()
}
