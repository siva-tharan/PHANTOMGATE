package deception

type File struct {
	Name string `json:"name"`
	Size string `json:"size"`
	Type string `json:"type"`
}

func Files() []File {
	return []File{
		{Name: "readme.txt", Size: "1 KB", Type: "TEXT"},
		{Name: "credentials.txt", Size: "2 KB", Type: "DECOY"},
		{Name: "passwords.txt", Size: "3 KB", Type: "DECOY"},
		{Name: "system.log", Size: "4 KB", Type: "LOG"},
	}
}

func Read(name string) (string, bool) {
	switch name {
	case "readme.txt":
		return "PHANTOMGATE SIMULATED ENVIRONMENT\nThis system contains decoy resources for cybersecurity research.", true

	case "credentials.txt", "passwords.txt":
		return "ACCESS DENIED: Decoy sensitive resource access recorded.", true

	case "system.log":
		return "System initialized.\nMonitoring enabled.\nEnvironment: SIMULATED", true

	default:
		return "", false
	}
}
