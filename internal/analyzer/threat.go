package analyzer

import "strings"

func Analyze(input string) (int, string, string) {
	cmd := strings.ToLower(strings.TrimSpace(input))

	switch {
	case strings.Contains(cmd, "password"),
		strings.Contains(cmd, "credentials"),
		strings.Contains(cmd, "secret"):
		return 35, "HIGH", "Sensitive decoy resource accessed"

	case strings.HasPrefix(cmd, "sudo"):
		return 50, "HIGH", "Simulated privilege escalation attempt"

	case strings.HasPrefix(cmd, "rm "),
		strings.HasPrefix(cmd, "wget "),
		strings.HasPrefix(cmd, "curl "):
		return 45, "HIGH", "Potentially dangerous command detected"

	case cmd == "":
		return 0, "LOW", "Empty input"

	default:
		return 0, "LOW", "Normal simulated activity"
	}
}
