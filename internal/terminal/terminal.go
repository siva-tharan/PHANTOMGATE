package terminal

import "strings"

func Run(input string) string {
	cmd := strings.TrimSpace(strings.ToLower(input))

	switch cmd {
	case "":
		return "Please enter a command."

	case "help":
		return "Available commands:\nhelp\nwhoami\npwd\nls\ncat readme.txt\nuname -a\nclear\nexit"

	case "whoami":
		return "guest@phantomgate"

	case "pwd":
		return "/home/guest"

	case "ls":
		return "readme.txt\ncredentials.txt\npasswords.txt\nsystem.log"

	case "cat readme.txt":
		return "PHANTOMGATE DECEPTION ENVIRONMENT\nThis is a simulated system."

	case "cat credentials.txt", "cat passwords.txt":
		return "ACCESS DENIED: Sensitive decoy resource detected."

	case "uname -a":
		return "Linux phantom-node 6.1.0 x86_64 GNU/Linux [SIMULATED]"

	case "clear":
		return "__CLEAR__"

	case "exit":
		return "Session closed. This was a simulation."

	default:
		if strings.HasPrefix(cmd, "sudo") ||
			strings.HasPrefix(cmd, "rm ") ||
			strings.HasPrefix(cmd, "wget ") ||
			strings.HasPrefix(cmd, "curl ") {
			return "BLOCKED: Simulated security policy alert."
		}

		return "Command not found: " + input + "\nType 'help' for available commands."
	}
}
