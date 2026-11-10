
async function postJSON(url, data) {
    const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
    });

    const result = await response.json();

    if (!response.ok) {
        throw new Error(result.error || "Request failed");
    }

    return result;
}

// TERMINAL

function addTerminalLine(text, className = "") {
    const output = document.getElementById("terminal-output");
    if (!output) return;

    const line = document.createElement("p");
    line.textContent = text;

    if (className) line.className = className;

    output.appendChild(line);
    output.scrollTop = output.scrollHeight;
}

async function setupTerminal() {
    const form = document.getElementById("command-form");
    const input = document.getElementById("command-input");

    if (!form || !input) return;

    form.addEventListener("submit", async (event) => {
        event.preventDefault();

        const command = input.value.trim();
        if (!command) return;

        addTerminalLine("guest@phantomgate:~$ " + command, "command-line");
        input.value = "";

        try {
            const result = await postJSON("/api/command", {
                input: command
            });

            if (result.output === "__CLEAR__") {
                document.getElementById("terminal-output").replaceChildren();
            } else {
                addTerminalLine(result.output);
            }

            if (result.score > 0) {
                addTerminalLine(
                    `[${result.severity}] Threat score: ${result.score} — ${result.details}`,
                    "alert-line"
                );
            }
        } catch (error) {
            addTerminalLine("ERROR: " + error.message, "alert-line");
        }

        input.focus();
    });

    input.focus();
}

// FILE EXPLORER

async function setupExplorer() {
    const list = document.getElementById("file-list");
    const preview = document.getElementById("file-preview");

    if (!list || !preview) return;

    try {
        const response = await fetch("/api/files");

        if (!response.ok) {
            throw new Error("Unable to load files");
        }

        const files = await response.json();
        list.replaceChildren();

        files.forEach((file) => {
            const button = document.createElement("button");

            button.type = "button";
            button.className = "file-item";
            button.textContent =
                `${file.name} | ${file.size} | ${file.type}`;

            button.addEventListener("click", async () => {
                preview.textContent = "Loading...";

                try {
                    const result = await postJSON("/api/file/read", {
                        name: file.name
                    });

                    preview.textContent = result.content;
                } catch (error) {
                    preview.textContent = error.message;
                }
            });

            list.appendChild(button);
        });

    } catch (error) {
        list.textContent = error.message;
    }
}

// DECOY LOGIN

async function setupLogin() {
    const form = document.getElementById("login-form");
    const username = document.getElementById("username");
    const resultBox = document.getElementById("login-result");

    if (!form || !username || !resultBox) return;

    form.addEventListener("submit", async (event) => {
        event.preventDefault();

        try {
            const result = await postJSON("/api/login", {
                input: username.value.trim()
            });

            resultBox.textContent = result.message;
            resultBox.className = "result alert-line";
            username.value = "";

        } catch (error) {
            resultBox.textContent = error.message;
            resultBox.className = "result alert-line";
        }
    });
}

// INVESTIGATION

function addCell(row, value, className = "") {
    const cell = document.createElement("td");
    cell.textContent = value ?? "-";

    if (className) {
        cell.className = className;
    }

    row.appendChild(cell);
}

async function loadEvents() {
    const body =
        document.getElementById("event-list") ||
        document.getElementById("events-body");

    const status = document.getElementById("event-status");

    if (!body) return;

    body.replaceChildren();

    try {
        const response = await fetch("/api/events");

        if (!response.ok) {
            throw new Error("Unable to load events");
        }

        const events = await response.json();

        if (!events || events.length === 0) {
            const row = document.createElement("tr");
            const cell = document.createElement("td");

            cell.colSpan = 8;
            cell.textContent = "No activity recorded yet.";

            row.appendChild(cell);
            body.appendChild(row);

            if (status) status.textContent = "No interactions recorded.";
            return;
        }

        [...events].reverse().forEach((event) => {
            const row = document.createElement("tr");

            addCell(
                row,
                event.time ? new Date(event.time).toLocaleString() : "-"
            );

            addCell(row, event.visitor_ip);
            addCell(row, event.type);
            addCell(row, event.input);
            addCell(row, event.user_agent);

            addCell(
                row,
                event.severity,
                String(event.severity || "").toLowerCase()
            );

            addCell(row, String(event.score));
            addCell(row, event.details);

            body.appendChild(row);
        });

        if (status) {
            status.textContent =
                "Total recorded interactions: " + events.length;
        }

    } catch (error) {
        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 8;
        cell.textContent = error.message;

        row.appendChild(cell);
        body.appendChild(row);

        if (status) status.textContent = error.message;
    }
}

// PAGE INITIALIZATION

document.addEventListener("DOMContentLoaded", () => {
    const page = document.body.dataset.page;

    if (page === "terminal") {
        setupTerminal();
    }

    if (page === "explorer") {
        setupExplorer();
    }

    if (page === "login") {
        setupLogin();
    }

    if (page === "investigation") {
        loadEvents();

        const refreshButton =
            document.getElementById("refresh-events");

        if (refreshButton) {
            refreshButton.addEventListener("click", loadEvents);
        }

        setInterval(loadEvents, 10000);
    }
});
