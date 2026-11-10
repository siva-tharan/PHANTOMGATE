package logger

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Event struct {
	Time      time.Time `json:"time"`
	Type      string    `json:"type"`
	Input     string    `json:"input"`
	Severity  string    `json:"severity"`
	Score     int       `json:"score"`
	Details   string    `json:"details"`
	VisitorIP string    `json:"visitor_ip"`
	UserAgent string    `json:"user_agent"`
}

type Logger struct {
	mu     sync.Mutex
	file   *os.File
	events []Event
}

func New(path string) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}

	logger := &Logger{
		file: file,
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err == nil {
			logger.events = append(logger.events, event)
		}
	}

	if err := scanner.Err(); err != nil {
		file.Close()
		return nil, err
	}

	return logger, nil
}

func (l *Logger) Record(event Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	if _, err := l.file.Write(append(data, '\n')); err != nil {
		return err
	}

	l.events = append(l.events, event)
	return nil
}

func (l *Logger) List() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()

	events := make([]Event, len(l.events))
	copy(events, l.events)

	return events
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.file.Close()
}
