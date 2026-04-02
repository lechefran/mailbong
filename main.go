package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

type App struct {
	Client      *IMAPClient
	Login       func(context.Context) (SessionWithInboxRead, error)
	Action      string
	Timeout     time.Duration
	Range       string
	Now         func() time.Time
	Output      io.Writer
	PrintEmails func(io.Writer, []EmailSummary) error
}

type InboxReader interface {
	ReadInboxAll() ([]EmailSummary, error)
	ReadInboxToday(time.Time) ([]EmailSummary, error)
	ReadInboxThisWeek(time.Time) ([]EmailSummary, error)
	ReadInboxThisMonth(time.Time) ([]EmailSummary, error)
}

type SessionWithInboxRead interface {
	InboxReader
	DeleteInboxAll() ([]EmailSummary, error)
	DeleteInboxToday(time.Time) ([]EmailSummary, error)
	DeleteInboxThisWeek(time.Time) ([]EmailSummary, error)
	DeleteInboxThisMonth(time.Time) ([]EmailSummary, error)
	Logout() error
}

func (a *App) Run(ctx context.Context) error {
	if a == nil || a.Client == nil {
		return fmt.Errorf("imap client is required")
	}

	timeout := a.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	login := a.Login
	if login == nil {
		login = func(ctx context.Context) (SessionWithInboxRead, error) {
			return a.Client.Login(ctx)
		}
	}

	session, err := login(runCtx)
	if err != nil {
		return err
	}
	defer session.Logout()

	log.Printf("connected to IMAP server %s as %s", a.Client.Address, a.Client.Email)

	emails, err := a.runActionByRange(session)
	if err != nil {
		return err
	}

	output := a.Output
	if output == nil {
		output = os.Stdout
	}

	printEmails := a.PrintEmails
	if printEmails == nil {
		printEmails = writeEmailSummaries
	}
	if err := printEmails(output, emails); err != nil {
		return err
	}
	if a.Action == "delete" {
		if _, err := fmt.Fprintf(output, "deleted %d emails\n", len(emails)); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	app, err := newAppFromFlags()
	if err != nil {
		log.Fatal(err)
	}

	if err := app.Run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func newAppFromFlags() (*App, error) {
	action := flag.String("action", envOrDefault("MAILBIN_ACTION", "read"), "action to perform: read or delete")
	address := flag.String("imap-addr", envOrDefault("MAILBIN_IMAP_ADDR", ""), "IMAP server address in host:port format")
	email := flag.String("email", envOrDefault("MAILBIN_EMAIL", ""), "email address used for IMAP login")
	emailRange := flag.String("range", envOrDefault("MAILBIN_RANGE", "all"), "email range to read: all, today, week, or month")
	timeout := flag.Duration("timeout", 15*time.Second, "connection timeout")
	flag.Parse()

	password, err := resolvePassword(os.Stdin, os.Stderr, os.Getenv, stdinIsInteractive())
	if err != nil {
		return nil, err
	}

	client := &IMAPClient{
		Address:  *address,
		Email:    *email,
		Password: password,
	}

	return &App{
		Client:  client,
		Action:  *action,
		Timeout: *timeout,
		Range:   *emailRange,
		Now:     time.Now,
		Output:  os.Stdout,
	}, nil
}

func resolvePassword(input io.Reader, prompt io.Writer, getenv func(string) string, interactive bool) (string, error) {
	if password := getenv("MAILBIN_PASSWORD"); password != "" {
		return password, nil
	}

	if !interactive {
		return "", fmt.Errorf("MAILBIN_PASSWORD is required when stdin is not interactive")
	}

	if prompt != nil {
		if _, err := fmt.Fprint(prompt, "Enter IMAP password: "); err != nil {
			return "", fmt.Errorf("write password prompt: %w", err)
		}
	}

	reader := bufio.NewReader(input)
	password, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read password: %w", err)
	}

	password = strings.TrimRight(password, "\r\n")
	if password == "" {
		return "", fmt.Errorf("password is required")
	}

	return password, nil
}

func stdinIsInteractive() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}

	return info.Mode()&os.ModeCharDevice != 0
}

func (a *App) runActionByRange(session SessionWithInboxRead) ([]EmailSummary, error) {
	switch a.Action {
	case "", "read":
		return a.readByRange(session)
	case "delete":
		return a.deleteByRange(session)
	default:
		return nil, fmt.Errorf("invalid action %q: must be read or delete", a.Action)
	}
}

func (a *App) readByRange(session InboxReader) ([]EmailSummary, error) {
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}

	switch a.Range {
	case "", "all":
		return session.ReadInboxAll()
	case "today":
		return session.ReadInboxToday(now())
	case "week":
		return session.ReadInboxThisWeek(now())
	case "month":
		return session.ReadInboxThisMonth(now())
	default:
		return nil, fmt.Errorf("invalid range %q: must be one of all, today, week, or month", a.Range)
	}
}

func (a *App) deleteByRange(session SessionWithInboxRead) ([]EmailSummary, error) {
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}

	switch a.Range {
	case "", "all":
		return session.DeleteInboxAll()
	case "today":
		return session.DeleteInboxToday(now())
	case "week":
		return session.DeleteInboxThisWeek(now())
	case "month":
		return session.DeleteInboxThisMonth(now())
	default:
		return nil, fmt.Errorf("invalid range %q: must be one of all, today, week, or month", a.Range)
	}
}

func writeEmailSummaries(output io.Writer, emails []EmailSummary) error {
	for _, email := range emails {
		if _, err := fmt.Fprintf(
			output,
			"%s | mailbox=%s | %s | from=%s | to=%s | uid=%d\n",
			email.ReceivedAt.Format(time.RFC3339),
			email.Mailbox,
			email.Subject,
			email.From,
			email.To,
			email.UID,
		); err != nil {
			return err
		}
	}

	return nil
}

func envOrDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	return value
}
