package main

import (
	"context"
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
	Accounts    []ConfiguredAccount
	Login       func(context.Context, *IMAPClient) (SessionWithInboxRead, error)
	Action      string
	Timeout     time.Duration
	Range       string
	Now         func() time.Time
	Output      io.Writer
	PrintEmails func(io.Writer, []EmailSummary) error
}

type ConfiguredAccount struct {
	Name   string
	Client *IMAPClient
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
	if a == nil {
		return fmt.Errorf("app is required")
	}

	accounts, err := a.resolveAccounts()
	if err != nil {
		return err
	}

	timeout := a.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	login := a.Login
	if login == nil {
		login = func(ctx context.Context, client *IMAPClient) (SessionWithInboxRead, error) {
			return client.Login(ctx)
		}
	}

	output := a.Output
	if output == nil {
		output = os.Stdout
	}

	printEmails := a.PrintEmails
	if printEmails == nil {
		printEmails = writeEmailSummaries
	}

	var failures []string
	for index, account := range accounts {
		runCtx, cancel := context.WithTimeout(ctx, timeout)
		session, err := login(runCtx, account.Client)
		cancel()
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", account.Name, err))
			continue
		}

		log.Printf("connected to IMAP server %s as %s", account.Client.Address, account.Client.Email)

		if len(accounts) > 1 {
			if index > 0 {
				if _, err := fmt.Fprintln(output); err != nil {
					_ = session.Logout()
					return err
				}
			}
			if _, err := fmt.Fprintf(output, "account=%s email=%s\n", account.Name, account.Client.Email); err != nil {
				_ = session.Logout()
				return err
			}
		}

		emails, err := a.runActionByRange(session)
		logoutErr := session.Logout()
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", account.Name, err))
			continue
		}
		if logoutErr != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", account.Name, logoutErr))
			continue
		}

		if err := printEmails(output, emails); err != nil {
			return err
		}
		if err := writeActionSummary(output, a.Action, len(emails)); err != nil {
			return err
		}
	}

	if len(failures) > 0 {
		return fmt.Errorf("%d account(s) failed: %s", len(failures), strings.Join(failures, "; "))
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
	configPath := flag.String("config", envOrDefault("MAILBIN_CONFIG", ""), "path to accounts config JSON")
	accountName := flag.String("account", envOrDefault("MAILBIN_ACCOUNT", ""), "account name from config to run")
	provider := flag.String("provider", envOrDefault("MAILBIN_PROVIDER", ""), "email provider name for built-in IMAP defaults")
	address := flag.String("imap-addr", envOrDefault("MAILBIN_IMAP_ADDR", ""), "IMAP server address in host:port format")
	email := flag.String("email", envOrDefault("MAILBIN_EMAIL", ""), "email address used for IMAP login")
	emailRange := flag.String("range", envOrDefault("MAILBIN_RANGE", "all"), "email range to read: all, today, week, or month")
	timeout := flag.Duration("timeout", 15*time.Second, "connection timeout")
	flag.Parse()

	if *configPath == "" {
		password, err := resolvePassword(os.Stdin, os.Stderr, os.Getenv, stdinIsInteractive())
		if err != nil {
			return nil, err
		}
		addressValue, err := resolveIMAPAddress(*provider, *address)
		if err != nil {
			return nil, err
		}

		client := &IMAPClient{
			Address:  addressValue,
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

	accounts, err := loadConfiguredAccounts(*configPath, *accountName, os.Stdin, os.Stderr, os.Getenv, stdinIsInteractive())
	if err != nil {
		return nil, err
	}

	return &App{
		Accounts: accounts,
		Action:   *action,
		Timeout:  *timeout,
		Range:    *emailRange,
		Now:      time.Now,
		Output:   os.Stdout,
	}, nil
}

func resolvePassword(input io.Reader, prompt io.Writer, getenv func(string) string, interactive bool) (string, error) {
	if password := getenv("MAILBIN_PASSWORD"); password != "" {
		return password, nil
	}

	if !interactive {
		return "", fmt.Errorf("MAILBIN_PASSWORD is required when stdin is not interactive")
	}

	return promptPassword(input, prompt, "Enter IMAP password: ")
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

func (a *App) resolveAccounts() ([]ConfiguredAccount, error) {
	if len(a.Accounts) > 0 {
		return a.Accounts, nil
	}
	if a.Client != nil {
		return []ConfiguredAccount{
			{
				Name:   defaultAccountName(a.Client.Email),
				Client: a.Client,
			},
		}, nil
	}

	return nil, fmt.Errorf("at least one account is required")
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

func writeActionSummary(output io.Writer, action string, count int) error {
	switch action {
	case "", "read":
		_, err := fmt.Fprintf(output, "retrieved %d emails\n", count)
		return err
	case "delete":
		_, err := fmt.Fprintf(output, "deleted %d emails\n", count)
		return err
	default:
		return fmt.Errorf("invalid action %q: must be read or delete", action)
	}
}

func defaultAccountName(email string) string {
	if email == "" {
		return "account"
	}

	return email
}

func envOrDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	return value
}
