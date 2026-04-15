package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lechefran/mailbin"
)

const defaultAccountTimeout = 30 * time.Second

type App struct {
	Accounts    []ConfiguredAccount
	Delete      func(context.Context, mailbin.Config, mailbin.DeleteCriteria) (mailbin.DeleteResult, error)
	Timeout     time.Duration
	Concurrency int
	DefaultAge  int
	Now         func() time.Time
	Output      io.Writer
}

type accountDeleteResult struct {
	AccountName string
	Result      mailbin.DeleteResult
	Err         error
}

type indexedAccountDeleteResult struct {
	Index  int
	Result accountDeleteResult
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
	configPath := flag.String("config", envOrDefault("MAILBIN_CONFIG", ""), "path to accounts config JSON")
	accountName := flag.String("account", envOrDefault("MAILBIN_ACCOUNT", ""), "account name from config to run")
	provider := flag.String("provider", envOrDefault("MAILBIN_PROVIDER", ""), "email provider name for built-in IMAP defaults")
	address := flag.String("imap-addr", envOrDefault("MAILBIN_IMAP_ADDR", ""), "IMAP server address in host:port format")
	email := flag.String("email", envOrDefault("MAILBIN_EMAIL", ""), "email address used for IMAP login")
	ageDefault, err := envIntOrDefault("MAILBIN_AGE", -1)
	if err != nil {
		return nil, err
	}
	age := flag.Int("age", ageDefault, "minimum email age in days to delete")
	concurrencyDefault, err := envIntOrDefault("MAILBIN_CONCURRENCY", 0)
	if err != nil {
		return nil, err
	}
	concurrency := flag.Int("concurrency", concurrencyDefault, "max concurrent account runs (0 = unlimited)")
	timeout := flag.Duration("timeout", defaultAccountTimeout, "connection timeout")
	flag.Parse()

	if *concurrency < 0 {
		return nil, fmt.Errorf("concurrency must be 0 or greater")
	}

	var accounts []ConfiguredAccount
	if *configPath == "" {
		password, err := resolvePassword(os.Stdin, os.Stderr, os.Getenv, stdinIsInteractive())
		if err != nil {
			return nil, err
		}
		addressValue, err := resolveIMAPAddress(*provider, *address)
		if err != nil {
			return nil, err
		}

		accounts = []ConfiguredAccount{
			{
				Name: defaultAccountName(strings.TrimSpace(*email)),
				Config: mailbin.Config{
					Provider: strings.TrimSpace(*provider),
					Address:  addressValue,
					Email:    strings.TrimSpace(*email),
					Password: password,
				},
			},
		}
	} else {
		accounts, err = loadConfiguredAccounts(*configPath, *accountName, os.Stdin, os.Stderr, os.Getenv, stdinIsInteractive())
		if err != nil {
			return nil, err
		}
	}

	return &App{
			Accounts:    accounts,
			Timeout:     *timeout,
			Concurrency: *concurrency,
			DefaultAge:  *age,
			Now:         time.Now,
			Output:      os.Stdout,
		}, nil
}

func (a *App) Run(ctx context.Context) error {
	criteria, err := a.criteriaForAge(a.DefaultAge)
	if err != nil {
		return err
	}

	results, err := a.runDelete(ctx, criteria)
	if err != nil && totalDeletedMessages(results) == 0 {
		return err
	}

	output := a.Output
	if output == nil {
		output = os.Stdout
	}
	if writeErr := writeDeleteOutput(output, results); writeErr != nil {
		return writeErr
	}

	return err
}

func totalDeletedMessages(results []accountDeleteResult) int {
	total := 0
	for _, result := range results {
		total += len(result.Result.Deleted)
	}

	return total
}

func (a *App) criteriaForAge(age int) (mailbin.DeleteCriteria, error) {
	if age < 0 {
		return mailbin.DeleteCriteria{}, fmt.Errorf("age is required and must be 0 or greater")
	}

	now := time.Now
	if a != nil && a.Now != nil {
		now = a.Now
	}

	return mailbin.DeleteCriteria{
		ReceivedBefore: deleteCutoff(now(), age),
	}, nil
}

func (a *App) runDelete(ctx context.Context, criteria mailbin.DeleteCriteria) ([]accountDeleteResult, error) {
	if a == nil {
		return nil, fmt.Errorf("app is required")
	}
	if len(a.Accounts) == 0 {
		return nil, fmt.Errorf("at least one account is required")
	}
	if criteria.ReceivedBefore.IsZero() {
		return nil, fmt.Errorf("received-before cutoff is required")
	}

	deleteAccount := a.Delete
	if deleteAccount == nil {
		deleteAccount = deleteWithClient
	}

	timeout := a.Timeout
	if timeout <= 0 {
		timeout = defaultAccountTimeout
	}

	results := make(chan indexedAccountDeleteResult, len(a.Accounts))
	var sem chan struct{}
	if a.Concurrency > 0 {
		sem = make(chan struct{}, a.Concurrency)
	}

	var wg sync.WaitGroup
	for index, account := range a.Accounts {
		index := index
		account := account

		wg.Add(1)
		go func() {
			defer wg.Done()
			if sem != nil {
				sem <- struct{}{}
				defer func() {
					<-sem
				}()
			}

			runCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			result, err := deleteAccount(runCtx, account.Config, criteria)
			results <- indexedAccountDeleteResult{
				Index: index,
				Result: accountDeleteResult{
					AccountName: account.Name,
					Result:      result,
					Err:         err,
				},
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	collected := make([]accountDeleteResult, len(a.Accounts))
	for result := range results {
		collected[result.Index] = result.Result
	}

	totalDeleted := 0
	failures := make([]string, 0, len(collected))
	for _, result := range collected {
		totalDeleted += len(result.Result.Deleted)
		if result.Err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", result.AccountName, result.Err))
		}
	}

	if totalDeleted == 0 && len(failures) > 0 {
		return collected, fmt.Errorf("%d account(s) failed: %s", len(failures), strings.Join(failures, "; "))
	}

	if len(failures) > 0 {
		return collected, fmt.Errorf("%d account(s) failed: %s", len(failures), strings.Join(failures, "; "))
	}

	return collected, nil
}

func deleteWithClient(ctx context.Context, config mailbin.Config, criteria mailbin.DeleteCriteria) (mailbin.DeleteResult, error) {
	if config.Logf == nil {
		config.Logf = log.Printf
	}

	client, err := mailbin.NewClient(config)
	if err != nil {
		return mailbin.DeleteResult{}, err
	}

	return client.Delete(ctx, criteria)
}

func writeDeleteOutput(output io.Writer, results []accountDeleteResult) error {
	if len(results) == 0 {
		return nil
	}

	totalDeleted := 0
	multipleAccounts := len(results) > 1
	for _, result := range results {
		totalDeleted += len(result.Result.Deleted)
		if err := writeMessageSummaries(output, result.AccountName, multipleAccounts, result.Result.Deleted); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(output, "deleted %d emails\n", totalDeleted); err != nil {
		return err
	}

	_, err := fmt.Fprintf(
		output,
		"summary: deleted total=%d emails across accounts=%d (successful=%d failed=%d)\n",
		totalDeleted,
		len(results),
		successfulAccountCount(results),
		failedAccountCount(results),
	)
	return err
}

func writeMessageSummaries(output io.Writer, accountName string, includeAccount bool, summaries []mailbin.MessageSummary) error {
	for _, summary := range summaries {
		accountPrefix := ""
		if includeAccount {
			accountPrefix = fmt.Sprintf("account=%s | ", accountName)
		}
		receivedAt := "unknown-time"
		if !summary.ReceivedAt.IsZero() {
			receivedAt = summary.ReceivedAt.Format(time.RFC3339)
		}
		subject := summary.Subject
		if subject == "" {
			subject = "-"
		}
		from := summary.From
		if from == "" {
			from = "-"
		}
		to := summary.To
		if to == "" {
			to = "-"
		}
		if _, err := fmt.Fprintf(
			output,
			"%s | %smailbox=%s | %s | from=%s | to=%s | uid=%d\n",
			receivedAt,
			accountPrefix,
			summary.Mailbox,
			subject,
			from,
			to,
			summary.UID,
		); err != nil {
			return err
		}
	}

	return nil
}

func successfulAccountCount(results []accountDeleteResult) int {
	successful := 0
	for _, result := range results {
		if result.Err == nil {
			successful++
		}
	}

	return successful
}

func failedAccountCount(results []accountDeleteResult) int {
	failed := 0
	for _, result := range results {
		if result.Err != nil {
			failed++
		}
	}

	return failed
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

func defaultAccountName(email string) string {
	email = strings.TrimSpace(email)
	if email == "" {
		return "account"
	}

	return email
}

func deleteCutoff(now time.Time, age int) time.Time {
	return startOfDay(now.AddDate(0, 0, -age)).AddDate(0, 0, 1)
}

func startOfDay(value time.Time) time.Time {
	year, month, day := value.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, value.Location())
}

func envOrDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	return value
}

func envIntOrDefault(key string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", key, err)
	}

	return parsed, nil
}
