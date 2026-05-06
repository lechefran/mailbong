package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lechefran/mailbin"
)

const defaultAccountTimeout = 30 * time.Second

func main() {
	app, schedule, err := newAppFromFlags()
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runOnCronSchedule(ctx, app, time.Now, schedule); err != nil {
		log.Fatal(err)
	}
}

func newAppFromFlags() (*App, CronSchedule, error) {
	configPath := flag.String("config", envOrDefault("MAILBIN_CONFIG", ""), "path to app config json file")
	flag.Parse()

	configValue := strings.TrimSpace(*configPath)
	if configValue == "" {
		return nil, CronSchedule{}, fmt.Errorf("config file is required")
	}

	loadedConfig, err := loadConfiguredAccounts(configValue)
	if err != nil {
		return nil, CronSchedule{}, err
	}

	var getEmailAddressesFunc func(context.Context) (EmailsResponse, error)
	if strings.TrimSpace(os.Getenv("GET_ADDR_URL")) != "" {
		getEmailAddressesFunc = getEmailAddresses
	}

	return &App{
		Accounts:          loadedConfig.Accounts,
		GetEmailAddresses: getEmailAddressesFunc,
		DefaultAge:        loadedConfig.Age,
		Now:               time.Now,
		Output:            os.Stdout,
	}, loadedConfig.Schedule, nil
}

func (a *App) Run(ctx context.Context) error {
	criteria, err := a.criteriaForAge(ctx, a.DefaultAge)
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

func runOnCronSchedule(ctx context.Context, app *App, now func() time.Time, schedule CronSchedule) error {
	if app == nil {
		return fmt.Errorf("app is required")
	}

	if now == nil {
		now = time.Now
	}

	for {
		runAt, err := nextCronRun(now(), schedule)
		if err != nil {
			return err
		}
		waitDuration := runAt.Sub(now())
		if waitDuration <= 0 {
			waitDuration = time.Second
		}

		log.Printf("next delete run scheduled at %s", runAt.Format(time.RFC3339))

		timer := time.NewTimer(waitDuration)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}

		if err := app.Run(ctx); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("scheduled delete run failed: %v", err)
			continue
		}

		log.Printf("scheduled delete run completed")
	}
}

func totalDeletedMessages(results []accountDeleteResult) int {
	total := 0
	for _, result := range results {
		total += len(result.Result.Deleted)
	}

	return total
}

func (a *App) criteriaForAge(ctx context.Context, age int) (mailbin.DeleteCriteria, error) {
	if age < 0 {
		return mailbin.DeleteCriteria{}, fmt.Errorf("age is required and must be 0 or greater")
	}

	now := time.Now
	var blacklistFromAccounts []string
	if a != nil && a.Now != nil {
		now = a.Now
	}
	if a != nil && a.GetEmailAddresses != nil {
		getEmailAddressesRes, err := a.GetEmailAddresses(ctx)
		if err != nil {
			return mailbin.DeleteCriteria{}, err
		}
		blacklistFromAccounts = append(blacklistFromAccounts, getEmailAddressesRes.Addresses...)
	}

	return mailbin.DeleteCriteria{
		ReceivedBefore: deleteCutoff(now(), age),
		FromAccounts:   normalizeBlacklistFromAccounts(blacklistFromAccounts),
	}, nil
}

func normalizeBlacklistFromAccounts(accounts []string) []string {
	normalized := make([]string, 0, len(accounts))
	seen := make(map[string]struct{}, len(accounts))
	for _, account := range accounts {
		account = strings.TrimSpace(account)
		if account == "" {
			continue
		}

		key := strings.ToLower(account)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, account)
	}

	return normalized
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

	results := make(chan indexedAccountDeleteResult, len(a.Accounts))

	var wg sync.WaitGroup
	for index, account := range a.Accounts {
		index := index
		account := account

		wg.Add(1)
		go func() {
			defer wg.Done()

			runCtx, cancel := context.WithTimeout(ctx, defaultAccountTimeout)
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

func defaultAccountName(email string) string {
	email = strings.TrimSpace(email)
	if email == "" {
		return "account"
	}

	return email
}

func parseCronSchedule(value string) (CronSchedule, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return CronSchedule{}, fmt.Errorf("cron must be an expression with 5 fields")
	}

	parts := strings.Fields(value)
	if len(parts) != 5 {
		return CronSchedule{}, fmt.Errorf("cron %q must have 5 cron fields", value)
	}

	minute, err := parseCronField(parts[0], 0, 59, false)
	if err != nil {
		return CronSchedule{}, fmt.Errorf("cron minute field: %w", err)
	}
	hour, err := parseCronField(parts[1], 0, 23, false)
	if err != nil {
		return CronSchedule{}, fmt.Errorf("cron hour field: %w", err)
	}
	dayOfMonth, err := parseCronField(parts[2], 1, 31, false)
	if err != nil {
		return CronSchedule{}, fmt.Errorf("cron day-of-month field: %w", err)
	}
	month, err := parseCronField(parts[3], 1, 12, false)
	if err != nil {
		return CronSchedule{}, fmt.Errorf("cron month field: %w", err)
	}
	dayOfWeek, err := parseCronField(parts[4], 0, 7, true)
	if err != nil {
		return CronSchedule{}, fmt.Errorf("cron day-of-week field: %w", err)
	}

	return CronSchedule{
		Minute:     minute,
		Hour:       hour,
		DayOfMonth: dayOfMonth,
		Month:      month,
		DayOfWeek:  dayOfWeek,
	}, nil
}

func parseCronField(value string, min int, max int, allowSevenAlias bool) (cronField, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return cronField{}, fmt.Errorf("field is required")
	}
	if value == "*" {
		return cronField{Any: true}, nil
	}

	field := cronField{Values: make(map[int]struct{})}
	segments := strings.Split(value, ",")
	for _, segment := range segments {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			return cronField{}, fmt.Errorf("invalid empty segment")
		}

		base := segment
		step := 1
		hasStep := false
		if strings.Contains(segment, "/") {
			stepParts := strings.Split(segment, "/")
			if len(stepParts) != 2 || stepParts[0] == "" || stepParts[1] == "" {
				return cronField{}, fmt.Errorf("invalid step segment %q", segment)
			}
			base = stepParts[0]
			parsedStep, err := strconv.Atoi(stepParts[1])
			if err != nil || parsedStep <= 0 {
				return cronField{}, fmt.Errorf("invalid step value in %q", segment)
			}
			step = parsedStep
			hasStep = true
		}

		start := min
		end := max
		switch {
		case base == "*":
		case strings.Contains(base, "-"):
			rangeParts := strings.Split(base, "-")
			if len(rangeParts) != 2 || rangeParts[0] == "" || rangeParts[1] == "" {
				return cronField{}, fmt.Errorf("invalid range %q", base)
			}
			rangeStart, err := strconv.Atoi(rangeParts[0])
			if err != nil {
				return cronField{}, fmt.Errorf("invalid range start %q", rangeParts[0])
			}
			rangeEnd, err := strconv.Atoi(rangeParts[1])
			if err != nil {
				return cronField{}, fmt.Errorf("invalid range end %q", rangeParts[1])
			}
			start = rangeStart
			end = rangeEnd
		default:
			single, err := strconv.Atoi(base)
			if err != nil {
				return cronField{}, fmt.Errorf("invalid value %q", base)
			}
			start = single
			end = single
			if hasStep {
				end = max
			}
		}

		if start < min || start > max {
			return cronField{}, fmt.Errorf("value %d out of range [%d,%d]", start, min, max)
		}
		if end < min || end > max {
			return cronField{}, fmt.Errorf("value %d out of range [%d,%d]", end, min, max)
		}
		if start > end {
			return cronField{}, fmt.Errorf("range start %d is greater than end %d", start, end)
		}

		for item := start; item <= end; item++ {
			if (item-start)%step != 0 {
				continue
			}
			valueToStore := item
			if allowSevenAlias && item == 7 {
				valueToStore = 0
			}
			field.Values[valueToStore] = struct{}{}
		}
	}

	if len(field.Values) == 0 {
		return cronField{}, fmt.Errorf("field has no values")
	}

	return field, nil
}

func nextCronRun(value time.Time, schedule CronSchedule) (time.Time, error) {
	candidate := value.Truncate(time.Minute).Add(time.Minute)
	maxChecks := 5 * 366 * 24 * 60
	for check := 0; check < maxChecks; check++ {
		if schedule.matches(candidate) {
			return candidate, nil
		}
		candidate = candidate.Add(time.Minute)
	}

	return time.Time{}, fmt.Errorf("cron has no matching run time in next 5 years")
}

func (s CronSchedule) matches(value time.Time) bool {
	if !s.Minute.matches(value.Minute()) {
		return false
	}
	if !s.Hour.matches(value.Hour()) {
		return false
	}
	if !s.Month.matches(int(value.Month())) {
		return false
	}

	dayOfMonthMatch := s.DayOfMonth.matches(value.Day())
	dayOfWeekMatch := s.DayOfWeek.matches(int(value.Weekday()))
	switch {
	case s.DayOfMonth.Any && s.DayOfWeek.Any:
		return true
	case s.DayOfMonth.Any:
		return dayOfWeekMatch
	case s.DayOfWeek.Any:
		return dayOfMonthMatch
	default:
		return dayOfMonthMatch || dayOfWeekMatch
	}
}

func (f cronField) matches(value int) bool {
	if f.Any {
		return true
	}
	_, exists := f.Values[value]
	return exists
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

func getEmailAddresses(ctx context.Context) (EmailsResponse, error) {
	url := strings.TrimSpace(os.Getenv("GET_ADDR_URL"))
	if url == "" {
		return EmailsResponse{}, nil
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return EmailsResponse{}, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+os.Getenv("API_KEY"))

	apiRes, err := client.Do(req)
	if err != nil {
		return EmailsResponse{}, err
	}
	defer apiRes.Body.Close()

	if apiRes.StatusCode < 200 || apiRes.StatusCode >= 300 {
		return EmailsResponse{}, fmt.Errorf("get email addresses failed: %s", apiRes.Status)
	}

	var res EmailsResponse
	if err = json.NewDecoder(apiRes.Body).Decode(&res); err != nil {
		return EmailsResponse{}, err
	}
	return res, nil
}
