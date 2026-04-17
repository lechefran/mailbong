package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lechefran/mailbin"
)

func TestAppRunWritesDeletedSummariesAndCounts(t *testing.T) {
	buffer := &bytes.Buffer{}
	app := &App{
		Accounts: []ConfiguredAccount{
			{
				Name: "gmail",
				Config: mailbin.Config{
					Email: "one@example.com",
				},
			},
		},
		DefaultAge: 30,
		Output:     buffer,
		Delete: func(ctx context.Context, config mailbin.Config, criteria mailbin.DeleteCriteria) (mailbin.DeleteResult, error) {
			return mailbin.DeleteResult{
				Deleted: []mailbin.MessageSummary{
					{
						Mailbox:    "INBOX",
						ReceivedAt: time.Date(2026, time.April, 1, 8, 0, 0, 0, time.UTC),
						Subject:    "Today message",
						From:       "alerts@example.com",
						To:         "user@example.com",
						UID:        7,
					},
				},
			}, nil
		},
	}

	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	output := buffer.String()
	if !strings.Contains(output, "Today message") {
		t.Fatalf("Run() output = %q, want subject", output)
	}
	if !strings.Contains(output, "deleted 1 emails") {
		t.Fatalf("Run() output = %q, want count", output)
	}
	if !strings.Contains(output, "summary: deleted total=1 emails across accounts=1 (successful=1 failed=0)") {
		t.Fatalf("Run() output = %q, want summary", output)
	}
}

func TestAppRunBuildsCutoffFromCurrentTime(t *testing.T) {
	now := time.Date(2026, time.April, 14, 21, 30, 0, 0, time.UTC)
	var gotCriteria mailbin.DeleteCriteria

	app := &App{
		Accounts: []ConfiguredAccount{
			{
				Name: "gmail",
				Config: mailbin.Config{
					Email: "one@example.com",
				},
			},
		},
		DefaultAge: 90,
		Now: func() time.Time {
			return now
		},
		Output: &bytes.Buffer{},
		Delete: func(ctx context.Context, config mailbin.Config, criteria mailbin.DeleteCriteria) (mailbin.DeleteResult, error) {
			gotCriteria = criteria
			return mailbin.DeleteResult{}, nil
		},
	}

	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	wantCutoff := deleteCutoff(now, 90)
	if !gotCriteria.ReceivedBefore.Equal(wantCutoff) {
		t.Fatalf("Run() cutoff = %v, want %v", gotCriteria.ReceivedBefore, wantCutoff)
	}
}

func TestAppRunHonorsConcurrencyLimit(t *testing.T) {
	started := make(chan string, 2)
	release := make(chan struct{})
	buffer := &bytes.Buffer{}

	app := &App{
		Accounts: []ConfiguredAccount{
			{
				Name: "gmail",
				Config: mailbin.Config{
					Email: "one@example.com",
				},
			},
			{
				Name: "icloud",
				Config: mailbin.Config{
					Email: "two@example.com",
				},
			},
		},
		DefaultAge:  30,
		Concurrency: 1,
		Output:      buffer,
		Delete: func(ctx context.Context, config mailbin.Config, criteria mailbin.DeleteCriteria) (mailbin.DeleteResult, error) {
			started <- config.Email
			<-release
			return mailbin.DeleteResult{}, nil
		},
	}

	errs := make(chan error, 1)
	go func() {
		errs <- app.Run(context.Background())
	}()

	first := <-started
	select {
	case second := <-started:
		t.Fatalf("started accounts = %q and %q, want only one before release", first, second)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)

	second := <-started
	if first == second {
		t.Fatalf("started accounts = %q and %q, want distinct accounts", first, second)
	}

	if err := <-errs; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestAppRunAggregatesFailuresInInputOrder(t *testing.T) {
	buffer := &bytes.Buffer{}
	app := &App{
		Accounts: []ConfiguredAccount{
			{
				Name: "gmail",
				Config: mailbin.Config{
					Email: "one@example.com",
				},
			},
			{
				Name: "icloud",
				Config: mailbin.Config{
					Email: "two@example.com",
				},
			},
		},
		DefaultAge: 30,
		Output:     buffer,
		Delete: func(ctx context.Context, config mailbin.Config, criteria mailbin.DeleteCriteria) (mailbin.DeleteResult, error) {
			if config.Email == "one@example.com" {
				return mailbin.DeleteResult{}, errors.New("first failed")
			}
			return mailbin.DeleteResult{}, errors.New("second failed")
		},
	}

	err := app.Run(context.Background())
	if err == nil {
		t.Fatal("Run() error = nil, want failure")
	}
	if !strings.Contains(err.Error(), "gmail: first failed; icloud: second failed") {
		t.Fatalf("Run() error = %v, want ordered failures", err)
	}
	if buffer.Len() != 0 {
		t.Fatalf("Run() output = %q, want no summary when all failed and nothing deleted", buffer.String())
	}
}

func TestAppRunPreservesPartialDeletesOnFailure(t *testing.T) {
	buffer := &bytes.Buffer{}
	app := &App{
		Accounts: []ConfiguredAccount{
			{
				Name: "gmail",
				Config: mailbin.Config{
					Email: "one@example.com",
				},
			},
		},
		DefaultAge: 30,
		Output:     buffer,
		Delete: func(ctx context.Context, config mailbin.Config, criteria mailbin.DeleteCriteria) (mailbin.DeleteResult, error) {
			return mailbin.DeleteResult{
				Deleted: []mailbin.MessageSummary{
					{Mailbox: "INBOX", Subject: "partial", UID: 42},
				},
				Incomplete: true,
			}, errors.New("delete incomplete")
		},
	}

	err := app.Run(context.Background())
	if err == nil {
		t.Fatal("Run() error = nil, want failure")
	}

	output := buffer.String()
	if !strings.Contains(output, "partial") {
		t.Fatalf("Run() output = %q, want deleted summary", output)
	}
	if !strings.Contains(output, "deleted 1 emails") {
		t.Fatalf("Run() output = %q, want delete count", output)
	}
}

func TestResolvePassword(t *testing.T) {
	testCases := []struct {
		name          string
		input         string
		envValue      string
		interactive   bool
		wantPassword  string
		wantPrompt    string
		wantErrorText string
	}{
		{
			name:         "uses env password",
			envValue:     "env-secret",
			interactive:  false,
			wantPassword: "env-secret",
		},
		{
			name:         "prompts on interactive stdin",
			input:        "typed-secret\n",
			interactive:  true,
			wantPassword: "typed-secret",
			wantPrompt:   "Enter IMAP password: ",
		},
		{
			name:          "errors on non interactive stdin",
			interactive:   false,
			wantErrorText: "MAILBIN_PASSWORD is required",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			prompt := &bytes.Buffer{}
			password, err := resolvePassword(
				strings.NewReader(testCase.input),
				prompt,
				func(string) string { return testCase.envValue },
				testCase.interactive,
			)

			if testCase.wantErrorText != "" {
				if err == nil || !strings.Contains(err.Error(), testCase.wantErrorText) {
					t.Fatalf("resolvePassword() error = %v, want %q", err, testCase.wantErrorText)
				}
				return
			}

			if err != nil {
				t.Fatalf("resolvePassword() error = %v", err)
			}
			if password != testCase.wantPassword {
				t.Fatalf("resolvePassword() password = %q, want %q", password, testCase.wantPassword)
			}
			if prompt.String() != testCase.wantPrompt {
				t.Fatalf("resolvePassword() prompt = %q, want %q", prompt.String(), testCase.wantPrompt)
			}
		})
	}
}

func TestParseCronSchedule(t *testing.T) {
	testCases := []struct {
		name      string
		value     string
		want      CronSchedule
		wantError string
	}{
		{
			name:  "valid all wildcards",
			value: "* * * * *",
			want: CronSchedule{
				Minute:     cronField{Any: true},
				Hour:       cronField{Any: true},
				DayOfMonth: cronField{Any: true},
				Month:      cronField{Any: true},
				DayOfWeek:  cronField{Any: true},
			},
		},
		{
			name:      "invalid field count",
			value:     "0 0 * *",
			wantError: "5 cron fields",
		},
		{
			name:      "invalid minute",
			value:     "60 0 * * *",
			wantError: "minute field",
		},
		{
			name:      "invalid day-of-week",
			value:     "0 0 * * 8",
			wantError: "day-of-week field",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := parseCronSchedule(testCase.value)
			if testCase.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), testCase.wantError) {
					t.Fatalf("parseCronSchedule() error = %v, want %q", err, testCase.wantError)
				}
				return
			}

			if err != nil {
				t.Fatalf("parseCronSchedule() error = %v", err)
			}
			if got.Minute.Any != testCase.want.Minute.Any ||
				got.Hour.Any != testCase.want.Hour.Any ||
				got.DayOfMonth.Any != testCase.want.DayOfMonth.Any ||
				got.Month.Any != testCase.want.Month.Any ||
				got.DayOfWeek.Any != testCase.want.DayOfWeek.Any {
				t.Fatalf("parseCronSchedule() = %+v, want %+v", got, testCase.want)
			}
		})
	}
}

func TestNextCronRun(t *testing.T) {
	location := time.FixedZone("UTC-5", -5*60*60)
	testCases := []struct {
		name       string
		expression string
		now        time.Time
		want       time.Time
	}{
		{
			name:       "daily midnight",
			expression: "0 0 * * *",
			now:        time.Date(2026, time.April, 16, 23, 30, 0, 0, location),
			want:       time.Date(2026, time.April, 17, 0, 0, 0, 0, location),
		},
		{
			name:       "every fifteen minutes",
			expression: "*/15 * * * *",
			now:        time.Date(2026, time.April, 16, 10, 7, 45, 0, location),
			want:       time.Date(2026, time.April, 16, 10, 15, 0, 0, location),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			schedule, err := parseCronSchedule(testCase.expression)
			if err != nil {
				t.Fatalf("parseCronSchedule() error = %v", err)
			}

			got, err := nextCronRun(testCase.now, schedule)
			if err != nil {
				t.Fatalf("nextCronRun() error = %v", err)
			}
			if !got.Equal(testCase.want) {
				t.Fatalf("nextCronRun() = %v, want %v", got, testCase.want)
			}
		})
	}
}
