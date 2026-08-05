package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lechefran/mailbin"
)

func testMailConfig(email string) mailbin.Config {
	return mailbin.Config{
		Address:  "imap.example.com:993",
		Email:    email,
		Password: "secret",
	}
}

func TestAppRunWritesDeleteSummary(t *testing.T) {
	buffer := &bytes.Buffer{}
	app := &App{
		Accounts: []ConfiguredAccount{
			{
				Name:   "gmail",
				Config: testMailConfig("one@example.com"),
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

	want := "summary: deleted total=1 emails across accounts=1 (successful=1 failed=0)\n"
	if got := buffer.String(); got != want {
		t.Fatalf("Run() output = %q, want %q", got, want)
	}
}

func TestAppRunRejectsNilApp(t *testing.T) {
	var app *App
	if err := app.Run(context.Background()); err == nil || err.Error() != "app is required" {
		t.Fatalf("Run() error = %v, want app is required", err)
	}
}

func TestAppRunBuildsCutoffFromCurrentTime(t *testing.T) {
	now := time.Date(2026, time.April, 14, 21, 30, 0, 0, time.UTC)
	var gotCriteria mailbin.DeleteCriteria

	app := &App{
		Accounts: []ConfiguredAccount{
			{
				Name:   "gmail",
				Config: testMailConfig("one@example.com"),
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

func TestAppRunMapsFetchedBlacklistToCriteriaFromAccounts(t *testing.T) {
	var gotCriteria mailbin.DeleteCriteria

	app := &App{
		Accounts: []ConfiguredAccount{
			{
				Name:   "gmail",
				Config: testMailConfig("one@example.com"),
			},
		},
		GetEmailAddresses: func(ctx context.Context) (EmailsResponse, error) {
			return EmailsResponse{
				Addresses: []string{
					" fetched@example.com ",
					"BLOCKED@example.com",
					"blocked@example.com",
				},
			}, nil
		},
		DefaultAge: 30,
		Output:     &bytes.Buffer{},
		Delete: func(ctx context.Context, config mailbin.Config, criteria mailbin.DeleteCriteria) (mailbin.DeleteResult, error) {
			gotCriteria = criteria
			return mailbin.DeleteResult{}, nil
		},
	}

	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	want := []string{"fetched@example.com", "BLOCKED@example.com"}
	if !slices.Equal(gotCriteria.FromAccounts, want) {
		t.Fatalf("Run() FromAccounts = %#v, want %#v", gotCriteria.FromAccounts, want)
	}
}

func TestAppRunAggregatesFailuresInInputOrder(t *testing.T) {
	buffer := &bytes.Buffer{}
	app := &App{
		Accounts: []ConfiguredAccount{
			{
				Name:   "gmail",
				Config: testMailConfig("one@example.com"),
			},
			{
				Name:   "icloud",
				Config: testMailConfig("two@example.com"),
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
				Name:   "gmail",
				Config: testMailConfig("one@example.com"),
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

	want := "summary: deleted total=1 emails across accounts=1 (successful=0 failed=1)\n"
	if got := buffer.String(); got != want {
		t.Fatalf("Run() output = %q, want %q", got, want)
	}
}

func TestGetEmailAddressesSendsHeadersAndDecodesAddresses(t *testing.T) {
	const apiKey = "test-api-key"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("request method = %s, want GET", r.Method)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Fatalf("Accept header = %q, want application/json", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+apiKey {
			t.Fatalf("Authorization header = %q, want bearer token", got)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"addresses":["one@example.com","two@example.com"]}`))
	}))
	defer server.Close()

	got, err := getEmailAddresses(context.Background(), server.URL, apiKey)
	if err != nil {
		t.Fatalf("getEmailAddresses() error = %v", err)
	}

	want := []string{"one@example.com", "two@example.com"}
	if !slices.Equal(got.Addresses, want) {
		t.Fatalf("getEmailAddresses() addresses = %#v, want %#v", got.Addresses, want)
	}
}

func TestGetEmailAddressesReturnsErrors(t *testing.T) {
	testCases := []struct {
		name          string
		status        int
		body          string
		wantErrorText string
	}{
		{
			name:          "non success status",
			status:        http.StatusUnauthorized,
			body:          `{"error":"unauthorized"}`,
			wantErrorText: "401 Unauthorized",
		},
		{
			name:          "invalid json",
			status:        http.StatusOK,
			body:          `{`,
			wantErrorText: "unexpected EOF",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(testCase.status)
				_, _ = w.Write([]byte(testCase.body))
			}))
			defer server.Close()

			_, err := getEmailAddresses(context.Background(), server.URL, "test-api-key")
			if err == nil || !strings.Contains(err.Error(), testCase.wantErrorText) {
				t.Fatalf("getEmailAddresses() error = %v, want %q", err, testCase.wantErrorText)
			}
		})
	}
}

func TestGetEmailAddressesHonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := getEmailAddresses(ctx, "https://example.com", "test-api-key")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("getEmailAddresses() error = %v, want context cancellation", err)
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
