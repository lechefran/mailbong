package main

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lechefran/mailban"
	"github.com/lechefran/mailbin"
)

func TestBlacklistFromAccountsAddsHighScoringMailbanSenders(t *testing.T) {
	output := &bytes.Buffer{}
	var gotConfig mailban.Config

	app := &App{
		Accounts: []ConfiguredAccount{
			{
				Name: "gmail",
				Config: mailbin.Config{
					Address:  "imap.gmail.example:993",
					Email:    "one@example.com",
					Password: "secret",
				},
			},
		},
		BlacklistFromAccounts: []string{"manual@example.com", "blocked@example.com"},
		Timeout:               5 * time.Second,
		Output:                output,
		AssessSenders: func(ctx context.Context, config mailban.Config) ([]mailban.SenderAssessment, error) {
			gotConfig = config
			return []mailban.SenderAssessment{
				{Address: "safe@example.com", Score: 0},
				{Address: " blocked@example.com ", Score: 60, Reasons: []string{"spamhaus dbl: abused legit domain"}},
				{Address: "suspicious@example.com", Score: 79, Reasons: []string{" stopforumspam: moderate confidence ", ""}},
				{Address: "phish@example.com", Score: mailbanBlacklistScoreThreshold, Reasons: []string{"spamhaus dbl: phishing domain", "stopforumspam: blacklist=true"}},
				{Address: "malware@example.com", Score: 100, Reasons: []string{"spamhaus dbl: malware domain"}},
			}, nil
		},
	}

	got, err := app.blacklistFromAccounts(context.Background())
	if err != nil {
		t.Fatalf("blacklistFromAccounts() error = %v", err)
	}

	want := []string{"manual@example.com", "blocked@example.com", "phish@example.com", "malware@example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("blacklistFromAccounts() = %#v, want %#v", got, want)
	}
	wantOutput := strings.Join([]string{
		"mailban: account=gmail | address=safe@example.com | score=0 | reasons=-",
		"mailban: account=gmail | address=blocked@example.com | score=60 | reasons=spamhaus dbl: abused legit domain",
		"mailban: account=gmail | address=suspicious@example.com | score=79 | reasons=stopforumspam: moderate confidence",
		"mailban: account=gmail | address=phish@example.com | score=80 | reasons=spamhaus dbl: phishing domain; stopforumspam: blacklist=true",
		"mailban: account=gmail | address=malware@example.com | score=100 | reasons=spamhaus dbl: malware domain",
		"",
	}, "\n")
	if output.String() != wantOutput {
		t.Fatalf("mailban output = %q, want %q", output.String(), wantOutput)
	}
	if gotConfig.Host != "imap.gmail.example" {
		t.Fatalf("mailban host = %q, want imap.gmail.example", gotConfig.Host)
	}
	if gotConfig.Port != 993 {
		t.Fatalf("mailban port = %d, want 993", gotConfig.Port)
	}
	if gotConfig.Username != "one@example.com" {
		t.Fatalf("mailban username = %q, want one@example.com", gotConfig.Username)
	}
	if gotConfig.Password != "secret" {
		t.Fatalf("mailban password = %q, want secret", gotConfig.Password)
	}
	if gotConfig.Timeout != 5*time.Second {
		t.Fatalf("mailban timeout = %v, want 5s", gotConfig.Timeout)
	}
	if gotConfig.BatchSize != mailbanBatchSize {
		t.Fatalf("mailban batch size = %d, want %d", gotConfig.BatchSize, mailbanBatchSize)
	}
}

func TestBlacklistFromAccountsReturnsMailbanErrors(t *testing.T) {
	app := &App{
		Accounts: []ConfiguredAccount{
			{
				Name: "gmail",
				Config: mailbin.Config{
					Address:  "imap.gmail.example:993",
					Email:    "one@example.com",
					Password: "secret",
				},
			},
		},
		AssessSenders: func(ctx context.Context, config mailban.Config) ([]mailban.SenderAssessment, error) {
			return nil, errors.New("lookup failed")
		},
	}

	_, err := app.blacklistFromAccounts(context.Background())
	if err == nil {
		t.Fatal("blacklistFromAccounts() error = nil, want failure")
	}
	if !strings.Contains(err.Error(), `account "gmail"`) || !strings.Contains(err.Error(), "assess blacklist senders: lookup failed") {
		t.Fatalf("blacklistFromAccounts() error = %v, want account context", err)
	}
}

func TestMailbanConfigFromAccountRequiresHostPortAddress(t *testing.T) {
	_, err := mailbanConfigFromAccount(mailbin.Config{
		Address: "imap.example.com",
		Email:   "one@example.com",
	}, time.Second)
	if err == nil {
		t.Fatal("mailbanConfigFromAccount() error = nil, want failure")
	}
	if !strings.Contains(err.Error(), "parse imap address") {
		t.Fatalf("mailbanConfigFromAccount() error = %v, want parse imap address", err)
	}
}

func TestFormatMailbanReasons(t *testing.T) {
	testCases := []struct {
		name    string
		reasons []string
		want    string
	}{
		{
			name: "none",
			want: "-",
		},
		{
			name:    "blank only",
			reasons: []string{"", "  "},
			want:    "-",
		},
		{
			name:    "trims and joins",
			reasons: []string{" one ", "two"},
			want:    "one; two",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := formatMailbanReasons(testCase.reasons); got != testCase.want {
				t.Fatalf("formatMailbanReasons() = %q, want %q", got, testCase.want)
			}
		})
	}
}
