package main

import (
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
		AssessSenders: func(ctx context.Context, config mailban.Config) ([]mailban.SenderAssessment, error) {
			gotConfig = config
			return []mailban.SenderAssessment{
				{Address: "safe@example.com", Score: 0},
				{Address: " blocked@example.com ", Score: 60},
				{Address: "suspicious@example.com", Score: 79},
				{Address: "phish@example.com", Score: mailbanBlacklistScoreThreshold},
				{Address: "malware@example.com", Score: 100},
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
