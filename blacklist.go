package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/lechefran/mailban"
	"github.com/lechefran/mailbin"
)

const (
	mailbanBatchSize               = 100
	mailbanBlacklistScoreThreshold = 80
)

type SenderAssessor func(context.Context, mailban.Config) ([]mailban.SenderAssessment, error)

func (a *App) blacklistFromAccounts(ctx context.Context) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	blacklist := append([]string(nil), a.BlacklistFromAccounts...)
	if len(a.Accounts) == 0 {
		return normalizeBlacklistFromAccounts(blacklist), nil
	}

	assessSenders := a.AssessSenders
	if assessSenders == nil {
		assessSenders = assessSendersWithMailbanClient
	}

	timeout := a.accountTimeout()
	for _, account := range a.Accounts {
		config, err := mailbanConfigFromAccount(account.Config, timeout)
		if err != nil {
			return nil, fmt.Errorf("account %q: %w", account.Name, err)
		}

		runCtx, cancel := context.WithTimeout(ctx, timeout)
		assessments, err := assessSenders(runCtx, config)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("account %q: assess blacklist senders: %w", account.Name, err)
		}
		if err := a.writeMailbanAssessments(account.Name, assessments); err != nil {
			return nil, fmt.Errorf("account %q: write mailban sender scores: %w", account.Name, err)
		}

		for _, assessment := range assessments {
			if assessment.Score < mailbanBlacklistScoreThreshold {
				continue
			}
			blacklist = append(blacklist, assessment.Address)
		}
	}

	return normalizeBlacklistFromAccounts(blacklist), nil
}

func (a *App) writeMailbanAssessments(accountName string, assessments []mailban.SenderAssessment) error {
	output := a.outputWriter()
	for _, assessment := range assessments {
		address := strings.TrimSpace(assessment.Address)
		if address == "" {
			address = "-"
		}
		reasons := formatMailbanReasons(assessment.Reasons)

		if _, err := fmt.Fprintf(
			output,
			"mailban: account=%s | address=%s | score=%d | reasons=%s\n",
			accountName,
			address,
			assessment.Score,
			reasons,
		); err != nil {
			return err
		}
	}

	return nil
}

func formatMailbanReasons(reasons []string) string {
	formatted := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		reason = strings.TrimSpace(reason)
		if reason == "" {
			continue
		}
		formatted = append(formatted, reason)
	}
	if len(formatted) == 0 {
		return "-"
	}

	return strings.Join(formatted, "; ")
}

func assessSendersWithMailbanClient(ctx context.Context, config mailban.Config) ([]mailban.SenderAssessment, error) {
	client, err := mailban.NewClient(config)
	if err != nil {
		return nil, err
	}

	return client.Senders(ctx)
}

func mailbanConfigFromAccount(config mailbin.Config, timeout time.Duration) (mailban.Config, error) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(config.Address))
	if err != nil {
		return mailban.Config{}, fmt.Errorf("parse imap address %q: %w", config.Address, err)
	}

	port, err := strconv.Atoi(portText)
	if err != nil {
		return mailban.Config{}, fmt.Errorf("parse imap port %q: %w", portText, err)
	}

	return mailban.Config{
		Host:      host,
		Port:      port,
		Username:  strings.TrimSpace(config.Email),
		Password:  config.Password,
		Timeout:   timeout,
		BatchSize: mailbanBatchSize,
	}, nil
}
