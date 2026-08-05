package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lechefran/mailbin"
)

func (a *App) Run(ctx context.Context) error {
	if a == nil {
		return fmt.Errorf("app is required")
	}

	criteria, err := a.criteriaForAge(ctx, a.DefaultAge)
	if err != nil {
		return err
	}

	results, err := a.runDelete(ctx, criteria)
	if err != nil && !hasDeletedMessages(results) {
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

func hasDeletedMessages(results []accountDeleteResult) bool {
	for _, result := range results {
		if len(result.Result.Deleted) > 0 {
			return true
		}
	}

	return false
}

func (a *App) criteriaForAge(ctx context.Context, age int) (mailbin.DeleteCriteria, error) {
	if age < 0 {
		return mailbin.DeleteCriteria{}, fmt.Errorf("age is required and must be 0 or greater")
	}

	now := a.Now
	var blacklistFromAccounts []string
	if now == nil {
		now = time.Now
	}
	if a.GetEmailAddresses != nil {
		getEmailAddressesRes, err := a.GetEmailAddresses(ctx)
		if err != nil {
			return mailbin.DeleteCriteria{}, err
		}
		blacklistFromAccounts = getEmailAddressesRes.Addresses
	}

	return mailbin.DeleteCriteria{
		ReceivedBefore: deleteCutoff(now(), age),
		FromAccounts:   normalizeBlacklistFromAccounts(blacklistFromAccounts),
	}, nil
}

func deleteCutoff(now time.Time, age int) time.Time {
	cutoffDay := now.AddDate(0, 0, -age)
	year, month, day := cutoffDay.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, cutoffDay.Location()).AddDate(0, 0, 1)
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
