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
