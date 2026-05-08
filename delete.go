package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/lechefran/mailbin"
)

const defaultAccountTimeout = 30 * time.Second

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
