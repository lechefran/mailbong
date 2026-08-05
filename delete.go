package main

import (
	"context"
	"fmt"
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

	results := make([]accountDeleteResult, len(a.Accounts))

	var wg sync.WaitGroup
	for index, account := range a.Accounts {
		wg.Go(func() {
			runCtx, cancel := context.WithTimeout(ctx, defaultAccountTimeout)
			defer cancel()

			result, err := deleteAccount(runCtx, account.Config, criteria)
			results[index] = accountDeleteResult{
				AccountName: account.Name,
				Result:      result,
				Err:         err,
			}
		})
	}
	wg.Wait()

	failures := make([]string, 0, len(results))
	for _, result := range results {
		if result.Err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", result.AccountName, result.Err))
		}
	}

	if len(failures) > 0 {
		return results, fmt.Errorf("%d account(s) failed: %s", len(failures), strings.Join(failures, "; "))
	}

	return results, nil
}

func deleteWithClient(ctx context.Context, config mailbin.Config, criteria mailbin.DeleteCriteria) (mailbin.DeleteResult, error) {
	client, err := mailbin.NewClient(config)
	if err != nil {
		return mailbin.DeleteResult{}, err
	}

	return client.Delete(ctx, criteria)
}
