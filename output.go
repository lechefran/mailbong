package main

import (
	"fmt"
	"io"
)

func writeDeleteOutput(output io.Writer, results []accountDeleteResult) error {
	if len(results) == 0 {
		return nil
	}

	totalDeleted := 0
	failedAccounts := 0
	for _, result := range results {
		totalDeleted += len(result.Result.Deleted)
		if result.Err != nil {
			failedAccounts++
		}
	}

	_, err := fmt.Fprintf(
		output,
		"summary: deleted total=%d emails across accounts=%d (successful=%d failed=%d)\n",
		totalDeleted,
		len(results),
		len(results)-failedAccounts,
		failedAccounts,
	)
	return err
}
