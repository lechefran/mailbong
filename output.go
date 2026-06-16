package main

import (
	"fmt"
	"io"
	"time"

	"github.com/lechefran/mailbin"
)

func writeDeleteOutput(output io.Writer, results []accountDeleteResult) error {
	if len(results) == 0 {
		return nil
	}

	totalDeleted := 0
	multipleAccounts := len(results) > 1
	for _, result := range results {
		totalDeleted += len(result.Result.Deleted)
		if err := writeMessageSummaries(output, result.AccountName, multipleAccounts, result.Result.Deleted); err != nil {
			return err
		}
	}

	_, err := fmt.Fprintf(
		output,
		"summary: deleted total=%d emails across accounts=%d (successful=%d failed=%d)\n",
		totalDeleted,
		len(results),
		successfulAccountCount(results),
		failedAccountCount(results),
	)
	return err
}

func writeMessageSummaries(output io.Writer, accountName string, includeAccount bool, summaries []mailbin.MessageSummary) error {
	for _, summary := range summaries {
		accountPrefix := ""
		if includeAccount {
			accountPrefix = fmt.Sprintf("account=%s | ", accountName)
		}
		receivedAt := "unknown-time"
		if !summary.ReceivedAt.IsZero() {
			receivedAt = summary.ReceivedAt.Format(time.RFC3339)
		}
		subject := summary.Subject
		if subject == "" {
			subject = "-"
		}
		from := summary.From
		if from == "" {
			from = "-"
		}
		to := summary.To
		if to == "" {
			to = "-"
		}
		if _, err := fmt.Fprintf(
			output,
			"%s | %smailbox=%s | %s | from=%s | to=%s | uid=%d\n",
			receivedAt,
			accountPrefix,
			summary.Mailbox,
			subject,
			from,
			to,
			summary.UID,
		); err != nil {
			return err
		}
	}

	return nil
}

func successfulAccountCount(results []accountDeleteResult) int {
	successful := 0
	for _, result := range results {
		if result.Err == nil {
			successful++
		}
	}

	return successful
}

func failedAccountCount(results []accountDeleteResult) int {
	failed := 0
	for _, result := range results {
		if result.Err != nil {
			failed++
		}
	}

	return failed
}
