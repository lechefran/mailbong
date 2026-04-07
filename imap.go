package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/mail"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	gmailTrashMailbox = "[Gmail]/Trash"

	imapAddressAOL       = "imap.aol.com:993"
	imapAddressAOLExport = "export.imap.aol.com:993"
	imapAddressGmail     = "imap.gmail.com:993"
	imapAddressICloud    = "imap.mail.me.com:993"
	imapAddressOutlook   = "outlook.office365.com:993"
	imapAddressYahoo     = "imap.mail.yahoo.com:993"
	imapAddressZoho      = "imap.zoho.com:993"

	maxDeletePasses          = 3
	maxDeleteMailboxAttempts = 3
	maxMailboxCommandRetries = 3
	maxFetchRetryAttempts    = 3
	maxStoreRetryAttempts    = 3
	maxExpungeRetryAttempts  = 3
	defaultFetchBatchSize    = 20
	defaultDeleteBatchSize   = 20
)

type ADDR string

const (
	AOL        ADDR = imapAddressAOL
	AOL_EXPORT ADDR = imapAddressAOLExport
	GMAIL      ADDR = imapAddressGmail
	ICLOUD     ADDR = imapAddressICloud
	OUTLOOK    ADDR = imapAddressOutlook
	YAHOO      ADDR = imapAddressYahoo
	ZOHO       ADDR = imapAddressZoho
)

var providerIMAPAddresses = map[string]string{
	"aol":          imapAddressAOL,
	"aol-export":   imapAddressAOLExport,
	"aolexport":    imapAddressAOLExport,
	"gmail":        imapAddressGmail,
	"googlemail":   imapAddressGmail,
	"hotmail":      imapAddressOutlook,
	"icloud":       imapAddressICloud,
	"live":         imapAddressOutlook,
	"microsoft365": imapAddressOutlook,
	"office365":    imapAddressOutlook,
	"outlook":      imapAddressOutlook,
	"yahoo":        imapAddressYahoo,
	"zoho":         imapAddressZoho,
}

type IMAPClient struct {
	Provider       string
	Address        string
	Email          string
	Password       string
	TLSConfig      *tls.Config
	DialTLSContext func(context.Context, string, *tls.Config) (net.Conn, error)
	LookupIPAddrs  func(context.Context, string) ([]net.IPAddr, error)
}

type IMAPSession struct {
	conn           net.Conn
	reader         *bufio.Reader
	writer         *bufio.Writer
	nextTag        int
	commandTimeout time.Duration
	timedOut       bool
	client         *IMAPClient
}

type EmailSummary struct {
	Account        string
	Mailbox        string
	MessageID      string
	SequenceNumber int
	UID            uint32
	Flagged        bool
	ReceivedAt     time.Time
	Subject        string
	From           string
	To             string
}

type imapResponseLine struct {
	line    string
	literal []byte
}

type mailboxSearchResult struct {
	mailbox   string
	summaries []EmailSummary
}

var fetchBatchSize = defaultFetchBatchSize
var deleteBatchSize = defaultDeleteBatchSize

func resolveIMAPAddress(provider string, address string) (string, error) {
	address = strings.TrimSpace(address)
	if address != "" {
		return address, nil
	}

	normalizedProvider := strings.ToLower(strings.TrimSpace(provider))
	if normalizedProvider == "" {
		return "", fmt.Errorf("imap address or provider is required")
	}

	resolvedAddress, ok := providerIMAPAddresses[normalizedProvider]
	if !ok {
		return "", fmt.Errorf("unsupported provider %q", provider)
	}

	return resolvedAddress, nil
}

func (c *IMAPClient) Login(ctx context.Context) (*IMAPSession, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}

	email, err := quoteIMAPString(c.Email)
	if err != nil {
		return nil, fmt.Errorf("invalid email: %w", err)
	}

	password, err := quoteIMAPString(c.Password)
	if err != nil {
		return nil, fmt.Errorf("invalid password: %w", err)
	}

	host, port, err := net.SplitHostPort(c.Address)
	if err != nil {
		return nil, fmt.Errorf("invalid IMAP address %q: %w", c.Address, err)
	}

	tlsConfig := c.cloneTLSConfig(host)
	conn, err := c.connect(ctx, host, port, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("connect to IMAP server: %w", err)
	}

	session := &IMAPSession{
		conn:    conn,
		reader:  bufio.NewReader(conn),
		writer:  bufio.NewWriter(conn),
		nextTag: 1,
		client:  c,
	}

	if deadline, ok := ctx.Deadline(); ok {
		session.commandTimeout = time.Until(deadline)
	}

	if err := session.expectGreeting(); err != nil {
		conn.Close()
		return nil, err
	}

	if _, _, err := session.runCommand("LOGIN %s %s", email, password); err != nil {
		conn.Close()
		return nil, fmt.Errorf("login failed: %w", err)
	}

	return session, nil
}

func (c *IMAPClient) validate() error {
	switch {
	case c == nil:
		return fmt.Errorf("imap client is required")
	case c.Address == "":
		return fmt.Errorf("imap address is required")
	case c.Email == "":
		return fmt.Errorf("email is required")
	case c.Password == "":
		return fmt.Errorf("password is required")
	default:
		return nil
	}
}

func (c *IMAPClient) cloneTLSConfig(serverName string) *tls.Config {
	if c.TLSConfig == nil {
		return &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: serverName,
		}
	}

	config := c.TLSConfig.Clone()
	if config.MinVersion == 0 {
		config.MinVersion = tls.VersionTLS12
	}
	if config.ServerName == "" {
		config.ServerName = serverName
	}

	return config
}

func (c *IMAPClient) connect(ctx context.Context, host, port string, tlsConfig *tls.Config) (net.Conn, error) {
	address := net.JoinHostPort(host, port)

	conn, err := c.dialTLS(ctx, address, tlsConfig)
	if err == nil {
		return conn, nil
	}
	if !isDNSLookupError(err) {
		return nil, err
	}

	conn, fallbackErr := c.resolveAndDialTLS(ctx, host, port, tlsConfig)
	if fallbackErr == nil {
		return conn, nil
	}

	return nil, fmt.Errorf("%w; lookup fallback failed: %v", err, fallbackErr)
}

func (c *IMAPClient) dialTLS(ctx context.Context, address string, tlsConfig *tls.Config) (net.Conn, error) {
	if c != nil && c.DialTLSContext != nil {
		return c.DialTLSContext(ctx, address, tlsConfig)
	}

	dialer := &tls.Dialer{Config: tlsConfig}
	return dialer.DialContext(ctx, "tcp", address)
}

func (c *IMAPClient) resolveAndDialTLS(ctx context.Context, host, port string, tlsConfig *tls.Config) (net.Conn, error) {
	ipAddrs, err := c.lookupIPAddrs(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve host %s: %w", host, err)
	}
	if len(ipAddrs) == 0 {
		return nil, fmt.Errorf("resolve host %s: no IP addresses returned", host)
	}

	var lastErr error
	for _, ipAddr := range ipAddrs {
		conn, err := c.dialTLSByIP(ctx, ipAddr.IP.String(), port, host, tlsConfig)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, fmt.Errorf("resolve host %s: no IP addresses returned", host)
}

func (c *IMAPClient) lookupIPAddrs(ctx context.Context, host string) ([]net.IPAddr, error) {
	if c != nil && c.LookupIPAddrs != nil {
		return c.LookupIPAddrs(ctx, host)
	}

	resolver := &net.Resolver{PreferGo: true}
	return resolver.LookupIPAddr(ctx, host)
}

func (c *IMAPClient) dialTLSByIP(ctx context.Context, ip, port, serverName string, tlsConfig *tls.Config) (net.Conn, error) {
	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
	if err != nil {
		return nil, err
	}

	config := tlsConfig.Clone()
	if config.ServerName == "" {
		config.ServerName = serverName
	}

	tlsConn := tls.Client(rawConn, config)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

func (s *IMAPSession) Logout() error {
	if s == nil || s.conn == nil {
		return nil
	}

	_, _, commandErr := s.runCommand("LOGOUT")
	closeErr := s.conn.Close()
	s.conn = nil

	if commandErr != nil {
		return commandErr
	}

	return closeErr
}

func (s *IMAPSession) ReadInboxAll() ([]EmailSummary, error) {
	return s.readInboxByCriteria("ALL")
}

func (s *IMAPSession) ReadInboxToday(now time.Time) ([]EmailSummary, error) {
	return s.readInboxSince(startOfDay(now))
}

func (s *IMAPSession) ReadInboxThisWeek(now time.Time) ([]EmailSummary, error) {
	return s.readInboxSince(startOfDay(now.AddDate(0, 0, -7)))
}

func (s *IMAPSession) ReadInboxThisMonth(now time.Time) ([]EmailSummary, error) {
	return s.readInboxSince(startOfDay(now.AddDate(0, 0, -30)))
}

func (s *IMAPSession) readInboxSince(since time.Time) ([]EmailSummary, error) {
	return s.readInboxByCriteria("SINCE %s", formatIMAPDate(since))
}

func (s *IMAPSession) DeleteInboxOlderThanDays(now time.Time, days int, includeFlagged bool) ([]EmailSummary, error) {
	if days < 0 {
		return nil, fmt.Errorf("age must be 0 or greater")
	}

	cutoff := startOfDay(now.AddDate(0, 0, -days)).AddDate(0, 0, 1)
	if includeFlagged {
		log.Printf("include-flagged is enabled but ignored; flagged/starred emails are always skipped")
	}

	return s.deleteInboxByCriteria("BEFORE %s UNFLAGGED", formatIMAPDate(cutoff))
}

func (s *IMAPSession) readInboxByCriteria(format string, args ...any) ([]EmailSummary, error) {
	results, err := s.searchMailboxes(format, args...)
	if err != nil {
		return nil, err
	}

	return dedupeEmailSummaries(flattenMailboxResults(results)), nil
}

func (s *IMAPSession) deleteInboxByCriteria(format string, args ...any) ([]EmailSummary, error) {
	var deletedSummaries []EmailSummary
	var firstErr error

deletePasses:
	for pass := 0; pass < maxDeletePasses; pass++ {
		mailboxes, err := s.listMailboxes()
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			break
		}
		mailboxes = prioritizeDeleteMailboxes(mailboxes, s.isGmailAccount())
		log.Printf("delete pass %d/%d: scanning %d mailboxes", pass+1, maxDeletePasses, len(mailboxes))

		passDeletedCount := 0
		successfulMailboxScans := 0
		for _, mailbox := range mailboxes {
			log.Printf("delete pass %d: scanning mailbox %s", pass+1, mailbox)
			mailboxSummaries, hadSearchResults, err := s.deleteMailboxWithRetry(mailbox, format, args...)
			if err != nil {
				if isRetryableConnectionError(err) {
					log.Printf("skipping mailbox %s after retryable connection error during delete: %v", mailbox, err)
					if reconnectErr := s.reconnect(); reconnectErr != nil {
						if firstErr == nil && len(deletedSummaries) == 0 {
							firstErr = reconnectErr
						}
						break deletePasses
					}
					continue
				}
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			successfulMailboxScans++
			if !hadSearchResults {
				log.Printf("delete pass %d: mailbox %s had no matching emails", pass+1, mailbox)
				continue
			}

			passDeletedCount += len(mailboxSummaries)
			log.Printf("delete pass %d: mailbox %s deleted %d emails", pass+1, mailbox, len(mailboxSummaries))
			deletedSummaries = append(deletedSummaries, mailboxSummaries...)
		}

		if successfulMailboxScans == 0 && firstErr != nil && len(deletedSummaries) == 0 {
			if isRetryableConnectionError(firstErr) {
				log.Printf("delete pass %d: only retryable connection errors encountered; skipping failure: %v", pass+1, firstErr)
				return nil, nil
			}
			return nil, firstErr
		}

		if passDeletedCount == 0 {
			log.Printf("delete pass %d: no deletions found; stopping", pass+1)
			break
		}
		log.Printf("delete pass %d: deleted %d emails", pass+1, passDeletedCount)
	}

	if len(deletedSummaries) == 0 && firstErr != nil {
		if isRetryableConnectionError(firstErr) {
			log.Printf("delete completed with only retryable connection errors; returning no deletions without failing: %v", firstErr)
			return nil, nil
		}
		return nil, firstErr
	}

	return dedupeEmailSummaries(deletedSummaries), nil
}

func (s *IMAPSession) deleteMailboxWithRetry(mailbox string, format string, args ...any) ([]EmailSummary, bool, error) {
	var lastTimeoutErr error
	deletedSummaries := make([]EmailSummary, 0)

attemptLoop:
	for attempt := 0; attempt < maxDeleteMailboxAttempts; attempt++ {
		log.Printf("delete mailbox %s: attempt %d", mailbox, attempt+1)
		if err := s.selectMailboxWithRetry(mailbox); err != nil {
			return deletedSummaries, false, err
		}

		uids, err := s.searchUIDsWithRetry(mailbox, format, args...)
		if err != nil {
			return deletedSummaries, false, fmt.Errorf("search mailbox %s: %w", mailbox, err)
		}
		if len(uids) == 0 {
			if len(deletedSummaries) > 0 {
				return deletedSummaries, true, nil
			}
			return nil, false, nil
		}
		log.Printf("delete mailbox %s: matched %d emails", mailbox, len(uids))

		batchSize := deleteBatchSize
		if batchSize <= 0 {
			batchSize = defaultDeleteBatchSize
		}

		attemptDeletedSummaries := make([]EmailSummary, 0, len(uids))
		totalBatches := (len(uids) + batchSize - 1) / batchSize
		for start := 0; start < len(uids); start += batchSize {
			end := start + batchSize
			if end > len(uids) {
				end = len(uids)
			}

			log.Printf(
				"mailbox %s: streaming delete batch %d/%d (%d uids)",
				mailbox,
				(start/batchSize)+1,
				totalBatches,
				end-start,
			)

			summaries, err := s.fetchEmailSummariesByUID(mailbox, uids[start:end])
			if err != nil {
				if !isRetryableConnectionError(err) {
					return deletedSummaries, true, err
				}

				lastTimeoutErr = err
				log.Printf("retrying mailbox %s delete after timeout: %v", mailbox, err)
				if reconnectErr := s.reconnectAndSelectMailbox(mailbox); reconnectErr != nil {
					return deletedSummaries, true, reconnectErr
				}
				continue attemptLoop
			}

			deletedBatch := s.deleteSelectedMailboxMessages(summaries)
			attemptDeletedSummaries = append(attemptDeletedSummaries, deletedBatch...)
		}

		deletedSummaries = append(deletedSummaries, attemptDeletedSummaries...)
		return deletedSummaries, true, nil
	}

	if len(deletedSummaries) > 0 {
		log.Printf("mailbox %s: timed out during delete but retained %d successful deletions", mailbox, len(deletedSummaries))
		return deletedSummaries, true, nil
	}

	if lastTimeoutErr != nil {
		return nil, true, lastTimeoutErr
	}

	return nil, false, nil
}

func (s *IMAPSession) searchMailboxes(format string, args ...any) ([]mailboxSearchResult, error) {
	mailboxes, err := s.listMailboxes()
	if err != nil {
		return nil, err
	}

	var results []mailboxSearchResult
	var firstErr error
	successfulMailboxReads := 0
	for _, mailbox := range mailboxes {
		if err := s.selectMailboxWithRetry(mailbox); err != nil {
			if isRetryableConnectionError(err) {
				s.timedOut = true
				log.Printf("skipping mailbox %s after retryable connection error selecting: %v", mailbox, err)
				if reconnectErr := s.reconnect(); reconnectErr != nil {
					if firstErr == nil {
						firstErr = reconnectErr
					}
				}
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		sequenceNumbers, err := s.searchWithRetry(mailbox, format, args...)
		if err != nil {
			if isRetryableConnectionError(err) {
				s.timedOut = true
				log.Printf("skipping mailbox %s after retryable connection error searching: %v", mailbox, err)
				if reconnectErr := s.reconnect(); reconnectErr != nil {
					if firstErr == nil {
						firstErr = reconnectErr
					}
				}
				continue
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("search mailbox %s: %w", mailbox, err)
			}
			continue
		}

		mailboxSummaries, err := s.fetchEmailSummaries(mailbox, sequenceNumbers)
		if err != nil {
			if isRetryableConnectionError(err) {
				s.timedOut = true
				log.Printf("skipping mailbox %s after retryable connection error fetching: %v", mailbox, err)
				if reconnectErr := s.reconnect(); reconnectErr != nil {
					if firstErr == nil {
						firstErr = reconnectErr
					}
				}
				continue
			}
			if firstErr == nil {
				firstErr = fmt.Errorf("fetch mailbox %s: %w", mailbox, err)
			}
			continue
		}
		successfulMailboxReads++
		results = append(results, mailboxSearchResult{
			mailbox:   mailbox,
			summaries: mailboxSummaries,
		})
	}

	if successfulMailboxReads == 0 && firstErr != nil {
		if isRetryableConnectionError(firstErr) {
			log.Printf("read completed with only retryable connection errors; returning empty results without failing: %v", firstErr)
			return nil, nil
		}
		return nil, firstErr
	}

	return results, nil
}

func (s *IMAPSession) deleteSelectedMailboxMessages(summaries []EmailSummary) []EmailSummary {
	if len(summaries) == 0 {
		return nil
	}

	orderedSummaries := append([]EmailSummary(nil), summaries...)

	mailbox := orderedSummaries[0].Mailbox
	moveToTrashFirst := s.shouldMoveAllMailToTrash(mailbox)
	batchSize := deleteBatchSize
	if batchSize <= 0 {
		batchSize = defaultDeleteBatchSize
	}

	deletedSummaries := make([]EmailSummary, 0, len(orderedSummaries))
	pendingExpunge := make([]EmailSummary, 0, batchSize)
	totalBatches := (len(orderedSummaries) + batchSize - 1) / batchSize

	for batchStart := 0; batchStart < len(orderedSummaries); batchStart += batchSize {
		batchEnd := batchStart + batchSize
		if batchEnd > len(orderedSummaries) {
			batchEnd = len(orderedSummaries)
		}
		batch := orderedSummaries[batchStart:batchEnd]
		log.Printf(
			"mailbox %s: processing delete batch %d/%d (%d emails)",
			mailbox,
			(batchStart/batchSize)+1,
			totalBatches,
			len(batch),
		)

		for _, summary := range batch {
			subject := summary.Subject
			if subject == "" {
				subject = "-"
			}
			receivedAt := "unknown-time"
			if !summary.ReceivedAt.IsZero() {
				receivedAt = summary.ReceivedAt.Format(time.RFC3339)
			}
			log.Printf(
				"deleting email mailbox=%s seq=%d uid=%d received_at=%s message_id=%q subject=%q",
				summary.Mailbox,
				summary.SequenceNumber,
				summary.UID,
				receivedAt,
				summary.MessageID,
				subject,
			)

			if summary.Flagged {
				log.Printf(
					"skipping email mailbox=%s seq=%d uid=%d received_at=%s message_id=%q subject=%q: flagged/starred",
					summary.Mailbox,
					summary.SequenceNumber,
					summary.UID,
					receivedAt,
					summary.MessageID,
					subject,
				)
				continue
			}

			if moveToTrashFirst {
				moved, err := s.moveMessageToTrashByUIDWithRetry(summary, gmailTrashMailbox)
				if err != nil {
					log.Printf(
						"skipping email mailbox=%s seq=%d uid=%d received_at=%s message_id=%q subject=%q: move to trash failed: %v",
						summary.Mailbox,
						summary.SequenceNumber,
						summary.UID,
						receivedAt,
						summary.MessageID,
						subject,
						err,
					)
					continue
				}
				if !moved {
					log.Printf(
						"skipping email mailbox=%s seq=%d uid=%d received_at=%s message_id=%q subject=%q: unable to move to trash",
						summary.Mailbox,
						summary.SequenceNumber,
						summary.UID,
						receivedAt,
						summary.MessageID,
						subject,
					)
					continue
				}

				log.Printf(
					"moved email to trash mailbox=%s uid=%d received_at=%s message_id=%q subject=%q",
					summary.Mailbox,
					summary.UID,
					receivedAt,
					summary.MessageID,
					subject,
				)
				deletedSummaries = append(deletedSummaries, summary)
				continue
			}

			if err := s.storeDeletedFlagByUIDWithRetry(summary); err != nil {
				log.Printf(
					"skipping email mailbox=%s seq=%d uid=%d received_at=%s message_id=%q subject=%q: store deleted flag failed: %v",
					summary.Mailbox,
					summary.SequenceNumber,
					summary.UID,
					receivedAt,
					summary.MessageID,
					subject,
					err,
				)
				continue
			}
			pendingExpunge = append(pendingExpunge, summary)
		}

		if len(pendingExpunge) == 0 {
			continue
		}

		if err := s.expungeMailboxWithRetry(mailbox); err != nil {
			log.Printf(
				"mailbox %s: expunge failed for %d pending deletes: %v",
				mailbox,
				len(pendingExpunge),
				err,
			)
			continue
		}
		deletedSummaries = append(deletedSummaries, pendingExpunge...)
		pendingExpunge = pendingExpunge[:0]
	}

	if len(pendingExpunge) > 0 {
		if err := s.expungeMailboxWithRetry(mailbox); err != nil {
			log.Printf(
				"skipping %d pending deletes in mailbox=%s after final expunge failure: %v",
				len(pendingExpunge),
				mailbox,
				err,
			)
		} else {
			deletedSummaries = append(deletedSummaries, pendingExpunge...)
		}
	}

	return deletedSummaries
}

func (s *IMAPSession) storeDeletedFlagByUIDWithRetry(summary EmailSummary) error {
	var lastErr error
	for attempt := 0; attempt < maxStoreRetryAttempts; attempt++ {
		err := s.storeDeletedFlagByUID(summary.UID)
		if err == nil {
			return nil
		}
		if !isRetryableConnectionError(err) {
			return err
		}

		lastErr = err
		log.Printf(
			"retrying UID STORE for mailbox %s uid=%d after timeout (attempt %d/%d): %v",
			summary.Mailbox,
			summary.UID,
			attempt+1,
			maxStoreRetryAttempts,
			err,
		)
		if attempt == maxStoreRetryAttempts-1 {
			break
		}
		if err := s.reconnectAndSelectMailbox(summary.Mailbox); err != nil {
			return err
		}
	}

	if lastErr != nil {
		return lastErr
	}

	return fmt.Errorf("uid store failed")
}

func (s *IMAPSession) storeDeletedFlagByUID(uid uint32) error {
	if uid == 0 {
		return fmt.Errorf("uid is required")
	}

	_, _, err := s.runCommand(`UID STORE %d +FLAGS.SILENT (\Deleted)`, uid)
	return err
}

func (s *IMAPSession) moveMessageToTrashByUID(uid uint32, trashMailbox string) error {
	if uid == 0 {
		return fmt.Errorf("uid is required")
	}

	quotedTrashMailbox, err := quoteIMAPString(trashMailbox)
	if err != nil {
		return err
	}

	_, _, err = s.runCommand(`UID MOVE %d %s`, uid, quotedTrashMailbox)
	return err
}

func (s *IMAPSession) moveMessageToTrashByUIDWithRetry(summary EmailSummary, trashMailbox string) (bool, error) {
	var lastErr error
	for attempt := 0; attempt < maxStoreRetryAttempts; attempt++ {
		err := s.moveMessageToTrashByUID(summary.UID, trashMailbox)
		if err == nil {
			return true, nil
		}
		if isUnsupportedMoveError(err) {
			log.Printf(
				"UID MOVE unsupported for mailbox=%s uid=%d; skipping all-mail delete for this message",
				summary.Mailbox,
				summary.UID,
			)
			return false, nil
		}
		if !isRetryableConnectionError(err) {
			return false, err
		}

		lastErr = err
		log.Printf(
			"retrying UID MOVE for mailbox %s uid=%d after timeout (attempt %d/%d): %v",
			summary.Mailbox,
			summary.UID,
			attempt+1,
			maxStoreRetryAttempts,
			err,
		)
		if attempt == maxStoreRetryAttempts-1 {
			break
		}
		if err := s.reconnectAndSelectMailbox(summary.Mailbox); err != nil {
			return false, err
		}
	}

	if lastErr != nil {
		return false, lastErr
	}

	return false, fmt.Errorf("uid move failed")
}

func (s *IMAPSession) reconnectAndSelectMailbox(mailbox string) error {
	if err := s.reconnect(); err != nil {
		return err
	}
	if err := s.selectMailbox(mailbox); err != nil {
		return err
	}

	return nil
}

func (s *IMAPSession) expungeMailboxWithRetry(mailbox string) error {
	var lastErr error
	for attempt := 0; attempt < maxExpungeRetryAttempts; attempt++ {
		_, _, err := s.runCommand("EXPUNGE")
		if err == nil {
			return nil
		}
		if !isRetryableConnectionError(err) {
			return err
		}

		lastErr = err
		log.Printf(
			"retrying EXPUNGE for mailbox %s after timeout (attempt %d/%d): %v",
			mailbox,
			attempt+1,
			maxExpungeRetryAttempts,
			err,
		)
		if attempt == maxExpungeRetryAttempts-1 {
			break
		}
		if err := s.reconnectAndSelectMailbox(mailbox); err != nil {
			return err
		}
	}

	if lastErr != nil {
		return lastErr
	}

	return fmt.Errorf("expunge failed")
}

func (s *IMAPSession) listMailboxes() ([]string, error) {
	var lines []imapResponseLine
	var err error
	for attempt := 0; attempt < maxMailboxCommandRetries; attempt++ {
		lines, _, err = s.runCommand(`LIST "" "*"`)
		if err == nil {
			break
		}
		if !isRetryableConnectionError(err) {
			return nil, fmt.Errorf("list mailboxes: %w", err)
		}

		log.Printf(
			"retrying LIST after retryable connection error (attempt %d/%d): %v",
			attempt+1,
			maxMailboxCommandRetries,
			err,
		)
		if attempt == maxMailboxCommandRetries-1 {
			return nil, fmt.Errorf("list mailboxes: %w", err)
		}
		if reconnectErr := s.reconnect(); reconnectErr != nil {
			return nil, fmt.Errorf("list mailboxes reconnect: %w", reconnectErr)
		}
	}

	var mailboxes []string
	for _, responseLine := range lines {
		if !strings.HasPrefix(responseLine.line, "* LIST ") {
			continue
		}

		mailbox, selectable, err := parseListMailbox(responseLine.line)
		if err != nil {
			return nil, err
		}
		if !selectable {
			continue
		}

		mailboxes = append(mailboxes, mailbox)
	}

	if len(mailboxes) == 0 {
		return nil, fmt.Errorf("no selectable mailboxes found")
	}

	sort.SliceStable(mailboxes, func(i, j int) bool {
		leftPriority := mailboxPriority(mailboxes[i])
		rightPriority := mailboxPriority(mailboxes[j])
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}

		return strings.ToLower(mailboxes[i]) < strings.ToLower(mailboxes[j])
	})

	return mailboxes, nil
}

func (s *IMAPSession) selectMailbox(mailbox string) error {
	quotedMailbox, err := quoteIMAPString(mailbox)
	if err != nil {
		return err
	}

	_, _, err = s.runCommand("SELECT %s", quotedMailbox)
	if err != nil {
		return fmt.Errorf("select mailbox %s: %w", mailbox, err)
	}

	return nil
}

func (s *IMAPSession) selectMailboxWithRetry(mailbox string) error {
	var lastErr error
	for attempt := 0; attempt < maxMailboxCommandRetries; attempt++ {
		if err := s.selectMailbox(mailbox); err == nil {
			return nil
		} else if !isRetryableConnectionError(err) {
			return err
		} else {
			lastErr = err
		}

		log.Printf(
			"retrying SELECT for mailbox %s after retryable connection error (attempt %d/%d): %v",
			mailbox,
			attempt+1,
			maxMailboxCommandRetries,
			lastErr,
		)
		if attempt == maxMailboxCommandRetries-1 {
			break
		}
		if err := s.reconnect(); err != nil {
			return err
		}
	}

	if lastErr != nil {
		return lastErr
	}

	return fmt.Errorf("select mailbox %s failed", mailbox)
}

func (s *IMAPSession) search(format string, args ...any) ([]int, error) {
	lines, _, err := s.runCommand("SEARCH "+format, args...)
	if err != nil {
		return nil, fmt.Errorf("search mailbox: %w", err)
	}

	ids, found := parseSearchIDs(lines)
	if !found || len(ids) == 0 {
		return nil, nil
	}

	sequenceNumbers := make([]int, 0, len(ids))
	for _, id := range ids {
		sequenceNumbers = append(sequenceNumbers, int(id))
	}

	return sequenceNumbers, nil
}

func (s *IMAPSession) searchWithRetry(mailbox string, format string, args ...any) ([]int, error) {
	var lastErr error
	for attempt := 0; attempt < maxMailboxCommandRetries; attempt++ {
		sequenceNumbers, err := s.search(format, args...)
		if err == nil {
			return sequenceNumbers, nil
		}
		if !isRetryableConnectionError(err) {
			return nil, err
		}

		lastErr = err
		log.Printf(
			"retrying SEARCH for mailbox %s after retryable connection error (attempt %d/%d): %v",
			mailbox,
			attempt+1,
			maxMailboxCommandRetries,
			err,
		)
		if attempt == maxMailboxCommandRetries-1 {
			break
		}
		if reconnectErr := s.reconnectAndSelectMailbox(mailbox); reconnectErr != nil {
			return nil, reconnectErr
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, fmt.Errorf("search mailbox %s failed", mailbox)
}

func (s *IMAPSession) searchUIDs(format string, args ...any) ([]uint32, error) {
	lines, _, err := s.runCommand("UID SEARCH "+format, args...)
	if err != nil {
		return nil, fmt.Errorf("search mailbox: %w", err)
	}

	uids, _ := parseSearchIDs(lines)
	if len(uids) == 0 {
		return nil, nil
	}

	return uids, nil
}

func parseSearchIDs(lines []imapResponseLine) ([]uint32, bool) {
	sawRecognized := false
	for _, responseLine := range lines {
		ids, lineRecognized := parseSearchIDsFromLine(responseLine.line)
		if !lineRecognized {
			continue
		}
		sawRecognized = true
		if len(ids) == 0 {
			continue
		}

		return ids, true
	}

	return nil, sawRecognized
}

func parseSearchIDsFromLine(line string) ([]uint32, bool) {
	trimmed := strings.TrimSpace(line)
	upper := strings.ToUpper(trimmed)
	switch {
	case strings.HasPrefix(upper, "* SEARCH"):
		fields := strings.Fields(trimmed)
		if len(fields) <= 2 {
			return nil, true
		}
		return parseIDTokens(fields[2:]), true
	case strings.HasPrefix(upper, "* ESEARCH"):
		return parseESearchIDs(trimmed), true
	default:
		return nil, false
	}
}

func parseESearchIDs(line string) []uint32 {
	upper := strings.ToUpper(line)
	allIndex := strings.Index(upper, " ALL ")
	if allIndex == -1 {
		return nil
	}

	afterAll := strings.TrimSpace(line[allIndex+len(" ALL "):])
	if afterAll == "" {
		return nil
	}

	return parseIDTokens(strings.Fields(afterAll))
}

func parseIDTokens(tokens []string) []uint32 {
	var ids []uint32
	for _, token := range tokens {
		expanded := expandIDToken(token)
		if len(expanded) == 0 {
			continue
		}
		ids = append(ids, expanded...)
	}

	return ids
}

func expandIDToken(token string) []uint32 {
	cleanToken := strings.Trim(token, "(),")
	if cleanToken == "" || strings.Contains(cleanToken, "*") {
		return nil
	}

	parts := strings.Split(cleanToken, ",")
	var ids []uint32
	for _, part := range parts {
		segment := strings.TrimSpace(part)
		if segment == "" {
			continue
		}

		if strings.Contains(segment, ":") {
			rangeIDs := expandIDRange(segment)
			if len(rangeIDs) == 0 {
				continue
			}
			ids = append(ids, rangeIDs...)
			continue
		}

		value, err := strconv.ParseUint(segment, 10, 32)
		if err != nil {
			continue
		}
		ids = append(ids, uint32(value))
	}

	return ids
}

func expandIDRange(segment string) []uint32 {
	rangeParts := strings.SplitN(segment, ":", 2)
	if len(rangeParts) != 2 {
		return nil
	}

	start, err := strconv.ParseUint(strings.TrimSpace(rangeParts[0]), 10, 32)
	if err != nil {
		return nil
	}
	end, err := strconv.ParseUint(strings.TrimSpace(rangeParts[1]), 10, 32)
	if err != nil {
		return nil
	}

	start32 := uint32(start)
	end32 := uint32(end)
	if start32 <= end32 {
		ids := make([]uint32, 0, int(end32-start32)+1)
		for value := start32; value <= end32; value++ {
			ids = append(ids, value)
		}
		return ids
	}

	ids := make([]uint32, 0, int(start32-end32)+1)
	for value := start32; value >= end32; value-- {
		ids = append(ids, value)
		if value == 0 {
			break
		}
	}
	return ids
}

func (s *IMAPSession) searchUIDsWithRetry(mailbox string, format string, args ...any) ([]uint32, error) {
	var lastErr error
	for attempt := 0; attempt < maxMailboxCommandRetries; attempt++ {
		uids, err := s.searchUIDs(format, args...)
		if err == nil {
			return uids, nil
		}
		if !isRetryableConnectionError(err) {
			return nil, err
		}

		lastErr = err
		log.Printf(
			"retrying UID SEARCH for mailbox %s after retryable connection error (attempt %d/%d): %v",
			mailbox,
			attempt+1,
			maxMailboxCommandRetries,
			err,
		)
		if attempt == maxMailboxCommandRetries-1 {
			break
		}
		if reconnectErr := s.reconnectAndSelectMailbox(mailbox); reconnectErr != nil {
			return nil, reconnectErr
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, fmt.Errorf("uid search mailbox %s failed", mailbox)
}

func (s *IMAPSession) fetchEmailSummaries(mailbox string, sequenceNumbers []int) ([]EmailSummary, error) {
	if len(sequenceNumbers) == 0 {
		return nil, nil
	}

	return s.fetchEmailSummariesInBatches(
		mailbox,
		len(sequenceNumbers),
		func(start, end int) ([]EmailSummary, error) {
			return s.fetchEmailSummaryBatch(mailbox, sequenceNumbers[start:end])
		},
	)
}

func (s *IMAPSession) fetchEmailSummariesByUID(mailbox string, uids []uint32) ([]EmailSummary, error) {
	if len(uids) == 0 {
		return nil, nil
	}

	return s.fetchEmailSummariesInBatches(
		mailbox,
		len(uids),
		func(start, end int) ([]EmailSummary, error) {
			return s.fetchEmailSummaryBatchByUID(mailbox, uids[start:end])
		},
	)
}

func (s *IMAPSession) fetchEmailSummariesInBatches(
	mailbox string,
	total int,
	fetchBatch func(start, end int) ([]EmailSummary, error),
) ([]EmailSummary, error) {
	batchSize := fetchBatchSize
	if batchSize <= 0 {
		batchSize = defaultFetchBatchSize
	}

	summaries := make([]EmailSummary, 0, total)
	for start := 0; start < total; start += batchSize {
		end := start + batchSize
		if end > total {
			end = total
		}

		batchSummaries, err := s.fetchBatchWithRetry(mailbox, start, end, fetchBatch)
		if err != nil {
			return nil, fmt.Errorf("fetch email summaries: %w", err)
		}
		summaries = append(summaries, batchSummaries...)
	}

	return summaries, nil
}

func (s *IMAPSession) fetchBatchWithRetry(
	mailbox string,
	start int,
	end int,
	fetchBatch func(start, end int) ([]EmailSummary, error),
) ([]EmailSummary, error) {
	var lastErr error
	for attempt := 0; attempt < maxFetchRetryAttempts; attempt++ {
		batchSummaries, err := fetchBatch(start, end)
		if err == nil {
			return batchSummaries, nil
		}
		if !isRetryableConnectionError(err) || s.client == nil {
			return nil, err
		}

		lastErr = err
		log.Printf(
			"retrying fetch for mailbox %s after timeout (attempt %d/%d): %v",
			mailbox,
			attempt+1,
			maxFetchRetryAttempts,
			err,
		)
		if attempt == maxFetchRetryAttempts-1 {
			break
		}
		if reconnectErr := s.reconnectAndSelectMailbox(mailbox); reconnectErr != nil {
			return nil, reconnectErr
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return nil, fmt.Errorf("fetch batch failed")
}

func (s *IMAPSession) fetchEmailSummaryBatch(mailbox string, sequenceNumbers []int) ([]EmailSummary, error) {
	values := make([]string, 0, len(sequenceNumbers))
	for _, sequenceNumber := range sequenceNumbers {
		values = append(values, strconv.Itoa(sequenceNumber))
	}

	lines, _, err := s.runCommand(
		"FETCH %s (UID FLAGS INTERNALDATE BODY.PEEK[HEADER.FIELDS (MESSAGE-ID SUBJECT FROM TO)])",
		strings.Join(values, ","),
	)
	if err != nil {
		return nil, err
	}

	summaries := make([]EmailSummary, 0, len(sequenceNumbers))
	for _, responseLine := range lines {
		if !strings.HasPrefix(responseLine.line, "* ") || !strings.Contains(responseLine.line, " FETCH ") {
			continue
		}

		summary, err := parseFetchSummary(mailbox, responseLine)
		if err != nil {
			return nil, err
		}
		summaries = append(summaries, summary)
	}

	return summaries, nil
}

func (s *IMAPSession) fetchEmailSummaryBatchByUID(mailbox string, uids []uint32) ([]EmailSummary, error) {
	values := make([]string, 0, len(uids))
	for _, uid := range uids {
		values = append(values, strconv.FormatUint(uint64(uid), 10))
	}

	lines, _, err := s.runCommand(
		"UID FETCH %s (UID FLAGS INTERNALDATE BODY.PEEK[HEADER.FIELDS (MESSAGE-ID SUBJECT FROM TO)])",
		strings.Join(values, ","),
	)
	if err != nil {
		return nil, err
	}

	summaries := make([]EmailSummary, 0, len(uids))
	for _, responseLine := range lines {
		if !strings.HasPrefix(responseLine.line, "* ") || !strings.Contains(responseLine.line, " FETCH ") {
			continue
		}

		summary, err := parseFetchSummary(mailbox, responseLine)
		if err != nil {
			return nil, err
		}
		summaries = append(summaries, summary)
	}

	return summaries, nil
}

func (s *IMAPSession) runCommand(format string, args ...any) ([]imapResponseLine, string, error) {
	if err := s.applyCommandDeadline(); err != nil {
		return nil, "", err
	}

	tag := fmt.Sprintf("A%04d", s.nextTag)
	s.nextTag++

	command := fmt.Sprintf(format, args...)
	if _, err := fmt.Fprintf(s.writer, "%s %s\r\n", tag, command); err != nil {
		return nil, "", fmt.Errorf("write %s command: %w", tag, err)
	}
	if err := s.writer.Flush(); err != nil {
		return nil, "", fmt.Errorf("flush %s command: %w", tag, err)
	}

	return s.readTaggedResponse(tag)
}

func (s *IMAPSession) expectGreeting() error {
	if err := s.applyCommandDeadline(); err != nil {
		return err
	}

	line, err := s.readLine()
	if err != nil {
		return fmt.Errorf("read server greeting: %w", err)
	}
	if !strings.HasPrefix(strings.ToUpper(line), "* OK") {
		return fmt.Errorf("unexpected server greeting: %s", line)
	}

	return nil
}

func (s *IMAPSession) applyCommandDeadline() error {
	if s == nil || s.conn == nil {
		return nil
	}
	if s.commandTimeout <= 0 {
		return nil
	}
	if err := s.conn.SetDeadline(time.Now().Add(s.commandTimeout)); err != nil {
		return fmt.Errorf("set connection deadline: %w", err)
	}

	return nil
}

func (s *IMAPSession) readTaggedResponse(tag string) ([]imapResponseLine, string, error) {
	var responseLines []imapResponseLine

	for {
		line, err := s.readLine()
		if err != nil {
			return nil, "", fmt.Errorf("read %s response: %w", tag, err)
		}

		responseLine := imapResponseLine{line: line}
		if literalSize, ok := parseLiteralSize(line); ok {
			literal, err := s.readLiteral(literalSize)
			if err != nil {
				return nil, "", fmt.Errorf("read %s literal: %w", tag, err)
			}
			responseLine.literal = literal
		}

		if !strings.HasPrefix(line, tag+" ") {
			responseLines = append(responseLines, responseLine)
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, "", fmt.Errorf("malformed %s response: %s", tag, line)
		}

		switch strings.ToUpper(fields[1]) {
		case "OK":
			return responseLines, line, nil
		case "NO", "BAD":
			return responseLines, "", errors.New(line)
		default:
			return responseLines, "", fmt.Errorf("unexpected %s response: %s", tag, line)
		}
	}
}

func (s *IMAPSession) readLine() (string, error) {
	line, err := s.reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	return strings.TrimRight(line, "\r\n"), nil
}

func quoteIMAPString(value string) (string, error) {
	if strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("value cannot contain a newline")
	}

	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + replacer.Replace(value) + `"`, nil
}

func parseFetchSummary(mailbox string, responseLine imapResponseLine) (EmailSummary, error) {
	fields := strings.Fields(responseLine.line)
	if len(fields) < 3 {
		return EmailSummary{}, fmt.Errorf("malformed FETCH response: %s", responseLine.line)
	}

	sequenceNumber, err := strconv.Atoi(fields[1])
	if err != nil {
		return EmailSummary{}, fmt.Errorf("parse FETCH sequence number %q: %w", fields[1], err)
	}

	uid, err := extractUint32Token(responseLine.line, "UID ")
	if err != nil {
		return EmailSummary{}, err
	}

	internalDateValue, err := extractQuotedToken(responseLine.line, `INTERNALDATE "`)
	if err != nil {
		return EmailSummary{}, err
	}

	receivedAt, err := time.Parse("02-Jan-2006 15:04:05 -0700", internalDateValue)
	if err != nil {
		return EmailSummary{}, fmt.Errorf("parse INTERNALDATE %q: %w", internalDateValue, err)
	}
	flagged := parseFlaggedFromFetchLine(responseLine.line)

	headers, err := mail.ReadMessage(bytes.NewReader(responseLine.literal))
	if err != nil {
		return EmailSummary{}, fmt.Errorf("parse message headers: %w", err)
	}

	return EmailSummary{
		Mailbox:        mailbox,
		MessageID:      normalizeMessageID(headers.Header.Get("Message-Id")),
		SequenceNumber: sequenceNumber,
		UID:            uid,
		Flagged:        flagged,
		ReceivedAt:     receivedAt,
		Subject:        headers.Header.Get("Subject"),
		From:           headers.Header.Get("From"),
		To:             headers.Header.Get("To"),
	}, nil
}

func parseFlaggedFromFetchLine(line string) bool {
	upper := strings.ToUpper(line)
	flagsIndex := strings.Index(upper, "FLAGS (")
	if flagsIndex == -1 {
		return false
	}

	start := flagsIndex + len("FLAGS (")
	rest := upper[start:]
	end := strings.IndexByte(rest, ')')
	if end == -1 {
		return false
	}

	return strings.Contains(rest[:end], `\FLAGGED`)
}

func extractUint32Token(line, prefix string) (uint32, error) {
	start := strings.Index(line, prefix)
	if start == -1 {
		return 0, fmt.Errorf("missing %s token in response: %s", strings.TrimSpace(prefix), line)
	}

	start += len(prefix)
	end := start
	for end < len(line) && line[end] >= '0' && line[end] <= '9' {
		end++
	}

	value, err := strconv.ParseUint(line[start:end], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse %s value: %w", strings.TrimSpace(prefix), err)
	}

	return uint32(value), nil
}

func extractQuotedToken(line, prefix string) (string, error) {
	start := strings.Index(line, prefix)
	if start == -1 {
		return "", fmt.Errorf("missing %s token in response: %s", strings.TrimSpace(prefix), line)
	}

	start += len(prefix)
	end := start
	for end < len(line) && line[end] != '"' {
		end++
	}
	if end >= len(line) {
		return "", fmt.Errorf("unterminated quoted token in response: %s", line)
	}

	return line[start:end], nil
}

func parseLiteralSize(line string) (int, bool) {
	start := strings.LastIndex(line, "{")
	if start == -1 || !strings.HasSuffix(line, "}") {
		return 0, false
	}

	size, err := strconv.Atoi(line[start+1 : len(line)-1])
	if err != nil {
		return 0, false
	}

	return size, true
}

func (s *IMAPSession) readLiteral(size int) ([]byte, error) {
	literal := make([]byte, size)
	if _, err := io.ReadFull(s.reader, literal); err != nil {
		return nil, err
	}

	return literal, nil
}

func formatIMAPDate(value time.Time) string {
	return value.Format("02-Jan-2006")
}

func startOfDay(value time.Time) time.Time {
	year, month, day := value.Date()
	return time.Date(year, month, day, 0, 0, 0, 0, value.Location())
}

func parseListMailbox(line string) (string, bool, error) {
	remaining := strings.TrimSpace(strings.TrimPrefix(line, "* LIST"))
	if !strings.HasPrefix(remaining, "(") {
		return "", false, fmt.Errorf("malformed LIST response: %s", line)
	}

	flagsEnd := strings.Index(remaining, ")")
	if flagsEnd == -1 {
		return "", false, fmt.Errorf("malformed LIST flags: %s", line)
	}

	flags := strings.ToUpper(remaining[1:flagsEnd])
	remaining = strings.TrimSpace(remaining[flagsEnd+1:])

	_, consumed, err := consumeIMAPListToken(remaining)
	if err != nil {
		return "", false, fmt.Errorf("parse LIST delimiter: %w", err)
	}
	remaining = strings.TrimSpace(remaining[consumed:])

	mailbox, _, err := consumeIMAPListToken(remaining)
	if err != nil {
		return "", false, fmt.Errorf("parse LIST mailbox: %w", err)
	}

	return mailbox, !strings.Contains(flags, `\NOSELECT`), nil
}

func consumeIMAPListToken(input string) (string, int, error) {
	if input == "" {
		return "", 0, fmt.Errorf("missing token")
	}

	if input[0] == '"' {
		value, consumed, err := consumeQuotedString(input)
		if err != nil {
			return "", 0, err
		}

		return value, consumed, nil
	}

	tokenEnd := strings.IndexAny(input, " \t")
	if tokenEnd == -1 {
		return input, len(input), nil
	}

	return input[:tokenEnd], tokenEnd, nil
}

func consumeQuotedString(input string) (string, int, error) {
	var builder strings.Builder
	escaped := false

	for i := 1; i < len(input); i++ {
		character := input[i]
		switch {
		case escaped:
			builder.WriteByte(character)
			escaped = false
		case character == '\\':
			escaped = true
		case character == '"':
			return builder.String(), i + 1, nil
		default:
			builder.WriteByte(character)
		}
	}

	return "", 0, fmt.Errorf("unterminated quoted string: %s", input)
}

func dedupeEmailSummaries(summaries []EmailSummary) []EmailSummary {
	seenMessageIDs := make(map[string]struct{}, len(summaries))
	deduped := make([]EmailSummary, 0, len(summaries))

	for _, summary := range summaries {
		messageID := normalizeMessageID(summary.MessageID)
		if messageID == "" {
			deduped = append(deduped, summary)
			continue
		}

		if _, exists := seenMessageIDs[messageID]; exists {
			continue
		}

		seenMessageIDs[messageID] = struct{}{}
		deduped = append(deduped, summary)
	}

	return deduped
}

func flattenMailboxResults(results []mailboxSearchResult) []EmailSummary {
	total := 0
	for _, result := range results {
		total += len(result.summaries)
	}

	summaries := make([]EmailSummary, 0, total)
	for _, result := range results {
		summaries = append(summaries, result.summaries...)
	}

	return summaries
}

func normalizeMessageID(messageID string) string {
	return strings.TrimSpace(messageID)
}

func prioritizeDeleteMailboxes(mailboxes []string, isGmailAccount bool) []string {
	prioritized := append([]string(nil), mailboxes...)
	sort.SliceStable(prioritized, func(i, j int) bool {
		leftPriority := deleteMailboxPriority(prioritized[i], isGmailAccount)
		rightPriority := deleteMailboxPriority(prioritized[j], isGmailAccount)
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}

		return strings.ToLower(prioritized[i]) < strings.ToLower(prioritized[j])
	})

	return prioritized
}

func deleteMailboxPriority(mailbox string, isGmailAccount bool) int {
	lowerMailbox := strings.ToLower(mailbox)

	switch {
	case isGmailAccount && isAllMailMailbox(lowerMailbox):
		return 0
	default:
		return mailboxPriority(mailbox) + 1
	}
}

func (s *IMAPSession) isGmailAccount() bool {
	if s == nil || s.client == nil {
		return false
	}

	return s.client.isGmail()
}

func (c *IMAPClient) isGmail() bool {
	if c == nil {
		return false
	}

	switch strings.ToLower(strings.TrimSpace(c.Provider)) {
	case "gmail", "googlemail":
		return true
	}

	host, _, err := net.SplitHostPort(strings.TrimSpace(c.Address))
	if err != nil {
		return false
	}

	return strings.EqualFold(host, "imap.gmail.com")
}

func (c *IMAPClient) isTaggedGmail() bool {
	if c == nil {
		return false
	}

	switch strings.ToLower(strings.TrimSpace(c.Provider)) {
	case "gmail", "googlemail":
		return true
	default:
		return false
	}
}

func mailboxPriority(mailbox string) int {
	lowerMailbox := strings.ToLower(mailbox)

	switch {
	case lowerMailbox == "inbox" || strings.HasSuffix(lowerMailbox, "/inbox"):
		return 0
	case isArchiveMailbox(lowerMailbox):
		return 1
	case isAllMailMailbox(lowerMailbox):
		return 3
	case isSpamMailbox(lowerMailbox), isTrashMailbox(lowerMailbox):
		return 2
	default:
		return 1
	}
}

func isAllMailMailbox(mailbox string) bool {
	return strings.Contains(mailbox, "all mail")
}

func (s *IMAPSession) shouldMoveAllMailToTrash(mailbox string) bool {
	if s == nil || s.client == nil {
		return false
	}
	if !s.client.isTaggedGmail() {
		return false
	}

	return isAllMailMailbox(strings.ToLower(mailbox))
}

func isArchiveMailbox(mailbox string) bool {
	return strings.Contains(mailbox, "archive")
}

func isSpamMailbox(mailbox string) bool {
	return strings.Contains(mailbox, "spam") || strings.Contains(mailbox, "junk")
}

func isTrashMailbox(mailbox string) bool {
	return strings.Contains(mailbox, "trash") || strings.Contains(mailbox, "bin")
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	return strings.Contains(strings.ToLower(err.Error()), "i/o timeout")
}

func isRetryableConnectionError(err error) bool {
	if err == nil {
		return false
	}
	if isTimeoutError(err) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EPIPE) {
		return true
	}

	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "broken pipe") ||
		strings.Contains(lower, "connection reset by peer") ||
		strings.Contains(lower, "use of closed network connection")
}

func isUnsupportedMoveError(err error) bool {
	if err == nil {
		return false
	}

	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "unsupported uid command") ||
		strings.Contains(lower, "unknown command") ||
		strings.Contains(lower, "not supported") ||
		strings.Contains(lower, "does not support")
}

func isDNSLookupError(err error) bool {
	if err == nil {
		return false
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}

	return strings.Contains(strings.ToLower(err.Error()), "no such host")
}

func (s *IMAPSession) reconnect() error {
	if s == nil || s.client == nil {
		return fmt.Errorf("imap client is required for reconnect")
	}
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}

	ctx := context.Background()
	cancel := func() {}
	if s.commandTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, s.commandTimeout)
	}
	defer cancel()

	reconnected, err := s.client.Login(ctx)
	if err != nil {
		return err
	}

	*s = *reconnected
	return nil
}
