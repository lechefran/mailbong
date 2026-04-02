package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"sort"
	"strconv"
	"strings"
	"time"
)

type IMAPClient struct {
	Address   string
	Email     string
	Password  string
	TLSConfig *tls.Config
}

type IMAPSession struct {
	conn    net.Conn
	reader  *bufio.Reader
	writer  *bufio.Writer
	nextTag int
}

type EmailSummary struct {
	Mailbox        string
	MessageID      string
	SequenceNumber int
	UID            uint32
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

const maxDeletePasses = 5

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

	host, _, err := net.SplitHostPort(c.Address)
	if err != nil {
		return nil, fmt.Errorf("invalid IMAP address %q: %w", c.Address, err)
	}

	tlsConfig := c.cloneTLSConfig(host)
	dialer := &tls.Dialer{Config: tlsConfig}

	conn, err := dialer.DialContext(ctx, "tcp", c.Address)
	if err != nil {
		return nil, fmt.Errorf("connect to IMAP server: %w", err)
	}

	session := &IMAPSession{
		conn:    conn,
		reader:  bufio.NewReader(conn),
		writer:  bufio.NewWriter(conn),
		nextTag: 1,
	}

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			conn.Close()
			return nil, fmt.Errorf("set connection deadline: %w", err)
		}
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

func (s *IMAPSession) DeleteInboxAll() ([]EmailSummary, error) {
	return s.deleteInboxByCriteria("ALL")
}

func (s *IMAPSession) DeleteInboxToday(now time.Time) ([]EmailSummary, error) {
	return s.deleteInboxSince(startOfDay(now))
}

func (s *IMAPSession) DeleteInboxThisWeek(now time.Time) ([]EmailSummary, error) {
	return s.deleteInboxSince(startOfDay(now.AddDate(0, 0, -7)))
}

func (s *IMAPSession) DeleteInboxThisMonth(now time.Time) ([]EmailSummary, error) {
	return s.deleteInboxSince(startOfDay(now.AddDate(0, 0, -30)))
}

func (s *IMAPSession) readInboxSince(since time.Time) ([]EmailSummary, error) {
	return s.readInboxByCriteria("SINCE %s", formatIMAPDate(since))
}

func (s *IMAPSession) deleteInboxSince(since time.Time) ([]EmailSummary, error) {
	return s.deleteInboxByCriteria("SINCE %s", formatIMAPDate(since))
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

	for pass := 0; pass < maxDeletePasses; pass++ {
		results, err := s.searchMailboxes(format, args...)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			break
		}

		passDeletedCount := 0
		for _, result := range results {
			if len(result.summaries) == 0 {
				continue
			}

			if err := s.deleteMailboxMessages(result.mailbox, result.summaries); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}

			passDeletedCount += len(result.summaries)
			deletedSummaries = append(deletedSummaries, result.summaries...)
		}

		if passDeletedCount == 0 {
			break
		}
	}

	if len(deletedSummaries) == 0 && firstErr != nil {
		return nil, firstErr
	}

	return dedupeEmailSummaries(deletedSummaries), nil
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
		if err := s.selectMailbox(mailbox); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}

		sequenceNumbers, err := s.search(format, args...)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("search mailbox %s: %w", mailbox, err)
			}
			continue
		}

		mailboxSummaries, err := s.fetchEmailSummaries(mailbox, sequenceNumbers)
		if err != nil {
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
		return nil, firstErr
	}

	return results, nil
}

func (s *IMAPSession) deleteMailboxMessages(mailbox string, summaries []EmailSummary) error {
	if len(summaries) == 0 {
		return nil
	}

	if err := s.selectMailbox(mailbox); err != nil {
		return err
	}

	sequenceSet := buildSequenceSet(summaries)
	if _, _, err := s.runCommand(`STORE %s +FLAGS.SILENT (\Deleted)`, sequenceSet); err != nil {
		return fmt.Errorf("store deleted flag for mailbox %s: %w", mailbox, err)
	}
	if _, _, err := s.runCommand("EXPUNGE"); err != nil {
		return fmt.Errorf("expunge mailbox %s: %w", mailbox, err)
	}

	return nil
}

func (s *IMAPSession) listMailboxes() ([]string, error) {
	lines, _, err := s.runCommand(`LIST "" "*"`)
	if err != nil {
		return nil, fmt.Errorf("list mailboxes: %w", err)
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

func (s *IMAPSession) search(format string, args ...any) ([]int, error) {
	lines, _, err := s.runCommand("SEARCH "+format, args...)
	if err != nil {
		return nil, fmt.Errorf("search mailbox: %w", err)
	}

	for _, responseLine := range lines {
		if !strings.HasPrefix(responseLine.line, "* SEARCH") {
			continue
		}

		fields := strings.Fields(responseLine.line)
		if len(fields) <= 2 {
			return nil, nil
		}

		sequenceNumbers := make([]int, 0, len(fields)-2)
		for _, value := range fields[2:] {
			sequenceNumber, err := strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("parse search sequence number %q: %w", value, err)
			}
			sequenceNumbers = append(sequenceNumbers, sequenceNumber)
		}

		return sequenceNumbers, nil
	}

	return nil, fmt.Errorf("missing SEARCH response")
}

func (s *IMAPSession) fetchEmailSummaries(mailbox string, sequenceNumbers []int) ([]EmailSummary, error) {
	if len(sequenceNumbers) == 0 {
		return nil, nil
	}

	values := make([]string, 0, len(sequenceNumbers))
	for _, sequenceNumber := range sequenceNumbers {
		values = append(values, strconv.Itoa(sequenceNumber))
	}

	lines, _, err := s.runCommand(
		"FETCH %s (UID INTERNALDATE BODY.PEEK[HEADER.FIELDS (MESSAGE-ID SUBJECT FROM TO)])",
		strings.Join(values, ","),
	)
	if err != nil {
		return nil, fmt.Errorf("fetch email summaries: %w", err)
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

func (s *IMAPSession) runCommand(format string, args ...any) ([]imapResponseLine, string, error) {
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
	line, err := s.readLine()
	if err != nil {
		return fmt.Errorf("read server greeting: %w", err)
	}
	if !strings.HasPrefix(strings.ToUpper(line), "* OK") {
		return fmt.Errorf("unexpected server greeting: %s", line)
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

	headers, err := mail.ReadMessage(bytes.NewReader(responseLine.literal))
	if err != nil {
		return EmailSummary{}, fmt.Errorf("parse message headers: %w", err)
	}

	return EmailSummary{
		Mailbox:        mailbox,
		MessageID:      normalizeMessageID(headers.Header.Get("Message-Id")),
		SequenceNumber: sequenceNumber,
		UID:            uid,
		ReceivedAt:     receivedAt,
		Subject:        headers.Header.Get("Subject"),
		From:           headers.Header.Get("From"),
		To:             headers.Header.Get("To"),
	}, nil
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

func buildSequenceSet(summaries []EmailSummary) string {
	values := make([]string, 0, len(summaries))
	for _, summary := range summaries {
		values = append(values, strconv.Itoa(summary.SequenceNumber))
	}

	return strings.Join(values, ",")
}

func mailboxPriority(mailbox string) int {
	lowerMailbox := strings.ToLower(mailbox)

	switch {
	case lowerMailbox == "inbox" || strings.HasSuffix(lowerMailbox, "/inbox"):
		return 0
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

func isSpamMailbox(mailbox string) bool {
	return strings.Contains(mailbox, "spam") || strings.Contains(mailbox, "junk")
}

func isTrashMailbox(mailbox string) bool {
	return strings.Contains(mailbox, "trash") || strings.Contains(mailbox, "bin")
}
