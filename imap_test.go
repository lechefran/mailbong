package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestIMAPClientLoginSuccess(t *testing.T) {
	server := newFakeIMAPServer(t, fakeIMAPServerConfig{
		email:    "user@example.com",
		password: `pa"ss\word`,
		accept:   true,
	})
	t.Cleanup(server.Close)

	client := &IMAPClient{
		Address:   server.Address(),
		Email:     "user@example.com",
		Password:  `pa"ss\word`,
		TLSConfig: server.ClientTLSConfig(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := client.Login(ctx)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if err := session.Logout(); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
}

func TestIMAPClientLoginRejected(t *testing.T) {
	server := newFakeIMAPServer(t, fakeIMAPServerConfig{
		email:    "user@example.com",
		password: "correct-password",
		accept:   false,
	})
	t.Cleanup(server.Close)

	client := &IMAPClient{
		Address:   server.Address(),
		Email:     "user@example.com",
		Password:  "wrong-password",
		TLSConfig: server.ClientTLSConfig(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := client.Login(ctx)
	if err == nil {
		t.Fatal("Login() error = nil, want failure")
	}
	if !strings.Contains(err.Error(), "login failed") {
		t.Fatalf("Login() error = %v, want login failure", err)
	}
}

func TestIMAPClientLoginRejectsCredentialsWithNewlines(t *testing.T) {
	client := &IMAPClient{
		Address:  "imap.example.com:993",
		Email:    "user@example.com",
		Password: "bad\npassword",
	}

	_, err := client.Login(context.Background())
	if err == nil {
		t.Fatal("Login() error = nil, want validation failure")
	}
	if !strings.Contains(err.Error(), "invalid password") {
		t.Fatalf("Login() error = %v, want invalid password", err)
	}
}

func TestIMAPClientLoginFallsBackAfterDNSLookupFailure(t *testing.T) {
	server := newFakeIMAPServer(t, fakeIMAPServerConfig{
		email:    "user@example.com",
		password: "correct-password",
		accept:   true,
	})
	t.Cleanup(server.Close)

	_, port, err := net.SplitHostPort(server.Address())
	if err != nil {
		t.Fatalf("SplitHostPort(server.Address()) error = %v", err)
	}

	client := &IMAPClient{
		Address:  net.JoinHostPort("imap.gmail.com", port),
		Email:    "user@example.com",
		Password: "correct-password",
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		DialTLSContext: func(ctx context.Context, address string, tlsConfig *tls.Config) (net.Conn, error) {
			return nil, &net.DNSError{
				Err:        "no such host",
				Name:       "imap.gmail.com",
				IsNotFound: true,
			}
		},
		LookupIPAddrs: func(ctx context.Context, host string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := client.Login(ctx)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	if err := session.Logout(); err != nil {
		t.Fatalf("Logout() error = %v", err)
	}
}

func TestIsRetryableConnectionError(t *testing.T) {
	testCases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "deadline exceeded", err: context.DeadlineExceeded, want: true},
		{name: "io eof", err: io.EOF, want: true},
		{name: "epipe", err: syscall.EPIPE, want: true},
		{name: "broken pipe text", err: errors.New("write: broken pipe"), want: true},
		{name: "connection reset text", err: errors.New("read: connection reset by peer"), want: true},
		{name: "closed network text", err: errors.New("use of closed network connection"), want: true},
		{name: "other", err: errors.New("permission denied"), want: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got := isRetryableConnectionError(testCase.err)
			if got != testCase.want {
				t.Fatalf("isRetryableConnectionError(%v) = %v, want %v", testCase.err, got, testCase.want)
			}
		})
	}
}

func TestParseSearchIDsFromLine(t *testing.T) {
	testCases := []struct {
		name       string
		line       string
		wantIDs    []uint32
		wantParsed bool
	}{
		{
			name:       "classic search ids",
			line:       "* SEARCH 10 20 30",
			wantIDs:    []uint32{10, 20, 30},
			wantParsed: true,
		},
		{
			name:       "esearch all range",
			line:       `* ESEARCH (TAG "A0001") UID ALL 100:102,200`,
			wantIDs:    []uint32{100, 101, 102, 200},
			wantParsed: true,
		},
		{
			name:       "esearch empty",
			line:       `* ESEARCH (TAG "A0001") COUNT 0`,
			wantIDs:    nil,
			wantParsed: true,
		},
		{
			name:       "unrelated line",
			line:       "* OK [CAPABILITY IMAP4rev1] ready",
			wantIDs:    nil,
			wantParsed: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			gotIDs, gotParsed := parseSearchIDsFromLine(testCase.line)
			if gotParsed != testCase.wantParsed {
				t.Fatalf("parseSearchIDsFromLine(%q) parsed = %v, want %v", testCase.line, gotParsed, testCase.wantParsed)
			}
			if !slices.Equal(gotIDs, testCase.wantIDs) {
				t.Fatalf("parseSearchIDsFromLine(%q) ids = %v, want %v", testCase.line, gotIDs, testCase.wantIDs)
			}
		})
	}
}

func TestParseSearchIDsPrefersLineWithIDs(t *testing.T) {
	lines := []imapResponseLine{
		{line: `* ESEARCH (TAG "A0001") COUNT 2`},
		{line: `* ESEARCH (TAG "A0001") UID ALL 10:11`},
	}

	ids, found := parseSearchIDs(lines)
	if !found {
		t.Fatal("parseSearchIDs() found = false, want true")
	}
	want := []uint32{10, 11}
	if !slices.Equal(ids, want) {
		t.Fatalf("parseSearchIDs() ids = %v, want %v", ids, want)
	}
}

func TestParseESearchIDsSupportsSplitAllSets(t *testing.T) {
	line := `* ESEARCH UID ALL 100:101, 200 300:301`
	ids := parseESearchIDs(line)
	want := []uint32{100, 101, 200, 300, 301}
	if !slices.Equal(ids, want) {
		t.Fatalf("parseESearchIDs() ids = %v, want %v", ids, want)
	}
}

func TestParseFlaggedFromFetchLine(t *testing.T) {
	testCases := []struct {
		name string
		line string
		want bool
	}{
		{
			name: "flagged",
			line: `* 1 FETCH (UID 123 FLAGS (\Seen \Flagged) INTERNALDATE "01-Apr-2026 08:00:00 +0000")`,
			want: true,
		},
		{
			name: "not flagged",
			line: `* 1 FETCH (UID 123 FLAGS (\Seen) INTERNALDATE "01-Apr-2026 08:00:00 +0000")`,
			want: false,
		},
		{
			name: "no flags",
			line: `* 1 FETCH (UID 123 INTERNALDATE "01-Apr-2026 08:00:00 +0000")`,
			want: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got := parseFlaggedFromFetchLine(testCase.line)
			if got != testCase.want {
				t.Fatalf("parseFlaggedFromFetchLine(%q) = %v, want %v", testCase.line, got, testCase.want)
			}
		})
	}
}

func TestIMAPSessionReadInboxViews(t *testing.T) {
	now := time.Date(2026, time.April, 1, 15, 30, 0, 0, time.UTC)
	server := newFakeIMAPServer(t, fakeIMAPServerConfig{
		email:    "user@example.com",
		password: "correct-password",
		accept:   true,
		mailboxes: []fakeIMAPMailbox{
			{
				Name:         "INBOX",
				UnquotedList: true,
				Messages: []fakeIMAPMessage{
					{
						UID:        101,
						MessageID:  "<today@example.com>",
						ReceivedAt: time.Date(2026, time.April, 1, 8, 0, 0, 0, time.UTC),
						Subject:    "Today message",
						From:       "alerts@example.com",
						To:         "user@example.com",
					},
					{
						UID:        102,
						MessageID:  "<week@example.com>",
						ReceivedAt: time.Date(2026, time.March, 28, 10, 0, 0, 0, time.UTC),
						Subject:    "This week message",
						From:       "reports@example.com",
						To:         "user@example.com",
					},
				},
			},
			{
				Name: "Archive",
				Messages: []fakeIMAPMessage{
					{
						UID:        103,
						MessageID:  "<month@example.com>",
						ReceivedAt: time.Date(2026, time.March, 10, 11, 0, 0, 0, time.UTC),
						Subject:    "This month message",
						From:       "digest@example.com",
						To:         "user@example.com",
					},
				},
			},
			{
				Name:      "BrokenFetch",
				FailFetch: true,
				Messages: []fakeIMAPMessage{
					{
						UID:        203,
						MessageID:  "<brokenfetch@example.com>",
						ReceivedAt: time.Date(2026, time.March, 20, 11, 0, 0, 0, time.UTC),
						Subject:    "Broken fetch message",
						From:       "brokenfetch@example.com",
						To:         "user@example.com",
					},
				},
			},
			{
				Name:       "BrokenSearch",
				FailSearch: true,
				Messages: []fakeIMAPMessage{
					{
						UID:        202,
						MessageID:  "<brokensearch@example.com>",
						ReceivedAt: time.Date(2026, time.March, 21, 11, 0, 0, 0, time.UTC),
						Subject:    "Broken search message",
						From:       "brokensearch@example.com",
						To:         "user@example.com",
					},
				},
			},
			{
				Name: "[Gmail]/Spam",
				Messages: []fakeIMAPMessage{
					{
						UID:        104,
						MessageID:  "<spam@example.com>",
						ReceivedAt: time.Date(2026, time.March, 29, 9, 0, 0, 0, time.UTC),
						Subject:    "Spam message",
						From:       "spam@example.com",
						To:         "user@example.com",
					},
				},
			},
			{
				Name: "[Gmail]/Trash",
				Messages: []fakeIMAPMessage{
					{
						UID:        105,
						MessageID:  "<trash@example.com>",
						ReceivedAt: time.Date(2026, time.March, 5, 9, 0, 0, 0, time.UTC),
						Subject:    "Trash message",
						From:       "trash@example.com",
						To:         "user@example.com",
					},
				},
			},
			{
				Name: "[Gmail]/All Mail",
				Messages: []fakeIMAPMessage{
					{
						UID:        106,
						MessageID:  "<today@example.com>",
						ReceivedAt: time.Date(2026, time.April, 1, 8, 0, 0, 0, time.UTC),
						Subject:    "Today message duplicate",
						From:       "alerts@example.com",
						To:         "user@example.com",
					},
					{
						UID:        107,
						MessageID:  "<allmailonly@example.com>",
						ReceivedAt: time.Date(2026, time.March, 8, 7, 0, 0, 0, time.UTC),
						Subject:    "All mail only message",
						From:       "allmail@example.com",
						To:         "user@example.com",
					},
				},
			},
			{
				Name:       "BrokenSelect",
				FailSelect: true,
			},
			{
				Name:     "Noselect",
				NoSelect: true,
				Messages: nil,
			},
		},
	})
	t.Cleanup(server.Close)

	client := &IMAPClient{
		Provider:  "gmail",
		Address:   server.Address(),
		Email:     "user@example.com",
		Password:  "correct-password",
		TLSConfig: server.ClientTLSConfig(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := client.Login(ctx)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	defer session.Logout()

	testCases := []struct {
		name         string
		read         func() ([]EmailSummary, error)
		wantSubjects []string
	}{
		{
			name: "all",
			read: func() ([]EmailSummary, error) {
				return session.ReadInboxAll()
			},
			wantSubjects: []string{
				"Today message",
				"This week message",
				"This month message",
				"Spam message",
				"Trash message",
				"All mail only message",
			},
		},
		{
			name: "today",
			read: func() ([]EmailSummary, error) {
				return session.ReadInboxToday(now)
			},
			wantSubjects: []string{
				"Today message",
			},
		},
		{
			name: "week",
			read: func() ([]EmailSummary, error) {
				return session.ReadInboxThisWeek(now)
			},
			wantSubjects: []string{
				"Today message",
				"This week message",
				"Spam message",
			},
		},
		{
			name: "month",
			read: func() ([]EmailSummary, error) {
				return session.ReadInboxThisMonth(now)
			},
			wantSubjects: []string{
				"Today message",
				"This week message",
				"This month message",
				"Spam message",
				"Trash message",
				"All mail only message",
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			emails, err := testCase.read()
			if err != nil {
				t.Fatalf("%s read error = %v", testCase.name, err)
			}

			subjects := make([]string, 0, len(emails))
			for _, email := range emails {
				subjects = append(subjects, email.Subject)
			}

			if !slices.Equal(subjects, testCase.wantSubjects) {
				t.Fatalf("%s subjects = %v, want %v", testCase.name, subjects, testCase.wantSubjects)
			}

			if testCase.name == "all" {
				for _, email := range emails {
					if email.MessageID == "<today@example.com>" && email.Mailbox != "INBOX" {
						t.Fatalf("duplicate message kept mailbox %q, want INBOX", email.Mailbox)
					}
				}
			}
		})
	}
}

func TestMailboxPriorityTargetsArchive(t *testing.T) {
	if archivePriority := mailboxPriority("Archive"); archivePriority != 1 {
		t.Fatalf("mailboxPriority(Archive) = %d, want 1", archivePriority)
	}
	if inboxPriority := mailboxPriority("INBOX"); inboxPriority >= mailboxPriority("Archive") {
		t.Fatalf("mailboxPriority(INBOX) = %d, want higher priority than Archive", inboxPriority)
	}
	if archivePriority := mailboxPriority("Archive"); archivePriority >= mailboxPriority("[Gmail]/Trash") {
		t.Fatalf("mailboxPriority(Archive) = %d, want higher priority than Trash", archivePriority)
	}
	if archivePriority := mailboxPriority("Archive"); archivePriority >= mailboxPriority("[Gmail]/All Mail") {
		t.Fatalf("mailboxPriority(Archive) = %d, want higher priority than All Mail", archivePriority)
	}
}

func TestPrioritizeDeleteMailboxesTargetsAllMailFirst(t *testing.T) {
	mailboxes := []string{
		"[Gmail]/Trash",
		"INBOX",
		"Archive",
		"[Gmail]/All Mail",
	}

	prioritized := prioritizeDeleteMailboxes(mailboxes, true)
	want := []string{
		"[Gmail]/All Mail",
		"INBOX",
		"Archive",
		"[Gmail]/Trash",
	}

	if !slices.Equal(prioritized, want) {
		t.Fatalf("prioritizeDeleteMailboxes() = %v, want %v", prioritized, want)
	}
}

func TestPrioritizeDeleteMailboxesLeavesAllMailInNormalOrderForNonGmail(t *testing.T) {
	mailboxes := []string{
		"[Gmail]/Trash",
		"INBOX",
		"Archive",
		"[Gmail]/All Mail",
	}

	prioritized := prioritizeDeleteMailboxes(mailboxes, false)
	want := []string{
		"INBOX",
		"Archive",
		"[Gmail]/Trash",
		"[Gmail]/All Mail",
	}

	if !slices.Equal(prioritized, want) {
		t.Fatalf("prioritizeDeleteMailboxes() = %v, want %v", prioritized, want)
	}
}

func TestIMAPSessionShouldMoveAllMailToTrash(t *testing.T) {
	testCases := []struct {
		name        string
		provider    string
		mailbox     string
		wantMove    bool
		withSession bool
	}{
		{
			name:        "gmail all mail",
			provider:    "gmail",
			mailbox:     "[Gmail]/All Mail",
			wantMove:    true,
			withSession: true,
		},
		{
			name:        "googlemail all mail",
			provider:    "googlemail",
			mailbox:     "[Gmail]/All Mail",
			wantMove:    true,
			withSession: true,
		},
		{
			name:        "gmail inbox",
			provider:    "gmail",
			mailbox:     "INBOX",
			wantMove:    false,
			withSession: true,
		},
		{
			name:        "non-gmail all mail name",
			provider:    "icloud",
			mailbox:     "[Gmail]/All Mail",
			wantMove:    false,
			withSession: true,
		},
		{
			name:        "nil session",
			provider:    "gmail",
			mailbox:     "[Gmail]/All Mail",
			wantMove:    false,
			withSession: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var session *IMAPSession
			if testCase.withSession {
				session = &IMAPSession{
					client: &IMAPClient{Provider: testCase.provider},
				}
			}

			got := session.shouldMoveAllMailToTrash(testCase.mailbox)
			if got != testCase.wantMove {
				t.Fatalf("shouldMoveAllMailToTrash(%q) = %v, want %v", testCase.mailbox, got, testCase.wantMove)
			}
		})
	}
}

func TestIsUnsupportedMoveError(t *testing.T) {
	testCases := []struct {
		name    string
		err     error
		want    bool
	}{
		{
			name: "unsupported uid command",
			err:  errors.New("A0007 BAD unsupported UID command"),
			want: true,
		},
		{
			name: "not supported",
			err:  errors.New("A0007 NO [CANNOT] MOVE not supported"),
			want: true,
		},
		{
			name: "timeout",
			err:  errors.New("read tcp: i/o timeout"),
			want: false,
		},
		{
			name: "nil",
			err:  nil,
			want: false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got := isUnsupportedMoveError(testCase.err)
			if got != testCase.want {
				t.Fatalf("isUnsupportedMoveError(%v) = %v, want %v", testCase.err, got, testCase.want)
			}
		})
	}
}

func TestIMAPSessionReadInboxAllHonorsDeadline(t *testing.T) {
	server := newFakeIMAPServer(t, fakeIMAPServerConfig{
		email:     "user@example.com",
		password:  "correct-password",
		accept:    true,
		stallList: 300 * time.Millisecond,
	})
	t.Cleanup(server.Close)

	client := &IMAPClient{
		Provider:  "gmail",
		Address:   server.Address(),
		Email:     "user@example.com",
		Password:  "correct-password",
		TLSConfig: server.ClientTLSConfig(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	session, err := client.Login(ctx)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	t.Cleanup(func() {
		_ = session.conn.Close()
	})

	_, err = session.ReadInboxAll()
	if err == nil {
		t.Fatal("ReadInboxAll() error = nil, want timeout")
	}

	lowerError := strings.ToLower(err.Error())
	if !strings.Contains(lowerError, "timeout") && !strings.Contains(lowerError, "deadline") {
		t.Fatalf("ReadInboxAll() error = %v, want timeout or deadline failure", err)
	}
}

func TestIMAPSessionReadInboxAllResetsDeadlinePerCommand(t *testing.T) {
	server := newFakeIMAPServer(t, fakeIMAPServerConfig{
		email:       "user@example.com",
		password:    "correct-password",
		accept:      true,
		stallList:   90 * time.Millisecond,
		stallSearch: 90 * time.Millisecond,
		mailboxes: []fakeIMAPMailbox{
			{
				Name: "INBOX",
				Messages: []fakeIMAPMessage{
					{
						UID:        101,
						MessageID:  "<today@example.com>",
						ReceivedAt: time.Date(2026, time.April, 1, 8, 0, 0, 0, time.UTC),
						Subject:    "Today message",
						From:       "alerts@example.com",
						To:         "user@example.com",
					},
				},
			},
		},
	})
	t.Cleanup(server.Close)

	client := &IMAPClient{
		Provider:  "gmail",
		Address:   server.Address(),
		Email:     "user@example.com",
		Password:  "correct-password",
		TLSConfig: server.ClientTLSConfig(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	session, err := client.Login(ctx)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	defer session.Logout()

	emails, err := session.ReadInboxAll()
	if err != nil {
		t.Fatalf("ReadInboxAll() error = %v", err)
	}
	if len(emails) != 1 {
		t.Fatalf("ReadInboxAll() emails = %v, want 1 email", emails)
	}
}

func TestIMAPSessionReadInboxAllReturnsPartialResultsAfterMailboxTimeout(t *testing.T) {
	now := time.Date(2026, time.April, 2, 15, 30, 0, 0, time.UTC)
	server := newFakeIMAPServer(t, fakeIMAPServerConfig{
		email:    "user@example.com",
		password: "correct-password",
		accept:   true,
		mailboxes: []fakeIMAPMailbox{
			{
				Name: "INBOX",
				Messages: []fakeIMAPMessage{
					{
						UID:        101,
						MessageID:  "<inbox@example.com>",
						ReceivedAt: time.Date(2026, time.April, 1, 8, 0, 0, 0, time.UTC),
						Subject:    "Inbox message",
						From:       "alerts@example.com",
						To:         "user@example.com",
					},
				},
			},
			{
				Name:                  "[Gmail]/Trash",
				StallSelect:           100 * time.Millisecond,
				StallAfterSelectCount: 1,
				Messages: []fakeIMAPMessage{
					{
						UID:        201,
						MessageID:  "<trash@example.com>",
						ReceivedAt: now,
						Subject:    "Trash message",
						From:       "trash@example.com",
						To:         "user@example.com",
					},
				},
			},
		},
	})
	t.Cleanup(server.Close)

	client := &IMAPClient{
		Provider:  "gmail",
		Address:   server.Address(),
		Email:     "user@example.com",
		Password:  "correct-password",
		TLSConfig: server.ClientTLSConfig(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	session, err := client.Login(ctx)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	defer session.Logout()

	emails, err := session.ReadInboxAll()
	if err != nil {
		t.Fatalf("ReadInboxAll() error = %v", err)
	}
	if len(emails) != 1 {
		t.Fatalf("ReadInboxAll() emails = %v, want 1 partial email", emails)
	}
	if emails[0].Subject != "Inbox message" {
		t.Fatalf("ReadInboxAll() subject = %q, want inbox email", emails[0].Subject)
	}
}

func TestIMAPSessionReadInboxAllFetchesLargeMailboxesInBatches(t *testing.T) {
	originalFetchBatchSize := fetchBatchSize
	fetchBatchSize = 2
	t.Cleanup(func() {
		fetchBatchSize = originalFetchBatchSize
	})

	messages := []fakeIMAPMessage{
		{
			UID:        101,
			MessageID:  "<one@example.com>",
			ReceivedAt: time.Date(2026, time.April, 1, 8, 0, 0, 0, time.UTC),
			Subject:    "One",
			From:       "one@example.com",
			To:         "user@example.com",
		},
		{
			UID:        102,
			MessageID:  "<two@example.com>",
			ReceivedAt: time.Date(2026, time.April, 1, 9, 0, 0, 0, time.UTC),
			Subject:    "Two",
			From:       "two@example.com",
			To:         "user@example.com",
		},
		{
			UID:        103,
			MessageID:  "<three@example.com>",
			ReceivedAt: time.Date(2026, time.April, 1, 10, 0, 0, 0, time.UTC),
			Subject:    "Three",
			From:       "three@example.com",
			To:         "user@example.com",
		},
	}

	server := newFakeIMAPServer(t, fakeIMAPServerConfig{
		email:    "user@example.com",
		password: "correct-password",
		accept:   true,
		mailboxes: []fakeIMAPMailbox{
			{
				Name:                  "INBOX",
				MaxFetchSequenceCount: 2,
				Messages:              messages,
			},
		},
	})
	t.Cleanup(server.Close)

	client := &IMAPClient{
		Address:   server.Address(),
		Email:     "user@example.com",
		Password:  "correct-password",
		TLSConfig: server.ClientTLSConfig(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := client.Login(ctx)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	defer session.Logout()

	emails, err := session.ReadInboxAll()
	if err != nil {
		t.Fatalf("ReadInboxAll() error = %v", err)
	}
	if len(emails) != 3 {
		t.Fatalf("ReadInboxAll() emails = %v, want 3 batched emails", emails)
	}
}

func TestIMAPSessionDeleteInboxOlderThanDays(t *testing.T) {
	now := time.Date(2026, time.April, 2, 15, 30, 0, 0, time.UTC)
	server := newFakeIMAPServer(t, fakeIMAPServerConfig{
		email:    "user@example.com",
		password: "correct-password",
		accept:   true,
		mailboxes: []fakeIMAPMailbox{
			{
				Name: "INBOX",
				Messages: []fakeIMAPMessage{
					{
						UID:        101,
						MessageID:  "<old@example.com>",
						ReceivedAt: time.Date(2026, time.January, 1, 8, 0, 0, 0, time.UTC),
						Subject:    "Old message",
						From:       "alerts@example.com",
						To:         "user@example.com",
					},
					{
						UID:        102,
						MessageID:  "<cutoff@example.com>",
						ReceivedAt: time.Date(2026, time.January, 2, 9, 0, 0, 0, time.UTC),
						Subject:    "Cutoff message",
						From:       "cutoff@example.com",
						To:         "user@example.com",
						Flagged:    true,
					},
					{
						UID:        103,
						MessageID:  "<newer@example.com>",
						ReceivedAt: time.Date(2026, time.January, 3, 10, 0, 0, 0, time.UTC),
						Subject:    "Newer message",
						From:       "newer@example.com",
						To:         "user@example.com",
					},
					{
						UID:        104,
						MessageID:  "<today@example.com>",
						ReceivedAt: time.Date(2026, time.April, 1, 8, 0, 0, 0, time.UTC),
						Subject:    "Today message",
						From:       "alerts@example.com",
						To:         "user@example.com",
					},
				},
			},
			{
				Name: "[Gmail]/All Mail",
				Messages: []fakeIMAPMessage{
					{
						UID:        105,
						MessageID:  "<old@example.com>",
						ReceivedAt: time.Date(2026, time.January, 1, 8, 0, 0, 0, time.UTC),
						Subject:    "Old message duplicate",
						From:       "alerts@example.com",
						To:         "user@example.com",
					},
					{
						UID:        106,
						MessageID:  "<archived-old@example.com>",
						ReceivedAt: time.Date(2025, time.December, 30, 7, 0, 0, 0, time.UTC),
						Subject:    "Archived old message",
						From:       "allmail@example.com",
						To:         "user@example.com",
					},
				},
			},
		},
	})
	t.Cleanup(server.Close)

	client := &IMAPClient{
		Address:   server.Address(),
		Email:     "user@example.com",
		Password:  "correct-password",
		TLSConfig: server.ClientTLSConfig(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := client.Login(ctx)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	defer session.Logout()

	deletedEmails, err := session.DeleteInboxOlderThanDays(now, 90, false)
	if err != nil {
		t.Fatalf("DeleteInboxOlderThanDays() error = %v", err)
	}

	deletedSubjects := make([]string, 0, len(deletedEmails))
	for _, email := range deletedEmails {
		deletedSubjects = append(deletedSubjects, email.Subject)
	}

	wantDeletedSubjects := []string{
		"Old message",
		"Archived old message",
	}
	if !slices.Equal(deletedSubjects, wantDeletedSubjects) {
		t.Fatalf("DeleteInboxOlderThanDays() subjects = %v, want %v", deletedSubjects, wantDeletedSubjects)
	}

	remainingEmails, err := session.ReadInboxAll()
	if err != nil {
		t.Fatalf("ReadInboxAll() error = %v", err)
	}
	remainingSubjects := make([]string, 0, len(remainingEmails))
	for _, email := range remainingEmails {
		remainingSubjects = append(remainingSubjects, email.Subject)
	}
	wantRemainingSubjects := []string{
		"Cutoff message",
		"Newer message",
		"Today message",
	}
	if !slices.Equal(remainingSubjects, wantRemainingSubjects) {
		t.Fatalf("remaining subjects = %v, want %v", remainingSubjects, wantRemainingSubjects)
	}
}

func TestIMAPSessionDeleteInboxOlderThanDaysSkipsFlaggedEvenWhenRequested(t *testing.T) {
	now := time.Date(2026, time.April, 2, 15, 30, 0, 0, time.UTC)
	server := newFakeIMAPServer(t, fakeIMAPServerConfig{
		email:    "user@example.com",
		password: "correct-password",
		accept:   true,
		mailboxes: []fakeIMAPMailbox{
			{
				Name: "INBOX",
				Messages: []fakeIMAPMessage{
					{
						UID:        101,
						MessageID:  "<flagged-old@example.com>",
						ReceivedAt: time.Date(2026, time.January, 2, 9, 0, 0, 0, time.UTC),
						Subject:    "Flagged old message",
						From:       "flagged@example.com",
						To:         "user@example.com",
						Flagged:    true,
					},
				},
			},
		},
	})
	t.Cleanup(server.Close)

	client := &IMAPClient{
		Address:   server.Address(),
		Email:     "user@example.com",
		Password:  "correct-password",
		TLSConfig: server.ClientTLSConfig(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := client.Login(ctx)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	defer session.Logout()

	deletedEmails, err := session.DeleteInboxOlderThanDays(now, 90, true)
	if err != nil {
		t.Fatalf("DeleteInboxOlderThanDays() error = %v", err)
	}
	if len(deletedEmails) != 0 {
		t.Fatalf("DeleteInboxOlderThanDays() deleted = %v, want no flagged emails deleted", deletedEmails)
	}

	remainingEmails, err := session.ReadInboxAll()
	if err != nil {
		t.Fatalf("ReadInboxAll() error = %v", err)
	}
	if len(remainingEmails) != 1 {
		t.Fatalf("ReadInboxAll() emails = %v, want 1 flagged email remaining", remainingEmails)
	}
	if remainingEmails[0].Subject != "Flagged old message" {
		t.Fatalf("remaining subject = %q, want flagged email", remainingEmails[0].Subject)
	}
}

func TestIMAPSessionDeleteInboxOlderThanDaysSkipsFlaggedIfSearchReturnsIt(t *testing.T) {
	now := time.Date(2026, time.April, 2, 15, 30, 0, 0, time.UTC)
	server := newFakeIMAPServer(t, fakeIMAPServerConfig{
		email:    "user@example.com",
		password: "correct-password",
		accept:   true,
		mailboxes: []fakeIMAPMailbox{
			{
				Name:            "[Gmail]/All Mail",
				IgnoreUnflagged: true,
				Messages: []fakeIMAPMessage{
					{
						UID:        101,
						MessageID:  "<flagged-old@example.com>",
						ReceivedAt: time.Date(2025, time.December, 1, 8, 0, 0, 0, time.UTC),
						Subject:    "Flagged old message",
						From:       "flagged@example.com",
						To:         "user@example.com",
						Flagged:    true,
					},
					{
						UID:        102,
						MessageID:  "<regular-old@example.com>",
						ReceivedAt: time.Date(2025, time.December, 2, 8, 0, 0, 0, time.UTC),
						Subject:    "Regular old message",
						From:       "regular@example.com",
						To:         "user@example.com",
					},
				},
			},
			{
				Name: "[Gmail]/Trash",
			},
		},
	})
	t.Cleanup(server.Close)

	client := &IMAPClient{
		Provider:  "gmail",
		Address:   server.Address(),
		Email:     "user@example.com",
		Password:  "correct-password",
		TLSConfig: server.ClientTLSConfig(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := client.Login(ctx)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	defer session.Logout()

	deletedEmails, err := session.DeleteInboxOlderThanDays(now, 90, false)
	if err != nil {
		t.Fatalf("DeleteInboxOlderThanDays() error = %v", err)
	}
	if len(deletedEmails) != 1 {
		t.Fatalf("DeleteInboxOlderThanDays() deleted = %v, want only non-flagged email deleted", deletedEmails)
	}
	if deletedEmails[0].Subject != "Regular old message" {
		t.Fatalf("deleted subject = %q, want regular old message", deletedEmails[0].Subject)
	}

	remainingEmails, err := session.ReadInboxAll()
	if err != nil {
		t.Fatalf("ReadInboxAll() error = %v", err)
	}
	if len(remainingEmails) != 1 {
		t.Fatalf("ReadInboxAll() emails = %v, want 1 flagged email remaining", remainingEmails)
	}
	if remainingEmails[0].Subject != "Flagged old message" {
		t.Fatalf("remaining subject = %q, want flagged email", remainingEmails[0].Subject)
	}
}

func TestIMAPSessionDeleteInboxOlderThanDaysGmailAllMailUsesPerEmailDelete(t *testing.T) {
	now := time.Date(2026, time.April, 2, 15, 30, 0, 0, time.UTC)
	server := newFakeIMAPServer(t, fakeIMAPServerConfig{
		email:    "user@example.com",
		password: "correct-password",
		accept:   true,
		mailboxes: []fakeIMAPMailbox{
			{
				Name: "INBOX",
				Messages: []fakeIMAPMessage{
					{
						UID:        101,
						MessageID:  "<inbox-old@example.com>",
						ReceivedAt: time.Date(2026, time.January, 1, 8, 0, 0, 0, time.UTC),
						Subject:    "Inbox old message",
						From:       "alerts@example.com",
						To:         "user@example.com",
					},
				},
			},
			{
				Name: "[Gmail]/All Mail",
				Messages: []fakeIMAPMessage{
					{
						UID:        201,
						MessageID:  "<allmail-old@example.com>",
						ReceivedAt: time.Date(2025, time.December, 1, 8, 0, 0, 0, time.UTC),
						Subject:    "All Mail old message",
						From:       "allmail@example.com",
						To:         "user@example.com",
					},
				},
			},
			{
				Name: "[Gmail]/Trash",
			},
		},
	})
	t.Cleanup(server.Close)

	client := &IMAPClient{
		Provider:  "gmail",
		Address:   server.Address(),
		Email:     "user@example.com",
		Password:  "correct-password",
		TLSConfig: server.ClientTLSConfig(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := client.Login(ctx)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	defer session.Logout()

	deletedEmails, err := session.DeleteInboxOlderThanDays(now, 90, false)
	if err != nil {
		t.Fatalf("DeleteInboxOlderThanDays() error = %v", err)
	}

	deletedSubjects := make([]string, 0, len(deletedEmails))
	for _, email := range deletedEmails {
		deletedSubjects = append(deletedSubjects, email.Subject)
	}
	wantDeletedSubjects := []string{
		"All Mail old message",
		"Inbox old message",
	}
	if !slices.Equal(deletedSubjects, wantDeletedSubjects) {
		t.Fatalf("DeleteInboxOlderThanDays() subjects = %v, want %v", deletedSubjects, wantDeletedSubjects)
	}
}

func TestIMAPSessionDeleteInboxOlderThanDaysDeletesEachMessageIndividually(t *testing.T) {
	now := time.Date(2026, time.April, 2, 15, 30, 0, 0, time.UTC)
	server := newFakeIMAPServer(t, fakeIMAPServerConfig{
		email:    "user@example.com",
		password: "correct-password",
		accept:   true,
		mailboxes: []fakeIMAPMailbox{
			{
				Name: "INBOX",
				Messages: []fakeIMAPMessage{
					{
						UID:        101,
						MessageID:  "<old-one@example.com>",
						ReceivedAt: time.Date(2025, time.December, 1, 8, 0, 0, 0, time.UTC),
						Subject:    "Old one",
						From:       "one@example.com",
						To:         "user@example.com",
					},
					{
						UID:        102,
						MessageID:  "<old-two@example.com>",
						ReceivedAt: time.Date(2025, time.December, 2, 8, 0, 0, 0, time.UTC),
						Subject:    "Old two",
						From:       "two@example.com",
						To:         "user@example.com",
					},
					{
						UID:        103,
						MessageID:  "<old-three@example.com>",
						ReceivedAt: time.Date(2025, time.December, 3, 8, 0, 0, 0, time.UTC),
						Subject:    "Old three",
						From:       "three@example.com",
						To:         "user@example.com",
					},
				},
			},
		},
	})
	t.Cleanup(server.Close)

	client := &IMAPClient{
		Address:   server.Address(),
		Email:     "user@example.com",
		Password:  "correct-password",
		TLSConfig: server.ClientTLSConfig(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := client.Login(ctx)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	defer session.Logout()

	deletedEmails, err := session.DeleteInboxOlderThanDays(now, 90, false)
	if err != nil {
		t.Fatalf("DeleteInboxOlderThanDays() error = %v", err)
	}
	if len(deletedEmails) != 3 {
		t.Fatalf("DeleteInboxOlderThanDays() deleted = %v, want 3 emails", deletedEmails)
	}
	deletedSubjects := make([]string, 0, len(deletedEmails))
	for _, email := range deletedEmails {
		deletedSubjects = append(deletedSubjects, email.Subject)
	}
	wantDeletedSubjects := []string{"Old one", "Old two", "Old three"}
	if !slices.Equal(deletedSubjects, wantDeletedSubjects) {
		t.Fatalf("DeleteInboxOlderThanDays() subjects = %v, want %v", deletedSubjects, wantDeletedSubjects)
	}

	remainingEmails, err := session.ReadInboxAll()
	if err != nil {
		t.Fatalf("ReadInboxAll() error = %v", err)
	}
	if len(remainingEmails) != 0 {
		t.Fatalf("remaining emails = %v, want none", remainingEmails)
	}
}

func TestIMAPSessionDeleteInboxOlderThanDaysSkipsStoreFailures(t *testing.T) {
	now := time.Date(2026, time.April, 2, 15, 30, 0, 0, time.UTC)
	server := newFakeIMAPServer(t, fakeIMAPServerConfig{
		email:    "user@example.com",
		password: "correct-password",
		accept:   true,
		mailboxes: []fakeIMAPMailbox{
			{
				Name:      "Apparel",
				FailStore: true,
				Messages: []fakeIMAPMessage{
					{
						UID:        101,
						MessageID:  "<apparel-one@example.com>",
						ReceivedAt: time.Date(2025, time.December, 1, 8, 0, 0, 0, time.UTC),
						Subject:    "Apparel one",
						From:       "one@example.com",
						To:         "user@example.com",
					},
					{
						UID:        102,
						MessageID:  "<apparel-two@example.com>",
						ReceivedAt: time.Date(2025, time.December, 2, 8, 0, 0, 0, time.UTC),
						Subject:    "Apparel two",
						From:       "two@example.com",
						To:         "user@example.com",
					},
				},
			},
		},
	})
	t.Cleanup(server.Close)

	client := &IMAPClient{
		Address:   server.Address(),
		Email:     "user@example.com",
		Password:  "correct-password",
		TLSConfig: server.ClientTLSConfig(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := client.Login(ctx)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	defer session.Logout()

	deletedEmails, err := session.DeleteInboxOlderThanDays(now, 90, false)
	if err != nil {
		t.Fatalf("DeleteInboxOlderThanDays() error = %v", err)
	}
	if len(deletedEmails) != 0 {
		t.Fatalf("DeleteInboxOlderThanDays() deleted = %v, want no emails deleted on store failures", deletedEmails)
	}

	remainingEmails, err := session.ReadInboxAll()
	if err != nil {
		t.Fatalf("ReadInboxAll() error = %v", err)
	}
	if len(remainingEmails) != 2 {
		t.Fatalf("remaining emails = %v, want both emails retained", remainingEmails)
	}
}

func TestIMAPSessionDeleteInboxOlderThanDaysRecoversAfterAllMailStoreTimeout(t *testing.T) {
	now := time.Date(2026, time.April, 2, 15, 30, 0, 0, time.UTC)
	server := newFakeIMAPServer(t, fakeIMAPServerConfig{
		email:    "user@example.com",
		password: "correct-password",
		accept:   true,
		mailboxes: []fakeIMAPMailbox{
			{
				Name:               "[Gmail]/All Mail",
				StallStore:         100 * time.Millisecond,
				StallStoreFirstOps: 1,
				Messages: []fakeIMAPMessage{
					{
						UID:        101,
						MessageID:  "<allmail-one@example.com>",
						ReceivedAt: time.Date(2025, time.December, 1, 8, 0, 0, 0, time.UTC),
						Subject:    "All Mail one",
						From:       "one@example.com",
						To:         "user@example.com",
					},
					{
						UID:        102,
						MessageID:  "<allmail-two@example.com>",
						ReceivedAt: time.Date(2025, time.December, 2, 8, 0, 0, 0, time.UTC),
						Subject:    "All Mail two",
						From:       "two@example.com",
						To:         "user@example.com",
					},
				},
			},
			{
				Name: "[Gmail]/Trash",
			},
		},
	})
	t.Cleanup(server.Close)

	client := &IMAPClient{
		Provider:  "gmail",
		Address:   server.Address(),
		Email:     "user@example.com",
		Password:  "correct-password",
		TLSConfig: server.ClientTLSConfig(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := client.Login(ctx)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	defer session.Logout()
	session.commandTimeout = 50 * time.Millisecond

	deletedEmails, err := session.DeleteInboxOlderThanDays(now, 90, false)
	if err != nil {
		t.Fatalf("DeleteInboxOlderThanDays() error = %v", err)
	}
	if len(deletedEmails) != 2 {
		t.Fatalf("DeleteInboxOlderThanDays() deleted = %v, want both all mail emails deleted", deletedEmails)
	}

	remainingEmails, err := session.ReadInboxAll()
	if err != nil {
		t.Fatalf("ReadInboxAll() error = %v", err)
	}
	if len(remainingEmails) != 0 {
		t.Fatalf("remaining emails = %v, want none", remainingEmails)
	}
}

func TestIMAPSessionDeleteInboxOlderThanDaysRescansMovedTrashCopies(t *testing.T) {
	now := time.Date(2026, time.April, 2, 15, 30, 0, 0, time.UTC)
	server := newFakeIMAPServer(t, fakeIMAPServerConfig{
		email:    "user@example.com",
		password: "correct-password",
		accept:   true,
		mailboxes: []fakeIMAPMailbox{
			{
				Name:          "INBOX",
				DeleteMovesTo: "[Gmail]/Trash",
				Messages: []fakeIMAPMessage{
					{
						UID:        301,
						MessageID:  "<moved-to-trash@example.com>",
						ReceivedAt: time.Date(2026, time.April, 1, 7, 0, 0, 0, time.UTC),
						Subject:    "Moved to trash first",
						From:       "alerts@example.com",
						To:         "user@example.com",
					},
				},
			},
			{
				Name:     "[Gmail]/Trash",
				Messages: nil,
			},
		},
	})
	t.Cleanup(server.Close)

	client := &IMAPClient{
		Address:   server.Address(),
		Email:     "user@example.com",
		Password:  "correct-password",
		TLSConfig: server.ClientTLSConfig(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	session, err := client.Login(ctx)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	defer session.Logout()

	deletedEmails, err := session.DeleteInboxOlderThanDays(now, 1, false)
	if err != nil {
		t.Fatalf("DeleteInboxOlderThanDays() error = %v", err)
	}
	if len(deletedEmails) != 1 {
		t.Fatalf("DeleteInboxOlderThanDays() deleted = %v, want 1 logical email", deletedEmails)
	}
	if deletedEmails[0].Mailbox != "INBOX" {
		t.Fatalf("DeleteInboxOlderThanDays() kept mailbox %q, want INBOX", deletedEmails[0].Mailbox)
	}

	remainingEmails, err := session.ReadInboxAll()
	if err != nil {
		t.Fatalf("ReadInboxAll() error = %v", err)
	}
	if len(remainingEmails) != 0 {
		t.Fatalf("remaining emails = %v, want none", remainingEmails)
	}
}

func TestIMAPSessionDeleteInboxOlderThanDaysSkipsTimedOutMailboxDeletes(t *testing.T) {
	now := time.Date(2026, time.April, 2, 15, 30, 0, 0, time.UTC)
	server := newFakeIMAPServer(t, fakeIMAPServerConfig{
		email:    "user@example.com",
		password: "correct-password",
		accept:   true,
		mailboxes: []fakeIMAPMailbox{
			{
				Name: "INBOX",
				Messages: []fakeIMAPMessage{
					{
						UID:        101,
						MessageID:  "<old-inbox@example.com>",
						ReceivedAt: time.Date(2026, time.January, 1, 8, 0, 0, 0, time.UTC),
						Subject:    "Old inbox message",
						From:       "alerts@example.com",
						To:         "user@example.com",
					},
				},
			},
			{
				Name:                  "[Gmail]/Trash",
				StallSelect:           100 * time.Millisecond,
				StallAfterSelectCount: 2,
				Messages: []fakeIMAPMessage{
					{
						UID:        201,
						MessageID:  "<old-trash@example.com>",
						ReceivedAt: time.Date(2026, time.January, 1, 9, 0, 0, 0, time.UTC),
						Subject:    "Old trash message",
						From:       "trash@example.com",
						To:         "user@example.com",
					},
				},
			},
		},
	})
	t.Cleanup(server.Close)

	client := &IMAPClient{
		Address:   server.Address(),
		Email:     "user@example.com",
		Password:  "correct-password",
		TLSConfig: server.ClientTLSConfig(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	session, err := client.Login(ctx)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	defer session.Logout()

	deletedEmails, err := session.DeleteInboxOlderThanDays(now, 90, false)
	if err != nil {
		t.Fatalf("DeleteInboxOlderThanDays() error = %v", err)
	}

	if len(deletedEmails) != 2 {
		t.Fatalf("DeleteInboxOlderThanDays() deleted = %v, want 2 deleted emails", deletedEmails)
	}
	if deletedEmails[0].Subject != "Old inbox message" {
		t.Fatalf("DeleteInboxOlderThanDays() subject = %q, want inbox email", deletedEmails[0].Subject)
	}
}

func TestIMAPSessionDeleteInboxOlderThanDaysReturnsPartialResultsAfterSearchTimeout(t *testing.T) {
	now := time.Date(2026, time.April, 2, 15, 30, 0, 0, time.UTC)
	server := newFakeIMAPServer(t, fakeIMAPServerConfig{
		email:    "user@example.com",
		password: "correct-password",
		accept:   true,
		mailboxes: []fakeIMAPMailbox{
			{
				Name: "INBOX",
				Messages: []fakeIMAPMessage{
					{
						UID:        101,
						MessageID:  "<old-inbox@example.com>",
						ReceivedAt: time.Date(2026, time.January, 1, 8, 0, 0, 0, time.UTC),
						Subject:    "Old inbox message",
						From:       "alerts@example.com",
						To:         "user@example.com",
					},
				},
			},
			{
				Name:                  "[Gmail]/Trash",
				StallSelect:           100 * time.Millisecond,
				StallAfterSelectCount: 1,
				Messages: []fakeIMAPMessage{
					{
						UID:        201,
						MessageID:  "<old-trash@example.com>",
						ReceivedAt: time.Date(2026, time.January, 1, 9, 0, 0, 0, time.UTC),
						Subject:    "Old trash message",
						From:       "trash@example.com",
						To:         "user@example.com",
					},
				},
			},
		},
	})
	t.Cleanup(server.Close)

	client := &IMAPClient{
		Address:   server.Address(),
		Email:     "user@example.com",
		Password:  "correct-password",
		TLSConfig: server.ClientTLSConfig(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	session, err := client.Login(ctx)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	defer session.Logout()

	deletedEmails, err := session.DeleteInboxOlderThanDays(now, 90, false)
	if err != nil {
		t.Fatalf("DeleteInboxOlderThanDays() error = %v", err)
	}
	if len(deletedEmails) != 1 {
		t.Fatalf("DeleteInboxOlderThanDays() deleted = %v, want 1 partial delete", deletedEmails)
	}
	if deletedEmails[0].Subject != "Old inbox message" {
		t.Fatalf("DeleteInboxOlderThanDays() subject = %q, want inbox email", deletedEmails[0].Subject)
	}
}

type fakeIMAPServer struct {
	listener     net.Listener
	config       *tls.Config
	email        string
	password     string
	accept       bool
	mailboxes    []fakeIMAPMailbox
	selected     string
	stallList    time.Duration
	stallSearch  time.Duration
	selectCounts map[string]int
	storeCounts  map[string]int
}

type fakeIMAPServerConfig struct {
	email       string
	password    string
	accept      bool
	mailboxes   []fakeIMAPMailbox
	stallList   time.Duration
	stallSearch time.Duration
}

type fakeIMAPMailbox struct {
	Name                  string
	NoSelect              bool
	UnquotedList          bool
	IgnoreUnflagged       bool
	FailSelect            bool
	FailSearch            bool
	FailFetch             bool
	FailStore             bool
	RequireMinimalFetch   bool
	DeleteMovesTo         string
	StallSelect           time.Duration
	StallAfterSelectCount int
	StallStore            time.Duration
	StallStoreFirstOps    int
	StallStoreMinCount    int
	MaxFetchSequenceCount int
	Messages              []fakeIMAPMessage
}

type fakeIMAPMessage struct {
	UID        uint32
	MessageID  string
	ReceivedAt time.Time
	Subject    string
	From       string
	To         string
	Flagged    bool
	Deleted    bool
}

func newFakeIMAPServer(t *testing.T, config fakeIMAPServerConfig) *fakeIMAPServer {
	t.Helper()

	certificate := newTestCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("tls.Listen() error = %v", err)
	}

	server := &fakeIMAPServer{
		listener: listener,
		config: &tls.Config{
			RootCAs:    newCertPool(t, certificate),
			ServerName: "localhost",
			MinVersion: tls.VersionTLS12,
		},
		email:        config.email,
		password:     config.password,
		accept:       config.accept,
		mailboxes:    config.mailboxes,
		stallList:    config.stallList,
		stallSearch:  config.stallSearch,
		selectCounts: make(map[string]int),
		storeCounts:  make(map[string]int),
	}

	go server.serve(t)
	return server
}

func (s *fakeIMAPServer) Address() string {
	return s.listener.Addr().String()
}

func (s *fakeIMAPServer) ClientTLSConfig() *tls.Config {
	return s.config.Clone()
}

func (s *fakeIMAPServer) Close() {
	_ = s.listener.Close()
}

func (s *fakeIMAPServer) serve(t *testing.T) {
	t.Helper()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}

		go s.handleConn(t, conn)
	}
}

func (s *fakeIMAPServer) handleConn(t *testing.T, conn net.Conn) {
	t.Helper()
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	if _, err := writer.WriteString("* OK IMAP4rev1 ready\r\n"); err != nil {
		t.Logf("WriteString(greeting) error = %v", err)
		return
	}
	if err := writer.Flush(); err != nil {
		t.Logf("Flush(greeting) error = %v", err)
		return
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		tag, command, args, err := parseIMAPCommand(strings.TrimRight(line, "\r\n"))
		if err != nil {
			t.Logf("parseIMAPCommand() error = %v", err)
			return
		}

		switch command {
		case "LOGIN":
			loginArgs, err := parseIMAPQuotedArgs(args)
			if err != nil {
				t.Logf("parseIMAPQuotedArgs(LOGIN) error = %v", err)
				return
			}

			if len(loginArgs) != 2 {
				t.Logf("LOGIN args = %v, want 2 values", args)
				return
			}

			if s.accept && loginArgs[0] == s.email && loginArgs[1] == s.password {
				if _, err := fmt.Fprintf(writer, "%s OK LOGIN completed\r\n", tag); err != nil {
					t.Logf("LOGIN OK response error = %v", err)
					return
				}
			} else {
				if _, err := fmt.Fprintf(writer, "%s NO invalid credentials\r\n", tag); err != nil {
					t.Logf("LOGIN NO response error = %v", err)
					return
				}
			}
		case "LIST":
			if s.stallList > 0 {
				time.Sleep(s.stallList)
			}
			if err := s.writeListResponse(writer, tag); err != nil {
				t.Logf("writeListResponse() error = %v", err)
				return
			}
		case "SELECT":
			selectArgs, err := parseIMAPQuotedArgs(args)
			if err != nil {
				t.Logf("parseIMAPQuotedArgs(SELECT) error = %v", err)
				return
			}
			mailbox, ok := s.findMailbox(selectArgs)
			if !ok || mailbox.NoSelect || mailbox.FailSelect {
				if _, err := fmt.Fprintf(writer, "%s NO unknown mailbox\r\n", tag); err != nil {
					t.Logf("SELECT NO response error = %v", err)
					return
				}
				break
			}
			s.selectCounts[mailbox.Name]++
			if mailbox.StallSelect > 0 && s.selectCounts[mailbox.Name] >= mailbox.StallAfterSelectCount {
				time.Sleep(mailbox.StallSelect)
			}
			s.selected = mailbox.Name
			if _, err := fmt.Fprintf(writer, "* %d EXISTS\r\n", len(mailbox.Messages)); err != nil {
				t.Logf("SELECT EXISTS response error = %v", err)
				return
			}
			if _, err := fmt.Fprintf(writer, "%s OK [READ-WRITE] SELECT completed\r\n", tag); err != nil {
				t.Logf("SELECT OK response error = %v", err)
				return
			}
		case "SEARCH":
			if s.stallSearch > 0 {
				time.Sleep(s.stallSearch)
			}
			sequenceNumbers, err := s.searchMessages(s.selected, args)
			if err != nil {
				if _, writeErr := fmt.Fprintf(writer, "%s NO %s\r\n", tag, err); writeErr != nil {
					t.Logf("SEARCH NO response error = %v", writeErr)
					return
				}
				break
			}

			var values []string
			for _, sequenceNumber := range sequenceNumbers {
				values = append(values, strconv.Itoa(sequenceNumber))
			}

			if len(values) == 0 {
				if _, err := writer.WriteString("* SEARCH\r\n"); err != nil {
					t.Logf("SEARCH empty response error = %v", err)
					return
				}
			} else {
				if _, err := fmt.Fprintf(writer, "* SEARCH %s\r\n", strings.Join(values, " ")); err != nil {
					t.Logf("SEARCH response error = %v", err)
					return
				}
			}
			if _, err := fmt.Fprintf(writer, "%s OK SEARCH completed\r\n", tag); err != nil {
				t.Logf("SEARCH OK response error = %v", err)
				return
			}
		case "STORE":
			if err := s.storeDeletedFlags(s.selected, args); err != nil {
				if _, writeErr := fmt.Fprintf(writer, "%s NO %s\r\n", tag, err); writeErr != nil {
					t.Logf("STORE NO response error = %v", writeErr)
					return
				}
				break
			}
			if _, err := fmt.Fprintf(writer, "%s OK STORE completed\r\n", tag); err != nil {
				t.Logf("STORE OK response error = %v", err)
				return
			}
		case "UID":
			uidParts := strings.SplitN(strings.TrimSpace(args), " ", 2)
			if len(uidParts) != 2 {
				if _, err := fmt.Fprintf(writer, "%s BAD unsupported UID command\r\n", tag); err != nil {
					t.Logf("UID BAD response error = %v", err)
					return
				}
				break
			}
			subCommand := strings.ToUpper(uidParts[0])
			switch subCommand {
			case "SEARCH":
				uids, err := s.searchMessageUIDs(s.selected, uidParts[1])
				if err != nil {
					if _, writeErr := fmt.Fprintf(writer, "%s NO %s\r\n", tag, err); writeErr != nil {
						t.Logf("UID SEARCH NO response error = %v", writeErr)
						return
					}
					break
				}

				if len(uids) == 0 {
					if _, err := writer.WriteString("* SEARCH\r\n"); err != nil {
						t.Logf("UID SEARCH empty response error = %v", err)
						return
					}
				} else {
					values := make([]string, 0, len(uids))
					for _, uid := range uids {
						values = append(values, strconv.FormatUint(uint64(uid), 10))
					}
					if _, err := fmt.Fprintf(writer, "* SEARCH %s\r\n", strings.Join(values, " ")); err != nil {
						t.Logf("UID SEARCH response error = %v", err)
						return
					}
				}
				if _, err := fmt.Fprintf(writer, "%s OK UID SEARCH completed\r\n", tag); err != nil {
					t.Logf("UID SEARCH OK response error = %v", err)
					return
				}
			case "FETCH":
				if err := s.writeUIDFetchResponse(writer, tag, s.selected, uidParts[1]); err != nil {
					if _, writeErr := fmt.Fprintf(writer, "%s NO %s\r\n", tag, err); writeErr != nil {
						t.Logf("UID FETCH NO response error = %v", writeErr)
						return
					}
				}
			case "STORE":
				if err := s.storeDeletedFlagsByUID(s.selected, uidParts[1]); err != nil {
					if _, writeErr := fmt.Fprintf(writer, "%s NO %s\r\n", tag, err); writeErr != nil {
						t.Logf("UID STORE NO response error = %v", writeErr)
						return
					}
					break
				}
				if _, err := fmt.Fprintf(writer, "%s OK UID STORE completed\r\n", tag); err != nil {
					t.Logf("UID STORE OK response error = %v", err)
					return
				}
			case "MOVE":
				if err := s.moveMessagesByUID(s.selected, uidParts[1]); err != nil {
					if _, writeErr := fmt.Fprintf(writer, "%s NO %s\r\n", tag, err); writeErr != nil {
						t.Logf("UID MOVE NO response error = %v", writeErr)
						return
					}
					break
				}
				if _, err := fmt.Fprintf(writer, "%s OK UID MOVE completed\r\n", tag); err != nil {
					t.Logf("UID MOVE OK response error = %v", err)
					return
				}
			default:
				if _, err := fmt.Fprintf(writer, "%s BAD unsupported UID command\r\n", tag); err != nil {
					t.Logf("UID BAD response error = %v", err)
					return
				}
			}
		case "EXPUNGE":
			if err := s.expungeMailbox(s.selected); err != nil {
				if _, writeErr := fmt.Fprintf(writer, "%s NO %s\r\n", tag, err); writeErr != nil {
					t.Logf("EXPUNGE NO response error = %v", writeErr)
					return
				}
				break
			}
			if _, err := fmt.Fprintf(writer, "%s OK EXPUNGE completed\r\n", tag); err != nil {
				t.Logf("EXPUNGE OK response error = %v", err)
				return
			}
		case "FETCH":
			if err := s.writeFetchResponse(writer, tag, s.selected, args); err != nil {
				if _, writeErr := fmt.Fprintf(writer, "%s NO %s\r\n", tag, err); writeErr != nil {
					t.Logf("FETCH NO response error = %v", writeErr)
					return
				}
			}
		case "LOGOUT":
			if _, err := writer.WriteString("* BYE logging out\r\n"); err != nil {
				t.Logf("LOGOUT BYE response error = %v", err)
				return
			}
			if _, err := fmt.Fprintf(writer, "%s OK LOGOUT completed\r\n", tag); err != nil {
				t.Logf("LOGOUT OK response error = %v", err)
				return
			}
		default:
			if _, err := fmt.Fprintf(writer, "%s BAD unsupported command\r\n", tag); err != nil {
				t.Logf("BAD response error = %v", err)
				return
			}
		}

		if err := writer.Flush(); err != nil {
			t.Logf("Flush() error = %v", err)
			return
		}

		if command == "LOGOUT" {
			return
		}
	}
}

func (s *fakeIMAPServer) writeListResponse(writer *bufio.Writer, tag string) error {
	for _, mailbox := range s.mailboxes {
		flags := ""
		if mailbox.NoSelect {
			flags = `\Noselect`
		}
		if mailbox.UnquotedList {
			if _, err := fmt.Fprintf(writer, `* LIST (%s) "/" %s`+"\r\n", flags, mailbox.Name); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(writer, `* LIST (%s) "/" %q`+"\r\n", flags, mailbox.Name); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(writer, "%s OK LIST completed\r\n", tag); err != nil {
		return err
	}

	return nil
}

func (s *fakeIMAPServer) findMailbox(args []string) (*fakeIMAPMailbox, bool) {
	if len(args) != 1 {
		return nil, false
	}

	for index := range s.mailboxes {
		if s.mailboxes[index].Name == args[0] {
			return &s.mailboxes[index], true
		}
	}

	return nil, false
}

func (s *fakeIMAPServer) searchMessages(mailboxName, criteria string) ([]int, error) {
	mailbox, ok := s.findMailbox([]string{mailboxName})
	if !ok {
		return nil, fmt.Errorf("no selected mailbox")
	}
	if mailbox.FailSearch {
		return nil, fmt.Errorf("search failed for mailbox %s", mailbox.Name)
	}

	criteria = strings.TrimSpace(criteria)
	tokens := strings.Fields(criteria)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("unsupported SEARCH criteria: %s", criteria)
	}

	var (
		matchAll   bool
		sinceDate  *time.Time
		beforeDate *time.Time
		unflagged  bool
	)

	for index := 0; index < len(tokens); index++ {
		switch strings.ToUpper(tokens[index]) {
		case "ALL":
			matchAll = true
		case "SINCE":
			index++
			if index >= len(tokens) {
				return nil, fmt.Errorf("unsupported SEARCH criteria: %s", criteria)
			}
			since, err := time.Parse("02-Jan-2006", tokens[index])
			if err != nil {
				return nil, err
			}
			sinceDate = &since
		case "BEFORE":
			index++
			if index >= len(tokens) {
				return nil, fmt.Errorf("unsupported SEARCH criteria: %s", criteria)
			}
			before, err := time.Parse("02-Jan-2006", tokens[index])
			if err != nil {
				return nil, err
			}
			beforeDate = &before
		case "UNFLAGGED":
			unflagged = true
		default:
			return nil, fmt.Errorf("unsupported SEARCH criteria: %s", criteria)
		}
	}

	if !matchAll && sinceDate == nil && beforeDate == nil {
		return nil, fmt.Errorf("unsupported SEARCH criteria: %s", criteria)
	}

	var sequenceNumbers []int
	for index, message := range mailbox.Messages {
		if message.Deleted {
			continue
		}
		if unflagged && message.Flagged && !mailbox.IgnoreUnflagged {
			continue
		}
		if sinceDate != nil && startOfDay(message.ReceivedAt).Before(*sinceDate) {
			continue
		}
		if beforeDate != nil && !startOfDay(message.ReceivedAt).Before(*beforeDate) {
			continue
		}

		sequenceNumbers = append(sequenceNumbers, index+1)
	}

	return sequenceNumbers, nil
}

func (s *fakeIMAPServer) searchMessageUIDs(mailboxName, criteria string) ([]uint32, error) {
	sequenceNumbers, err := s.searchMessages(mailboxName, criteria)
	if err != nil {
		return nil, err
	}

	mailbox, ok := s.findMailbox([]string{mailboxName})
	if !ok {
		return nil, fmt.Errorf("no selected mailbox")
	}

	uids := make([]uint32, 0, len(sequenceNumbers))
	for _, sequenceNumber := range sequenceNumbers {
		if sequenceNumber <= 0 || sequenceNumber > len(mailbox.Messages) {
			return nil, fmt.Errorf("sequence number %d out of range", sequenceNumber)
		}
		uids = append(uids, mailbox.Messages[sequenceNumber-1].UID)
	}

	return uids, nil
}

func (s *fakeIMAPServer) writeFetchResponse(writer *bufio.Writer, tag, mailboxName, args string) error {
	mailbox, ok := s.findMailbox([]string{mailboxName})
	if !ok {
		return fmt.Errorf("no selected mailbox")
	}
	if mailbox.FailFetch {
		return fmt.Errorf("fetch failed for mailbox %s", mailbox.Name)
	}

	parts := strings.SplitN(strings.TrimSpace(args), " ", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid FETCH args: %s", args)
	}
	if mailbox.RequireMinimalFetch && strings.Contains(parts[1], "INTERNALDATE") {
		return fmt.Errorf("mailbox %s requires minimal fetch", mailbox.Name)
	}

	sequenceNumbers, err := parseSequenceSet(parts[0])
	if err != nil {
		return err
	}
	if mailbox.MaxFetchSequenceCount > 0 && len(sequenceNumbers) > mailbox.MaxFetchSequenceCount {
		return fmt.Errorf("too many FETCH sequence numbers: %d", len(sequenceNumbers))
	}

	for _, sequenceNumber := range sequenceNumbers {
		if sequenceNumber <= 0 || sequenceNumber > len(mailbox.Messages) {
			return fmt.Errorf("sequence number %d out of range", sequenceNumber)
		}

		message := mailbox.Messages[sequenceNumber-1]
		if message.Deleted {
			continue
		}
		headers := fmt.Sprintf(
			"Message-ID: %s\r\nSubject: %s\r\nFrom: %s\r\nTo: %s\r\n\r\n",
			message.MessageID,
			message.Subject,
			message.From,
			message.To,
		)
		flags := ""
		if message.Flagged {
			flags = `\Flagged`
		}

		if _, err := fmt.Fprintf(
			writer,
			"* %d FETCH (UID %d FLAGS (%s) INTERNALDATE %q BODY[HEADER.FIELDS (MESSAGE-ID SUBJECT FROM TO)] {%d}\r\n",
			sequenceNumber,
			message.UID,
			flags,
			message.ReceivedAt.Format("02-Jan-2006 15:04:05 -0700"),
			len(headers),
		); err != nil {
			return err
		}
		if _, err := writer.WriteString(headers); err != nil {
			return err
		}
		if _, err := writer.WriteString(")\r\n"); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(writer, "%s OK FETCH completed\r\n", tag); err != nil {
		return err
	}

	return nil
}

func (s *fakeIMAPServer) writeUIDFetchResponse(writer *bufio.Writer, tag, mailboxName, args string) error {
	mailbox, ok := s.findMailbox([]string{mailboxName})
	if !ok {
		return fmt.Errorf("no selected mailbox")
	}
	if mailbox.FailFetch {
		return fmt.Errorf("fetch failed for mailbox %s", mailbox.Name)
	}

	parts := strings.SplitN(strings.TrimSpace(args), " ", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid UID FETCH args: %s", args)
	}

	uids, err := parseUIDSet(parts[0])
	if err != nil {
		return err
	}

	for _, uid := range uids {
		sequenceNumber, found := findSequenceNumberByUID(mailbox.Messages, uid)
		if !found {
			return fmt.Errorf("uid %d out of range", uid)
		}

		message := mailbox.Messages[sequenceNumber-1]
		if message.Deleted {
			continue
		}

		headers := fmt.Sprintf(
			"Message-ID: %s\r\nSubject: %s\r\nFrom: %s\r\nTo: %s\r\n\r\n",
			message.MessageID,
			message.Subject,
			message.From,
			message.To,
		)
		flags := ""
		if message.Flagged {
			flags = `\Flagged`
		}

		if _, err := fmt.Fprintf(
			writer,
			"* %d FETCH (UID %d FLAGS (%s) INTERNALDATE %q BODY[HEADER.FIELDS (MESSAGE-ID SUBJECT FROM TO)] {%d}\r\n",
			sequenceNumber,
			message.UID,
			flags,
			message.ReceivedAt.Format("02-Jan-2006 15:04:05 -0700"),
			len(headers),
		); err != nil {
			return err
		}
		if _, err := writer.WriteString(headers); err != nil {
			return err
		}
		if _, err := writer.WriteString(")\r\n"); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(writer, "%s OK UID FETCH completed\r\n", tag); err != nil {
		return err
	}

	return nil
}

func (s *fakeIMAPServer) storeDeletedFlags(mailboxName, args string) error {
	mailbox, ok := s.findMailbox([]string{mailboxName})
	if !ok {
		return fmt.Errorf("no selected mailbox")
	}
	if mailbox.FailStore {
		return fmt.Errorf("store failed for mailbox %s", mailbox.Name)
	}

	parts := strings.SplitN(strings.TrimSpace(args), " ", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid STORE args: %s", args)
	}

	if !strings.Contains(parts[1], `\Deleted`) {
		return fmt.Errorf("unsupported STORE flags: %s", args)
	}

	sequenceNumbers, err := parseSequenceSet(parts[0])
	if err != nil {
		return err
	}
	s.storeCounts[mailbox.Name]++
	if mailbox.StallStore > 0 {
		if mailbox.StallStoreFirstOps > 0 {
			if s.storeCounts[mailbox.Name] <= mailbox.StallStoreFirstOps {
				time.Sleep(mailbox.StallStore)
			}
		} else if len(sequenceNumbers) >= mailbox.StallStoreMinCount {
			time.Sleep(mailbox.StallStore)
		}
	}

	for _, sequenceNumber := range sequenceNumbers {
		if sequenceNumber <= 0 || sequenceNumber > len(mailbox.Messages) {
			return fmt.Errorf("sequence number %d out of range", sequenceNumber)
		}

		mailbox.Messages[sequenceNumber-1].Deleted = true
	}

	return nil
}

func (s *fakeIMAPServer) storeDeletedFlagsByUID(mailboxName, args string) error {
	mailbox, ok := s.findMailbox([]string{mailboxName})
	if !ok {
		return fmt.Errorf("no selected mailbox")
	}
	if mailbox.FailStore {
		return fmt.Errorf("store failed for mailbox %s", mailbox.Name)
	}

	parts := strings.SplitN(strings.TrimSpace(args), " ", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid UID STORE args: %s", args)
	}

	if !strings.Contains(parts[1], `\Deleted`) {
		return fmt.Errorf("unsupported UID STORE flags: %s", args)
	}

	uids, err := parseUIDSet(parts[0])
	if err != nil {
		return err
	}
	s.storeCounts[mailbox.Name]++
	if mailbox.StallStore > 0 {
		if mailbox.StallStoreFirstOps > 0 {
			if s.storeCounts[mailbox.Name] <= mailbox.StallStoreFirstOps {
				time.Sleep(mailbox.StallStore)
			}
		} else if len(uids) >= mailbox.StallStoreMinCount {
			time.Sleep(mailbox.StallStore)
		}
	}

	for _, uid := range uids {
		sequenceNumber, found := findSequenceNumberByUID(mailbox.Messages, uid)
		if !found {
			return fmt.Errorf("uid %d out of range", uid)
		}
		mailbox.Messages[sequenceNumber-1].Deleted = true
	}

	return nil
}

func (s *fakeIMAPServer) moveMessagesByUID(mailboxName, args string) error {
	sourceMailbox, ok := s.findMailbox([]string{mailboxName})
	if !ok {
		return fmt.Errorf("no selected mailbox")
	}

	parts := strings.SplitN(strings.TrimSpace(args), " ", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid UID MOVE args: %s", args)
	}

	uids, err := parseUIDSet(parts[0])
	if err != nil {
		return err
	}

	moveArgs, err := parseIMAPQuotedArgs(parts[1])
	if err != nil {
		return err
	}
	if len(moveArgs) != 1 {
		return fmt.Errorf("invalid UID MOVE mailbox args: %s", args)
	}

	targetMailbox, ok := s.findMailbox(moveArgs)
	if !ok {
		return fmt.Errorf("target mailbox %s not found", moveArgs[0])
	}

	uidSet := make(map[uint32]struct{}, len(uids))
	for _, uid := range uids {
		uidSet[uid] = struct{}{}
	}

	var movedMessages []fakeIMAPMessage
	remainingMessages := sourceMailbox.Messages[:0]
	for _, message := range sourceMailbox.Messages {
		if _, shouldMove := uidSet[message.UID]; shouldMove && !message.Deleted {
			moved := message
			moved.Deleted = false
			movedMessages = append(movedMessages, moved)
			continue
		}
		remainingMessages = append(remainingMessages, message)
	}
	sourceMailbox.Messages = remainingMessages

	if len(movedMessages) > 0 {
		targetMailbox.Messages = append(targetMailbox.Messages, movedMessages...)
	}

	return nil
}

func (s *fakeIMAPServer) expungeMailbox(mailboxName string) error {
	mailbox, ok := s.findMailbox([]string{mailboxName})
	if !ok {
		return fmt.Errorf("no selected mailbox")
	}

	var movedMessages []fakeIMAPMessage
	filtered := mailbox.Messages[:0]
	for _, message := range mailbox.Messages {
		if message.Deleted {
			if mailbox.DeleteMovesTo != "" {
				movedCopy := message
				movedCopy.Deleted = false
				movedMessages = append(movedMessages, movedCopy)
			}
			continue
		}
		filtered = append(filtered, message)
	}
	mailbox.Messages = filtered

	if mailbox.DeleteMovesTo != "" && len(movedMessages) > 0 {
		targetMailbox, ok := s.findMailbox([]string{mailbox.DeleteMovesTo})
		if !ok {
			return fmt.Errorf("target mailbox %s not found", mailbox.DeleteMovesTo)
		}
		targetMailbox.Messages = append(targetMailbox.Messages, movedMessages...)
	}

	return nil
}

func parseSequenceSet(value string) ([]int, error) {
	parts := strings.Split(value, ",")
	sequenceNumbers := make([]int, 0, len(parts))
	for _, part := range parts {
		sequenceNumber, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		sequenceNumbers = append(sequenceNumbers, sequenceNumber)
	}

	return sequenceNumbers, nil
}

func parseUIDSet(value string) ([]uint32, error) {
	parts := strings.Split(value, ",")
	uids := make([]uint32, 0, len(parts))
	for _, part := range parts {
		uid, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, err
		}
		uids = append(uids, uint32(uid))
	}

	return uids, nil
}

func findSequenceNumberByUID(messages []fakeIMAPMessage, uid uint32) (int, bool) {
	for index, message := range messages {
		if message.UID == uid {
			return index + 1, true
		}
	}

	return 0, false
}

func parseIMAPCommand(line string) (string, string, string, error) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("invalid command line: %s", line)
	}

	tag := parts[0]
	command := strings.ToUpper(parts[1])
	if len(parts) == 2 {
		return tag, command, "", nil
	}

	return tag, command, parts[2], nil
}

func parseIMAPQuotedArgs(input string) ([]string, error) {
	var args []string
	remaining := strings.TrimSpace(input)

	for remaining != "" {
		if remaining[0] != '"' {
			return nil, fmt.Errorf("argument %q is not quoted", remaining)
		}

		value, consumed, err := consumeQuotedString(remaining)
		if err != nil {
			return nil, err
		}

		args = append(args, value)
		remaining = strings.TrimSpace(remaining[consumed:])
	}

	return args, nil
}

func newTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate() error = %v", err)
	}

	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair() error = %v", err)
	}

	certificate.Leaf, err = x509.ParseCertificate(certificateDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}

	return certificate
}

func newCertPool(t *testing.T, certificate tls.Certificate) *x509.CertPool {
	t.Helper()

	pool := x509.NewCertPool()
	if certificate.Leaf == nil {
		t.Fatal("certificate leaf is required")
	}
	pool.AddCert(certificate.Leaf)

	return pool
}
