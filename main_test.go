package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestAppReadByRange(t *testing.T) {
	now := time.Date(2026, time.April, 1, 15, 30, 0, 0, time.UTC)
	expected := []EmailSummary{
		{UID: 1, Subject: "sample"},
	}

	testCases := []struct {
		name          string
		appRange      string
		wantMethod    string
		wantErrorText string
	}{
		{name: "default all", appRange: "", wantMethod: "read-all"},
		{name: "all", appRange: "all", wantMethod: "read-all"},
		{name: "today", appRange: "today", wantMethod: "read-today"},
		{name: "week", appRange: "week", wantMethod: "read-week"},
		{name: "month", appRange: "month", wantMethod: "read-month"},
		{name: "invalid", appRange: "year", wantErrorText: `invalid range "year"`},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			reader := &stubInboxReader{
				emails: expected,
			}

			app := &App{
				Range: testCase.appRange,
				Now: func() time.Time {
					return now
				},
			}

			emails, err := app.readByRange(reader)
			if testCase.wantErrorText != "" {
				if err == nil || !strings.Contains(err.Error(), testCase.wantErrorText) {
					t.Fatalf("readByRange() error = %v, want %q", err, testCase.wantErrorText)
				}
				return
			}

			if err != nil {
				t.Fatalf("readByRange() error = %v", err)
			}
			if len(emails) != len(expected) || emails[0].UID != expected[0].UID {
				t.Fatalf("readByRange() emails = %v, want %v", emails, expected)
			}
			if reader.called != testCase.wantMethod {
				t.Fatalf("reader called %q, want %q", reader.called, testCase.wantMethod)
			}
			if (testCase.wantMethod == "today" || testCase.wantMethod == "week" || testCase.wantMethod == "month") && !reader.calledWith.Equal(now) {
				t.Fatalf("reader called with %v, want %v", reader.calledWith, now)
			}
		})
	}
}

func TestAppRunAction(t *testing.T) {
	now := time.Date(2026, time.April, 1, 15, 30, 0, 0, time.UTC)
	expected := []EmailSummary{{UID: 1, Subject: "sample"}}

	testCases := []struct {
		name           string
		action         string
		rangeValue     string
		age            int
		includeFlagged bool
		wantMethod     string
		wantErrorText  string
	}{
		{name: "default read", action: "", rangeValue: "all", wantMethod: "read-all"},
		{name: "read today", action: "read", rangeValue: "today", wantMethod: "read-today"},
		{name: "delete by age", action: "delete", age: 90, wantMethod: "delete-age"},
		{name: "delete flagged by age", action: "delete", age: 90, includeFlagged: true, wantMethod: "delete-age"},
		{name: "delete missing age", action: "delete", age: -1, wantErrorText: "age is required for delete action"},
		{name: "invalid action", action: "destroy", rangeValue: "all", wantErrorText: `invalid action "destroy"`},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			session := &stubSession{
				stubInboxReader: stubInboxReader{
					emails: expected,
				},
			}

			app := &App{
				Action:         testCase.action,
				Age:            testCase.age,
				IncludeFlagged: testCase.includeFlagged,
				Range:          testCase.rangeValue,
				Now: func() time.Time {
					return now
				},
			}

			emails, err := app.runAction(session)
			if testCase.wantErrorText != "" {
				if err == nil || !strings.Contains(err.Error(), testCase.wantErrorText) {
					t.Fatalf("runAction() error = %v, want %q", err, testCase.wantErrorText)
				}
				return
			}

			if err != nil {
				t.Fatalf("runAction() error = %v", err)
			}
			if len(emails) != 1 || emails[0].UID != expected[0].UID {
				t.Fatalf("runAction() emails = %v, want %v", emails, expected)
			}
			if session.called != testCase.wantMethod {
				t.Fatalf("session called %q, want %q", session.called, testCase.wantMethod)
			}
			if testCase.wantMethod == "delete-age" && session.calledAge != testCase.age {
				t.Fatalf("session calledAge = %d, want %d", session.calledAge, testCase.age)
			}
			if testCase.wantMethod == "delete-age" && session.calledIncludeFlagged != testCase.includeFlagged {
				t.Fatalf("session calledIncludeFlagged = %v, want %v", session.calledIncludeFlagged, testCase.includeFlagged)
			}
		})
	}
}

func TestAppRunPrintsEmailsForRange(t *testing.T) {
	buffer := &bytes.Buffer{}
	client := &stubLoginReader{
		session: &stubSession{
			stubInboxReader: stubInboxReader{
				emails: []EmailSummary{
					{
						UID:        7,
						ReceivedAt: time.Date(2026, time.April, 1, 8, 0, 0, 0, time.UTC),
						Subject:    "Today message",
						From:       "alerts@example.com",
						To:         "user@example.com",
					},
				},
			},
		},
		Address: "imap.example.com:993",
		Email:   "user@example.com",
	}

	app := &App{
		Client: &IMAPClient{
			Address: client.Address,
			Email:   client.Email,
		},
		Login: func(context.Context, *IMAPClient) (SessionWithInboxRead, error) {
			return client.session, nil
		},
		Range:   "today",
		Timeout: time.Second,
		Now: func() time.Time {
			return time.Date(2026, time.April, 1, 12, 0, 0, 0, time.UTC)
		},
		Output: buffer,
	}

	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	output := buffer.String()
	if !strings.Contains(output, "Today message") {
		t.Fatalf("Run() output = %q, want subject", output)
	}
	if !strings.Contains(output, "retrieved 1 emails") {
		t.Fatalf("Run() output = %q, want retrieved count", output)
	}
	if client.session.called != "read-today" {
		t.Fatalf("session called %q, want read-today", client.session.called)
	}
	if !client.session.loggedOut {
		t.Fatal("session was not logged out")
	}
}

func TestAppRunDeletePrintsEmailsAndCount(t *testing.T) {
	buffer := &bytes.Buffer{}
	client := &stubLoginReader{
		session: &stubSession{
			stubInboxReader: stubInboxReader{
				emails: []EmailSummary{
					{
						UID:        7,
						Mailbox:    "INBOX",
						ReceivedAt: time.Date(2026, time.April, 1, 8, 0, 0, 0, time.UTC),
						Subject:    "Today message",
						From:       "alerts@example.com",
						To:         "user@example.com",
					},
					{
						UID:        8,
						Mailbox:    "[Gmail]/Spam",
						ReceivedAt: time.Date(2026, time.April, 1, 9, 0, 0, 0, time.UTC),
						Subject:    "Spam message",
						From:       "spam@example.com",
						To:         "user@example.com",
					},
				},
			},
		},
		Address: "imap.example.com:993",
		Email:   "user@example.com",
	}

	app := &App{
		Client: &IMAPClient{
			Address: client.Address,
			Email:   client.Email,
		},
		Login: func(context.Context, *IMAPClient) (SessionWithInboxRead, error) {
			return client.session, nil
		},
		Action:         "delete",
		Age:            0,
		IncludeFlagged: false,
		Timeout:        time.Second,
		Now: func() time.Time {
			return time.Date(2026, time.April, 1, 12, 0, 0, 0, time.UTC)
		},
		Output: buffer,
	}

	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	output := buffer.String()
	if !strings.Contains(output, "Today message") {
		t.Fatalf("Run() output = %q, want first subject", output)
	}
	if !strings.Contains(output, "Spam message") {
		t.Fatalf("Run() output = %q, want second subject", output)
	}
	if !strings.Contains(output, "deleted 2 emails") {
		t.Fatalf("Run() output = %q, want deleted count", output)
	}
	if client.session.called != "delete-age" {
		t.Fatalf("session called %q, want delete-age", client.session.called)
	}
	if client.session.calledAge != 0 {
		t.Fatalf("session calledAge = %d, want 0", client.session.calledAge)
	}
	if client.session.calledIncludeFlagged {
		t.Fatal("session calledIncludeFlagged = true, want false")
	}
}

func TestAppRunMultipleAccountsAggregatesOutput(t *testing.T) {
	buffer := &bytes.Buffer{}
	sessions := map[string]*stubSession{
		"one@example.com": {
			stubInboxReader: stubInboxReader{
				emails: []EmailSummary{
					{UID: 1, Subject: "First account message"},
				},
			},
		},
		"two@example.com": {
			stubInboxReader: stubInboxReader{
				emails: []EmailSummary{
					{UID: 2, Subject: "Second account message"},
				},
			},
		},
	}

	app := &App{
		Accounts: []ConfiguredAccount{
			{
				Name: "gmail",
				Client: &IMAPClient{
					Address: "imap.gmail.com:993",
					Email:   "one@example.com",
				},
			},
			{
				Name: "icloud",
				Client: &IMAPClient{
					Address: "imap.mail.me.com:993",
					Email:   "two@example.com",
				},
			},
		},
		Login: func(_ context.Context, client *IMAPClient) (SessionWithInboxRead, error) {
			return sessions[client.Email], nil
		},
		Range:   "all",
		Timeout: time.Second,
		Output:  buffer,
	}

	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	output := buffer.String()
	if !strings.Contains(output, "account=gmail |") {
		t.Fatalf("Run() output = %q, want gmail account label", output)
	}
	if !strings.Contains(output, "account=icloud |") {
		t.Fatalf("Run() output = %q, want icloud account label", output)
	}
	if strings.Count(output, "retrieved 2 emails") != 1 {
		t.Fatalf("Run() output = %q, want one aggregated summary", output)
	}
	if !strings.Contains(output, "summary: read total=2 emails across accounts=2 (successful=2 failed=0)") {
		t.Fatalf("Run() output = %q, want cross-account read summary", output)
	}
	if !sessions["one@example.com"].loggedOut || !sessions["two@example.com"].loggedOut {
		t.Fatalf("sessions logged out = %#v", sessions)
	}
}

func TestAppRunDeleteMultipleAccountsRunsConcurrentlyAndAggregatesCount(t *testing.T) {
	buffer := &bytes.Buffer{}
	started := make(chan string, 2)
	release := make(chan struct{})
	errs := make(chan error, 1)

	app := &App{
		Accounts: []ConfiguredAccount{
			{
				Name: "gmail",
				Client: &IMAPClient{
					Address: "imap.gmail.com:993",
					Email:   "one@example.com",
				},
			},
			{
				Name: "icloud",
				Client: &IMAPClient{
					Address: "imap.mail.me.com:993",
					Email:   "two@example.com",
				},
			},
		},
		Login: func(_ context.Context, client *IMAPClient) (SessionWithInboxRead, error) {
			return &blockingDeleteSession{
				email:   client.Email,
				started: started,
				release: release,
				emails: []EmailSummary{
					{
						UID:     1,
						Mailbox: "INBOX",
						Subject: client.Email,
					},
				},
			}, nil
		},
		Action:         "delete",
		Age:            90,
		IncludeFlagged: false,
		Concurrency:    2,
		Timeout:        time.Second,
		Output:         buffer,
	}

	go func() {
		errs <- app.Run(context.Background())
	}()

	first := <-started
	second := <-started
	if first == second {
		t.Fatalf("started accounts = %q and %q, want distinct concurrent deletes", first, second)
	}
	close(release)

	if err := <-errs; err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	output := buffer.String()
	if !strings.Contains(output, "account=gmail |") {
		t.Fatalf("Run() output = %q, want gmail account label", output)
	}
	if !strings.Contains(output, "account=icloud |") {
		t.Fatalf("Run() output = %q, want icloud account label", output)
	}
	if !strings.Contains(output, "deleted 2 emails") {
		t.Fatalf("Run() output = %q, want aggregated deleted count", output)
	}
	if !strings.Contains(output, "summary: deleted total=2 emails across accounts=2 (successful=2 failed=0)") {
		t.Fatalf("Run() output = %q, want cross-account delete summary", output)
	}
}

func TestAppRunReadMultipleAccountsRunsConcurrentlyAndAggregatesCount(t *testing.T) {
	buffer := &bytes.Buffer{}
	started := make(chan string, 2)
	release := make(chan struct{})
	errs := make(chan error, 1)

	app := &App{
		Accounts: []ConfiguredAccount{
			{
				Name: "gmail",
				Client: &IMAPClient{
					Address: "imap.gmail.com:993",
					Email:   "one@example.com",
				},
			},
			{
				Name: "icloud",
				Client: &IMAPClient{
					Address: "imap.mail.me.com:993",
					Email:   "two@example.com",
				},
			},
		},
		Login: func(_ context.Context, client *IMAPClient) (SessionWithInboxRead, error) {
			return &blockingReadSession{
				email:   client.Email,
				started: started,
				release: release,
				emails: []EmailSummary{
					{
						UID:     1,
						Mailbox: "INBOX",
						Subject: client.Email,
					},
				},
			}, nil
		},
		Range:   "all",
		Timeout: time.Second,
		Output:  buffer,
	}

	go func() {
		errs <- app.Run(context.Background())
	}()

	first := <-started
	second := <-started
	if first == second {
		t.Fatalf("started accounts = %q and %q, want distinct concurrent reads", first, second)
	}
	close(release)

	if err := <-errs; err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	output := buffer.String()
	if !strings.Contains(output, "account=gmail |") {
		t.Fatalf("Run() output = %q, want gmail account label", output)
	}
	if !strings.Contains(output, "account=icloud |") {
		t.Fatalf("Run() output = %q, want icloud account label", output)
	}
	if !strings.Contains(output, "retrieved 2 emails") {
		t.Fatalf("Run() output = %q, want aggregated retrieved count", output)
	}
	if !strings.Contains(output, "summary: read total=2 emails across accounts=2 (successful=2 failed=0)") {
		t.Fatalf("Run() output = %q, want cross-account read summary", output)
	}
}

func TestAppRunDoesNotPrintEmptySummaryWhenAllAccountsFail(t *testing.T) {
	buffer := &bytes.Buffer{}

	app := &App{
		Accounts: []ConfiguredAccount{
			{
				Name: "gmail",
				Client: &IMAPClient{
					Address: "imap.gmail.com:993",
					Email:   "one@example.com",
				},
			},
			{
				Name: "icloud",
				Client: &IMAPClient{
					Address: "imap.mail.me.com:993",
					Email:   "two@example.com",
				},
			},
		},
		Login: func(_ context.Context, client *IMAPClient) (SessionWithInboxRead, error) {
			return nil, fmt.Errorf("login failed for %s", client.Email)
		},
		Range:   "all",
		Timeout: time.Second,
		Output:  buffer,
	}

	err := app.Run(context.Background())
	if err == nil {
		t.Fatal("Run() error = nil, want failure")
	}
	if !strings.Contains(err.Error(), "2 account(s) failed") {
		t.Fatalf("Run() error = %v, want aggregated failure", err)
	}
	if buffer.Len() != 0 {
		t.Fatalf("Run() output = %q, want no empty summary", buffer.String())
	}
}

func TestAppRunIgnoresLogoutTimeoutAfterSuccessfulDelete(t *testing.T) {
	buffer := &bytes.Buffer{}
	app := &App{
		Client: &IMAPClient{
			Address: "imap.example.com:993",
			Email:   "user@example.com",
		},
		Login: func(context.Context, *IMAPClient) (SessionWithInboxRead, error) {
			return &timeoutLogoutSession{
				stubSession: stubSession{
					stubInboxReader: stubInboxReader{
						emails: []EmailSummary{
							{UID: 1, Subject: "Old message"},
						},
					},
				},
			}, nil
		},
		Action:  "delete",
		Age:     90,
		Timeout: time.Second,
		Output:  buffer,
	}

	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	output := buffer.String()
	if !strings.Contains(output, "Old message") {
		t.Fatalf("Run() output = %q, want deleted message", output)
	}
	if !strings.Contains(output, "deleted 1 emails") {
		t.Fatalf("Run() output = %q, want delete summary", output)
	}
}

func TestResolvePassword(t *testing.T) {
	testCases := []struct {
		name          string
		input         string
		envValue      string
		interactive   bool
		wantPassword  string
		wantPrompt    string
		wantErrorText string
	}{
		{
			name:         "uses env password",
			envValue:     "env-secret",
			interactive:  false,
			wantPassword: "env-secret",
		},
		{
			name:         "prompts on interactive stdin",
			input:        "typed-secret\n",
			interactive:  true,
			wantPassword: "typed-secret",
			wantPrompt:   "Enter IMAP password: ",
		},
		{
			name:          "errors on non interactive stdin",
			interactive:   false,
			wantErrorText: "MAILBIN_PASSWORD is required",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			prompt := &bytes.Buffer{}
			password, err := resolvePassword(
				strings.NewReader(testCase.input),
				prompt,
				func(string) string { return testCase.envValue },
				testCase.interactive,
			)

			if testCase.wantErrorText != "" {
				if err == nil || !strings.Contains(err.Error(), testCase.wantErrorText) {
					t.Fatalf("resolvePassword() error = %v, want %q", err, testCase.wantErrorText)
				}
				return
			}

			if err != nil {
				t.Fatalf("resolvePassword() error = %v", err)
			}
			if password != testCase.wantPassword {
				t.Fatalf("resolvePassword() password = %q, want %q", password, testCase.wantPassword)
			}
			if prompt.String() != testCase.wantPrompt {
				t.Fatalf("resolvePassword() prompt = %q, want %q", prompt.String(), testCase.wantPrompt)
			}
		})
	}
}

type stubLoginReader struct {
	session *stubSession
	Address string
	Email   string
}

type stubInboxReader struct {
	called               string
	calledWith           time.Time
	calledAge            int
	calledIncludeFlagged bool
	emails               []EmailSummary
}

func (s *stubInboxReader) ReadInboxAll() ([]EmailSummary, error) {
	s.called = "read-all"
	return s.emails, nil
}

func (s *stubInboxReader) ReadInboxToday(now time.Time) ([]EmailSummary, error) {
	s.called = "read-today"
	s.calledWith = now
	return s.emails, nil
}

func (s *stubInboxReader) ReadInboxThisWeek(now time.Time) ([]EmailSummary, error) {
	s.called = "read-week"
	s.calledWith = now
	return s.emails, nil
}

func (s *stubInboxReader) ReadInboxThisMonth(now time.Time) ([]EmailSummary, error) {
	s.called = "read-month"
	s.calledWith = now
	return s.emails, nil
}

func (s *stubSession) DeleteInboxOlderThanDays(now time.Time, age int, includeFlagged bool) ([]EmailSummary, error) {
	s.called = "delete-age"
	s.calledWith = now
	s.calledAge = age
	s.calledIncludeFlagged = includeFlagged
	return s.emails, nil
}

type stubSession struct {
	stubInboxReader
	loggedOut bool
}

func (s *stubSession) Logout() error {
	s.loggedOut = true
	return nil
}

type timeoutLogoutSession struct {
	stubSession
}

func (s *timeoutLogoutSession) Logout() error {
	s.loggedOut = true
	return &net.DNSError{
		Err:         "i/o timeout",
		IsTimeout:   true,
		IsTemporary: true,
	}
}

type blockingDeleteSession struct {
	email     string
	started   chan<- string
	release   <-chan struct{}
	emails    []EmailSummary
	loggedOut bool
}

func (s *blockingDeleteSession) ReadInboxAll() ([]EmailSummary, error) {
	return nil, nil
}

func (s *blockingDeleteSession) ReadInboxToday(time.Time) ([]EmailSummary, error) {
	return nil, nil
}

func (s *blockingDeleteSession) ReadInboxThisWeek(time.Time) ([]EmailSummary, error) {
	return nil, nil
}

func (s *blockingDeleteSession) ReadInboxThisMonth(time.Time) ([]EmailSummary, error) {
	return nil, nil
}

func (s *blockingDeleteSession) DeleteInboxOlderThanDays(time.Time, int, bool) ([]EmailSummary, error) {
	s.started <- s.email
	<-s.release
	return s.emails, nil
}

func (s *blockingDeleteSession) Logout() error {
	s.loggedOut = true
	return nil
}

type blockingReadSession struct {
	email     string
	started   chan<- string
	release   <-chan struct{}
	emails    []EmailSummary
	loggedOut bool
}

func (s *blockingReadSession) ReadInboxAll() ([]EmailSummary, error) {
	s.started <- s.email
	<-s.release
	return s.emails, nil
}

func (s *blockingReadSession) ReadInboxToday(time.Time) ([]EmailSummary, error) {
	return nil, nil
}

func (s *blockingReadSession) ReadInboxThisWeek(time.Time) ([]EmailSummary, error) {
	return nil, nil
}

func (s *blockingReadSession) ReadInboxThisMonth(time.Time) ([]EmailSummary, error) {
	return nil, nil
}

func (s *blockingReadSession) DeleteInboxOlderThanDays(time.Time, int, bool) ([]EmailSummary, error) {
	return nil, nil
}

func (s *blockingReadSession) Logout() error {
	s.loggedOut = true
	return nil
}
