package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lechefran/mailbin"
)

func TestLoadConfiguredAccountsUsesProviderDefaults(t *testing.T) {
	configPath := writeAccountsConfig(t, `{
  "age": 30,
  "apiKey": " test-api-key ",
  "cron": "0 0 * * *",
  "getEmailAddressesUrl": " https://example.com/getEmailAddresses ",
  "accounts": [
    {
      "name": "gmail",
      "email": "one@example.com",
      "provider": "gmail",
      "password": "gmail-secret"
    },
    {
      "name": "icloud",
      "email": "two@example.com",
      "provider": "icloud",
      "password": "icloud-secret"
    }
  ]
}`)

	loadedConfig, err := loadConfiguredAccounts(
		configPath,
	)
	if err != nil {
		t.Fatalf("loadConfiguredAccounts() error = %v", err)
	}
	accounts := loadedConfig.Accounts
	if len(accounts) != 2 {
		t.Fatalf("loadConfiguredAccounts() count = %d, want 2", len(accounts))
	}
	if accounts[0].Config.Address != string(mailbin.GMAIL) {
		t.Fatalf("first account address = %q, want %q", accounts[0].Config.Address, string(mailbin.GMAIL))
	}
	if accounts[1].Config.Address != string(mailbin.ICLOUD) {
		t.Fatalf("second account address = %q, want %q", accounts[1].Config.Address, string(mailbin.ICLOUD))
	}
	if accounts[0].Config.Password != "gmail-secret" || accounts[1].Config.Password != "icloud-secret" {
		t.Fatalf("account passwords = %#v, want configured passwords", accounts)
	}
	if loadedConfig.Age != 30 {
		t.Fatalf("age = %d, want 30", loadedConfig.Age)
	}
	if loadedConfig.APIKey != "test-api-key" {
		t.Fatalf("api key = %q, want test-api-key", loadedConfig.APIKey)
	}
	if loadedConfig.GetEmailAddressesURL != "https://example.com/getEmailAddresses" {
		t.Fatalf("get email addresses url = %q, want configured url", loadedConfig.GetEmailAddressesURL)
	}
}

func TestLoadConfiguredAccountsUsesAddressOverride(t *testing.T) {
	configPath := writeAccountsConfig(t, `{
  "age": 30,
  "apiKey": "test-api-key",
  "cron": "0 0 * * *",
  "getEmailAddressesUrl": "https://example.com/getEmailAddresses",
  "accounts": [
    {
      "name": "custom",
      "email": "custom@example.com",
      "provider": "gmail",
      "imap_addr": "imap.custom.example:993",
      "password": "custom-secret"
    }
  ]
}`)

	loadedConfig, err := loadConfiguredAccounts(
		configPath,
	)
	if err != nil {
		t.Fatalf("loadConfiguredAccounts() error = %v", err)
	}
	accounts := loadedConfig.Accounts
	if accounts[0].Config.Address != "imap.custom.example:993" {
		t.Fatalf("override address = %q, want custom address", accounts[0].Config.Address)
	}
}

func TestLoadConfiguredAccountsIgnoresBlacklistField(t *testing.T) {
	configPath := writeAccountsConfig(t, `{
  "age": 30,
  "apiKey": "test-api-key",
  "cron": "0 0 * * *",
  "getEmailAddressesUrl": "https://example.com/getEmailAddresses",
  "blacklist": [
    "blocked@example.com"
  ],
  "accounts": [
    {
      "name": "gmail",
      "email": "one@example.com",
      "provider": "gmail",
      "password": "gmail-secret"
    }
  ]
}`)

	loadedConfig, err := loadConfiguredAccounts(
		configPath,
	)
	if err != nil {
		t.Fatalf("loadConfiguredAccounts() error = %v", err)
	}
	if len(loadedConfig.Accounts) != 1 {
		t.Fatalf("loadConfiguredAccounts() count = %d, want 1", len(loadedConfig.Accounts))
	}
}

func TestLoadConfiguredAccountsRequiresAgeAndCron(t *testing.T) {
	testCases := []struct {
		name          string
		config        string
		wantErrorText string
	}{
		{
			name: "missing age",
			config: `{
  "apiKey": "test-api-key",
  "cron": "0 0 * * *",
  "getEmailAddressesUrl": "https://example.com/getEmailAddresses",
  "accounts": [
    {
      "email": "one@example.com",
      "provider": "gmail",
      "password": "gmail-secret"
    }
  ]
}`,
			wantErrorText: "missing age",
		},
		{
			name: "negative age",
			config: `{
  "age": -1,
  "apiKey": "test-api-key",
  "cron": "0 0 * * *",
  "getEmailAddressesUrl": "https://example.com/getEmailAddresses",
  "accounts": [
    {
      "email": "one@example.com",
      "provider": "gmail",
      "password": "gmail-secret"
    }
  ]
}`,
			wantErrorText: "age must be 0 or greater",
		},
		{
			name: "missing cron",
			config: `{
  "age": 30,
  "apiKey": "test-api-key",
  "getEmailAddressesUrl": "https://example.com/getEmailAddresses",
  "accounts": [
    {
      "email": "one@example.com",
      "provider": "gmail",
      "password": "gmail-secret"
    }
  ]
}`,
			wantErrorText: "missing cron",
		},
		{
			name: "invalid cron",
			config: `{
  "age": 30,
  "apiKey": "test-api-key",
  "cron": "0 0 * *",
  "getEmailAddressesUrl": "https://example.com/getEmailAddresses",
  "accounts": [
    {
      "email": "one@example.com",
      "provider": "gmail",
      "password": "gmail-secret"
    }
  ]
}`,
			wantErrorText: "cron",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			configPath := writeAccountsConfig(t, testCase.config)
			_, err := loadConfiguredAccounts(configPath)
			if err == nil || !strings.Contains(err.Error(), testCase.wantErrorText) {
				t.Fatalf("loadConfiguredAccounts() error = %v, want %q", err, testCase.wantErrorText)
			}
		})
	}
}

func TestLoadConfiguredAccountsRequiresPassword(t *testing.T) {
	testCases := []struct {
		name          string
		accountJSON   string
		wantErrorText string
	}{
		{
			name: "missing password",
			accountJSON: `{
      "email": "one@example.com",
      "provider": "gmail"
    }`,
			wantErrorText: "missing password",
		},
		{
			name: "blank password",
			accountJSON: `{
      "email": "one@example.com",
      "provider": "gmail",
      "password": " "
    }`,
			wantErrorText: "missing password",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			configPath := writeAccountsConfig(t, `{
  "age": 30,
  "apiKey": "test-api-key",
  "cron": "0 0 * * *",
  "getEmailAddressesUrl": "https://example.com/getEmailAddresses",
  "accounts": [
    `+testCase.accountJSON+`
  ]
}`)
			_, err := loadConfiguredAccounts(configPath)
			if err == nil || !strings.Contains(err.Error(), testCase.wantErrorText) {
				t.Fatalf("loadConfiguredAccounts() error = %v, want %q", err, testCase.wantErrorText)
			}
		})
	}
}

func TestLoadConfiguredAccountsRequiresEmailAPIConfig(t *testing.T) {
	testCases := []struct {
		name          string
		config        string
		wantErrorText string
	}{
		{
			name: "missing api key",
			config: `{
  "age": 30,
  "cron": "0 0 * * *",
  "getEmailAddressesUrl": "https://example.com/getEmailAddresses",
  "accounts": [
    {
      "email": "one@example.com",
      "provider": "gmail",
      "password": "gmail-secret"
    }
  ]
}`,
			wantErrorText: "api key is missing",
		},
		{
			name: "missing get email addresses url",
			config: `{
  "age": 30,
  "apiKey": "test-api-key",
  "cron": "0 0 * * *",
  "accounts": [
    {
      "email": "one@example.com",
      "provider": "gmail",
      "password": "gmail-secret"
    }
  ]
}`,
			wantErrorText: "get email addresses url is missing",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			configPath := writeAccountsConfig(t, testCase.config)
			_, err := loadConfiguredAccounts(configPath)
			if err == nil || !strings.Contains(err.Error(), testCase.wantErrorText) {
				t.Fatalf("loadConfiguredAccounts() error = %v, want %q", err, testCase.wantErrorText)
			}
		})
	}
}

func writeAccountsConfig(t *testing.T, contents string) string {
	t.Helper()

	configPath := filepath.Join(t.TempDir(), "accounts.json")
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	return configPath
}
