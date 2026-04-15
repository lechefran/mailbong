package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveIMAPAddress(t *testing.T) {
	testCases := []struct {
		name          string
		provider      string
		address       string
		wantAddress   string
		wantErrorText string
	}{
		{
			name:        "provider default",
			provider:    "gmail",
			wantAddress: string(GMAIL),
		},
		{
			name:        "provider alias",
			provider:    "office365",
			wantAddress: string(OUTLOOK),
		},
		{
			name:        "address override wins",
			provider:    "gmail",
			address:     "imap.custom.example:993",
			wantAddress: "imap.custom.example:993",
		},
		{
			name:          "missing provider and address",
			wantErrorText: "imap address or provider is required",
		},
		{
			name:          "unsupported provider",
			provider:      "fastmail",
			wantErrorText: `unsupported provider "fastmail"`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			address, err := resolveIMAPAddress(testCase.provider, testCase.address)
			if testCase.wantErrorText != "" {
				if err == nil || !strings.Contains(err.Error(), testCase.wantErrorText) {
					t.Fatalf("resolveIMAPAddress() error = %v, want %q", err, testCase.wantErrorText)
				}
				return
			}

			if err != nil {
				t.Fatalf("resolveIMAPAddress() error = %v", err)
			}
			if address != testCase.wantAddress {
				t.Fatalf("resolveIMAPAddress() = %q, want %q", address, testCase.wantAddress)
			}
		})
	}
}

func TestLoadConfiguredAccountsUsesProviderDefaults(t *testing.T) {
	configPath := writeAccountsConfig(t, `{
  "accounts": [
    {
      "name": "gmail",
      "email": "one@example.com",
      "provider": "gmail",
      "password_env": "MAILBIN_GMAIL_PASSWORD"
    },
    {
      "name": "icloud",
      "email": "two@example.com",
      "provider": "icloud",
      "password_env": "MAILBIN_ICLOUD_PASSWORD"
    }
  ]
}`)

	accounts, err := loadConfiguredAccounts(
		configPath,
		"",
		strings.NewReader(""),
		&bytes.Buffer{},
		func(key string) string {
			switch key {
			case "MAILBIN_GMAIL_PASSWORD":
				return "gmail-secret"
			case "MAILBIN_ICLOUD_PASSWORD":
				return "icloud-secret"
			default:
				return ""
			}
		},
		false,
	)
	if err != nil {
		t.Fatalf("loadConfiguredAccounts() error = %v", err)
	}
	if len(accounts) != 2 {
		t.Fatalf("loadConfiguredAccounts() count = %d, want 2", len(accounts))
	}
	if accounts[0].Config.Address != string(GMAIL) {
		t.Fatalf("first account address = %q, want %q", accounts[0].Config.Address, string(GMAIL))
	}
	if accounts[1].Config.Address != string(ICLOUD) {
		t.Fatalf("second account address = %q, want %q", accounts[1].Config.Address, string(ICLOUD))
	}
	if accounts[0].Config.Password != "gmail-secret" || accounts[1].Config.Password != "icloud-secret" {
		t.Fatalf("account passwords = %#v, want provider env passwords", accounts)
	}
}

func TestLoadConfiguredAccountsSelectsOneAccount(t *testing.T) {
	configPath := writeAccountsConfig(t, `{
  "accounts": [
    {
      "name": "gmail",
      "email": "one@example.com",
      "provider": "gmail",
      "password_env": "MAILBIN_GMAIL_PASSWORD"
    },
    {
      "name": "icloud",
      "email": "two@example.com",
      "provider": "icloud",
      "password_env": "MAILBIN_ICLOUD_PASSWORD"
    }
  ]
}`)

	accounts, err := loadConfiguredAccounts(
		configPath,
		"icloud",
		strings.NewReader(""),
		&bytes.Buffer{},
		func(key string) string {
			if key == "MAILBIN_ICLOUD_PASSWORD" {
				return "icloud-secret"
			}
			return ""
		},
		false,
	)
	if err != nil {
		t.Fatalf("loadConfiguredAccounts() error = %v", err)
	}
	if len(accounts) != 1 {
		t.Fatalf("loadConfiguredAccounts() count = %d, want 1", len(accounts))
	}
	if accounts[0].Name != "icloud" {
		t.Fatalf("selected account = %q, want icloud", accounts[0].Name)
	}
	if accounts[0].Config.Address != string(ICLOUD) {
		t.Fatalf("selected account address = %q, want %q", accounts[0].Config.Address, string(ICLOUD))
	}
}

func TestLoadConfiguredAccountsUsesAddressOverride(t *testing.T) {
	configPath := writeAccountsConfig(t, `{
  "accounts": [
    {
      "name": "custom",
      "email": "custom@example.com",
      "provider": "gmail",
      "imap_addr": "imap.custom.example:993",
      "password_env": "MAILBIN_CUSTOM_PASSWORD"
    }
  ]
}`)

	accounts, err := loadConfiguredAccounts(
		configPath,
		"",
		strings.NewReader(""),
		&bytes.Buffer{},
		func(key string) string {
			if key == "MAILBIN_CUSTOM_PASSWORD" {
				return "custom-secret"
			}
			return ""
		},
		false,
	)
	if err != nil {
		t.Fatalf("loadConfiguredAccounts() error = %v", err)
	}
	if accounts[0].Config.Address != "imap.custom.example:993" {
		t.Fatalf("override address = %q, want custom address", accounts[0].Config.Address)
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
