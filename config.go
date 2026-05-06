package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lechefran/mailbin"
)

type ADDR string

const (
	AOL        ADDR = mailbin.AOL
	AOL_EXPORT ADDR = mailbin.AOL_EXPORT
	GMAIL      ADDR = mailbin.GMAIL
	ICLOUD     ADDR = mailbin.ICLOUD
	OUTLOOK    ADDR = mailbin.OUTLOOK
	YAHOO      ADDR = mailbin.YAHOO
	ZOHO       ADDR = mailbin.ZOHO
)

type ConfiguredAccount struct {
	Name   string
	Config mailbin.Config
}

type loadedAccountsConfig struct {
	Accounts []ConfiguredAccount
	Age      int
	Schedule CronSchedule
}

type accountsConfig struct {
	Accounts []accountConfig `json:"accounts"`
	Age      *int            `json:"age"`
	Cron     string          `json:"cron"`
}

type accountConfig struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
	Provider    string `json:"provider"`
	IMAPAddr    string `json:"imap_addr"`
	PasswordEnv string `json:"password_env"`
}

func resolveIMAPAddress(provider string, address string) (string, error) {
	return mailbin.ResolveIMAPAddress(provider, address)
}

func loadConfiguredAccounts(
	configPath string,
	selectedAccount string,
	input io.Reader,
	prompt io.Writer,
	getenv func(string) string,
	interactive bool,
) (loadedAccountsConfig, error) {
	config, err := readAccountsConfig(configPath)
	if err != nil {
		return loadedAccountsConfig{}, err
	}

	selectedAccount = strings.TrimSpace(selectedAccount)
	loaded := loadedAccountsConfig{
		Accounts: make([]ConfiguredAccount, 0, len(config.Accounts)),
		Age:      *config.Age,
	}
	schedule, err := parseCronSchedule(config.Cron)
	if err != nil {
		return loadedAccountsConfig{}, err
	}
	loaded.Schedule = schedule

	for _, configured := range config.Accounts {
		name := strings.TrimSpace(configured.Name)
		if name == "" {
			name = defaultAccountName(strings.TrimSpace(configured.Email))
		}
		if selectedAccount != "" && name != selectedAccount {
			continue
		}

		address, err := resolveIMAPAddress(configured.Provider, configured.IMAPAddr)
		if err != nil {
			return loadedAccountsConfig{}, fmt.Errorf("account %q: %w", name, err)
		}

		password, err := resolveConfiguredAccountPassword(name, configured.PasswordEnv, input, prompt, getenv, interactive)
		if err != nil {
			return loadedAccountsConfig{}, fmt.Errorf("account %q: %w", name, err)
		}

		loaded.Accounts = append(loaded.Accounts, ConfiguredAccount{
			Name: name,
			Config: mailbin.Config{
				Provider: strings.TrimSpace(configured.Provider),
				Address:  address,
				Email:    strings.TrimSpace(configured.Email),
				Password: password,
			},
		})
	}

	if selectedAccount != "" && len(loaded.Accounts) == 0 {
		return loadedAccountsConfig{}, fmt.Errorf("account %q was not found in %s", selectedAccount, configPath)
	}
	if len(loaded.Accounts) == 0 {
		return loadedAccountsConfig{}, fmt.Errorf("accounts config %q does not define any accounts", configPath)
	}

	return loaded, nil
}

func readAccountsConfig(configPath string) (*accountsConfig, error) {
	contents, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read accounts config %q: %w", configPath, err)
	}

	var config accountsConfig
	if err := json.Unmarshal(contents, &config); err != nil {
		return nil, fmt.Errorf("parse accounts config %q: %w", configPath, err)
	}

	if len(config.Accounts) == 0 {
		return nil, fmt.Errorf("accounts config %q does not define any accounts", configPath)
	}
	if config.Age == nil {
		return nil, fmt.Errorf("accounts config %q is missing age", configPath)
	}
	if *config.Age < 0 {
		return nil, fmt.Errorf("accounts config %q age must be 0 or greater", configPath)
	}
	if strings.TrimSpace(config.Cron) == "" {
		return nil, fmt.Errorf("accounts config %q is missing cron", configPath)
	}

	seenNames := make(map[string]struct{}, len(config.Accounts))
	for index, account := range config.Accounts {
		if strings.TrimSpace(account.Email) == "" {
			return nil, fmt.Errorf("account %d is missing email", index+1)
		}

		name := strings.TrimSpace(account.Name)
		if name == "" {
			name = defaultAccountName(strings.TrimSpace(account.Email))
		}
		if _, exists := seenNames[name]; exists {
			return nil, fmt.Errorf("accounts config %q contains duplicate account name %q", configPath, name)
		}
		seenNames[name] = struct{}{}
	}

	return &config, nil
}

func normalizeBlacklistFromAccounts(accounts []string) []string {
	normalized := make([]string, 0, len(accounts))
	seen := make(map[string]struct{}, len(accounts))
	for _, account := range accounts {
		account = strings.TrimSpace(account)
		if account == "" {
			continue
		}

		key := strings.ToLower(account)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		normalized = append(normalized, account)
	}

	return normalized
}

func resolveConfiguredAccountPassword(
	accountName string,
	passwordEnv string,
	input io.Reader,
	prompt io.Writer,
	getenv func(string) string,
	interactive bool,
) (string, error) {
	passwordEnv = strings.TrimSpace(passwordEnv)
	if passwordEnv == "" {
		return resolvePassword(input, prompt, getenv, interactive)
	}
	if password := getenv(passwordEnv); password != "" {
		return password, nil
	}
	if password := getenv("MAILBIN_PASSWORD"); password != "" {
		return password, nil
	}
	if !interactive {
		return "", fmt.Errorf("%s is required when stdin is not interactive", passwordEnv)
	}

	return promptPassword(
		input,
		prompt,
		fmt.Sprintf("Enter IMAP password for %s: ", accountName),
	)
}

func promptPassword(input io.Reader, prompt io.Writer, promptText string) (string, error) {
	if prompt != nil {
		if _, err := fmt.Fprint(prompt, promptText); err != nil {
			return "", fmt.Errorf("write password prompt: %w", err)
		}
	}

	reader := bufio.NewReader(input)
	password, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("read password: %w", err)
	}

	value := strings.TrimRight(password, "\r\n")
	if value == "" {
		return "", fmt.Errorf("password is required")
	}

	return value, nil
}
