package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/lechefran/mailbin"
)

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
	Name     string `json:"name"`
	Email    string `json:"email"`
	Provider string `json:"provider"`
	IMAPAddr string `json:"imap_addr"`
	Password string `json:"password"`
}

func loadConfiguredAccounts(
	configPath string,
) (loadedAccountsConfig, error) {
	config, err := readAccountsConfig(configPath)
	if err != nil {
		return loadedAccountsConfig{}, err
	}

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

		address, err := mailbin.ResolveIMAPAddress(configured.Provider, configured.IMAPAddr)
		if err != nil {
			return loadedAccountsConfig{}, fmt.Errorf("account %q: %w", name, err)
		}

		loaded.Accounts = append(loaded.Accounts, ConfiguredAccount{
			Name: name,
			Config: mailbin.Config{
				Provider: strings.TrimSpace(configured.Provider),
				Address:  address,
				Email:    strings.TrimSpace(configured.Email),
				Password: configured.Password,
			},
		})
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
		if strings.TrimSpace(account.Password) == "" {
			return nil, fmt.Errorf("account %d is missing password", index+1)
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
