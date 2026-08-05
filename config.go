package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/lechefran/mailbin"
)

type loadedAccountsConfig struct {
	Accounts             []ConfiguredAccount
	Age                  int
	APIKey               string
	Schedule             CronSchedule
	GetEmailAddressesURL string
}

type accountsConfig struct {
	Accounts             []accountConfig `json:"accounts"`
	Age                  *int            `json:"age"`
	APIKey               string          `json:"apiKey"`
	Cron                 string          `json:"cron"`
	GetEmailAddressesURL string          `json:"getEmailAddressesUrl"`
}

type accountConfig struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Provider string `json:"provider"`
	IMAPAddr string `json:"imap_addr"`
	Password string `json:"password"`
}

func loadConfiguredAccounts(configPath string) (loadedAccountsConfig, error) {
	config, err := readAppConfig(configPath)
	if err != nil {
		return loadedAccountsConfig{}, err
	}

	loaded := loadedAccountsConfig{
		Accounts:             make([]ConfiguredAccount, 0, len(config.Accounts)),
		Age:                  *config.Age,
		APIKey:               strings.TrimSpace(config.APIKey),
		GetEmailAddressesURL: strings.TrimSpace(config.GetEmailAddressesURL),
	}
	schedule, err := parseCronSchedule(config.Cron)
	if err != nil {
		return loadedAccountsConfig{}, err
	}
	loaded.Schedule = schedule

	for _, configured := range config.Accounts {
		name := configuredAccountName(configured)

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

	return loaded, nil
}

func readAppConfig(configPath string) (*accountsConfig, error) {
	contents, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read accounts config %q: %w", configPath, err)
	}

	var config accountsConfig
	if err := json.Unmarshal(contents, &config); err != nil {
		return nil, fmt.Errorf("parse app config %q: %w", configPath, err)
	}

	if len(config.Accounts) == 0 {
		return nil, fmt.Errorf("app config %q does not define any accounts", configPath)
	}
	if config.Age == nil {
		return nil, fmt.Errorf("app config %q is missing age", configPath)
	}
	if *config.Age < 0 {
		return nil, fmt.Errorf("app config %q age must be 0 or greater", configPath)
	}
	if strings.TrimSpace(config.APIKey) == "" {
		return nil, fmt.Errorf("app config %q api key is missing", configPath)
	}
	if strings.TrimSpace(config.Cron) == "" {
		return nil, fmt.Errorf("app config %q is missing cron", configPath)
	}
	if strings.TrimSpace(config.GetEmailAddressesURL) == "" {
		return nil, fmt.Errorf("app config %q get email addresses url is missing", configPath)
	}

	seenNames := make(map[string]struct{}, len(config.Accounts))
	for index, account := range config.Accounts {
		if strings.TrimSpace(account.Email) == "" {
			return nil, fmt.Errorf("account %d is missing email", index+1)
		}
		if strings.TrimSpace(account.Password) == "" {
			return nil, fmt.Errorf("account %d is missing password", index+1)
		}

		name := configuredAccountName(account)
		if _, exists := seenNames[name]; exists {
			return nil, fmt.Errorf("accounts config %q contains duplicate account name %q", configPath, name)
		}
		seenNames[name] = struct{}{}
	}

	return &config, nil
}

func configuredAccountName(account accountConfig) string {
	if name := strings.TrimSpace(account.Name); name != "" {
		return name
	}

	return strings.TrimSpace(account.Email)
}
