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
	ApiKey               string
	Schedule             CronSchedule
	GetEmailAddressesUrl string
}

type accountsConfig struct {
	Accounts             []accountConfig `json:"accounts"`
	Age                  *int            `json:"age"`
	ApiKey               string          `json:"apiKey"`
	Cron                 string          `json:"cron"`
	GetEmailAddressesUrl string          `json:"getEmailAddressesUrl"`
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
	config, err := readAppConfig(configPath)
	if err != nil {
		return loadedAccountsConfig{}, err
	}

	loaded := loadedAccountsConfig{
		Accounts:             make([]ConfiguredAccount, 0, len(config.Accounts)),
		Age:                  *config.Age,
		ApiKey:               config.ApiKey,
		GetEmailAddressesUrl: config.GetEmailAddressesUrl,
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
	if strings.TrimSpace(config.ApiKey) == "" {
		return nil, fmt.Errorf("app config %q api key is missing", configPath)
	}
	if strings.TrimSpace(config.Cron) == "" {
		return nil, fmt.Errorf("app config %q is missing cron", configPath)
	}
	if strings.TrimSpace(config.GetEmailAddressesUrl) == "" {
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
