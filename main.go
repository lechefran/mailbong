package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	app, schedule, err := newApp()
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := runOnCronSchedule(ctx, app, time.Now, schedule); err != nil {
		log.Fatal(err)
	}
}

func newApp() (*App, CronSchedule, error) {
	configPath := flag.String("config", os.Getenv("MAILBONG_CONFIG"), "path to app config json file")
	flag.Parse()

	configValue := strings.TrimSpace(*configPath)
	if configValue == "" {
		return nil, CronSchedule{}, fmt.Errorf("config file is required")
	}

	loadedConfig, err := loadConfiguredAccounts(configValue)
	if err != nil {
		return nil, CronSchedule{}, err
	}

	getEmailAddressesFunc := func(ctx context.Context) (EmailsResponse, error) {
		return getEmailAddresses(ctx, loadedConfig.GetEmailAddressesURL, loadedConfig.APIKey)
	}

	return &App{
		Accounts:          loadedConfig.Accounts,
		GetEmailAddresses: getEmailAddressesFunc,
		DefaultAge:        loadedConfig.Age,
		Now:               time.Now,
		Output:            os.Stdout,
	}, loadedConfig.Schedule, nil
}
