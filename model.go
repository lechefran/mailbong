package main

import (
	"context"
	"io"
	"time"

	"github.com/lechefran/mailbin"
)

type App struct {
	Accounts          []ConfiguredAccount
	GetEmailAddresses func(context.Context) (EmailsResponse, error)
	Delete            func(context.Context, mailbin.Config, mailbin.DeleteCriteria) (mailbin.DeleteResult, error)
	DefaultAge        int
	Now               func() time.Time
	Output            io.Writer
}

type accountDeleteResult struct {
	AccountName string
	Result      mailbin.DeleteResult
	Err         error
}

type CronSchedule struct {
	Minute     cronField
	Hour       cronField
	DayOfMonth cronField
	Month      cronField
	DayOfWeek  cronField
}

type cronField struct {
	Any    bool
	Values map[int]struct{}
}

type EmailsResponse struct {
	Addresses []string `json:"addresses"`
}

type ConfiguredAccount struct {
	Name   string
	Config mailbin.Config
}
