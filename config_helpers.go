package main

import "strings"

func defaultAccountName(email string) string {
	email = strings.TrimSpace(email)
	if email == "" {
		return "account"
	}

	return email
}
