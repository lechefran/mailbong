package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const blacklistRequestTimeout = 5 * time.Second

func getEmailAddresses(ctx context.Context, url, key string) (EmailsResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return EmailsResponse{}, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)

	client := http.Client{Timeout: blacklistRequestTimeout}
	apiRes, err := client.Do(req)
	if err != nil {
		return EmailsResponse{}, err
	}
	defer apiRes.Body.Close()

	if apiRes.StatusCode < 200 || apiRes.StatusCode >= 300 {
		return EmailsResponse{}, fmt.Errorf("get email addresses failed: %s", apiRes.Status)
	}

	var res EmailsResponse
	if err = json.NewDecoder(apiRes.Body).Decode(&res); err != nil {
		return EmailsResponse{}, err
	}
	return res, nil
}
