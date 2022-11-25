package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const githubAPIURL = "https://api.github.com/repos/apernet/hysteria/releases/latest"

type releaseInfo struct {
	URL         string `json:"html_url"`
	TagName     string `json:"tag_name"`
	CreatedAt   string `json:"created_at"`
	PublishedAt string `json:"published_at"`
}

func checkUpdate() {
	sv := strings.Split(appVersion, "-")[0]
	info, err := fetchLatestRelease()
	if err == nil && info.TagName != sv {
		logrus.WithFields(logrus.Fields{
			"version": info.TagName,
			"url":     info.URL,
		}).Info("New version available")
	}
}

func fetchLatestRelease() (*releaseInfo, error) {
	hc := &http.Client{
		Timeout: time.Second * 20,
	}
	resp, err := hc.Get(githubAPIURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var info releaseInfo
	err = json.Unmarshal(body, &info)
	return &info, err
}
