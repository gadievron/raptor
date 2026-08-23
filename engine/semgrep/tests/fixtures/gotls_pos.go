package main

import "crypto/tls"

func deprecatedTLS10() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS10}
}

func deprecatedSSL30() *tls.Config {
	cfg := tls.Config{ServerName: "example", MinVersion: tls.VersionSSL30}
	return &cfg
}

func explicitZero() *tls.Config {
	return &tls.Config{MinVersion: 0}
}
