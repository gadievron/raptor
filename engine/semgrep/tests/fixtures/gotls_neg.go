package main

import "crypto/tls"

func modernTLS() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

func modernTLS13() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13}
}
