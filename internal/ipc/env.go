package ipc

import (
	"os"
	"strings"
)

// curatedEnvKeys lists environment variables propagated from client to daemon.
var curatedEnvKeys = []string{
	"HOME", "PATH", "USER", "SHELL", "TERM",
	"LANG", "GOPATH", "GOROOT",
}

// curatedEnvPrefixes lists prefixes for additional propagated variables.
var curatedEnvPrefixes = []string{
	"LC_",
}

// CaptureEnv builds a curated environment map from the current process.
func CaptureEnv() map[string]string {
	env := make(map[string]string)
	for _, key := range curatedEnvKeys {
		if val, ok := os.LookupEnv(key); ok {
			env[key] = val
		}
	}
	for _, kv := range os.Environ() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		for _, prefix := range curatedEnvPrefixes {
			if strings.HasPrefix(k, prefix) {
				env[k] = v
			}
		}
	}
	return env
}
