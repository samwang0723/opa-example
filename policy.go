//go:build go1.16

package main

import (
	_ "embed"
)

//go:embed ads.rego
var policy []byte

func readPolicy(path string) ([]byte, error) {
	return policy, nil
}
