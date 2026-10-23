//go:build !unix

package policy

func copyOwner(from, to string) {}
