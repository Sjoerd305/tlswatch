// Package upgradetest runs an old release of tlswatch, fills it through its
// own web UI the way a user would, stops it, and starts this build on the
// same database: the upgrade a user does by swapping the binary. It needs
// the old binary, so it is not part of go test ./...; CI downloads the
// oldest release, checks its signed checksum and runs
//
//	TLSWATCH_UPGRADE_FROM=/path/to/tlswatch-v0.1.0-linux-amd64 go test -tags upgrade ./internal/upgradetest
package upgradetest
