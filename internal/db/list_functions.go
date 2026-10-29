package db

import (
	"database/sql/driver"
	"encoding/json"
	"net"
	"strconv"
	"strings"

	"modernc.org/sqlite"
)

// List queries use the same Unicode folding, address spelling and tag
// splitting as Go. SQLite's built-in lower() only folds ASCII.
func init() {
	sqlite.MustRegisterDeterministicScalarFunction("tlswatch_lower", 1, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		s, _ := args[0].(string)
		return strings.ToLower(s), nil
	})
	sqlite.MustRegisterDeterministicScalarFunction("tlswatch_hostport", 2, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		host, _ := args[0].(string)
		port, _ := args[1].(int64)
		return net.JoinHostPort(host, strconv.FormatInt(port, 10)), nil
	})
	sqlite.MustRegisterDeterministicScalarFunction("tlswatch_tags", 1, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		s, _ := args[0].(string)
		tags := []string{}
		if s != "" {
			tags = strings.Split(s, ",")
		}
		b, err := json.Marshal(tags)
		return string(b), err
	})
}
