package usererr

import (
	"errors"
	"fmt"
	"testing"
)

func TestMessage(t *testing.T) {
	if m, ok := Message(fmt.Errorf("save: %w", Wrap(errors.New("name is required")))); !ok || m != "Name is required" {
		t.Fatalf("%q %v", m, ok)
	}
	if _, ok := Message(errors.New("database is locked")); ok {
		t.Fatal("plain error treated as a user message")
	}
	if Wrap(nil) != nil {
		t.Fatal("Wrap(nil)")
	}
}
