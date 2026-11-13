package main

import "testing"

func TestFocusOnlyMatchingTmuxClientSession(t *testing.T) {
	c := &localSnapshot{taskContext: taskContext{Multiplexer: "tmux"}, Socket: "/tmp/socket", ServerPID: "42", SessionID: "$1"}
	client := &recentSession{Socket: c.Socket, ServerPID: c.ServerPID, Session: c.SessionID, Pane: "%999"}
	if !sameContextSession(client, c) {
		t.Fatal("same session, different pane should be reusable")
	}
	client.Session = "$2"
	if sameContextSession(client, c) {
		t.Fatal("different session must not be hijacked")
	}
	client.Session = c.SessionID
	client.ServerPID = "43"
	if sameContextSession(client, c) {
		t.Fatal("recycled server")
	}
	client.ServerPID = c.ServerPID
	client.Socket = "/tmp/other"
	if sameContextSession(client, c) || sameContextSession(nil, c) {
		t.Fatal("wrong socket or unknown client")
	}
}
