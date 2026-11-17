package main

// consoleOwnedAlone reports whether a console shared by count processes was
// created for this process alone, and so may be closed by it.
func consoleOwnedAlone(count int) bool { return count == 1 }
