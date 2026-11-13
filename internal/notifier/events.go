package notifier

func codexEvent(_ []byte, _ bool) (event, bool) {
	// Turn/Stop is never evidence of whole-task completion. Legacy entrypoints
	// remain callable but silent for old hook configurations.
	return event{}, false
}
