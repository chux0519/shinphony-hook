package main

// TF 161: the scheduled task started the console-subsystem Hook directly, so
// Windows opened a console window for it at logon and on every start. Where
// Windows supports it the task runs the Hook under `conhost.exe --headless`;
// otherwise it runs the Hook directly, and `supervise`/`serve` close the console
// Windows created for them. These pieces are plain so they are tested on every
// platform.

// windowsHeadlessConsoleMinBuild is Windows 10 21H2, the first build whose
// conhost.exe is relied on for `--headless`; Windows 11 builds are above it.
const windowsHeadlessConsoleMinBuild = 19044

func windowsHeadlessConsoleSupported(build uint32) bool {
	return build >= windowsHeadlessConsoleMinBuild
}

// windowsTaskAction is the scheduled task's action, plus what identifies the
// task as ours: the Hook it runs (Program) and, in the headless form, the
// conhost.exe that runs it.
type windowsTaskAction struct {
	Execute   string
	Arguments string
	Program   string
	Conhost   string
}

// windowsTaskActionFor builds the action. exe is the Hook, quotedExe the same
// path quoted for a command line, arguments the Hook's own arguments. Without
// headless support, or without a conhost.exe, the Hook runs directly.
func windowsTaskActionFor(exe, quotedExe, arguments, conhost string, headless bool) windowsTaskAction {
	if !headless || conhost == "" {
		return windowsTaskAction{Execute: exe, Arguments: arguments, Program: exe}
	}
	return windowsTaskAction{
		Execute:   conhost,
		Arguments: "--headless " + quotedExe + " " + arguments,
		Program:   exe,
		Conhost:   conhost,
	}
}
