// verifyrelease checks a signed release directory before it is published to
// the download bucket. It trusts only the pinned bootstrap public key (the one
// the App ships), never a key found inside the release itself.
//
// Usage:
//
//	verifyrelease --dir build/releases/SEQ --pinned-key-file deploy/bootstrap-public-key.txt \
//	  --origin https://downloads.potafree.net --after CURRENT_STABLE_SEQUENCE
//	verifyrelease --metadata-url https://downloads.potafree.net/agent/stable/metadata \
//	  --pinned-root-file deploy/root.json
//
// The second form verifies the published TUF metadata chain (root -> timestamp
// -> snapshot -> targets) and prints the signed sequence and hashes as JSON.
// tool/verify_reproducible.sh uses it. Both print a JSON summary on success and
// exit non-zero with a reason otherwise.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	dir := flag.String("dir", "", "signed release directory")
	keyFile := flag.String("pinned-key-file", "", "file with the pinned base64 bootstrap public key")
	origin := flag.String("origin", "https://downloads.potafree.net", "public origin signed into target URLs")
	after := flag.Int64("after", 0, "currently published sequence; the release must be newer")
	metadataURL := flag.String("metadata-url", "", "verify published TUF metadata from this base URL instead of a release directory")
	rootFile := flag.String("pinned-root-file", "", "file with the pinned root.json for --metadata-url")
	flag.Parse()
	if *metadataURL != "" {
		if *rootFile == "" {
			fmt.Fprintln(os.Stderr, "--metadata-url needs --pinned-root-file")
			os.Exit(2)
		}
		summary, err := VerifyMetadataURL(strings.TrimRight(*metadataURL, "/"), *rootFile, time.Now())
		if err != nil {
			fmt.Fprintln(os.Stderr, "metadata rejected:", err)
			os.Exit(1)
		}
		out, err := json.Marshal(summary)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(string(out))
		return
	}
	if *dir == "" || *keyFile == "" {
		fmt.Fprintln(os.Stderr, "--dir and --pinned-key-file are required")
		os.Exit(2)
	}
	pinned, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read pinned key:", err)
		os.Exit(2)
	}
	summary, err := Verify(*dir, strings.TrimSpace(string(pinned)), strings.TrimRight(*origin, "/"), *after)
	if err != nil {
		fmt.Fprintln(os.Stderr, "release rejected:", err)
		os.Exit(1)
	}
	fmt.Println(summary.JSON())
}
