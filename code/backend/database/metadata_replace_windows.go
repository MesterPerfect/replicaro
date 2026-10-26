//go:build windows

package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/local/replicaro/appdata"
	"golang.org/x/sys/windows"
)

// The retry budget and backoff are variables so tests can shorten them.
var (
	metadataReplaceRetryBudget  = 30 * time.Second
	metadataReplaceFirstBackoff = 50 * time.Millisecond
	metadataReplaceMaxBackoff   = 2 * time.Second
	metadataReplaceAttempt      = appdata.AtomicReplace
)

// replaceMetadataCacheFile swaps the rebuilt cache over the original. Unlike a
// Unix rename, the Windows swap fails while another program has either file
// open without delete sharing, and antivirus scanners, the search indexer and
// backup or sync tools routinely open new and changed files for a moment. The
// replacement took a full rebuild (often native listings of every snapshot) to
// produce, so a failed swap is retried with backoff for up to 30 seconds
// before the rebuild is thrown away. If the swap still fails, the original
// cache stays in place and the caller removes the replacement.
//
// Only sharing violations and access-denied errors are retried. Access denied
// is what Windows reports for a file in a pending delete and what filter
// drivers such as antivirus commonly return while they hold a file. MoveFileEx
// also reports it when replacing a destination that is still open, even when
// the holder allows delete sharing, which is the usual antivirus or indexer
// case. A lasting ACL problem just fails 30 seconds later than it would have.
//
// The caller holds the vault's low-priority shared lease, and ctx is that
// lease's context: it is canceled as soon as a backup or any other exclusive
// operation asks for the vault, and on shutdown or vault removal. The wait
// stops on cancellation so it never delays them; the rebuild is discarded
// and refreshed again later, the same as a yield at any earlier point.
func replaceMetadataCacheFile(ctx context.Context, source, destination string) error {
	deadline := time.Now().Add(metadataReplaceRetryBudget)
	backoff := metadataReplaceFirstBackoff
	for {
		err := metadataReplaceAttempt(source, destination)
		if err == nil || !metadataReplaceRetryable(err) {
			return err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("replace metadata cache: the file stayed locked or inaccessible for %s: %w", metadataReplaceRetryBudget, err)
		}
		timer := time.NewTimer(min(backoff, remaining))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		backoff = min(2*backoff, metadataReplaceMaxBackoff)
	}
}

func metadataReplaceRetryable(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}
