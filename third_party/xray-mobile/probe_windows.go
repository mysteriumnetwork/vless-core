package XRay

import "context"

// ProbeContext is [Probe] for a caller that may be told to stop waiting: the
// Windows core, whose start has to give way to a disconnect or a shutdown
// instead of holding it up for the length of the timeout.
func ProbeContext(ctx context.Context, domain string, timeoutMs int) error {
	return probe(ctx, domain, timeoutMs)
}
