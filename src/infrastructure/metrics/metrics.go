package metrics

import "github.com/gnaivex/tools/metrics"

func init() {
	metrics.MustRegister(
		apiRequestsTotal,
		apiRequestsDuration,
	)
}
