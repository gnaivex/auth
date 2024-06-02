package metrics

import (
	"strconv"
	"time"

	"github.com/gnaivex/tools/metrics"
)

const labelEndpoint = "endpoint"
const labelStatus = "status"

var apiRequestsTotal = metrics.NewCounterVec(
	"api_requests_count",
	"Total number of requests.",
	[]string{labelEndpoint, labelStatus},
)

var apiRequestsDuration = metrics.NewHistogramVec(
	"api_requests_duration",
	"Requests to provider processing time in ms.",
	metrics.DefBuckets,
	[]string{labelEndpoint, labelStatus},
)

func IncStartedJobsCount(endpoint string, status int) {
	labels := metrics.Labels{labelEndpoint: endpoint, labelStatus: strconv.Itoa(status)}

	apiRequestsTotal.With(labels).Inc()
}

func RecordAPIRequestsDuration(endpoint string, status int, duration time.Duration) {
	labels := metrics.Labels{labelEndpoint: endpoint, labelStatus: strconv.Itoa(status)}

	apiRequestsDuration.With(labels).Observe(duration.Seconds())
}
