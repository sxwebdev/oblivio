package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ApplicationInfo is a gauge that tracks build and runtime information
var ApplicationInfo = promauto.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "application_info",
		Help: "build and runtime information",
	},
	[]string{
		"application",
		"version",
		"branch",
		"revision",
		"pipeline_id",
		"start_time",
	},
)

type BuildInfo struct {
	Application string
	Version     string
	Branch      string
	Revision    string
	PipelineID  string
}

func Init(info BuildInfo) {
	ApplicationInfo.WithLabelValues(
		info.Application,
		info.Version,
		info.Branch,
		info.Revision,
		info.PipelineID,
		time.Now().UTC().Format(time.RFC3339),
	).Set(1)
}
