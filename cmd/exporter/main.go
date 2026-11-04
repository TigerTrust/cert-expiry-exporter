// Command cert-expiry-exporter is a Kubernetes-aware Prometheus exporter
// for TLS certificate expiry in Secrets.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/tigertrust/cert-expiry-exporter/internal/collector"
)

const usage = `cert-expiry-exporter — TigerTrust Kubernetes cert expiry exporter

Flags:
`

func main() {
	fs := flag.NewFlagSet("cert-expiry-exporter", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage); fs.PrintDefaults() }

	metricsAddr := fs.String("metrics-addr", ":8080", "address to serve /metrics on")
	probeAddr := fs.String("probe-addr", ":8081", "address to serve health probes on")
	namespaces := fs.String("namespaces", "", "comma-separated namespaces (empty = all)")
	requireAnnotation := fs.Bool("require-annotation", false, "only observe Secrets with annotation "+collector.AnnotationMonitor+"=true")
	interval := fs.Duration("interval", 60*time.Second, "sync interval")
	kubeconfig := fs.String("kubeconfig", "", "path to kubeconfig (empty = in-cluster config, then $KUBECONFIG, then ~/.kube/config)")
	logFormat := fs.String("log-format", "text", "log format: text|json")

	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}

	logger := newLogger(*logFormat)
	slog.SetDefault(logger)

	cfg, err := loadKubeConfig(*kubeconfig)
	if err != nil {
		logger.Error("load kubeconfig", "err", err)
		os.Exit(1)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		logger.Error("kubernetes client", "err", err)
		os.Exit(1)
	}

	metrics := collector.NewMetrics()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// /metrics server
	go serveHTTP(*metricsAddr, "metrics", func(mux *http.ServeMux) {
		mux.Handle("/metrics", promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{Registry: metrics.Registry}))
	}, logger)

	// health probes
	go serveHTTP(*probeAddr, "probes", func(mux *http.ServeMux) {
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})
		mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})
	}, logger)

	logger.Info("starting",
		"metrics", *metricsAddr,
		"probe", *probeAddr,
		"interval", interval.String(),
		"namespaces", *namespaces,
		"require_annotation", *requireAnnotation,
	)

	runCfg := collector.Config{
		Namespaces:        splitNS(*namespaces),
		RequireAnnotation: *requireAnnotation,
		Interval:          *interval,
		Logger:            logger,
	}
	if err := collector.Run(ctx, client, runCfg, metrics); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("exporter loop", "err", err)
		os.Exit(1)
	}
}

func serveHTTP(addr, label string, register func(*http.ServeMux), logger *slog.Logger) {
	mux := http.NewServeMux()
	register(mux)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	logger.Info("http listen", "label", label, "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("http serve", "label", label, "err", err)
	}
}

func loadKubeConfig(path string) (*rest.Config, error) {
	// Try in-cluster first when path is empty.
	if path == "" {
		if cfg, err := rest.InClusterConfig(); err == nil {
			return cfg, nil
		}
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if path != "" {
		rules.ExplicitPath = path
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{}).ClientConfig()
}

func splitNS(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func newLogger(format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	switch format {
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	default:
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
}
