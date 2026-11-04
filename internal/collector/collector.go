// Package collector parses TLS Secrets and exposes Prometheus metrics
// describing each certificate's expiry.
package collector

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// AnnotationMonitor is read when --require-annotation is set.
	AnnotationMonitor = "tigertrust.io/monitor"
)

// Metrics bundles the Prometheus collectors this exporter publishes.
type Metrics struct {
	Registry      *prometheus.Registry
	ExpirySeconds *prometheus.GaugeVec
	NotAfterDays  *prometheus.GaugeVec
	Info          *prometheus.GaugeVec
	LastSync      prometheus.Gauge
	SyncErrors    prometheus.Counter
}

// NewMetrics builds a fresh metric set and registers it on its own registry.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	labels := []string{"namespace", "secret", "common_name", "issuer"}
	m := &Metrics{
		Registry: reg,
		ExpirySeconds: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "tigertrust",
			Name:      "cert_expiry_timestamp_seconds",
			Help:      "Unix timestamp (seconds) when the certificate in a TLS Secret expires.",
		}, labels),
		NotAfterDays: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "tigertrust",
			Name:      "cert_not_after_days",
			Help:      "Days until the certificate in a TLS Secret expires. Negative if already expired.",
		}, labels),
		Info: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "tigertrust",
			Name:      "cert_info",
			Help:      "Static per-certificate info, always 1.",
		}, append(labels, "algorithm", "san_count")),
		LastSync: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "tigertrust",
			Name:      "exporter_last_sync_timestamp_seconds",
			Help:      "Unix timestamp of the last successful Secret sync.",
		}),
		SyncErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "tigertrust",
			Name:      "exporter_sync_errors_total",
			Help:      "Number of sync iterations that failed to list Secrets.",
		}),
	}
	reg.MustRegister(m.ExpirySeconds, m.NotAfterDays, m.Info, m.LastSync, m.SyncErrors)
	return m
}

// Config controls the Run loop.
type Config struct {
	Namespaces         []string // empty slice => all namespaces
	RequireAnnotation  bool     // only Secrets with AnnotationMonitor="true"
	Interval           time.Duration
	Logger             *slog.Logger
}

// Run lists Secrets on each tick and updates Metrics. It returns when ctx is done.
func Run(ctx context.Context, client kubernetes.Interface, cfg Config, m *Metrics) error {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 60 * time.Second
	}
	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	// Run an initial sync immediately.
	if err := Sync(ctx, client, cfg, m); err != nil {
		cfg.Logger.Error("initial sync failed", "err", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := Sync(ctx, client, cfg, m); err != nil {
				m.SyncErrors.Inc()
				cfg.Logger.Error("sync failed", "err", err)
			}
		}
	}
}

// Sync performs one list + parse + metric update pass.
func Sync(ctx context.Context, client kubernetes.Interface, cfg Config, m *Metrics) error {
	namespaces := cfg.Namespaces
	if len(namespaces) == 0 {
		namespaces = []string{metav1.NamespaceAll}
	}

	// We rebuild the known-set each pass so metrics for deleted Secrets go away.
	m.ExpirySeconds.Reset()
	m.NotAfterDays.Reset()
	m.Info.Reset()

	for _, ns := range namespaces {
		secrets, err := client.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			return fmt.Errorf("list secrets in %q: %w", ns, err)
		}
		for i := range secrets.Items {
			s := &secrets.Items[i]
			if !shouldObserve(s, cfg.RequireAnnotation) {
				continue
			}
			cert, err := extractLeafCert(s)
			if err != nil {
				cfg.Logger.Warn("skip secret", "namespace", s.Namespace, "name", s.Name, "err", err)
				continue
			}
			observe(m, s, cert)
		}
	}
	m.LastSync.SetToCurrentTime()
	return nil
}

func shouldObserve(s *corev1.Secret, requireAnnotation bool) bool {
	isTLS := s.Type == corev1.SecretTypeTLS
	hasMonitor := strings.EqualFold(s.Annotations[AnnotationMonitor], "true")
	if requireAnnotation {
		return hasMonitor
	}
	return isTLS || hasMonitor
}

func extractLeafCert(s *corev1.Secret) (*x509.Certificate, error) {
	data, ok := s.Data[corev1.TLSCertKey]
	if !ok || len(data) == 0 {
		// Some operators store under non-standard keys when the Secret isn't type=tls.
		for _, k := range []string{"ca.crt", "cert", "cert.pem", "certificate"} {
			if d, ok := s.Data[k]; ok && len(d) > 0 {
				data = d
				break
			}
		}
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("no tls.crt (or recognized cert key) in secret")
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("no CERTIFICATE PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

func observe(m *Metrics, s *corev1.Secret, cert *x509.Certificate) {
	cn := cert.Subject.CommonName
	issuer := cert.Issuer.CommonName
	labels := prometheus.Labels{
		"namespace":   s.Namespace,
		"secret":      s.Name,
		"common_name": cn,
		"issuer":      issuer,
	}
	m.ExpirySeconds.With(labels).Set(float64(cert.NotAfter.Unix()))
	m.NotAfterDays.With(labels).Set(time.Until(cert.NotAfter).Hours() / 24)

	infoLabels := prometheus.Labels{
		"namespace":   s.Namespace,
		"secret":      s.Name,
		"common_name": cn,
		"issuer":      issuer,
		"algorithm":   cert.PublicKeyAlgorithm.String() + "/" + cert.SignatureAlgorithm.String(),
		"san_count":   fmt.Sprintf("%d", len(cert.DNSNames)+len(cert.IPAddresses)),
	}
	m.Info.With(infoLabels).Set(1)
}
