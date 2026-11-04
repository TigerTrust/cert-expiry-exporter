package collector

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func genPEM(t *testing.T, cn string, notAfter time.Time) []byte {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{cn},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	var out []byte
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	return out
}

func TestExtractLeafCert_TLSKey(t *testing.T) {
	s := &corev1.Secret{
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{corev1.TLSCertKey: genPEM(t, "a.example", time.Now().Add(24*time.Hour))},
	}
	c, err := extractLeafCert(s)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject.CommonName != "a.example" {
		t.Errorf("CN=%q", c.Subject.CommonName)
	}
}

func TestExtractLeafCert_FallbackKey(t *testing.T) {
	s := &corev1.Secret{
		Data: map[string][]byte{"ca.crt": genPEM(t, "ca.example", time.Now().Add(24*time.Hour))},
	}
	c, err := extractLeafCert(s)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject.CommonName != "ca.example" {
		t.Errorf("CN=%q", c.Subject.CommonName)
	}
}

func TestExtractLeafCert_MissingData(t *testing.T) {
	if _, err := extractLeafCert(&corev1.Secret{Type: corev1.SecretTypeTLS}); err == nil {
		t.Fatal("expected error on empty secret")
	}
}

func TestShouldObserve(t *testing.T) {
	tls := &corev1.Secret{Type: corev1.SecretTypeTLS}
	opaque := &corev1.Secret{Type: corev1.SecretTypeOpaque}
	annotated := &corev1.Secret{Type: corev1.SecretTypeOpaque, ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{AnnotationMonitor: "true"}}}

	if !shouldObserve(tls, false) {
		t.Error("TLS secret should be observed by default")
	}
	if shouldObserve(opaque, false) {
		t.Error("Opaque without annotation should be skipped")
	}
	if !shouldObserve(annotated, false) {
		t.Error("Annotated opaque should be observed")
	}
	if shouldObserve(tls, true) {
		t.Error("TLS without annotation should be skipped when requireAnnotation=true")
	}
	if !shouldObserve(annotated, true) {
		t.Error("Annotated opaque should be observed when requireAnnotation=true")
	}
}

func TestSync_WithFakeClient(t *testing.T) {
	futureSec := time.Now().Add(100 * 24 * time.Hour)
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "default"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{corev1.TLSCertKey: genPEM(t, "a.example", futureSec)},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "kube-system"},
			Type:       corev1.SecretTypeOpaque, // not observed by default
			Data:       map[string][]byte{"ca.crt": genPEM(t, "b.example", futureSec)},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: "default", Annotations: map[string]string{AnnotationMonitor: "true"}},
			Type:       corev1.SecretTypeOpaque,
			Data:       map[string][]byte{"ca.crt": genPEM(t, "c.example", futureSec)},
		},
	)

	m := NewMetrics()
	if err := Sync(context.Background(), client, Config{}, m); err != nil {
		t.Fatal(err)
	}
	// a and c should be observed; b should not.
	count := testutil.CollectAndCount(m.NotAfterDays)
	if count != 2 {
		t.Fatalf("NotAfterDays series count = %d, want 2", count)
	}
	if got := testutil.ToFloat64(m.LastSync); got == 0 {
		t.Error("LastSync should be set")
	}
}

func TestSync_RequireAnnotation(t *testing.T) {
	futureSec := time.Now().Add(100 * 24 * time.Hour)
	client := fake.NewSimpleClientset(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "default"},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{corev1.TLSCertKey: genPEM(t, "a.example", futureSec)},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: "default", Annotations: map[string]string{AnnotationMonitor: "true"}},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{corev1.TLSCertKey: genPEM(t, "c.example", futureSec)},
		},
	)
	m := NewMetrics()
	if err := Sync(context.Background(), client, Config{RequireAnnotation: true}, m); err != nil {
		t.Fatal(err)
	}
	// Only c should be observed.
	count := testutil.CollectAndCount(m.NotAfterDays)
	if count != 1 {
		t.Fatalf("NotAfterDays series count = %d, want 1", count)
	}
	// Scrape metrics and ensure only `c.example` appears.
	// (testutil.CollectAndFormat exists in newer client_golang; we just do a
	// textual smoke via Gather.)
	got := gatherText(t, m)
	if !strings.Contains(got, `common_name="c.example"`) {
		t.Errorf("metrics missing c.example: %s", got)
	}
	if strings.Contains(got, `common_name="a.example"`) {
		t.Errorf("metrics unexpectedly include a.example: %s", got)
	}
}

func gatherText(t *testing.T, m *Metrics) string {
	t.Helper()
	mfs, err := m.Registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, mf := range mfs {
		for _, met := range mf.GetMetric() {
			b.WriteString(mf.GetName())
			b.WriteString("{")
			for _, lp := range met.GetLabel() {
				b.WriteString(lp.GetName())
				b.WriteString(`="`)
				b.WriteString(lp.GetValue())
				b.WriteString(`",`)
			}
			b.WriteString("}\n")
		}
	}
	return b.String()
}
