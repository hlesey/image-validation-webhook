// image-validation-webhook is a minimal ImagePolicyWebhook backend for labs.
//
// The API server POSTs an ImageReview with the Pod's images; the backend answers
// allowed=true only if every image comes from an allowed registry prefix.
//
// It generates a self-signed certificate at startup, so there is no CA to copy:
// the API server's backend kubeconfig uses insecure-skip-tls-verify (lab only).
// Not production-ready: no client authentication, no certificate verification.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// ImageReview is the subset of imagepolicy.k8s.io/v1alpha1 ImageReview the backend needs.
type ImageReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Spec       *ImageReviewSpec   `json:"spec,omitempty"`
	Status     *ImageReviewStatus `json:"status,omitempty"`
}

type ImageReviewSpec struct {
	Containers  []ImageReviewContainerSpec `json:"containers"`
	Annotations map[string]string          `json:"annotations,omitempty"`
	Namespace   string                     `json:"namespace,omitempty"`
}

type ImageReviewContainerSpec struct {
	Image string `json:"image"`
}

type ImageReviewStatus struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// normalize returns the image with its registry, the way the container runtime resolves it:
// "nginx:1.27" -> "docker.io/library/nginx:1.27", "bitnami/redis" -> "docker.io/bitnami/redis".
func normalize(image string) string {
	first, rest, found := strings.Cut(image, "/")
	if !found {
		return "docker.io/library/" + image
	}
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return image
	}
	return "docker.io/" + first + "/" + rest
}

// parseAllowed turns "ghcr.io, quay.io/cilium" into prefixes ending in "/", so that
// "ghcr.io/" does not also match "ghcr.io.evil.com/...".
func parseAllowed(list string) []string {
	var out []string
	for _, p := range strings.Split(list, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasSuffix(p, "/") {
			p += "/"
		}
		out = append(out, p)
	}
	return out
}

// review decides on one ImageReview: every container image must match an allowed prefix.
func review(spec ImageReviewSpec, allowed []string) ImageReviewStatus {
	var denied []string
	for i, c := range spec.Containers {
		full := normalize(c.Image)
		ok := false
		for _, p := range allowed {
			if strings.HasPrefix(full, p) {
				ok = true
				break
			}
		}
		if !ok {
			denied = append(denied, fmt.Sprintf("container %d image %q (%s)", i+1, c.Image, full))
		}
	}
	if len(denied) > 0 {
		return ImageReviewStatus{
			Allowed: false,
			Reason:  fmt.Sprintf("denied: %s; allowed registries: %s", strings.Join(denied, ", "), strings.Join(allowed, " ")),
		}
	}
	return ImageReviewStatus{Allowed: true}
}

func handler(allowed []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST an ImageReview", http.StatusMethodNotAllowed)
			return
		}
		var req ImageReview
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil || req.Spec == nil {
			http.Error(w, "invalid ImageReview", http.StatusBadRequest)
			return
		}
		status := review(*req.Spec, allowed)
		images := make([]string, 0, len(req.Spec.Containers))
		for _, c := range req.Spec.Containers {
			images = append(images, c.Image)
		}
		log.Printf("namespace=%q images=%v allowed=%t %s", req.Spec.Namespace, images, status.Allowed, status.Reason)

		apiVersion := req.APIVersion
		if apiVersion == "" {
			apiVersion = "imagepolicy.k8s.io/v1alpha1"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ImageReview{APIVersion: apiVersion, Kind: "ImageReview", Status: &status})
	}
}

// selfSigned creates an in-memory certificate for localhost, 127.0.0.1 and the host name.
func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	host, _ := os.Hostname()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "image-validation-webhook"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost", "image-validation-webhook", host},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func main() {
	listen := flag.String("listen", envOr("LISTEN", ":8080"), "address to listen on (env LISTEN)")
	path := flag.String("path", envOr("WEBHOOK_PATH", "/validate"), "URL path of the webhook (env WEBHOOK_PATH)")
	registries := flag.String("allowed-registries", envOr("ALLOWED_REGISTRIES", "ghcr.io/"),
		"comma-separated allowed image prefixes (env ALLOWED_REGISTRIES)")
	flag.Parse()

	allowed := parseAllowed(*registries)
	cert, err := selfSigned()
	if err != nil {
		log.Fatalf("certificate: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(*path, handler(allowed))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })

	srv := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("image-validation-webhook on https://%s%s, allowed registries: %v", *listen, *path, allowed)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
