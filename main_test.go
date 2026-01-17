package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"nginx":                         "docker.io/library/nginx",
		"nginx:1.27":                    "docker.io/library/nginx:1.27",
		"bitnami/redis:7":               "docker.io/bitnami/redis:7",
		"ghcr.io/hlesey/nginx:1.27":     "ghcr.io/hlesey/nginx:1.27",
		"localhost/app":                 "localhost/app",
		"localhost:5000/app:1":          "localhost:5000/app:1",
		"registry.k8s.io/pause:3.10":    "registry.k8s.io/pause:3.10",
		"docker.io/library/busybox:1.0": "docker.io/library/busybox:1.0",
	}
	for in, want := range cases {
		if got := normalize(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReview(t *testing.T) {
	allowed := parseAllowed("ghcr.io, quay.io/cilium/")
	cases := []struct {
		images []string
		want   bool
	}{
		{[]string{"ghcr.io/hlesey/nginx:1.27"}, true},
		{[]string{"quay.io/cilium/cilium:v1.18"}, true},
		{[]string{"nginx:1.27"}, false},
		{[]string{"ghcr.io.evil.com/app"}, false},
		{[]string{"quay.io/other/app"}, false},
		{[]string{"ghcr.io/hlesey/nginx:1.27", "busybox"}, false},
	}
	for _, c := range cases {
		spec := ImageReviewSpec{}
		for _, i := range c.images {
			spec.Containers = append(spec.Containers, ImageReviewContainerSpec{Image: i})
		}
		if got := review(spec, allowed); got.Allowed != c.want {
			t.Errorf("review(%v).Allowed = %t, want %t (%s)", c.images, got.Allowed, c.want, got.Reason)
		}
	}
}

func TestHandler(t *testing.T) {
	body := []byte(`{"apiVersion":"imagepolicy.k8s.io/v1alpha1","kind":"ImageReview",
		"spec":{"containers":[{"image":"nginx:1.27"}],"namespace":"default"}}`)
	rec := httptest.NewRecorder()
	handler(parseAllowed("ghcr.io"))(rec, httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var resp ImageReview
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Kind != "ImageReview" || resp.APIVersion != "imagepolicy.k8s.io/v1alpha1" || resp.Status == nil || resp.Status.Allowed {
		t.Fatalf("unexpected response: %s", rec.Body.String())
	}
}
