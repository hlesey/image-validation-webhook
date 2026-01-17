# image-validation-webhook

A minimal [ImagePolicyWebhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#imagepolicywebhook)
backend for the Kubernetes Security (CKS) labs. The name follows the backend of
B. Muschko's *CKS Study Guide* (chapter 6).

The API server sends an `ImageReview` with the images of a new Pod; the backend answers
`allowed: true` only if every image comes from an allowed registry prefix.
Images without a registry are resolved like the container runtime does
(`nginx` is `docker.io/library/nginx`), and prefixes always end in `/`, so `ghcr.io/` does not
match `ghcr.io.evil.com/...`.

**Lab only, not production-ready:** it generates a self-signed certificate at startup (no CA to
distribute; the API server's backend kubeconfig uses `insecure-skip-tls-verify`) and does not
authenticate the API server.

## Configuration

| Flag | Env | Default |
|---|---|---|
| `--listen` | `LISTEN` | `:8080` |
| `--path` | `WEBHOOK_PATH` | `/validate` |
| `--allowed-registries` | `ALLOWED_REGISTRIES` | `ghcr.io/` (comma-separated prefixes) |

Every decision is logged: namespace, images, allowed, reason.

## Try it

```bash
make test
go run . --listen=127.0.0.1:8080 &
curl -sk -X POST -H 'Content-Type: application/json' https://127.0.0.1:8080/validate -d \
  '{"apiVersion":"imagepolicy.k8s.io/v1alpha1","kind":"ImageReview","spec":{"containers":[{"image":"nginx:1.27"}]}}'
# {"apiVersion":"imagepolicy.k8s.io/v1alpha1","kind":"ImageReview","status":{"allowed":false,"reason":"denied: ..."}}
```

## Build

```bash
make build-and-push   # linux/amd64 and linux/arm64, ghcr.io/hlesey/image-validation-webhook:1.0
```

Make the GHCR package public afterwards, so the cluster can pull it without credentials.

## Use in the lab

The static Pod manifest and the demo requests are in
`k8s-labs/src/security/admission/imagepolicywebhook/backend/`.
