// Package middleware/idempotency dedupes mutating RPCs by Idempotency-Key.
//
// Implementation note: the middleware runs at the HTTP layer (not as a
// Connect interceptor) so it can stash and replay the exact serialized
// response bytes without having to know the proto response type.
//
// Storage is the Postgres `idempotency_keys` table with a 24h TTL. Replay
// returns the cached body verbatim, including content-type and status.
package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/sxwebdev/oblivio/internal/store"
	"github.com/sxwebdev/oblivio/internal/store/repos/repo_idempotency_keys"
)

const (
	idempotencyHeader = "Idempotency-Key"
	idempotencyTTL    = 24 * time.Hour
	maxReplayBody     = 1 << 20 // 1 MiB cap on cached response size
)

// IdempotencyConfig lists fully-qualified procedures that are
// idempotency-gated (typically every Create/Update/Delete RPC).
type IdempotencyConfig struct {
	Procedures map[string]struct{}
}

// IdempotencyMiddleware caches successful response bytes keyed by
// (user_id, Idempotency-Key) and replays them when the client retries.
//
// The middleware is applied AFTER the authn middleware so that it can
// extract user_id from the request context.
type IdempotencyMiddleware struct {
	store *store.Store
	cfg   IdempotencyConfig
}

// NewIdempotencyMiddleware constructs the middleware.
func NewIdempotencyMiddleware(st *store.Store, cfg IdempotencyConfig) *IdempotencyMiddleware {
	return &IdempotencyMiddleware{store: st, cfg: cfg}
}

// Wrap returns an http.Handler that applies idempotency around `next`.
func (m *IdempotencyMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		procedure := procedureFromPath(r.URL.Path)
		if _, gated := m.cfg.Procedures[procedure]; !gated {
			next.ServeHTTP(w, r)
			return
		}
		key := r.Header.Get(idempotencyHeader)
		if key == "" {
			next.ServeHTTP(w, r)
			return
		}
		uc, ok := FromContext(r.Context())
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxReplayBody))
		if err != nil {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		_ = r.Body.Close()
		hash := sha256.Sum256(body)
		// Re-install body for the downstream handler.
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))

		repo := m.store.IdempotencyKeys()
		existing, err := repo.GetIdempotencyEntry(r.Context(), repo_idempotency_keys.GetIdempotencyEntryParams{
			UserID: uc.UserID,
			Key:    key,
		})
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "idempotency lookup failed", http.StatusInternalServerError)
			return
		}
		if existing != nil {
			if existing.Procedure != procedure {
				http.Error(w, "idempotency key reused on a different procedure", http.StatusConflict)
				return
			}
			if !bytes.Equal(existing.RequestHash, hash[:]) {
				http.Error(w, "idempotency key reused with different payload", http.StatusConflict)
				return
			}
			replay(w, existing.ResponseStatus, existing.ResponseBody)
			return
		}

		rec := &captureWriter{ResponseWriter: w, buf: &bytes.Buffer{}, max: maxReplayBody}
		next.ServeHTTP(rec, r)

		if rec.status < 200 || rec.status >= 300 {
			// Only cache 2xx responses; treat everything else as transient.
			return
		}
		if rec.truncated {
			return
		}
		if err := repo.InsertIdempotencyEntry(context.WithoutCancel(r.Context()), repo_idempotency_keys.InsertIdempotencyEntryParams{
			UserID:         uc.UserID,
			Key:            key,
			Procedure:      procedure,
			RequestHash:    hash[:],
			ResponseStatus: int32(rec.status),
			ResponseBody:   append([]byte(nil), rec.buf.Bytes()...),
			ExpiresAt:      pgtype.Timestamptz{Time: time.Now().Add(idempotencyTTL), Valid: true},
		}); err != nil {
			// We've already shipped the response; failing to cache is not
			// fatal for the user. A retry will simply repeat the work.
			return
		}
	})
}

// procedureFromPath turns "/oblivio.v1.ProjectsService/CreateProject" into
// itself, with the leading slash preserved (matches Spec.Procedure).
func procedureFromPath(p string) string {
	idx := strings.LastIndex(p, "/")
	if idx < 0 {
		return p
	}
	// strip query params (if any) — http.Request.URL.Path already does this.
	return p
}

type captureWriter struct {
	http.ResponseWriter
	buf       *bytes.Buffer
	max       int
	status    int
	truncated bool
}

func (c *captureWriter) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *captureWriter) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	if !c.truncated {
		remaining := c.max - c.buf.Len()
		if remaining > 0 {
			toCopy := len(p)
			if toCopy > remaining {
				toCopy = remaining
				c.truncated = true
			}
			c.buf.Write(p[:toCopy])
		} else {
			c.truncated = true
		}
	}
	return c.ResponseWriter.Write(p)
}

func replay(w http.ResponseWriter, status int32, body []byte) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/proto")
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(int(status))
	_, _ = w.Write(body)
}
