package api

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"

	"github.com/sxwebdev/oblivio/internal/auth"
	"github.com/sxwebdev/oblivio/internal/config"
	"github.com/sxwebdev/oblivio/internal/storage"
)

type Server struct {
	app *fiber.App
	cfg *config.Config
	db  *storage.DB
}

func New(cfg *config.Config, db *storage.DB) *Server {
	app := fiber.New(fiber.Config{BodyLimit: 1 << 20 /* 1MB */})
	// Middleware
	app.Use(recover.New())
	app.Use(logger.New())
	app.Use(cors.New(cors.Config{
		AllowCredentials: true,
		AllowOrigins:     "http://localhost:3000, http://127.0.0.1:3000, http://localhost:5173, http://127.0.0.1:5173, http://localhost:8080, http://127.0.0.1:8080",
		AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders:     "Content-Type, Authorization",
		AllowOriginsFunc: func(origin string) bool { return true },
	}))
	app.Use(func(c *fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("Referrer-Policy", "no-referrer")
		c.Set("Permissions-Policy", "geolocation=()")
		c.Set("X-Frame-Options", "DENY")
		c.Set("Cross-Origin-Opener-Policy", "same-origin")
		c.Set("Cross-Origin-Resource-Policy", "same-site")
		return c.Next()
	})

	s := &Server{app: app, cfg: cfg, db: db}
	s.routes()
	return s
}

func (s *Server) routes() {
	api := s.app.Group("/v1")
	// Health
	api.Get("/health", func(c *fiber.Ctx) error { return c.SendStatus(http.StatusNoContent) })
	// Auth with TOTP MFA
	api.Post("/auth/register", s.handleRegister)
	api.Post("/auth/mfa/verify", s.handleMFAVerify)
	api.Post("/auth/login", s.handleLogin)
	api.Post("/auth/logout", s.handleLogout)
	api.Get("/auth/me", s.handleMe)

	// Items (require auth)
	api.Get("/items/list", s.authRequired, s.handleItemsList)
	api.Get("/items", s.authRequired, s.handleItemsGet)
	api.Post("/items", s.authRequired, s.handleItemsPost)
	api.Put("/items/:id", s.authRequired, s.handleItemsPut)
	api.Delete("/items/:id", s.authRequired, s.handleItemsDelete)

	// Search (require auth)
	api.Post("/search/eq", s.authRequired, s.handleSearchEq)
}

// --- Auth Handlers ---
func (s *Server) handleRegister(c *fiber.Ctx) error {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.Unmarshal(c.Body(), &req); err != nil {
		return fiber.ErrBadRequest
	}
	if req.Username == "" || req.Password == "" {
		return fiber.ErrBadRequest
	}
	if _, err := s.db.GetUser(req.Username); err == nil {
		return fiber.NewError(http.StatusConflict, "user exists")
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		return fiber.ErrInternalServerError
	}
	// Generate TOTP secret for this user but mark mfa disabled until verified
	sec, err := auth.GenerateTOTPSecret()
	if err != nil {
		return fiber.ErrInternalServerError
	}
	if err := s.db.PutUser(storage.UserRecord{Username: req.Username, PassHash: hash, TOTPSecret: sec, MFAEnabled: false}); err != nil {
		return fiber.ErrInternalServerError
	}
	// Return otpauth URL to show QR and a note to verify
	uri := auth.BuildTOTPURI("Oblivio", req.Username, sec)
	return c.JSON(fiber.Map{"otpauth_url": uri})
}

func (s *Server) handleLogin(c *fiber.Ctx) error {
	var req struct{ Username, Password, Code string }
	if err := json.Unmarshal(c.Body(), &req); err != nil {
		return fiber.ErrBadRequest
	}
	u, err := s.db.GetUser(req.Username)
	if err != nil {
		return fiber.ErrUnauthorized
	}
	ok, _ := auth.VerifyPassword(req.Password, u.PassHash)
	if !ok {
		return fiber.ErrUnauthorized
	}
	if !u.MFAEnabled || u.TOTPSecret == "" {
		return fiber.NewError(http.StatusForbidden, "mfa not verified")
	}
	if !auth.ValidateTOTP(u.TOTPSecret, req.Code) {
		return fiber.ErrUnauthorized
	}
	// Create session token
	tok := randomToken()
	if err := s.db.PutSession(storage.SessionRecord{Token: tok, Username: u.Username, ExpiresAt: 0}); err != nil {
		return fiber.ErrInternalServerError
	}
	// Set cookie and return token too
	c.Cookie(&fiber.Cookie{Name: "sid", Value: tok, HTTPOnly: true, Secure: false, SameSite: "Lax", Path: "/"})
	return c.JSON(fiber.Map{"token": tok, "username": u.Username})
}

func (s *Server) handleMFAVerify(c *fiber.Ctx) error {
	var req struct{ Username, Password, Code string }
	if err := json.Unmarshal(c.Body(), &req); err != nil {
		return fiber.ErrBadRequest
	}
	u, err := s.db.GetUser(req.Username)
	if err != nil {
		return fiber.ErrUnauthorized
	}
	ok, _ := auth.VerifyPassword(req.Password, u.PassHash)
	if !ok {
		return fiber.ErrUnauthorized
	}
	if u.TOTPSecret == "" {
		return fiber.ErrBadRequest
	}
	if !auth.ValidateTOTP(u.TOTPSecret, req.Code) {
		return fiber.ErrUnauthorized
	}
	u.MFAEnabled = true
	if err := s.db.PutUser(*u); err != nil {
		return fiber.ErrInternalServerError
	}
	return c.SendStatus(http.StatusNoContent)
}

func (s *Server) handleLogout(c *fiber.Ctx) error {
	tok := s.extractToken(c)
	if tok != "" {
		_ = s.db.DeleteSession(tok)
	}
	c.Cookie(&fiber.Cookie{Name: "sid", Value: "", Expires: time.Now().Add(-1 * time.Hour), Path: "/"})
	return c.SendStatus(http.StatusNoContent)
}

func (s *Server) handleMe(c *fiber.Ctx) error {
	if u := c.Locals("user"); u != nil {
		return c.JSON(u)
	}
	// try by token
	tok := s.extractToken(c)
	if tok == "" {
		return fiber.ErrUnauthorized
	}
	if sess, err := s.db.GetSession(tok); err == nil {
		return c.JSON(fiber.Map{"username": sess.Username})
	}
	return fiber.ErrUnauthorized
}

// Middleware: require session
func (s *Server) authRequired(c *fiber.Ctx) error {
	tok := s.extractToken(c)
	if tok == "" {
		return fiber.ErrUnauthorized
	}
	sess, err := s.db.GetSession(tok)
	if err != nil {
		return fiber.ErrUnauthorized
	}
	c.Locals("user", fiber.Map{"username": sess.Username})
	return c.Next()
}

func (s *Server) extractToken(c *fiber.Ctx) string {
	// Header Authorization: Bearer <token>
	authz := c.Get("Authorization")
	if len(authz) > 7 && authz[:7] == "Bearer " {
		return authz[7:]
	}
	if v := c.Cookies("sid"); v != "" {
		return v
	}
	return ""
}

func randomToken() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *Server) handleItemsList(c *fiber.Ctx) error {
	limitStr := c.Query("limit", "50")
	limit, _ := strconv.Atoi(limitStr)
	var cursor []byte
	if curB64 := c.Query("cursor"); curB64 != "" {
		b, err := base64.StdEncoding.DecodeString(curB64)
		if err == nil {
			cursor = b
		}
	}
	// MVP: single default vault "default"
	entries, next, err := s.db.List("default", limit, cursor)
	if err != nil {
		return fiber.ErrInternalServerError
	}
	var nextStr string
	if len(next) > 0 {
		nextStr = base64.StdEncoding.EncodeToString(next)
	}
	return c.JSON(fiber.Map{"items": entries, "next_cursor": nextStr})
}

func (s *Server) handleItemsGet(c *fiber.Ctx) error {
	idsStr := c.Query("ids")
	if idsStr == "" {
		return fiber.ErrBadRequest
	}
	ids := make([]string, 0)
	for _, id := range splitComma(idsStr) {
		if id != "" {
			ids = append(ids, id)
		}
	}
	type Resp struct {
		ID         string `json:"item_id"`
		Ciphertext []byte `json:"ciphertext"`
	}
	out := make([]Resp, 0, len(ids))
	for _, id := range ids {
		rec, err := s.db.GetItem("default", id)
		if err != nil {
			continue
		}
		out = append(out, Resp{ID: rec.ItemID, Ciphertext: rec.Ciphertext})
	}
	return c.JSON(out)
}

func (s *Server) handleItemsPost(c *fiber.Ctx) error {
	var req struct {
		ItemID     string              `json:"item_id"`
		Version    uint32              `json:"version"`
		Ciphertext string              `json:"ciphertext_b64"`
		Tokens     map[string][]string `json:"tokens"`
	}
	if err := json.Unmarshal(c.Body(), &req); err != nil {
		return fiber.ErrBadRequest
	}
	ct, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return fiber.ErrBadRequest
	}
	rec := storage.ItemRecord{ItemID: req.ItemID, Version: req.Version, Ciphertext: ct}
	if rec.Version == 0 {
		rec.Version = 1
	}
	if err := s.db.PutItem("default", rec, req.Tokens); err != nil {
		return fiber.ErrInternalServerError
	}
	return c.JSON(fiber.Map{"item_id": rec.ItemID, "version": rec.Version})
}

func (s *Server) handleItemsPut(c *fiber.Ctx) error {
	id := c.Params("id")
	var req struct {
		ExpectedVersion uint32              `json:"expected_version"`
		Version         uint32              `json:"version"`
		Ciphertext      string              `json:"ciphertext_b64"`
		Tokens          map[string][]string `json:"tokens"`
	}
	if err := json.Unmarshal(c.Body(), &req); err != nil {
		return fiber.ErrBadRequest
	}
	// No version check in MVP; just write.
	ct, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		return fiber.ErrBadRequest
	}
	rec := storage.ItemRecord{ItemID: id, Version: req.Version, Ciphertext: ct}
	if rec.Version == 0 {
		rec.Version = 1
	}
	if err := s.db.PutItem("default", rec, req.Tokens); err != nil {
		return fiber.ErrInternalServerError
	}
	return c.SendStatus(http.StatusNoContent)
}

func (s *Server) handleItemsDelete(c *fiber.Ctx) error {
	id := c.Params("id")
	if id == "" {
		return fiber.ErrBadRequest
	}
	if err := s.db.DeleteItem("default", id); err != nil {
		return fiber.ErrInternalServerError
	}
	return c.SendStatus(http.StatusNoContent)
}

func (s *Server) handleSearchEq(c *fiber.Ctx) error {
	var req struct {
		Tokens []struct {
			Type     string `json:"type"`
			ValueB64 string `json:"value_b64"`
		} `json:"tokens"`
		Cursor string `json:"cursor"`
		Limit  int    `json:"limit"`
	}
	if err := json.Unmarshal(c.Body(), &req); err != nil {
		return fiber.ErrBadRequest
	}
	if req.Limit <= 0 || req.Limit > 500 {
		req.Limit = 50
	}
	// MVP: only first token type used
	if len(req.Tokens) == 0 {
		return c.JSON(fiber.Map{"item_ids": []string{}, "next_cursor": ""})
	}
	typ := req.Tokens[0].Type
	toks := make([]string, 0, len(req.Tokens))
	for _, t := range req.Tokens {
		if t.Type == typ {
			toks = append(toks, t.ValueB64)
		}
	}
	var cursor []byte
	if req.Cursor != "" {
		if b, err := base64.StdEncoding.DecodeString(req.Cursor); err == nil {
			cursor = b
		}
	}
	ids, next, err := s.db.SearchEq("default", typ, toks, req.Limit, cursor)
	if err != nil {
		return fiber.ErrInternalServerError
	}
	var nextStr string
	if len(next) > 0 {
		nextStr = base64.StdEncoding.EncodeToString(next)
	}
	return c.JSON(fiber.Map{"item_ids": ids, "next_cursor": nextStr})
}

func splitComma(s string) []string {
	out := make([]string, 0)
	cur := ""
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, cur)
			cur = ""
		} else {
			cur += string(s[i])
		}
	}
	out = append(out, cur)
	return out
}

func (s *Server) Listen(addr string) error {
	log.Printf("listening on %s", addr)
	return s.app.Listen(addr)
}
