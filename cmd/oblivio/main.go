package main

import (
	"log"
	"os"

	"github.com/sxwebdev/oblivio/internal/config"
	icrypto "github.com/sxwebdev/oblivio/internal/crypto"
	"github.com/sxwebdev/oblivio/internal/keys"
	"github.com/sxwebdev/oblivio/internal/server"
	"github.com/sxwebdev/oblivio/internal/storage"
	"github.com/sxwebdev/oblivio/internal/tpm"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// Derive K_root from admin secret (env for MVP) and TPM stub
	admin := []byte(os.Getenv("OBLIVIO_ADMIN_SECRET"))
	nv := tpm.NewNV()
	_ = nv
	sk, err := keys.DeriveStoreKeys(admin, []byte("tpm_stub"))
	if err != nil {
		log.Fatalf("keys: %v", err)
	}

	// Open DB
	db, err := storage.Open(cfg.DBPath, sk.KStoreMAC)
	if err != nil {
		log.Fatalf("db open: %v", err)
	}
	defer db.Close()

	// Startup checks
	if err := db.VerifyAllMACs(); err != nil {
		log.Fatalf("anti-tamper mac: %v", err)
	}
	root, err := db.ComputeRoot()
	if err != nil {
		log.Fatalf("compute root: %v", err)
	}
	// Read seal and compare
	if seal, err := db.ReadSeal(sk.KSeal); err == nil {
		if seal.RootGlobal != root {
			log.Fatalf("seal root mismatch")
		}
	}
	// Write fresh seal
	s := db.NewSeal(0, root)
	if err := db.WriteSeal(sk.KSeal, s); err != nil {
		log.Fatalf("write seal: %v", err)
	}
	_ = icrypto.ErrMACMismatch

	// HTTP Server
	srv := server.New(cfg, db)
	if err := srv.Listen(cfg.ListenAddr); err != nil {
		log.Fatal(err)
	}
}
