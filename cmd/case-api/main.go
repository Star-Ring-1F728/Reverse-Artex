// case-api is an independent read-only service; it never provisions credentials.
package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"reverse-artex/internal/caseapi"
	"reverse-artex/internal/caseledger"
)

func validListen(addr, cert, key string) bool {
	host, _, err := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	return err == nil && ip != nil && ((cert == "") == (key == "")) && (ip.IsLoopback() || cert != "")
}

func run(args []string) error {
	f := flag.NewFlagSet("case-api", flag.ContinueOnError)
	addr := f.String("listen", "127.0.0.1:8095", "literal IP:port; TLS required outside loopback")
	cert := f.String("tls-cert", "", "TLS certificate file")
	key := f.String("tls-key", "", "TLS private key file")
	if err := f.Parse(args); err != nil {
		return errors.New("invalid case API arguments")
	}
	if f.NArg() != 0 || !validListen(*addr, *cert, *key) {
		return errors.New("valid listen address and transport configuration required")
	}
	dsn := os.Getenv("RA_CASE_API_DATABASE_URL")
	if dsn == "" {
		return errors.New("RA_CASE_API_DATABASE_URL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return errors.New("case API database configuration invalid")
	}
	defer db.Close()
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	ctx, cancel := context.WithTimeout(context.Background(), caseapi.ReadTimeout)
	err = caseledger.CheckAPIService(ctx, db)
	cancel()
	if err != nil {
		return errors.New("case API database or service role unavailable")
	}
	handler := caseapi.Handler(func(ctx context.Context, sha [32]byte, tenant, id string) (caseledger.Stored, error) {
		return caseledger.ReadBearer(ctx, db, sha, tenant, id)
	})
	server := &http.Server{Addr: *addr, Handler: handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	stop, done := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer done()
	ended := make(chan struct{})
	shutdownDone := make(chan struct{})
	defer close(ended)
	go func() {
		defer close(shutdownDone)
		select {
		case <-stop.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if server.Shutdown(shutdown) != nil {
				_ = server.Close()
			}
		case <-ended:
		}
	}()
	if *cert != "" {
		err = server.ListenAndServeTLS(*cert, *key)
	} else {
		err = server.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		<-shutdownDone
		return nil
	}
	return errors.New("case API listener stopped")
}
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
