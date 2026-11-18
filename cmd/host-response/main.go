// host-response defaults to simulation. Linux netns isolation requires an
// explicit pinned Unix-socket adapter deployed separately from this controller.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"reverse-artex/internal/hostresponse"
	"runtime"
	"strings"
	"time"
)

func main() {
	addr := flag.String("listen", "127.0.0.1:9085", "private simulation response listener")
	out := flag.String("out", "artifacts/host-response", "durable host simulation audit")
	linux := flag.Bool("linux-adapter", false, "explicit opt-in to separately deployed Linux namespace adapter")
	socket := flag.String("linux-socket", "", "pinned private Unix socket")
	scopePath := flag.String("linux-scope", "", "operator-pinned Linux scope JSON")
	trustPath := flag.String("signed-trust", "", "explicit Linux-only signed host authorization trust; disables unsigned writes")
	flag.Parse()
	c := hostresponse.Config{SensorToken: os.Getenv("RA_HOST_SENSOR_TOKEN"), ReaderToken: os.Getenv("RA_HOST_READER_TOKEN"), OperatorToken: os.Getenv("RA_HOST_OPERATOR_TOKEN"), Sensor: value("RA_HOST_SENSOR_ID", "lab-host"), Tenant: value("RA_HOST_TENANT", "alpha"), Asset: value("RA_ASSET_ID", "lab-api"), Service: value("RA_HOST_SERVICE_ID", "lab-web"), Workload: value("RA_HOST_WORKLOAD_ID", "lab-workload")}
	if !c.Validate() {
		log.Fatal("distinct private role credentials and bounded host scope required")
	}
	var adapter hostresponse.Adapter = hostresponse.NewSimulation()
	var scope hostresponse.LinuxScope
	if *linux {
		if runtime.GOOS != "linux" || *socket == "" || *scopePath == "" {
			log.Fatal("explicit Linux scope/socket required")
		}
		info, err := os.Lstat(*scopePath)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
			log.Fatal("bounded regular Linux scope required")
		}
		raw, err := os.ReadFile(*scopePath)
		if err != nil {
			log.Fatal("Linux scope unavailable")
		}
		scope, err = hostresponse.DecodeLinuxScope(raw)
		if err != nil {
			log.Fatal(err)
		}
		adapter, err = hostresponse.NewLinuxAdapter(*socket, scope, os.Getenv("RA_LINUX_ADAPTER_READ_TOKEN"), os.Getenv("RA_LINUX_ADAPTER_WRITE_TOKEN"))
		if err != nil {
			log.Fatal(err)
		}
	} else if *socket != "" || *scopePath != "" || *trustPath != "" {
		log.Fatal("Linux adapter opt-in required")
	}
	var m *hostresponse.Manager
	var err error
	if *trustPath != "" {
		m, err = hostresponse.OpenSigned(*out, adapter, strings.Split(os.Getenv("RA_CANARY_IDS"), ","), scope, *trustPath)
	} else {
		m, err = hostresponse.Open(*out, adapter, strings.Split(os.Getenv("RA_CANARY_IDS"), ","))
	}
	if err != nil {
		log.Fatal(err)
	}
	defer m.Close()
	if _, _, err := m.Status(time.Now().UTC()); err != nil {
		log.Fatal("host response startup reconciliation unavailable")
	}
	server := &http.Server{Addr: *addr, Handler: hostresponse.Handler(m, c), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8192}
	if *linux {
		log.Print("explicit Linux network namespace isolation adapter selected")
	} else {
		log.Print("host response simulation only; no host changes")
	}
	log.Fatal(server.ListenAndServe())
}
func value(k, fallback string) string {
	if s := os.Getenv(k); s != "" {
		return s
	}
	return fallback
}
