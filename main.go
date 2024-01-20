package main

import (
	"context"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Below is an implementation of Bcrypt with Base64 encoding
// to encrypt user password using Go.
//
// TODO:
// - Create the journal for this program []
// - Add user interface to encrypt and decrypt [done]

const addr = "localhost:8080"

func main() {
	var (
		errChan = make(chan error, 1)
		sigChan = make(chan os.Signal, 1)
	)

	storage := newStorage()
	handler := &handler{storage: storage}
	server := http.Server{
		Addr:    addr,
		Handler: handler,
	}

	log.Println("App running at", addr)

	go func() {
		err := server.ListenAndServe()
		if err != nil {
			errChan <- err
		}
	}()

	// When an interrupt or termination signal
	// is sent, notify the channel
	signal.Notify(
		sigChan,
		os.Interrupt,
		syscall.SIGTERM,
	)

	select {
	case err := <-errChan:
		log.Fatalln(err)
	case sig := <-sigChan:
		log.Println("Signal received!", sig)
		err := server.Shutdown(context.Background())
		if err != nil {
			panic(err)
		}
	}

}

type response struct {
	Hash  string `json:"hash"`
	Equal string `json:"equal"`
}

type handler struct {
	storage *storage
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		if strings.Contains(r.URL.String(), "/hash") {
			h.handleHash(w, r)
			return
		}

		if strings.Contains(r.URL.String(), "/compare") {
			h.handleCompare(w, r)
			return
		}

	case http.MethodGet:
		h.serveIndex(w, r)
		return
	}

}

func (h *handler) serveIndex(w http.ResponseWriter, r *http.Request) {
	t := template.Must(template.ParseFiles("index.html"))
	err := t.Execute(w, nil)
	if err != nil {
		panic(err)
	}

}

type result struct {
	Result  string
	Elapsed string
}

func (h *handler) handleHash(w http.ResponseWriter, r *http.Request) {
	const tptText = `
        <div class="mt-2">Waktu: {{ .Elapsed }}</div>
		<div class="mt-2">Hasil Hash:</div>
        <p class="content subtitle is-6 is-bold"> {{ .Result }} </p>
	`

	c := r.FormValue("cost")
	p := r.FormValue("password")
	e := base64.StdEncoding.EncodeToString([]byte(p))

	cost, err := strconv.Atoi(c)
	if err != nil {
		panic(err)
	}

	st := time.Now()
	hs, err := bcrypt.GenerateFromPassword([]byte(e), cost)
	if err != nil {
		panic(err)
	}
	et := time.Since(st)

	hr := &result{Result: string(hs), Elapsed: et.String()}
	tpl := template.Must(template.New("hash").Parse(tptText))
	tpl.Execute(w, hr)
}

func (h *handler) handleCompare(w http.ResponseWriter, r *http.Request) {
	const tplText = `
          <div class="mt-2">Waktu: {{ .Elapsed }}</div>
          <div class="mt-2">Output: {{ .Result }}</div>
	`

	tpl := template.Must(template.New("compare").Parse(tplText))

	cr := &result{}

	en := r.FormValue("with_base64")
	ps := []byte(r.FormValue("plain_password"))
	hs := []byte(r.FormValue("hashed_password"))

	if en == "on" {
		ps = []byte(base64.StdEncoding.EncodeToString(ps))
	}

	st := time.Now()
	err := bcrypt.CompareHashAndPassword(hs, ps)
	if err != nil {
		et := time.Since(st)
		cr.Elapsed = et.String()
		cr.Result = h.handleBcryptError(err)

		tpl.Execute(w, cr)
		return
	}

	et := time.Since(st)
	cr.Elapsed = et.String()
	cr.Result = "Cocok"
	tpl.Execute(w, cr)
}

func (h *handler) handleBcryptError(err error) string {
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return "Tidak Cocok"
	}

	return "Terjadi Kesalahan!"
}
