package main

import (
	"context"
	"encoding/base64"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

// Below is an implementation of Bcrypt with Base64 encoding
// to encrypt user password using Go.
//
// TODO:
// - Create the journal for this program []
// - Add user interface to encrypt and decrypt [done]

const (
	cost = 11
	addr = "localhost:8080"
)

var (
	t = template.Must(template.ParseFiles("index.html"))
)

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
	err := t.Execute(w, nil)
	if err != nil {
		panic(err)
	}

}

func (h *handler) handleHash(w http.ResponseWriter, r *http.Request) {
	p := r.FormValue("password")
	e := base64.StdEncoding.EncodeToString([]byte(p))

	hs, err := bcrypt.GenerateFromPassword([]byte(e), cost)
	if err != nil {
		panic(err)
	}

	tpl := template.Must(template.New("hash").Parse("{{ . }}"))
	tpl.Execute(w, string(hs))
}

func (h *handler) handleCompare(w http.ResponseWriter, r *http.Request) {
	tpl := template.Must(template.New("compare").Parse("{{ . }}"))

	en := r.FormValue("with_base64")
	ps := []byte(r.FormValue("plain_password"))
	hs := []byte(r.FormValue("hashed_password"))

	if en == "on" {
		ps = []byte(base64.StdEncoding.EncodeToString(ps))
	}

	err := bcrypt.CompareHashAndPassword(hs, ps)
	if err != nil {
		tpl.Execute(w, err.Error())
		return
	}

	tpl.Execute(w, "Kata sandi dan hash cocok")
}
