// Copyright 2022 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

func printMessage(w http.ResponseWriter, r *http.Request) {
	log.Println(("Called /foo\n"))
	io.WriteString(w, "Call succeeded!\n")
}

func main() {
	log.Println(("starting the mTLS server\n"))

	http.HandleFunc("/foo", printMessage)

	// CA cert
	caCert, err := ioutil.ReadFile("./tests/testing_utils/cert/ca_cert.pem")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create TLS config with CA and require client cert verification.
	config := &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  caCertPool,
		MinVersion: tls.VersionTLS13,
	}
	config.BuildNameToCertificate()

	server := &http.Server{
		Addr:      ":3000",
		TLSConfig: config,
	}
	// Use server side cert and key
	log.Fatal(server.ListenAndServeTLS("./tests/testing_utils/cert/rsa_cert.pem", "./tests/testing_utils/cert/rsa_key.pem"))
}
