#!/bin/bash

DEBUG=true JWT_SECRET=aadsrwerrf WHITELIST_FRONT_URLS=https://doctor_hcw-athome.dev.oniabsis.com LISTEN=3443 API_USER=abcd API_SECRET=1234 CERT=certs/sample.localhost.cert.pem KEY=certs/sample.localhost.key.pem node server.js