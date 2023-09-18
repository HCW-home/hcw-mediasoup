#!/bin/bash

DEBUG=true \
 JWT_SECRET=aadsrwerrf \
 WHITELIST_FRONT_URLS=https://doctor_hcw-athome.dev.oniabsis.com \
 LISTEN=3443 \
 API_USER=abcd \
 TURN_SERVER1=turn:demo.hcw-at-home.com \
 TURN_USERNAME1=iabsis \
 TURN_PASSWORD1=1234 \
 API_SECRET=1234 \
 CERT=certs/sample.localhost.cert.pem \
 KEY=certs/sample.localhost.key.pem node server.js
