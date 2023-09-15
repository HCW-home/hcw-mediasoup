FROM debian:bullseye AS builder
RUN apt update && apt install -y ca-certificates
RUN echo deb [trusted=yes] https://projects.iabsis.com/repository/mediasoup-api/debian bionic main > /etc/apt/sources.list.d/mediasoup.list
RUN apt-get update && apt install -y mediasoup-api


FROM node:16-bullseye-slim

WORKDIR /usr/src/app
COPY --from=builder /usr/share/mediasoup-api/ /usr/src/app/

EXPOSE 3380
CMD [ "node", "server.js" ]
