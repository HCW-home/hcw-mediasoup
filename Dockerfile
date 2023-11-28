FROM node:16-bullseye-slim AS builder
WORKDIR /usr/src/app
COPY package*.json ./
RUN apt-get update && apt install -y python3-pip build-essential python openssl libssl-dev pkg-config
#RUN PYTHON=python3 npx yarn install
RUN npm i
COPY *.js .
COPY config/ config/
COPY lib/ lib/
COPY utils/ utils/
COPY certs/ certs/

FROM node:16-bullseye-slim

RUN adduser --system mediasoup
WORKDIR /usr/src/app
COPY --from=builder /usr/src/app/ /usr/src/app/
USER mediasoup

EXPOSE 3380
CMD [ "node", "server.js" ]
