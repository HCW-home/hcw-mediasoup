FROM node:16 AS builder
WORKDIR /usr/src/app
COPY package*.json ./
RUN apt-get update && apt install -y python3-pip
RUN PYTHON=python3 npx yarn install
COPY \
    certs/sample.localhost.cert.pem \
    certs/sample.localhost.key.pem \
    *.js \
    ./
COPY config/ config/
COPY lib/ lib/
COPY utils/ utils/
EXPOSE 3380
CMD [ "node", "server.js" ]