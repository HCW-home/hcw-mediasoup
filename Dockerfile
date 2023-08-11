FROM node:16
WORKDIR /usr/src/app
COPY package*.json ./
RUN apt-get update && apt install -y python3-pip
RUN PYTHON=python3 npx yarn install
COPY *.js .
COPY config/ config/
COPY lib/ lib/
COPY utils/ utils/
COPY certs/ certs/
EXPOSE 3380
CMD [ "node", "server.js" ]