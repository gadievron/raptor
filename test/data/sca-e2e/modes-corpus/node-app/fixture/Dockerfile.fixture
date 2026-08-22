FROM node:20.19.2-alpine

WORKDIR /app
COPY package.json .
RUN npm install
COPY . .
CMD ["node", "index.js"]
