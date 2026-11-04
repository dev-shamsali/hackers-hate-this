FROM node:latest
COPY . .
RUN npm install
ENV JWT_SECRET=secret123
CMD node src/app.js
