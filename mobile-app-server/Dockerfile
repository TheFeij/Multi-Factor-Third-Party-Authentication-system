# build stage
FROM golang:1.22.6-alpine3.19 AS builder
WORKDIR /app
COPY . .
RUN go build -o main service/main.go

# run stage
From alpine:3.19
WORKDIR /app
COPY --from=builder /app/main .
COPY /config/config.json /app/config/

EXPOSE 8083
CMD ["/app/main"]