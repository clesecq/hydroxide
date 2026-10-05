FROM docker.io/library/golang:latest AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION}" -o /hydroxide ./cmd/hydroxide

FROM docker.io/library/debian:trixie-slim

RUN apt-get update && apt-get install -y ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

COPY --from=build /hydroxide /usr/local/bin/hydroxide

ENTRYPOINT ["/usr/local/bin/hydroxide"]
