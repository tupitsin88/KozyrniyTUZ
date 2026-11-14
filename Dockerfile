FROM node:24-bookworm-slim@sha256:01d566e8d94d8c619591d78652babfccd3c6992a3dffa9ed5ab39e11cf6c70e9 AS frontend
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci
COPY web/ web/
RUN npm run build

FROM golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY web/embed.go web/embed.go
COPY --from=frontend /src/web/static/ web/static/
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath -o /out/club-membership ./cmd/server

FROM alpine:3.23@sha256:469c9ea410b9215eaee7976ba6c0639039b444be8e5d638f7abbada189971eb2
WORKDIR /app
COPY --from=build /out/club-membership ./club-membership
USER 65532:65532
EXPOSE 8080
STOPSIGNAL SIGINT
ENTRYPOINT ["/app/club-membership"]
