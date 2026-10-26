# The floating golang:1.26 tag picks up Go patch releases; CI rebuilds weekly so they ship
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /adguard-exporter .

FROM scratch
COPY --from=build /adguard-exporter /adguard-exporter
USER 65532:65532
EXPOSE 9618
ENTRYPOINT ["/adguard-exporter"]
