module github.com/cppla/autocar

go 1.25.0

// Local security-hardening fork of Hysteria core v2.12.1. See
// third_party/hysteria-core/AUTOCAR_PATCHES.md.
replace github.com/apernet/hysteria/core/v2 => ./third_party/hysteria-core

// Local HTTP/3 pre-read admission hook used by the hardened Hysteria core. See
// third_party/quic-go/AUTOCAR_PATCHES.md.
replace github.com/apernet/quic-go => ./third_party/quic-go

require (
	github.com/apernet/hysteria/core/v2 v2.12.1
	github.com/apernet/hysteria/extras/v2 v2.12.1
	github.com/apernet/quic-go v0.61.1-0.20260806010916-184d081eef3e
	github.com/quic-go/quic-go v0.61.0
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/klauspost/compress v1.18.7 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	github.com/stretchr/objx v0.5.3 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)
