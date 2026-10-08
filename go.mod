module github.com/cppla/autocar

go 1.27.1

// Preserve upstream type identity for H2 and the web-H3 adapter. See docs/DEPENDENCY-MAINTENANCE.md.
replace github.com/refraction-networking/utls => github.com/cppla/utls v0.0.0-20261008110020-7295e1b508c3

require (
	github.com/apernet/quic-go v0.63.1-0.20261004180939-a10df75c260c
	github.com/quic-go/qpack v0.6.0
	github.com/quic-go/quic-go v0.63.0
	github.com/refraction-networking/utls v1.8.3-0.20261006222701-ff1b50fbbe9a
	golang.org/x/net v0.59.0
)

require (
	github.com/klauspost/compress v1.20.1 // indirect
	github.com/molecule-man/go-brrr v1.2.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)
