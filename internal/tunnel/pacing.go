package tunnel

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/cppla/autocar/internal/accel"
	"github.com/cppla/autocar/internal/protocol"
	quic "github.com/quic-go/quic-go"
)

// PacingConfig configures AutoCAR's application-layer sender. Adaptive pacing
// uses public path statistics exposed by quic-go; it does not replace QUIC's
// congestion controller or retransmission logic.
type PacingConfig struct {
	Mode    accel.Mode
	Profile accel.Profile

	InitialRateBytesPerSecond int64
	MinRateBytesPerSecond     int64
	MaxRateBytesPerSecond     int64
	BurstBytes                int64
}

func (c PacingConfig) accelConfig(fixedRate uint64) (accel.Config, error) {
	mode := c.Mode
	if mode == "" {
		mode = accel.ModeAdaptive
	}
	fixed := int64(0)
	if fixedRate != 0 {
		if fixedRate > math.MaxInt64 {
			return accel.Config{}, fmt.Errorf("tunnel: fixed pacing rate %d exceeds the supported range", fixedRate)
		}
		mode = accel.ModeFixedRate
		fixed = int64(fixedRate)
	}
	config := accel.Config{
		Mode:                      mode,
		Profile:                   c.Profile,
		InitialRateBytesPerSecond: c.InitialRateBytesPerSecond,
		MinRateBytesPerSecond:     c.MinRateBytesPerSecond,
		MaxRateBytesPerSecond:     c.MaxRateBytesPerSecond,
		FixedRateBytesPerSecond:   fixed,
		BurstBytes:                c.BurstBytes,
	}
	if err := accel.Validate(config); err != nil {
		return accel.Config{}, fmt.Errorf("tunnel: pacing config: %w", err)
	}
	return config, nil
}

type connectionPacer struct {
	mu sync.Mutex

	config     PacingConfig
	controller *accel.Controller
	fixedRate  uint64
}

func newConnectionPacer(config PacingConfig, fixedRate uint64) (*connectionPacer, error) {
	controllerConfig, err := config.accelConfig(fixedRate)
	if err != nil {
		return nil, err
	}
	controller, err := accel.New(controllerConfig)
	if err != nil {
		return nil, fmt.Errorf("tunnel: create pacing controller: %w", err)
	}
	return &connectionPacer{config: config, controller: controller, fixedRate: fixedRate}, nil
}

func (p *connectionPacer) setFixedRate(rate uint64) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if rate == p.fixedRate && p.controller != nil {
		return nil
	}
	if rate == 0 {
		config, err := p.config.accelConfig(0)
		if err != nil {
			return err
		}
		controller, err := accel.New(config)
		if err != nil {
			return fmt.Errorf("tunnel: reset pacing controller: %w", err)
		}
		p.controller = controller
		p.fixedRate = 0
		return nil
	}
	if p.controller != nil && p.controller.Mode() == accel.ModeFixedRate {
		if rate > math.MaxInt64 {
			return fmt.Errorf("tunnel: fixed pacing rate %d exceeds the supported range", rate)
		}
		if err := p.controller.SetFixedRate(int64(rate)); err != nil {
			return fmt.Errorf("tunnel: update fixed pacing rate: %w", err)
		}
		p.fixedRate = rate
		return nil
	}
	config, err := p.config.accelConfig(rate)
	if err != nil {
		return err
	}
	controller, err := accel.New(config)
	if err != nil {
		return fmt.Errorf("tunnel: create fixed pacing controller: %w", err)
	}
	p.controller = controller
	p.fixedRate = rate
	return nil
}

func (p *connectionPacer) wait(ctx context.Context, bytes int, conn *quic.Conn) error {
	p.mu.Lock()
	controller := p.controller
	p.mu.Unlock()
	if controller == nil {
		return nil
	}
	stats := conn.ConnectionStats()
	_ = controller.Observe(accel.Snapshot{
		At:          time.Now(),
		SentBytes:   stats.BytesSent,
		LostBytes:   stats.BytesLost,
		MinRTT:      stats.MinRTT,
		SmoothedRTT: stats.SmoothedRTT,
	})
	return controller.Wait(ctx, bytes)
}

func (p *connectionPacer) maxChunkBytes() int {
	p.mu.Lock()
	controller := p.controller
	p.mu.Unlock()
	if controller == nil {
		return 0
	}
	if controller.Mode() == accel.ModeReno {
		return 0
	}
	burst := controller.BurstBytes()
	maxInt := int64(^uint(0) >> 1)
	if burst > maxInt {
		return int(maxInt)
	}
	return int(burst)
}

func (p *connectionPacer) metadata() (protocol.PacingMode, protocol.PacingProfile, uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.controller == nil {
		return protocol.PacingUnspecified, protocol.ProfileUnspecified, 0
	}
	return protocolMode(p.controller.Mode()), protocolProfile(p.controller.Profile()), p.fixedRate
}

func (p *connectionPacer) label() string {
	mode, profile, _ := p.metadata()
	switch mode {
	case protocol.PacingAdaptive:
		return "adaptive-" + pacingProfileName(profile)
	case protocol.PacingReno:
		return "reno"
	case protocol.PacingFixedRate:
		return "fixed-rate"
	default:
		return "unknown"
	}
}

// serverPacingNegotiator selects connection-scoped sender policies exactly
// once. All streams on one QUIC connection share transport statistics and one
// pacer, so allowing later streams to silently replace the policy would make
// existing flows and benchmark telemetry lie about their active sender.
type serverPacingNegotiator struct {
	mu sync.Mutex

	pacer            *connectionPacer
	maxTx            uint64
	maxRx            uint64
	allowClientRates bool

	initialized bool
	signature   pacingRequestSignature
	response    protocol.Response
}

type pacingRequestSignature struct {
	maxTx     uint64
	maxRx     uint64
	txMode    protocol.PacingMode
	txProfile protocol.PacingProfile
}

func newServerPacingNegotiator(
	config PacingConfig,
	maxTx, maxRx uint64,
	allowClientRates bool,
) (*serverPacingNegotiator, error) {
	if maxTx > protocol.MaxRate || maxRx > protocol.MaxRate {
		return nil, fmt.Errorf("tunnel: pacing rate exceeds protocol maximum")
	}
	baseFixedRate := uint64(0)
	if config.Mode == accel.ModeFixedRate {
		if maxTx == 0 {
			return nil, fmt.Errorf("tunnel: fixed-rate server pacing requires MaxTx")
		}
		baseFixedRate = maxTx
	}
	if allowClientRates && (maxTx == 0 || maxRx == 0) {
		return nil, fmt.Errorf("tunnel: client rate hints require finite MaxTx and MaxRx")
	}
	pacer, err := newConnectionPacer(config, baseFixedRate)
	if err != nil {
		return nil, err
	}
	return &serverPacingNegotiator{
		pacer:            pacer,
		maxTx:            maxTx,
		maxRx:            maxRx,
		allowClientRates: allowClientRates,
	}, nil
}

func (n *serverPacingNegotiator) negotiate(request protocol.Request) (protocol.Response, error) {
	signature := pacingRequestSignature{
		maxTx: request.MaxTx, maxRx: request.MaxRx,
		txMode: request.TxMode, txProfile: request.TxProfile,
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.initialized {
		if signature != n.signature {
			return protocol.Response{}, errors.New("tunnel: pacing metadata changed on an active connection")
		}
		return n.response, nil
	}
	if request.TxMode == protocol.PacingUnspecified || request.TxProfile == protocol.ProfileUnspecified {
		return protocol.Response{}, errors.New("tunnel: sender pacing metadata is required")
	}
	if request.TxMode == protocol.PacingFixedRate && request.MaxTx == 0 {
		return protocol.Response{}, errors.New("tunnel: fixed-rate sender omitted MaxTx")
	}
	if request.TxMode != protocol.PacingFixedRate && request.MaxTx != 0 {
		return protocol.Response{}, errors.New("tunnel: MaxTx requires fixed-rate sender pacing")
	}
	if !n.allowClientRates && (request.MaxTx != 0 || request.MaxRx != 0) {
		return protocol.Response{}, errors.New("tunnel: client rate hints are disabled")
	}

	clientRate := capRequestedRate(request.MaxTx, n.maxRx)
	_, _, serverRate := n.pacer.metadata()
	if n.allowClientRates && request.MaxRx != 0 {
		serverRate = capRequestedRate(request.MaxRx, n.maxTx)
	}
	if serverRate != 0 {
		if err := n.pacer.setFixedRate(serverRate); err != nil {
			return protocol.Response{}, err
		}
	}

	txMode := request.TxMode
	if clientRate != 0 {
		txMode = protocol.PacingFixedRate
	}
	rxMode, rxProfile, _ := n.pacer.metadata()
	response := protocol.Response{
		Status: protocol.StatusOK,
		MaxTx:  clientRate,
		MaxRx:  serverRate,
		TxMode: txMode, TxProfile: request.TxProfile,
		RxMode: rxMode, RxProfile: rxProfile,
	}
	n.initialized = true
	n.signature = signature
	n.response = response
	return response, nil
}

func protocolMode(mode accel.Mode) protocol.PacingMode {
	switch mode {
	case accel.ModeAdaptive:
		return protocol.PacingAdaptive
	case accel.ModeReno:
		return protocol.PacingReno
	case accel.ModeFixedRate:
		return protocol.PacingFixedRate
	default:
		return protocol.PacingUnspecified
	}
}

func protocolProfile(profile accel.Profile) protocol.PacingProfile {
	switch profile {
	case accel.ProfileConservative:
		return protocol.ProfileConservative
	case accel.ProfileBalanced:
		return protocol.ProfileBalanced
	case accel.ProfileAggressive:
		return protocol.ProfileAggressive
	default:
		return protocol.ProfileUnspecified
	}
}

func pacingModeName(mode protocol.PacingMode, profile protocol.PacingProfile) string {
	switch mode {
	case protocol.PacingAdaptive:
		return "adaptive-" + pacingProfileName(profile)
	case protocol.PacingReno:
		return "reno"
	case protocol.PacingFixedRate:
		return "fixed-rate"
	default:
		return ""
	}
}

func pacingProfileName(profile protocol.PacingProfile) string {
	switch profile {
	case protocol.ProfileConservative:
		return "conservative"
	case protocol.ProfileBalanced:
		return "balanced"
	case protocol.ProfileAggressive:
		return "aggressive"
	default:
		return "balanced"
	}
}

func capRequestedRate(request, ceiling uint64) uint64 {
	if request == 0 {
		return 0
	}
	if ceiling == 0 || request < ceiling {
		return request
	}
	return ceiling
}
