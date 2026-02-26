package cap

import (
	"context"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/marcelocantos/doit/internal/rules"
)

// Tier represents the safety level of a capability.
type Tier int

const (
	TierRead      Tier = iota // read-only operations (grep, cat, find, ls)
	TierBuild                 // build/compile operations (make, go build)
	TierWrite                 // file mutations (cp, mv, mkdir, tee)
	TierDangerous             // destructive operations (rm, chmod, git push)
)

func (t Tier) String() string {
	switch t {
	case TierRead:
		return "read"
	case TierBuild:
		return "build"
	case TierWrite:
		return "write"
	case TierDangerous:
		return "dangerous"
	default:
		return fmt.Sprintf("tier(%d)", int(t))
	}
}

// ParseTier converts a string to a Tier.
func ParseTier(s string) (Tier, error) {
	switch s {
	case "read":
		return TierRead, nil
	case "build":
		return TierBuild, nil
	case "write":
		return TierWrite, nil
	case "dangerous":
		return TierDangerous, nil
	default:
		return 0, fmt.Errorf("unknown tier: %q", s)
	}
}

// Capability is the interface every operation must implement.
type Capability interface {
	// Name returns the capability identifier used in pipelines and CLI.
	Name() string

	// Description returns a human-readable summary for help output.
	Description() string

	// Tier returns the safety classification.
	Tier() Tier

	// Validate checks args before execution. Returns a descriptive error
	// if args are invalid. Called before Run.
	Validate(args []string) error

	// Run executes the capability. It reads from stdin and writes to
	// stdout, streaming data through. The context carries cancellation.
	Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error
}

// Registry maps capability names to implementations and controls tier access.
type Registry struct {
	mu    sync.RWMutex
	caps  map[string]Capability
	tiers map[Tier]bool
	rules *rules.RuleSet
}

// NewRegistry creates a registry with all tiers enabled except Dangerous.
// Hardcoded safety rules are always active.
func NewRegistry() *Registry {
	return &Registry{
		caps: make(map[string]Capability),
		tiers: map[Tier]bool{
			TierRead:      true,
			TierBuild:     true,
			TierWrite:     true,
			TierDangerous: false,
		},
		rules: rules.NewRuleSet(rules.Hardcoded()...),
	}
}

// Register adds a capability to the registry.
func (r *Registry) Register(c Capability) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.caps[c.Name()] = c
}

// Lookup returns a capability by name.
func (r *Registry) Lookup(name string) (Capability, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.caps[name]
	if !ok {
		return nil, fmt.Errorf("unknown capability: %q", name)
	}
	return c, nil
}

// CheckTier returns an error if the given tier is not enabled.
func (r *Registry) CheckTier(t Tier) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.tiers[t] {
		return fmt.Errorf("tier %q is disabled", t)
	}
	return nil
}

// SetTier enables or disables a tier.
func (r *Registry) SetTier(t Tier, enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tiers[t] = enabled
}

// SetRules replaces the rule set. Config-driven rules are added on top of
// the hardcoded safety rules which are always present.
func (r *Registry) SetRules(rs *rules.RuleSet) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = rs
}

// CheckRules validates args against all rules for the named capability.
// When retry is true, only hardcoded rules are checked (config rules are
// bypassed for this invocation).
func (r *Registry) CheckRules(capName string, args []string, retry bool) error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.rules == nil {
		return nil
	}
	return r.rules.Check(capName, args, retry)
}

type contextKey struct{}

// NewContext returns a context with the registry attached.
func NewContext(ctx context.Context, reg *Registry) context.Context {
	return context.WithValue(ctx, contextKey{}, reg)
}

// RegistryFromContext retrieves the registry from a context.
func RegistryFromContext(ctx context.Context) (*Registry, bool) {
	reg, ok := ctx.Value(contextKey{}).(*Registry)
	return reg, ok
}

// All returns all registered capabilities sorted by name.
func (r *Registry) All() []Capability {
	r.mu.RLock()
	defer r.mu.RUnlock()
	caps := make([]Capability, 0, len(r.caps))
	for _, c := range r.caps {
		caps = append(caps, c)
	}
	sort.Slice(caps, func(i, j int) bool {
		return caps[i].Name() < caps[j].Name()
	})
	return caps
}
