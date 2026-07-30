package resources

// NoopLimiter represents a best-effort execution profile without cgroup
// resource isolation. Callers must expose that limitation through runtime
// status rather than treating configured limits as enforced.
type NoopLimiter struct{}

func (l *NoopLimiter) Create(id string, limits ResourceLimits) error {
	return nil
}

func (l *NoopLimiter) Attach(pid int) error {
	return nil
}

func (l *NoopLimiter) AttachID(id string, pid int) error {
	return nil
}

func (l *NoopLimiter) Destroy(id string) error {
	return nil
}
