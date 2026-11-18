package storagebudget

// Reserved admits a conservative peak before a compound operation. The caller
// must report every actual write with Written. The OS lock remains held by With;
// the allowance is discarded before unlocking and never survives a crash.
func (l *Lease) Reserved(growth int64, fn func() error) error {
	if l == nil {
		return fn()
	}
	if l.prepaid != nil {
		return ErrScope
	}
	if err := l.Allow(growth); err != nil {
		return err
	}
	remaining := growth
	l.prepaid = &remaining
	defer func() { l.prepaid = nil }()
	return fn()
}

// Written debits gross written bytes, including partial failed writes. Deletes
// and rewrites are deliberately not credited inside a conservative reservation.
func (l *Lease) Written(n int64) {
	if l != nil && l.prepaid != nil && n > 0 {
		*l.prepaid -= n
	}
}
