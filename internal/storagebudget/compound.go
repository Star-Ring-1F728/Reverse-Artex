package storagebudget

import (
	"bytes"
	"errors"
)

// Compound performs a read-only peak calculation and a bounded compound write
// under one OS lock and one fresh inventory. Every write must call Allow before
// I/O and Written for actual bytes, including partial errors. Rename/unlink may
// not create bytes. Gross debits intentionally grant no deletion/overwrite credit.
// Namespace changes must call InventoryAfter; failures are also rescanned.
// Nothing is cached after unlock; all other With callers retain their final scan.
func (b *Budget) Compound(prepare func() (int64, error), write func(*Lease) error) error {
	run := func() error {
		if b != nil {
			raw, err := b.readPolicy()
			if err != nil {
				return err
			}
			if !bytes.Equal(raw, b.config()) {
				return ErrScope
			}
		}
		growth, err := prepare()
		if err != nil {
			return err
		}
		if growth < 0 {
			return ErrScope
		}
		if b == nil {
			return write(nil)
		}
		used, err := b.scan()
		if err != nil {
			return err
		}
		if growth > b.Limit-used {
			return ErrFull
		}
		remaining := growth
		lease := &Lease{budget: b, prepaid: &remaining}
		err = write(lease)
		if remaining < 0 {
			return ErrFull
		}
		if lease.inventoryAfter || err != nil {
			final, scanErr := b.scan()
			if scanErr == nil && final > b.Limit {
				scanErr = ErrFull
			}
			return errors.Join(err, scanErr)
		}
		return err
	}
	if b == nil {
		return run()
	}
	return b.locked(run)
}

// InventoryAfter keeps namespace/file-type/count validation on compound changes.
func (l *Lease) InventoryAfter() {
	if l != nil {
		l.inventoryAfter = true
	}
}
