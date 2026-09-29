package sqlite

import (
	"context"
	"errors"
	"time"
)

// ClaimDueRotation claims a due policy for one rotation run. A missing
// policy returns false and a nil error.
//
// The due test runs in Go, not SQL. This store binds times through the
// driver's default text format, and rows written before times were
// normalised to UTC can hold other offsets, so a text comparison in SQL
// would order some instants wrongly. Instead the row is read, judged with
// the loop's own now.After(next), and updated by primary key, all inside one
// transaction.
//
// That is safe against concurrent claimers because SQLite admits one writer
// at a time and its transactions are serializable. A second claimer that
// read the row before the winner committed cannot then write: SQLite refuses
// the upgrade with SQLITE_BUSY (the winner still holds the write lock) or
// SQLITE_BUSY_SNAPSHOT (the winner has committed and the read is stale). A
// claimer that reads after the winner commits sees next_rotation_at already
// at until and finds nothing due. A busy or locked result is reported as not
// claimed, because this call wrote nothing and some other writer holds the
// database; the loop tries again on its next tick if the policy is still due.
func (s *Store) ClaimDueRotation(ctx context.Context, key, appID string, now, until time.Time) (bool, error) {
	now = now.UTC()
	until = until.UTC()

	claimed, err := s.claimDueRotation(ctx, key, appID, now, until)
	if err != nil {
		if isBusy(err) {
			return false, nil
		}
		return false, err
	}
	return claimed, nil
}

func (s *Store) claimDueRotation(ctx context.Context, key, appID string, now, until time.Time) (bool, error) {
	tx, err := s.sdb.BeginTxQuery(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback() //nolint:errcheck // rollback on deferred cleanup

	var m RotationPolicyModel
	err = tx.NewSelect(&m).
		Where("secret_key = ?", key).
		Where("app_id = ?", appID).
		Scan(ctx)
	if err != nil {
		if isNoRows(err) {
			return false, nil
		}
		return false, err
	}

	if !m.Enabled || m.NextRotationAt == nil || !now.After(*m.NextRotationAt) {
		return false, nil
	}

	res, err := tx.NewUpdate((*RotationPolicyModel)(nil)).
		Set("next_rotation_at = ?", until).
		Set("updated_at = ?", now).
		Where("id = ?", m.ID).
		Exec(ctx)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n != 1 {
		return false, nil
	}

	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// sqliteCoder is the method modernc.org/sqlite's *Error exposes. Matching it
// by method keeps this package from importing the driver directly.
type sqliteCoder interface {
	Code() int
}

// SQLite primary result codes. The driver may report an extended code, such
// as SQLITE_BUSY_SNAPSHOT (517), whose low byte is the primary code.
const (
	sqliteBusy   = 5
	sqliteLocked = 6
)

// isBusy reports whether err is SQLite refusing a lock because another
// connection holds it.
func isBusy(err error) bool {
	var c sqliteCoder
	if !errors.As(err, &c) {
		return false
	}
	switch c.Code() & 0xff {
	case sqliteBusy, sqliteLocked:
		return true
	}
	return false
}
