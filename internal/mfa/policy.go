package mfa

import (
	"errors"
	"fmt"
	"strings"
)

// Mode is the deployment-wide second-factor policy an administrator sets.
type Mode string

const (
	// ModeOptional: nobody is forced; a person who enrolls must use it.
	ModeOptional Mode = "optional"
	// ModeAdmins: every administrator must have a factor.
	ModeAdmins Mode = "admins"
	// ModeEveryone: every account must have a factor.
	ModeEveryone Mode = "everyone"
)

var ErrUnknownMode = errors.New("mfa: unknown policy mode")

// ParseMode accepts the stored or submitted form of a Mode.
func ParseMode(s string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case ModeOptional:
		return ModeOptional, nil
	case ModeAdmins:
		return ModeAdmins, nil
	case ModeEveryone:
		return ModeEveryone, nil
	}
	return "", fmt.Errorf("%w: %q", ErrUnknownMode, s)
}

// Label is the console wording for a mode.
func (m Mode) Label() string {
	switch m {
	case ModeAdmins:
		return "Required for administrators"
	case ModeEveryone:
		return "Required for everyone"
	default:
		return "Optional"
	}
}

// Required reports whether an account must have a second factor: the
// strongest applicable rule wins, so a per-user requirement can add to but
// never subtract from the deployment mode.
func Required(mode Mode, isAdmin, userRequired bool) bool {
	switch mode {
	case ModeEveryone:
		return true
	case ModeAdmins:
		return isAdmin || userRequired
	default:
		return userRequired
	}
}

// Status is what the console shows for one account.
type Status string

const (
	StatusNotEnrolled        Status = "Not enrolled"
	StatusEnrollmentRequired Status = "Enrollment required"
	StatusEnabled            Status = "Enabled"
)

// StatusFor derives the displayed status from an account's requirement and
// whether it has an active factor.
func StatusFor(required, enrolled bool) Status {
	switch {
	case enrolled:
		return StatusEnabled
	case required:
		return StatusEnrollmentRequired
	default:
		return StatusNotEnrolled
	}
}
