package fetchmail

import (
	"encoding/json"
	"fmt"
	"os"
)

// MessageState records what hydroxide fetchmail knows about a single Proton
// message it has already forwarded. Entries are keyed by Proton message ID
// in State.Messages; Time and ForwardedAt are informational/decision fields
// only, never used to identify a message.
type MessageState struct {
	// Time is the original message time (Unix seconds), kept for reference.
	Time int64 `json:"time"`
	// ForwardedAt is when hydroxide forwarded this message (Unix seconds).
	// It's the basis for -deleteafter.
	ForwardedAt int64 `json:"forwardedAt"`
}

// State is the on-disk "fetchids" file: the set of Proton message IDs
// hydroxide fetchmail has already forwarded, so repeated runs (e.g. from
// cron) don't re-forward the same mail.
type State struct {
	Messages map[string]MessageState `json:"messages"`
}

// LoadState reads the state file at path. A missing file is not an error:
// it returns a fresh, empty State (the case of a first run).
func LoadState(path string) (*State, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return &State{Messages: make(map[string]MessageState)}, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to open state file: %v", err)
	}
	defer f.Close()

	var s State
	if err := json.NewDecoder(f).Decode(&s); err != nil {
		return nil, fmt.Errorf("failed to read state file: %v", err)
	}
	if s.Messages == nil {
		s.Messages = make(map[string]MessageState)
	}
	return &s, nil
}

// Save writes the state file at path.
func (s *State) Save(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create state file: %v", err)
	}
	defer f.Close()

	if err := json.NewEncoder(f).Encode(s); err != nil {
		return fmt.Errorf("failed to write state file: %v", err)
	}
	return f.Close()
}
