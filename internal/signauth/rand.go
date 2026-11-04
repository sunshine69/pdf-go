package signauth

import "crypto/rand"

// randRead fills b from the system CSPRNG. It is a function so a test can
// inject a failure, which is the only way to cover the error paths of the
// generators.
func randRead(b []byte) (int, error) { return rand.Read(b) }
