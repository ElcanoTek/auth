package mfa

// generateForTest computes the code for an arbitrary step so window tests
// can name the previous and next codes without hard-coding more vectors.
func generateForTest(secret []byte, step int64) (string, error) {
	return hotpCode(secret, uint64(step)), nil
}
