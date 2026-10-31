package gwhttp

import (
	"errors"
	"net/http"
)

// decodeRecoveryAPIJSON preserves the strict candidate JSON parser while
// distinguishing an oversized request from malformed client input. The
// underlying decoder is bounded by candidateEnrollmentBodyLimit.
func decodeRecoveryAPIJSON(w http.ResponseWriter, r *http.Request, out any) bool {
	if err := decodeCandidateEnrollmentJSON(w, r, out); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeRecoveryAPIError(w, http.StatusRequestEntityTooLarge, "ERR_BODY_TOO_LARGE")
		} else {
			writeRecoveryAPIError(w, http.StatusBadRequest, "ERR_INVALID_REQUEST")
		}
		return false
	}
	return true
}
