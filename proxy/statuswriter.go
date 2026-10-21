package proxy

import "net/http"

// StatusWriter records the response status code. Unwrap lets ReverseProxy's
// http.ResponseController still reach Flush on the underlying writer.
type StatusWriter struct {
	http.ResponseWriter
	Status int
}

func NewStatusWriter(w http.ResponseWriter) *StatusWriter {
	return &StatusWriter{ResponseWriter: w, Status: http.StatusOK}
}

func (w *StatusWriter) WriteHeader(code int) {
	w.Status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *StatusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
