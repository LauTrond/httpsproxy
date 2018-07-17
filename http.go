package httpsproxy

import (
	"net/http"
)

func CopyHeader(dst, src http.Header) {
	for key,values := range src {
		for _,value := range values {
			dst.Add(key,value)
		}
	}
}

type FileHandler struct {
	ContentType string
	Data []byte
}

func (h *FileHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "", http.StatusMethodNotAllowed)
		return
	}
	if h.ContentType != "" {
		w.Header().Set("Content-Type", h.ContentType)
	}
	w.Write(h.Data)
}
