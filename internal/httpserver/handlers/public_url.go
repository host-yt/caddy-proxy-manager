package handlers

import "github.com/hostyt/proxy-gateway/internal/installstate"

func appURLFromInstallState(state *installstate.Manager) string {
	if state == nil {
		return ""
	}
	st := state.Get()
	if st.App == nil {
		return ""
	}
	return st.App.URL
}
