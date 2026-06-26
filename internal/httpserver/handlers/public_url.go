package handlers

import "github.com/host-yt/caddy-proxy-manager/internal/installstate"

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
