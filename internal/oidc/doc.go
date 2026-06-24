// Package oidc provides OIDC/OAuth login.
//
// Providers: Microsoft (Azure AD), Authentik, generic OIDC. Settings live in
// the DB so admin can rotate without redeploy. Bootstrap defaults read from
// env on first install.
package oidc
