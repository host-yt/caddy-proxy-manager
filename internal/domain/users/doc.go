package users

// Roles: super_admin, admin, support, client, api.
// Rule: only super_admin can create another super_admin.
// Recovery codes: 8x16-char one-time codes, Argon2id-hashed at rest.
