package aichat

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// settingKeys maps a provider id to its encrypted API-key setting row.
var settingKeys = map[string]string{
	"anthropic":  "ai.anthropic_key_enc",
	"openai":     "ai.openai_key_enc",
	"gemini":     "ai.gemini_key_enc",
	"openrouter": "ai.openrouter_key_enc",
}

// DecryptFunc reverses the at-rest encryption used for is_encrypted settings.
// Wire installstate.Manager.Decrypt here so we reuse the existing crypto path.
type DecryptFunc func(b64 string) (string, error)

// Factory builds provider clients by reading + decrypting settings rows. It
// owns no crypto of its own - it delegates to the injected DecryptFunc.
type Factory struct {
	DB      *sql.DB
	Decrypt DecryptFunc
}

// NewFactory wires a factory from a DB handle and the existing decrypt function
// (e.g. installstate.Manager.Decrypt).
func NewFactory(db *sql.DB, decrypt DecryptFunc) *Factory {
	return &Factory{DB: db, Decrypt: decrypt}
}

// Default reads ai.default_provider, loads + decrypts that provider's key, and
// returns a ready Client. Returns a *NotConfiguredError (errors.Is
// ErrNotConfigured) when no provider is selected or its key is empty.
func (f *Factory) Default(ctx context.Context) (Client, error) {
	provider, err := f.readSetting(ctx, "ai.default_provider")
	if err != nil {
		return nil, err
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return nil, &NotConfiguredError{Reason: "no default provider selected"}
	}
	return f.For(ctx, provider)
}

// For builds a Client for a specific provider id, decrypting its stored key.
func (f *Factory) For(ctx context.Context, provider string) (Client, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	keyRow, ok := settingKeys[provider]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, provider)
	}
	key, err := f.readEncryptedSetting(ctx, keyRow)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(key) == "" {
		return nil, &NotConfiguredError{Provider: provider, Reason: "key empty"}
	}
	return newClient(provider, key)
}

// newClient maps a provider id to its adapter. Keys are passed by value and
// never logged.
func newClient(provider, key string) (Client, error) {
	switch provider {
	case "anthropic":
		return &anthropicClient{apiKey: key}, nil
	case "openai":
		return &openaiClient{apiKey: key}, nil
	case "gemini":
		return &geminiClient{apiKey: key}, nil
	case "openrouter":
		return &openrouterClient{apiKey: key}, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, provider)
	}
}

// readSetting reads a plaintext settings row. Missing row returns "".
func (f *Factory) readSetting(ctx context.Context, key string) (string, error) {
	if f.DB == nil {
		return "", fmt.Errorf("aichat: no db")
	}
	var v string
	err := f.DB.QueryRowContext(ctx, "SELECT value FROM settings WHERE `key` = ?", key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("aichat: read setting: %w", err)
	}
	return v, nil
}

// readEncryptedSetting reads an is_encrypted row and decrypts it via the
// injected DecryptFunc. Empty stored value short-circuits to "" (not an error).
func (f *Factory) readEncryptedSetting(ctx context.Context, key string) (string, error) {
	raw, err := f.readSetting(ctx, key)
	if err != nil {
		return "", err
	}
	if raw == "" {
		return "", nil
	}
	if f.Decrypt == nil {
		return "", fmt.Errorf("aichat: no decryptor wired")
	}
	dec, err := f.Decrypt(raw)
	if err != nil {
		// Never surface ciphertext or key bytes in the error.
		return "", fmt.Errorf("aichat: decrypt setting %s failed", key)
	}
	return dec, nil
}
