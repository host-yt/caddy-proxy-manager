# SSO Jump - Integration Guide

This endpoint allows an external trusted system (e.g. FOSSBilling) to
automatically log a customer into the proxy panel without requiring them
to enter a password.

## URL format

  GET /auth/sso/jump?email=<email>&exp=<unix-timestamp>&sig=<hex-signature>

Parameters:
  email  - the customer's email address (must match their panel account)
  exp    - Unix timestamp (seconds) when the token expires (max 600 s from now)
  sig    - 64-character lowercase hex HMAC-SHA256 signature

## Signature formula

  message = "email=" + urlencode(email) + "&exp=" + str(exp)
  sig     = hmac_sha256_hex(secret, message)

The secret is the 128-character hex value from Admin → Settings → SSO Jump.

## PHP example

  <?php
  $email  = 'customer@example.com';
  $exp    = time() + 60;
  $secret = getenv('HOSTYT_SSO_SECRET');
  $msg    = 'email=' . rawurlencode($email) . '&exp=' . $exp;
  $sig    = hash_hmac('sha256', $msg, $secret);
  $url    = 'https://proxy.example.com/auth/sso/jump'
          . '?email=' . rawurlencode($email)
          . '&exp='   . $exp
          . '&sig='   . $sig;
  header('Location: ' . $url);
  exit;

## Security notes

- Each URL is valid for one use only (replay protection via Redis).
- Maximum token lifetime is 600 seconds; recommended is 60 seconds.
- Admin-role accounts are blocked unless the panel operator explicitly
  allows it in settings.
- The secret is stored AES-256-GCM encrypted on the panel side.

## Troubleshooting

  403 forbidden          - invalid signature; check HOSTYT_SSO_SECRET
  403 token expired      - URL too old; generate a fresh one
  403 exp too far        - exp value > now + 600 s; reduce TTL
  403 forbidden (replay) - URL already used; always generate a new one per click
  404                    - feature not enabled in panel settings
