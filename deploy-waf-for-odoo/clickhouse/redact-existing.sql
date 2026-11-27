-- Maschera password, token e sessioni nei log salvati PRIMA della redazione in vector/node.yaml.
-- Da eseguire una volta su installazioni esistenti:
--   docker compose exec -T clickhouse clickhouse-client -u waf_admin --password <pwd> --multiquery < clickhouse/redact-existing.sql
ALTER TABLE waf.events UPDATE
    uri = replaceRegexpAll(uri, '(?i)([?&](?:password|passwd|pwd|new_password|confirm_password|old_pwd|new_pwd|password_confirmation|secret|client_secret|token|access_token|refresh_token|id_token|api_key|apikey|csrf_token|session_id|totp_token|otp)=)[^&]*', '\\1[REDACTED]'),
    query = replaceRegexpAll(query, '(?i)((?:^|&)(?:password|passwd|pwd|new_password|confirm_password|old_pwd|new_pwd|password_confirmation|secret|client_secret|token|access_token|refresh_token|id_token|api_key|apikey|csrf_token|session_id|totp_token|otp)=)[^&]*', '\\1[REDACTED]'),
    request_body = replaceRegexpAll(replaceRegexpAll(request_body,
        '(?i)((?:^|&)(?:password|passwd|pwd|new_password|confirm_password|old_pwd|new_pwd|password_confirmation|secret|client_secret|token|access_token|refresh_token|id_token|api_key|apikey|csrf_token|session_id|totp_token|otp)=)[^&]*', '\\1[REDACTED]'),
        '(?i)("(?:password|passwd|pwd|new_password|confirm_password|old_pwd|new_pwd|password_confirmation|secret|client_secret|token|access_token|refresh_token|id_token|api_key|apikey|csrf_token|session_id|totp_token|otp)"\\s*:\\s*)"(?:[^"\\\\]|\\\\.)*"', '\\1"[REDACTED]"'),
    request_headers = mapApply((k, v) -> (k, multiIf(
        match(k, '(?i)^cookie$'), replaceRegexpAll(v, '=[^;]*', '=[REDACTED]'),
        match(k, '(?i)^(set-cookie|authorization|proxy-authorization|x-openerp-session-id|x-api-key|x-auth-token|x-csrf-token|x-csrftoken)$'), '[REDACTED]', v)), request_headers),
    response_headers = mapApply((k, v) -> (k, multiIf(
        match(k, '(?i)^set-cookie$'), replaceRegexpOne(v, '^([^=]*)=[^;]*', '\\1=[REDACTED]'),
        match(k, '(?i)^(cookie|authorization|proxy-authorization|x-openerp-session-id|x-api-key|x-auth-token|x-csrf-token|x-csrftoken)$'), '[REDACTED]', v)), response_headers)
WHERE 1 SETTINGS mutations_sync = 1;

ALTER TABLE waf.matches UPDATE
    value = if(match(variable, '(?i)((^|:)(password|passwd|pwd|new_password|confirm_password|old_pwd|new_pwd|password_confirmation|secret|client_secret|token|access_token|refresh_token|id_token|api_key|apikey|csrf_token|session_id|totp_token|otp)$|^REQUEST_(HEADERS|COOKIES):(cookie|set-cookie|authorization|proxy-authorization|x-openerp-session-id|x-api-key|x-auth-token|x-csrf-token|x-csrftoken|session_id)$)'),
        '[REDACTED]',
        replaceRegexpAll(replaceRegexpAll(value,
            '(?i)((?:^|[&?])(?:password|passwd|pwd|new_password|confirm_password|old_pwd|new_pwd|password_confirmation|secret|client_secret|token|access_token|refresh_token|id_token|api_key|apikey|csrf_token|session_id|totp_token|otp)=)[^&]*', '\\1[REDACTED]'),
            '(?i)("(?:password|passwd|pwd|new_password|confirm_password|old_pwd|new_pwd|password_confirmation|secret|client_secret|token|access_token|refresh_token|id_token|api_key|apikey|csrf_token|session_id|totp_token|otp)"\\s*:\\s*)"(?:[^"\\\\]|\\\\.)*"', '\\1"[REDACTED]"'))
WHERE 1 SETTINGS mutations_sync = 1;
