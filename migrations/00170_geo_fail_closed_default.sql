-- +goose Up
-- A missing GeoIP module or DB must deny, not serve unfiltered; fail-open becomes an explicit per-route choice.
-- +goose StatementBegin
ALTER TABLE routes MODIFY geo_fail_closed TINYINT(1) NOT NULL DEFAULT 1;
-- +goose StatementEnd
-- +goose StatementBegin
UPDATE routes SET geo_fail_closed = 1 WHERE geo_fail_closed = 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE routes MODIFY geo_fail_closed TINYINT(1) NOT NULL DEFAULT 0;
-- +goose StatementEnd
