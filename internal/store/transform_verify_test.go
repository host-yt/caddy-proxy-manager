package store

import (
	"strings"
	"testing"
)

func TestTransformDatetimePrecision(t *testing.T) {
	input := `CREATE TABLE host_access_log (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    ts DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    PRIMARY KEY (id)
) ENGINE=InnoDB;`
	got := TransformForSQLite(input)
	if strings.Contains(got, "DATETIME(3)") {
		t.Errorf("DATETIME(3) not stripped, got:\n%s", got)
	}
	if strings.Contains(got, "CURRENT_TIMESTAMP(3)") {
		t.Errorf("CURRENT_TIMESTAMP(3) not stripped, got:\n%s", got)
	}
	if !strings.Contains(got, "CURRENT_TIMESTAMP") {
		t.Errorf("CURRENT_TIMESTAMP missing, got:\n%s", got)
	}
}

func TestTransformTableLevelAutoIncrementPK(t *testing.T) {
	input := `CREATE TABLE alert_log (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    PRIMARY KEY (id),
    KEY idx_name (name)
) ENGINE=InnoDB;`
	got := TransformForSQLite(input)
	if !strings.Contains(got, "id INTEGER PRIMARY KEY") {
		t.Errorf("id not converted to INTEGER PRIMARY KEY, got:\n%s", got)
	}
	if strings.Contains(got, "PRIMARY KEY (id)") {
		t.Errorf("separate PRIMARY KEY (id) not removed, got:\n%s", got)
	}
	if strings.Contains(got, "AUTO_INCREMENT") {
		t.Errorf("AUTO_INCREMENT not stripped, got:\n%s", got)
	}
}

func TestTransformReversedAutoIncrementPK(t *testing.T) {
	input := `CREATE TABLE customer_wg (
    id BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL
) ENGINE=InnoDB;`
	got := TransformForSQLite(input)
	if !strings.Contains(got, "INTEGER PRIMARY KEY") {
		t.Errorf("reversed PK not converted, got:\n%s", got)
	}
}

func TestTransformNotNullInlineAutoIncrementPK(t *testing.T) {
	input := `CREATE TABLE custom_fields (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL
) ENGINE=InnoDB;`
	got := TransformForSQLite(input)
	if !strings.Contains(got, "INTEGER PRIMARY KEY") {
		t.Errorf("NOT NULL inline PK not converted, got:\n%s", got)
	}
}
