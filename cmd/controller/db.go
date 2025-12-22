package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func mustOpenDB() *gorm.DB {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		dbPath := envOrDefault("DB_PATH", "./data/arouter.db")
		if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
			log.Fatalf("create db dir failed: %v", err)
		}
		return openSQLiteWithPragma(dbPath)
	}
	if strings.HasPrefix(dsn, "sqlite:") {
		path := strings.TrimPrefix(dsn, "sqlite:")
		return openSQLiteWithPragma(path)
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("open mysql failed: %v", err)
	}
	return db
}

// openSQLiteWithPragma 为 sqlite 添加常用的 pragma，减少磁盘压力并提高兼容性。
func openSQLiteWithPragma(path string) *gorm.DB {
	// busy_timeout 避免瞬时锁导致失败；WAL 提高并发；同步设为 NORMAL 兼顾性能。
	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", path)
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("open sqlite failed: %v", err)
	}
	// 单连接即可，避免 WAL checkpoint 被阻塞
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1)
	}
	return db
}

// maybeCheckpoint 在 SQLite 下进行 WAL checkpoint，避免 WAL 长大导致“disk is full”。
func maybeCheckpoint(db *gorm.DB) {
	if db == nil || db.Dialector.Name() != "sqlite" {
		return
	}
	db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
}

// isSQLiteFull 检测 SQLite 的磁盘/权限问题。
func isSQLiteFull(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "database or disk is full") ||
		strings.Contains(msg, "no space left on device") ||
		strings.Contains(msg, "attempt to write a readonly database")
}

// ensureColumns 兜底补齐旧库缺失的字段，避免“no such column”。
func ensureColumns(db *gorm.DB) {
	type col struct {
		model interface{}
		name  string
		table string
		ctype string
	}
	cols := []col{
		{&Node{}, "quic_listen", "nodes", "TEXT"},
		{&Node{}, "transport", "nodes", "TEXT"},
		{&Node{}, "compression", "nodes", "TEXT"},
		{&Node{}, "compression_min", "nodes", "INTEGER"},
		{&Node{}, "max_mux_streams", "nodes", "INTEGER"},
		{&Node{}, "mux_max_age", "nodes", "TEXT"},
		{&Node{}, "mux_max_idle", "nodes", "TEXT"},
		{&Node{}, "mem_limit", "nodes", "TEXT"},
		{&Node{}, "quic_server_name", "nodes", "TEXT"},
		{&Node{}, "udp_session_ttl", "nodes", "TEXT"},
		{&Node{}, "controller_url", "nodes", "TEXT"},
		{&Node{}, "reroute_attempts", "nodes", "INTEGER"},
		{&Node{}, "insecure_skip_tls", "nodes", "BOOLEAN"},
		{&Node{}, "mtls_cert", "nodes", "TEXT"},
		{&Node{}, "mtls_key", "nodes", "TEXT"},
		{&Node{}, "mtls_ca", "nodes", "TEXT"},
		{&Node{}, "last_cpu", "nodes", "DOUBLE"},
		{&Node{}, "mem_used", "nodes", "BIGINT"},
		{&Node{}, "mem_total", "nodes", "BIGINT"},
		{&Node{}, "uptime_sec", "nodes", "BIGINT"},
		{&Node{}, "net_in_bytes", "nodes", "BIGINT"},
		{&Node{}, "net_out_bytes", "nodes", "BIGINT"},
		{&Node{}, "node_version", "nodes", "TEXT"},
		{&Node{}, "last_seen_at", "nodes", "DATETIME"},
		{&Node{}, "token", "nodes", "TEXT"},
		{&Node{}, "public_ips", "nodes", "TEXT"},
		{&User{}, "username", "users", "TEXT"},
		{&User{}, "password_hash", "users", "TEXT"},
		{&User{}, "is_admin", "users", "BOOLEAN"},
		{&Setting{}, "debug_log", "settings", "BOOLEAN"},
		{&Setting{}, "http_probe_url", "settings", "TEXT"},
		{&Setting{}, "max_mux_streams", "settings", "INTEGER"},
		{&Setting{}, "return_ack_timeout", "settings", "TEXT"},
		{&Setting{}, "encryption_policies", "settings", "TEXT"},
		{&RoutePlan{}, "return_path", "route_plans", "TEXT"},
		{&ReturnRouteStatus{}, "ready_at", "return_route_statuses", "BIGINT"},
		{&ReturnRouteStatus{}, "fail_total", "return_route_statuses", "BIGINT"},
		{&ReturnRouteStatus{}, "fail_at", "return_route_statuses", "BIGINT"},
		{&ReturnRouteStatus{}, "fail_reason", "return_route_statuses", "TEXT"},
		{&Peer{}, "entry_ip", "peers", "TEXT"},
		{&Peer{}, "exit_ip", "peers", "TEXT"},
	}
	for _, c := range cols {
		if !db.Migrator().HasColumn(c.model, c.name) {
			if err := db.Migrator().AddColumn(c.model, c.name); err != nil {
				log.Printf("add column %s via migrator failed: %v, trying raw alter", c.name, err)
				if err2 := addColumnRaw(db, c.table, c.name, c.ctype); err2 != nil {
					log.Printf("add column %s via raw alter failed: %v", c.name, err2)
				} else {
					log.Printf("added missing column %s via raw alter", c.name)
				}
			} else {
				log.Printf("added missing column %s", c.name)
			}
		}
	}
}

func addColumnRaw(db *gorm.DB, table, column, ctype string) error {
	dialect := strings.ToLower(db.Dialector.Name())
	switch dialect {
	case "sqlite":
		return db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, ctype)).Error
	case "mysql":
		mysqlType := ctype
		if strings.EqualFold(ctype, "BOOLEAN") {
			mysqlType = "TINYINT(1)"
		} else if strings.EqualFold(ctype, "TEXT") {
			mysqlType = "VARCHAR(255)"
		}
		return db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, mysqlType)).Error
	default:
		return fmt.Errorf("unsupported dialect %s", dialect)
	}
}
