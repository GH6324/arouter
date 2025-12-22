package main

import (
	"embed"
	_ "embed"
)

var buildVersion = "dev"
var jwtSecret []byte
var globalKey string

//go:embed certs/arouter.crt
var defaultCert []byte

//go:embed certs/arouter.key
var defaultKey []byte

//go:embed config_pull.sh.tmpl
var configPullTemplate string

//go:embed dist/arouter-*
var embeddedNodeBins embed.FS

//go:embed web/dist
var embeddedWeb embed.FS
