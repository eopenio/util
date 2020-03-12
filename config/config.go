// Copyright 2020 EOI, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/eopenio/errors"
	"github.com/eopenio/log"
	"github.com/eopenio/util/logutil"
	"github.com/eopenio/util/terror"
	"github.com/micro/go-micro/v2/config"
	"go.uber.org/zap"
	"io/ioutil"
	"strings"
)

const DefaultConfigFile = "etc/srv.toml"

type Config struct {
	Host             string   `toml:"host" json:"host"`
	AdvertiseAddress string   `toml:"advertise-address" json:"advertise-address"`
	Port             uint     `toml:"port" json:"port"`
	Socket           string   `toml:"socket" json:"socket"`
	TokenLimit       uint     `toml:"token-limit" json:"token-limit"`
	ServerVersion    string   `toml:"server-version" json:"server-version"`
	Log              Log      `toml:"log" json:"log"`
	Status           Status   `toml:"status" json:"status"`
	Security         Security `toml:"security" json:"security"`
}

// nullableBool defaults unset bool options to unset instead of false, which enables us to know if the user has set 2
// conflict options at the same time.
type nullableBool struct {
	IsValid bool
	IsTrue  bool
}

var (
	nbUnset = nullableBool{false, false}
	nbFalse = nullableBool{true, false}
	nbTrue  = nullableBool{true, true}
)

func (b *nullableBool) toBool() bool {
	return b.IsValid && b.IsTrue
}

func (b nullableBool) MarshalJSON() ([]byte, error) {
	switch b {
	case nbTrue:
		return json.Marshal(true)
	case nbFalse:
		return json.Marshal(false)
	default:
		return json.Marshal(nil)
	}
}

func (b *nullableBool) UnmarshalText(text []byte) error {
	str := string(text)
	switch str {
	case "", "null":
		*b = nbUnset
		return nil
	case "true":
		*b = nbTrue
	case "false":
		*b = nbFalse
	default:
		*b = nbUnset
		return errors.New("Invalid value for bool type: " + str)
	}
	return nil
}

func (b nullableBool) MarshalText() ([]byte, error) {
	if !b.IsValid {
		return []byte(""), nil
	}
	if b.IsTrue {
		return []byte("true"), nil
	}
	return []byte("false"), nil
}

func (b *nullableBool) UnmarshalJSON(data []byte) error {
	var err error
	var v interface{}
	if err = json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch raw := v.(type) {
	case bool:
		*b = nullableBool{true, raw}
	default:
		*b = nbUnset
	}
	return err
}

// Log is the log section of config.
type Log struct {
	// Log level.
	Level string `toml:"level" json:"level"`
	// Log format. one of json, text, or console.
	Format string `toml:"format" json:"format"`
	// Disable automatic timestamps in output. Deprecated: use EnableTimestamp instead.
	DisableTimestamp nullableBool `toml:"disable-timestamp" json:"disable-timestamp"`
	// EnableTimestamp enables automatic timestamps in log output.
	EnableTimestamp nullableBool `toml:"enable-timestamp" json:"enable-timestamp"`
	// DisableErrorStack stops annotating logs with the full stack error
	// message. Deprecated: use EnableErrorStack instead.
	DisableErrorStack nullableBool `toml:"disable-error-stack" json:"disable-error-stack"`
	// EnableErrorStack enables annotating logs with the full stack error
	// message.
	EnableErrorStack nullableBool `toml:"enable-error-stack" json:"enable-error-stack"`
	// File log config.
	File logutil.FileLogConfig `toml:"file" json:"file"`
}

func (l *Log) getDisableTimestamp() bool {
	if l.EnableTimestamp == nbUnset && l.DisableTimestamp == nbUnset {
		return false
	}
	if l.EnableTimestamp == nbUnset {
		return l.DisableTimestamp.toBool()
	}
	return !l.EnableTimestamp.toBool()
}

func (l *Log) getDisableErrorStack() bool {
	if l.EnableErrorStack == nbUnset && l.DisableErrorStack == nbUnset {
		return true
	}
	if l.EnableErrorStack == nbUnset {
		return l.DisableErrorStack.toBool()
	}
	return !l.EnableErrorStack.toBool()
}

// ToLogConfig converts *Log to *logutil.LogConfig.
func (l *Log) ToLogConfig() *logutil.LogConfig {
	return logutil.NewLogConfig(l.Level, l.Format, l.File, l.getDisableTimestamp(), func(config *log.Config) { config.DisableErrorVerbose = l.getDisableErrorStack() })
}

// Security is the security section of the config.
type Security struct {
	SkipGrantTable  bool     `toml:"skip-grant-table" json:"skip-grant-table"`
	SSLCA           string   `toml:"ssl-ca" json:"ssl-ca"`
	SSLCert         string   `toml:"ssl-cert" json:"ssl-cert"`
	SSLKey          string   `toml:"ssl-key" json:"ssl-key"`
	ClusterSSLCA    string   `toml:"cluster-ssl-ca" json:"cluster-ssl-ca"`
	ClusterSSLCert  string   `toml:"cluster-ssl-cert" json:"cluster-ssl-cert"`
	ClusterSSLKey   string   `toml:"cluster-ssl-key" json:"cluster-ssl-key"`
	ClusterVerifyCN []string `toml:"cluster-verify-cn" json:"cluster-verify-cn"`
}

// The ErrConfigValidationFailed error is used so that external callers can do a type assertion
// to defer handling of this specific error when someone does not want strict type checking.
// This is needed only because logging hasn't been set up at the time we parse the config file.
// This should all be ripped out once strict config checking is made the default behavior.
type ErrConfigValidationFailed struct {
	confFile       string
	UndecodedItems []string
}

func (e *ErrConfigValidationFailed) Error() string {
	return fmt.Sprintf("config file %s contained unknown configuration options: %s", e.confFile, strings.Join(e.UndecodedItems, ", "))
}

// ToTLSConfig generates tls's config based on security section of the config.
func (s *Security) ToTLSConfig() (tlsConfig *tls.Config, err error) {
	if len(s.ClusterSSLCA) != 0 {
		certPool := x509.NewCertPool()
		// Create a certificate pool from the certificate authority
		var ca []byte
		ca, err = ioutil.ReadFile(s.ClusterSSLCA)
		if err != nil {
			err = errors.Errorf("could not read ca certificate: %s", err)
			return
		}
		// Append the certificates from the CA
		if !certPool.AppendCertsFromPEM(ca) {
			err = errors.New("failed to append ca certs")
			return
		}
		tlsConfig = &tls.Config{
			RootCAs: certPool,
		}

		if len(s.ClusterSSLCert) != 0 && len(s.ClusterSSLKey) != 0 {
			getCert := func() (*tls.Certificate, error) {
				// Load the client certificates from disk
				cert, err := tls.LoadX509KeyPair(s.ClusterSSLCert, s.ClusterSSLKey)
				if err != nil {
					return nil, errors.Errorf("could not load client key pair: %s", err)
				}
				return &cert, nil
			}
			// pre-test cert's loading.
			if _, err = getCert(); err != nil {
				return
			}
			tlsConfig.GetClientCertificate = func(info *tls.CertificateRequestInfo) (certificate *tls.Certificate, err error) {
				return getCert()
			}
			tlsConfig.GetCertificate = func(info *tls.ClientHelloInfo) (certificate *tls.Certificate, err error) {
				return getCert()
			}
		}
	}
	return
}

// Status is the status section of the config.
type Status struct {
	StatusHost      string `toml:"status-host" json:"status-host"`
	MetricsAddr     string `toml:"metrics-addr" json:"metrics-addr"`
	StatusPort      uint   `toml:"status-port" json:"status-port"`
	MetricsInterval uint   `toml:"metrics-interval" json:"metrics-interval"`
	ReportStatus    bool   `toml:"report-status" json:"report-status"`
	RecordQPSbyDB   bool   `toml:"record-db-qps" json:"record-db-qps"`
}

var defaultConf = Config{
	Host:             "0.0.0.0",
	AdvertiseAddress: "",
	Port:             6068,
	TokenLimit:       1000,
	ServerVersion:    "",
	Log: Log{
		Level:             "info",
		Format:            "text",
		File:              logutil.NewFileLogConfig(logutil.DefaultLogMaxSize),
		DisableErrorStack: nbUnset,
		EnableErrorStack:  nbUnset, // If both options are nbUnset, getDisableErrorStack() returns true
		EnableTimestamp:   nbUnset,
		DisableTimestamp:  nbUnset, // If both options are nbUnset, getDisableTimestamp() returns false
	},
	Status: Status{
		ReportStatus:    true,
		StatusHost:      "0.0.0.0",
		StatusPort:      10080,
		MetricsInterval: 15,
		RecordQPSbyDB:   false,
	},
}

// Valid checks if this config is valid.
func (c *Config) Valid() error {
	if c.Log.EnableErrorStack == c.Log.DisableErrorStack && c.Log.EnableErrorStack != nbUnset {
		logutil.BgLogger().Warn(fmt.Sprintf("\"enable-error-stack\" (%v) conflicts \"disable-error-stack\" (%v). \"disable-error-stack\" is deprecated, please use \"enable-error-stack\" instead. disable-error-stack is ignored.", c.Log.EnableErrorStack, c.Log.DisableErrorStack))
		// if two options conflict, we will use the value of EnableErrorStack
		c.Log.DisableErrorStack = nbUnset
	}
	if c.Log.EnableTimestamp == c.Log.DisableTimestamp && c.Log.EnableTimestamp != nbUnset {
		logutil.BgLogger().Warn(fmt.Sprintf("\"enable-timestamp\" (%v) conflicts \"disable-timestamp\" (%v). \"disable-timestamp\" is deprecated, please use \"enable-timestamp\" instead", c.Log.EnableTimestamp, c.Log.DisableTimestamp))
		// if two options conflict, we will use the value of EnableTimestamp
		c.Log.DisableTimestamp = nbUnset
	}
	// test log level
	l := zap.NewAtomicLevel()
	return l.UnmarshalText([]byte(c.Log.Level))
}

// NewConfig creates a new config instance with default value.
func NewConfig() *Config {
	conf := defaultConf
	return &conf
}

func GetGlobalConfig(filename string) *Config {
	var configFile string
	if filename != "" {
		configFile = filename
	} else {
		configFile = DefaultConfigFile
	}
	terror.MustNil(config.LoadFile(configFile))
	return NewConfig()
}
