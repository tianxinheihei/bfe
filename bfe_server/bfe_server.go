// Copyright (c) 2019 Baidu, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// the main structure of bfe-server

package bfe_server

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

import (
	"github.com/baidu/go-lib/log"
)

import (
	"github.com/baidu/bfe/bfe_balance"
	"github.com/baidu/bfe/bfe_config/bfe_cluster_conf/cluster_conf"
	"github.com/baidu/bfe/bfe_config/bfe_conf"
	"github.com/baidu/bfe/bfe_config/bfe_tls_conf/session_ticket_key_conf"
	"github.com/baidu/bfe/bfe_config/bfe_tls_conf/tls_rule_conf"
	"github.com/baidu/bfe/bfe_http"
	"github.com/baidu/bfe/bfe_http2"
	"github.com/baidu/bfe/bfe_http2/bfe_h2c"
	"github.com/baidu/bfe/bfe_module"
	"github.com/baidu/bfe/bfe_route"
	"github.com/baidu/bfe/bfe_spdy"
	"github.com/baidu/bfe/bfe_stream"
	"github.com/baidu/bfe/bfe_tls"
	"github.com/baidu/bfe/bfe_util/signal_table"
	"github.com/baidu/bfe/bfe_websocket"
)

// BfeServer
type BfeServer struct {
	bfe_http.Server

	// service listeners
	listenerMap   map[string]net.Listener // all listeners
	HttpListener  net.Listener            // listener for http
	HttpsListener *HttpsListener          // listener for https

	connWaitGroup sync.WaitGroup // waits for server conns to finish

	// for http server
	ReverseProxy *ReverseProxy // reverse proxy

	// TLS session cache
	SessionCache *ServerSessionCache

	// TLS certificates
	MultiCert *MultiCertMap

	// TLS server rule
	TLSServerRule *TLSServerRuleMap

	// server config
	Config bfe_conf.BfeConfig

	// module and callback
	CallBacks *bfe_module.BfeCallbacks // call back functions
	Modules   *bfe_module.BfeModules   // bfe modules

	// web server for bfe monitor and reload
	Monitor *BfeMonitor

	// bufio cache
	BufioCache *BufioCache

	// signal table
	SignalTable *signal_table.SignalTable

	// server status
	serverStatus *ServerStatus

	confLock   sync.RWMutex              // mutex when reload data conf
	ServerConf *bfe_route.ServerDataConf // cluster_conf and host table conf
	balTable   *bfe_balance.BalTable     // for balance

	Version string // version of bfe server
}

// NewBfeModules create a new instance of BfeServer.
func NewBfeServer(cfg bfe_conf.BfeConfig,
	listenerMap map[string]net.Listener,
	version string) *BfeServer {

	s := new(BfeServer)

	// bfe config
	s.Config = cfg
	s.InitConfig()

	// set service listener
	s.listenerMap = listenerMap
	s.HttpListener = listenerMap["HTTP"]

	// initialize counters, proxyState
	s.serverStatus = NewServerStatus()

	// initialize bufioCache
	s.BufioCache = NewBufioCache()

	// create reverse proxy
	s.ReverseProxy = NewReverseProxy(s, s.serverStatus.ProxyState)

	// initialize callbacks
	s.CallBacks = bfe_module.NewBfeCallbacks()
	// create modules
	s.Modules = bfe_module.NewBfeModules()

	// initialize balTable
	s.balTable = bfe_balance.NewBalTable(s.GetCheckConf)

	// set keep-alive
	s.SetKeepAlivesEnabled(cfg.Server.KeepAliveEnabled)

	s.CloseNotifyCh = make(chan bool)

	s.Version = version

	return s
}

// InitConfig set some parameter based on config.
func (srv *BfeServer) InitConfig() {
	// set service port, according to config
	srv.Addr = fmt.Sprintf(":%d", srv.Config.Server.HttpPort)

	// set TlsHandshakeTimeout
	if srv.Config.Server.TlsHandshakeTimeout != 0 {
		srv.TlsHandshakeTimeout = time.Duration(srv.Config.Server.TlsHandshakeTimeout) * time.Second
	}

	// set ReadTimeout
	if srv.Config.Server.ClientReadTimeout != 0 {
		srv.ReadTimeout = time.Duration(srv.Config.Server.ClientReadTimeout) * time.Second
	}

	// set MaxHeaderBytes
	if srv.Config.Server.MaxHeaderBytes != 0 {
		srv.MaxHeaderBytes = srv.Config.Server.MaxHeaderBytes
	} else {
		srv.MaxHeaderBytes = bfe_http.DefaultMaxHeaderBytes
	}

	// set GracefulShutdownTimeout
	srv.GracefulShutdownTimeout = time.Duration(srv.Config.Server.GracefulShutdownTimeout) * time.Second

	// set MaxHeaderUriBytes
	if srv.Config.Server.MaxHeaderUriBytes != 0 {
		srv.MaxHeaderUriBytes = srv.Config.Server.MaxHeaderUriBytes
	} else {
		srv.MaxHeaderUriBytes = bfe_http.DefaultMaxHeaderUriBytes
	}
}

func (srv *BfeServer) InitHttp() (err error) {
	// initialize http next proto handlers
	httpNextProto := make(map[string]func(*bfe_http.Server, bfe_http.ResponseWriter, *bfe_http.Request, bfe_http.Handler))
	httpNextProto[bfe_websocket.WebSocket] = bfe_websocket.NewProtoHandler(&bfe_websocket.Server{
		BalanceHandler: srv.Balance})
	httpNextProto[bfe_h2c.H2C] = bfe_h2c.NewProtoHandler(nil)
	srv.HTTPNextProto = httpNextProto

	return nil
}

func (srv *BfeServer) InitHttps() (err error) {
	// initialize tls config
	if err := srv.initTLSConfig(); err != nil {
		return err
	}

	// init tls next proto handlers
	srv.initTLSNextProtoHandler()

	// initialize https listeners
	srv.HttpsListener = NewHttpsListener(srv.listenerMap["HTTPS"], srv.TLSConfig)

	return nil
}

func (srv *BfeServer) initTLSConfig() (err error) {
	srv.TLSConfig = new(bfe_tls.Config)
	httpsConf := srv.Config.HttpsBasic

	// set max and min TLS version
	srv.TLSConfig.MaxVersion, srv.TLSConfig.MinVersion = bfe_conf.GetTlsVersion(&httpsConf)

	// enable Sslv2 ClientHello for compatible with ancient TLS-capable clients
	srv.TLSConfig.EnableSslv2ClientHello = httpsConf.EnableSslv2ClientHello

	// initialize ciphersuites preference
	srv.TLSConfig.PreferServerCipherSuites = true
	cipherSuites, cipherSuitesPriority, err := bfe_conf.GetCipherSuites(httpsConf.CipherSuites)
	if err != nil {
		return fmt.Errorf("in ServerCertConfLoad() :%s", err.Error())
	}
	srv.TLSConfig.CipherSuites = cipherSuites
	srv.TLSConfig.CipherSuitesPriority = cipherSuitesPriority

	// set Ssl3PoodleProofed true make server free of poodle attach
	srv.TLSConfig.Ssl3PoodleProofed = true

	// initialize elliptic curves preference
	srv.TLSConfig.CurvePreferences, err = bfe_conf.GetCurvePreferences(httpsConf.CurvePreferences)
	if err != nil {
		return fmt.Errorf("in ServerCertConfLoad() :%s", err.Error())
	}

	// initialize session cache
	srv.initTLSSessionCache()

	// initialize session ticket
	if err = srv.initTLSSessionTicket(); err != nil {
		return err
	}

	// initialize tls rule
	if err = srv.initTLSRule(httpsConf); err != nil {
		return err
	}

	return nil
}

func (srv *BfeServer) initTLSSessionCache() {
	sessionCacheConf := srv.Config.SessionCache
	srv.TLSConfig.SessionCacheDisabled = sessionCacheConf.SessionCacheDisabled

	if !sessionCacheConf.SessionCacheDisabled {
		srv.SessionCache = NewServerSessionCache(sessionCacheConf, srv.serverStatus.ProxyState)
		srv.TLSConfig.ServerSessionCache = srv.SessionCache
	}
}

func (srv *BfeServer) initTLSSessionTicket() error {
	sessionTicketConf := srv.Config.SessionTicket

	// initialize session ticket key
	if !sessionTicketConf.SessionTicketsDisabled {
		srv.TLSConfig.SessionTicketsDisabled = false
		keyFile := sessionTicketConf.SessionTicketKeyFile
		keyConf, err := session_ticket_key_conf.SessionTicketKeyConfLoad(keyFile)
		if err != nil {
			return err
		}
		key, err := hex.DecodeString(keyConf.SessionTicketKey)
		if err != nil {
			return fmt.Errorf("wrong session ticket key %s (%s)", err, key)
		}

		copy(srv.TLSConfig.SessionTicketKeyName[:], key[:16])
		copy(srv.TLSConfig.SessionTicketKey[:], key[16:])
	} else {
		srv.TLSConfig.SessionTicketsDisabled = true
	}

	return nil
}

func (srv *BfeServer) initTLSRule(httpsConf bfe_conf.ConfigHttpsBasic) error {
	srv.MultiCert = NewMultiCertMap(srv.serverStatus.ProxyState)
	srv.TLSServerRule = NewTLSServerRuleMap(srv.serverStatus.ProxyState)
	if err := srv.tlsConfLoad(httpsConf.ServerCertConf, httpsConf.TlsRuleConf); err != nil {
		return err
	}

	cert := srv.MultiCert.GetDefault()
	if cert == nil {
		return fmt.Errorf("createTlsConfig get default Cert error")
	}

	// Note: config.Certficates must be initialized, but we just use config.MultiCert
	// for server certificates
	srv.TLSConfig.Certificates = make([]bfe_tls.Certificate, 1)
	srv.TLSConfig.Certificates[0] = *cert
	srv.TLSConfig.MultiCert = srv.MultiCert
	srv.TLSConfig.ServerRule = srv.TLSServerRule
	return nil
}

func (srv *BfeServer) initTLSNextProtoHandler() {
	// init next protocol handler
	tlsNextProto := make(map[string]func(*bfe_http.Server, *bfe_tls.Conn, bfe_http.Handler))
	tlsNextProto[tls_rule_conf.SPDY31] = bfe_spdy.NewProtoHandler(nil)
	tlsNextProto[tls_rule_conf.HTTP2] = bfe_http2.NewProtoHandler(nil)
	tlsNextProto[tls_rule_conf.STREAM] = bfe_stream.NewProtoHandler(&bfe_stream.Server{
		BalanceHandler: srv.Balance})
	srv.TLSNextProto = tlsNextProto

	// init params for http2
	bfe_http2.DisableConnHeaderCheck()
	bfe_http2.SetServerRule(srv.TLSServerRule)
	bfe_http2.EnableLargeConnRecvWindow()
}

func (srv *BfeServer) InitModules(confRoot string) error {
	return srv.Modules.Init(srv.CallBacks, srv.Monitor.WebHandlers, confRoot)
}

func (srv *BfeServer) InitSignalTable() {
	/* create signal table */
	srv.SignalTable = signal_table.NewSignalTable()

	/* register signal handlers */
	srv.SignalTable.Register(syscall.SIGQUIT, srv.ShutdownHandler)
	srv.SignalTable.Register(syscall.SIGTERM, signal_table.TermHandler)
	srv.SignalTable.Register(syscall.SIGHUP, signal_table.IgnoreHandler)
	srv.SignalTable.Register(syscall.SIGILL, signal_table.IgnoreHandler)
	srv.SignalTable.Register(syscall.SIGTRAP, signal_table.IgnoreHandler)
	srv.SignalTable.Register(syscall.SIGABRT, signal_table.IgnoreHandler)

	/* start signal handler routine */
	srv.SignalTable.StartSignalHandle()
}

func (s *BfeServer) InitWebMonitor(port int) error {
	var err error
	s.Monitor, err = newBfeMonitor(s, port)
	return err
}

// ShutdownHandler is signal handler for QUIT
func (s *BfeServer) ShutdownHandler(sig os.Signal) {
	shutdownTimeout := s.Config.Server.GracefulShutdownTimeout
	log.Logger.Info("get signal %s, graceful shutdown in %ds", sig, shutdownTimeout)

	// notify that server is in graceful shutdown state
	close(s.CloseNotifyCh)

	// close server listeners
	s.closeListeners()

	// waits server conns to finish
	connFinCh := make(chan bool)
	go func() {
		s.connWaitGroup.Wait()
		connFinCh <- true
	}()

	shutdownTimer := time.After(time.Duration(shutdownTimeout) * time.Second)

Loop:
	for {
		select {
		// waits server conns to finish
		case <-connFinCh:
			log.Logger.Info("graceful shutdown success.")
			break Loop

		// wait for shutdown timeout
		case <-shutdownTimer:
			log.Logger.Info("graceful shutdown timeout.")
			break Loop
		}
	}

	// shutdown server
	log.Logger.Close()
	os.Exit(0)
}

// CheckGracefulShutdown check wether the server is in graceful shutdown state.
func (s *BfeServer) CheckGracefulShutdown() bool {
	select {
	case <-s.CloseNotifyCh:
		return true
	default:
		return false
	}
}

func (s *BfeServer) GetServerConf() *bfe_route.ServerDataConf {
	s.confLock.RLock()
	sf := s.ServerConf
	s.confLock.RUnlock()

	return sf
}

// GetCheckConf implements CheckConfFetcher and return current
// health check configuration.
func (s *BfeServer) GetCheckConf(clusterName string) *cluster_conf.BackendCheck {
	sf := s.GetServerConf()
	cluster, err := sf.ClusterTable.Lookup(clusterName)
	if err != nil {
		return nil
	}
	return cluster.BackendCheckConf()
}
