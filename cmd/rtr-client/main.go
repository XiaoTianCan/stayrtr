package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	rtr "github.com/bgp/stayrtr/lib"
	"golang.org/x/crypto/ssh"
)

// RTRClient 管理 RTR 协议客户端会话
type RTRClient struct {
	addr     string
	connType int
	session  *rtr.ClientSession

	vrps      map[string]*rtr.VRP      // 前缀信息缓存
	brks      map[string]*rtr.BgpsecKey // BGPsec 密钥缓存
	serial    uint32                    // 当前 serial
	sessionID uint16                    // 会话 ID
	mutex     sync.RWMutex

	handler *ClientEventHandler
}

// ClientEventHandler 实现 RTRClientSessionEventHandler 接口
type ClientEventHandler struct {
	client *RTRClient
}

func (h *ClientEventHandler) HandlePDU(cs *rtr.ClientSession, pdu rtr.PDU) {
	switch pdu.(type) {
	case *rtr.PDUCacheResponse:
		p := pdu.(*rtr.PDUCacheResponse)
		h.client.mutex.Lock()
		h.client.sessionID = p.SessionId
		h.client.mutex.Unlock()
		log.Printf("[Cache Response] SessionID: %d\n", p.SessionId)

	case *rtr.PDUIPv4Prefix:
		p := pdu.(*rtr.PDUIPv4Prefix)
		h.client.handleIPv4Prefix(p)

	case *rtr.PDUIPv6Prefix:
		p := pdu.(*rtr.PDUIPv6Prefix)
		h.client.handleIPv6Prefix(p)

	case *rtr.PDURouterKey:
		p := pdu.(*rtr.PDURouterKey)
		h.client.handleRouterKey(p)

	case *rtr.PDUEndOfData:
		p := pdu.(*rtr.PDUEndOfData)
		h.client.mutex.Lock()
		h.client.serial = p.SerialNumber
		h.client.mutex.Unlock()
		log.Printf("[End of Data] SessionID: %d, Serial: %d, RefreshInterval: %d, RetryInterval: %d, ExpireInterval: %d\n",
			p.SessionId, p.SerialNumber, p.RefreshInterval, p.RetryInterval, p.ExpireInterval)

	case *rtr.PDUSerialNotify:
		p := pdu.(*rtr.PDUSerialNotify)
		log.Printf("[Serial Notify] SessionID: %d, Serial: %d\n", p.SessionId, p.SerialNumber)
		// 发送 Serial Query 更新数据
		h.client.mutex.RLock()
		sessionID := h.client.sessionID
		serial := h.client.serial
		h.client.mutex.RUnlock()
		h.client.session.SendSerialQuery(sessionID, serial)

	case *rtr.PDUCacheReset:
		log.Printf("[Cache Reset] 需要重新获取所有数据\n")
		h.client.session.SendResetQuery()

	case *rtr.PDUErrorReport:
		p := pdu.(*rtr.PDUErrorReport)
		log.Printf("[Error Report] ErrorCode: %d, Message: %s\n", p.ErrorCode, p.ErrorMsg)

	default:
		log.Printf("[Unknown PDU] Type: %s\n", rtr.TypeToString(pdu.GetType()))
	}
}

func (h *ClientEventHandler) ClientConnected(cs *rtr.ClientSession) {
	log.Println("[Connected] RTR 客户端已连接")
	// 发送初始 Reset Query
	h.client.session.SendResetQuery()
}

func (h *ClientEventHandler) ClientDisconnected(cs *rtr.ClientSession) {
	log.Println("[Disconnected] RTR 客户端已断开连接")
}

// handleIPv4Prefix 处理 IPv4 前缀 PDU
func (c *RTRClient) handleIPv4Prefix(pdu *rtr.PDUIPv4Prefix) {
	prefix := pdu.Prefix
	key := fmt.Sprintf("%s-%d-%d", prefix.String(), pdu.MaxLen, pdu.ASN)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if pdu.Flags == rtr.FLAG_ADDED {
		vrp := &rtr.VRP{
			Prefix: prefix,
			MaxLen: pdu.MaxLen,
			ASN:    pdu.ASN,
		}
		c.vrps[key] = vrp
		log.Printf("[IPv4 Add] Prefix: %s, MaxLen: %d, ASN: %d\n", prefix, pdu.MaxLen, pdu.ASN)
	} else {
		delete(c.vrps, key)
		log.Printf("[IPv4 Remove] Prefix: %s, MaxLen: %d, ASN: %d\n", prefix, pdu.MaxLen, pdu.ASN)
	}
}

// handleIPv6Prefix 处理 IPv6 前缀 PDU
func (c *RTRClient) handleIPv6Prefix(pdu *rtr.PDUIPv6Prefix) {
	prefix := pdu.Prefix
	key := fmt.Sprintf("%s-%d-%d", prefix.String(), pdu.MaxLen, pdu.ASN)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if pdu.Flags == rtr.FLAG_ADDED {
		vrp := &rtr.VRP{
			Prefix: prefix,
			MaxLen: pdu.MaxLen,
			ASN:    pdu.ASN,
		}
		c.vrps[key] = vrp
		log.Printf("[IPv6 Add] Prefix: %s, MaxLen: %d, ASN: %d\n", prefix, pdu.MaxLen, pdu.ASN)
	} else {
		delete(c.vrps, key)
		log.Printf("[IPv6 Remove] Prefix: %s, MaxLen: %d, ASN: %d\n", prefix, pdu.MaxLen, pdu.ASN)
	}
}

// handleRouterKey 处理 BGPsec 路由器密钥 PDU
func (c *RTRClient) handleRouterKey(pdu *rtr.PDURouterKey) {
	key := fmt.Sprintf("%d-%x", pdu.ASN, pdu.SubjectKeyIdentifier)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if pdu.Flags == rtr.FLAG_ADDED {
		brk := &rtr.BgpsecKey{
			ASN:    pdu.ASN,
			Ski:    pdu.SubjectKeyIdentifier,
			Pubkey: pdu.SubjectPublicKeyInfo,
		}
		c.brks[key] = brk
		log.Printf("[Router Key Add] ASN: %d, SKI: %x\n", pdu.ASN, pdu.SubjectKeyIdentifier)
	} else {
		delete(c.brks, key)
		log.Printf("[Router Key Remove] ASN: %d, SKI: %x\n", pdu.ASN, pdu.SubjectKeyIdentifier)
	}
}

// GetVRPs 获取当前所有 VRP
func (c *RTRClient) GetVRPs() []*rtr.VRP {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	vrps := make([]*rtr.VRP, 0, len(c.vrps))
	for _, vrp := range c.vrps {
		vrps = append(vrps, vrp)
	}
	return vrps
}

// GetBGPsecKeys 获取当前所有 BGPsec 密钥
func (c *RTRClient) GetBGPsecKeys() []*rtr.BgpsecKey {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	brks := make([]*rtr.BgpsecKey, 0, len(c.brks))
	for _, brk := range c.brks {
		brks = append(brks, brk)
	}
	return brks
}

// PrintStats 打印统计信息
func (c *RTRClient) PrintStats() {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	log.Printf("\n========== RTR Client Stats ==========\n")
	log.Printf("Session ID: %d\n", c.sessionID)
	log.Printf("Serial: %d\n", c.serial)
	log.Printf("Total VRPs: %d\n", len(c.vrps))
	log.Printf("Total BGPsec Keys: %d\n", len(c.brks))
	log.Printf("=====================================\n")
}

// Connect 连接到 RTR 服务器
func (c *RTRClient) Connect(protocol string) error {
	config := rtr.ClientConfiguration{
		ProtocolVersion: rtr.PROTOCOL_VERSION_1,
		Log:             &SimpleLogger{},
	}

	c.handler = &ClientEventHandler{client: c}
	c.session = rtr.NewClientSession(config, c.handler)

	var err error
	switch protocol {
	case "plain":
		c.connType = rtr.TYPE_PLAIN
		err = c.session.Start(c.addr, rtr.TYPE_PLAIN, nil, nil)

	case "tls":
		c.connType = rtr.TYPE_TLS
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // 仅用于测试，生产环境应该验证证书
		}
		err = c.session.Start(c.addr, rtr.TYPE_TLS, tlsConfig, nil)

	case "ssh":
		c.connType = rtr.TYPE_SSH
		sshConfig := &ssh.ClientConfig{
			User: "rpki",
			Auth: []ssh.AuthMethod{
				ssh.Password(""), // 无密码认证，仅用于测试
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // 仅用于测试
			Timeout:         10 * time.Second,
		}
		err = c.session.Start(c.addr, rtr.TYPE_SSH, nil, sshConfig)

	default:
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}

	return err
}

// SimpleLogger 简单日志实现
type SimpleLogger struct{}

func (l *SimpleLogger) Debugf(format string, args ...interface{}) {
	log.Printf("[DEBUG] "+format, args...)
}

func (l *SimpleLogger) Printf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func (l *SimpleLogger) Warnf(format string, args ...interface{}) {
	log.Printf("[WARN] "+format, args...)
}

func (l *SimpleLogger) Errorf(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

func (l *SimpleLogger) Infof(format string, args ...interface{}) {
	log.Printf("[INFO] "+format, args...)
}

func main() {
	host := flag.String("host", "127.0.0.1", "RTR 服务器主机名")
	port := flag.String("port", "8282", "RTR 服务器端口")
	protocol := flag.String("protocol", "plain", "连接协议 (plain/tls/ssh)")
	statsInterval := flag.Duration("stats", 30*time.Second, "统计信息输出间隔")
	flag.Parse()

	addr := fmt.Sprintf("%s:%s", *host, *port)

	client := &RTRClient{
		addr: addr,
		vrps: make(map[string]*rtr.VRP),
		brks: make(map[string]*rtr.BgpsecKey),
	}

	log.Printf("连接到 RTR 服务器: %s (协议: %s)\n", addr, *protocol)
	err := client.Connect(*protocol)
	if err != nil {
		log.Fatalf("连接失败: %v", err)
	}

	// 设置信号处理
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 定期打印统计信息
	ticker := time.NewTicker(*statsInterval)
	defer ticker.Stop()

	log.Println("RTR 客户端已启动，按 Ctrl+C 退出")

	for {
		select {
		case <-sigChan:
			log.Println("收到退出信号，正在关闭...")
			client.session.Disconnect()
			client.PrintStats()
			os.Exit(0)

		case <-ticker.C:
			client.PrintStats()
			vrps := client.GetVRPs()
			if len(vrps) > 0 && len(vrps) <= 10 {
				log.Println("当前 VRPs:")
				for _, vrp := range vrps {
					log.Printf("  - %s (MaxLen: %d, ASN: %d)\n", vrp.Prefix, vrp.MaxLen, vrp.ASN)
				}
			}
		}
	}
}
