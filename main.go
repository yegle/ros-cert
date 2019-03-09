package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-routeros/routeros"
	"golang.org/x/crypto/acme"
)

var (
	address        = flag.String("address", "router:8728", "RouterOS address and API port")
	username       = flag.String("username", "admin", "Username")
	password       = flag.String("password", "admin", "Password")
	hostname       = flag.String("hostname", "", "Hostname for which you want to ask for certificate")
	accountKeyFile = flag.String("account_key_file", "account.key", "Account key file, which can be reused later to revoke certificate.")
	accountURLFile = flag.String("account_url_file", "account.txt", "Account URL file, which can be reused later to revoke certificcate.")
	localIP        = flag.String("local_ip", "", "Local IP address, of which this tool will modify the router's firewall rule to redirect external traffic to this IP address. Linux users can leave this empty. IPv4 only for now.")
	rosKeyFile     = flag.String("ros_key_file", "ros.key", "The key file for ROS")
	rosCertFile    = flag.String("ros_cert_file", "ros.cert", "The cert file for ROS")
	staging        = flag.Bool("staging", true, "Whether to use the staging environment of Lets Encrypt")
)

const (
	keyType  = "RSA PRIVATE KEY"
	certType = "CERTIFICATE"
)

type client struct {
	*routeros.Client
}

func (c *client) Run(sentence ...string) (*routeros.Reply, error) {
	log.Printf("ROS> %s", strings.Join(sentence, " "))
	r, err := c.Client.Run(sentence...)
	return r, err
}

func (c *client) CertValidUntil(hostname string) (time.Time, error) {
	r, err := c.Run("/certificate/print", "?common-name="+hostname)
	if err != nil {
		return time.Now(), err
	}
	if len(r.Re) == 0 {
		return time.Now(), fmt.Errorf("no certificate for %s", hostname)
	} else if len(r.Re) > 1 {
		return time.Now(), fmt.Errorf("found multiple certificates for %s, please consider remove one of them before continuing", hostname)
	}
	ia := r.Re[0].Map["invalid-after"]
	t, err := time.Parse(ia, "jan/02/2006 15:04:05")
	if err != nil {
		return t, fmt.Errorf("parse string to time failed: %v", err)
	}
	return t, nil
}

func (c *client) HTTPPort() (int, error) {
	r, err := c.Run("/ip/service/print", "?name=www")
	if err != nil {
		return 0, fmt.Errorf("failed to determine www service's current port: %v", err)
	} else if r.Re[0].Map["invalid"] == "true" {
		return 0, fmt.Errorf("current HTTP port is invalid: %v", r.Re[0].Map)
	}
	ps := r.Re[0].Map["port"]
	port, err := strconv.Atoi(ps)
	if err != nil {
		return 0, fmt.Errorf("failed to convert %q to a port number: %v", ps, err)
	}
	return port, nil
}

func (c *client) ModifyHTTPPort() (int, error) {
	log.Printf("modify HTTP service port...")

	for i := 81; i < 100; i++ {
		log.Printf("attempt to modify HTTP service port to %d", i)
		if err := c.SetHTTPPort(i); err != nil {
			log.Printf("error: %v", err)
			continue
		}
		return i, nil
	}
	return 0, errors.New("failed to set www port to any valid port between 81 and 99")
}

func (c *client) SetHTTPPort(port int) error {
	_, err := c.Run("/ip/service/set", "=.id=www", "=port="+strconv.Itoa(port))
	if err != nil {
		return fmt.Errorf("failed to set www port to %d: %v", port, err)
	}
	log.Printf("check if HTTP service port is valid")
	if np, err := c.HTTPPort(); err != nil || np != port {
		return fmt.Errorf("port setting failed: %v", err)
	}
	return nil
}

// newClient creates a client to RouterOS
func newClient(address, username, password string) (*client, error) {
	c, err := routeros.Dial(address, username, password)
	if err != nil {
		return nil, err
	}

	_, err = c.Run("/system/routerboard/print")
	if err != nil {
		return nil, err
	}

	return &client{c}, nil
}

func getOrCreateAccountKey(keyfile string) (crypto.Signer, error) {
	if content, err := ioutil.ReadFile(keyfile); err == nil {
		b, _ := pem.Decode(content)
		if b == nil {
			return nil, fmt.Errorf("%q exist but is not in PEM format", keyfile)
		} else if b.Type != keyType {
			return nil, fmt.Errorf("expect %q contains PEM type %q, got %q", keyfile, keyType, b.Type)
		}
		return x509.ParseECPrivateKey(b.Bytes)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	if err := writeKey(key, keyfile); err != nil {
		return nil, err
	}
	return key, nil
}

func writeKey(key *rsa.PrivateKey, filename string) error {
	out, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	b := &pem.Block{
		Type:  keyType,
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	if err := pem.Encode(out, b); err != nil {
		return err
	}
	return nil
}

func getOrCreateAccount(ctx context.Context, client *acme.Client, url string) (*acme.Account, error) {
	if url != "" {
		return client.GetReg(ctx, url)
	}
	return client.Register(ctx, nil, acme.AcceptTOS)
}

func getAccountURL(urlfile string) string {
	bs, err := ioutil.ReadFile(urlfile)
	if err != nil {
		return ""
	}
	return string(bytes.TrimRight(bs, "\n"))
}

func writeAccountURL(urlfile, url string) error {
	out, err := os.OpenFile(urlfile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = out.WriteString(url)
	return err
}

func ip() (string, error) {
	// Note: it's simply too much work to actually figure it out correctly.
	// This is best effort and you should consider overriding the value using
	// --local_ip flag.
	if *localIP != "" {
		return *localIP, nil
	}
	conn, err := net.Dial("tcp", *address)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	local := conn.LocalAddr().(*net.TCPAddr)
	return local.IP.String(), nil
}

func (c *client) redirectHTTPTraffic(ip, port string) error {
	args := []string{
		"/ip/firewall/nat/add",
		"=chain=dstnat",
		"=dst-port=80",
		"=action=dst-nat",
		"=to-addresses=" + ip,
		"=to-ports=" + port,
		"=protocol=tcp",
		"=comment=ADDED_BY_ROS_CERTBOT",
	}
	if _, err := c.Run(args...); err != nil {
		return err
	}
	return nil
}
func (c *client) revertTrafficRedirection() {
	r, err := c.Run("/ip/firewall/nat/print", "?comment=ADDED_BY_ROS_CERTBOT")
	if err != nil {
		log.Printf("error querying firewall rules: %v", err)
	}

	remove := "/ip/firewall/nat/remove"
	for _, re := range r.Re {
		log.Printf("Deleting firewall rule: %s", re.Map)
		if _, err := c.Run([]string{remove, "=.id=" + re.Map[".id"]}...); err != nil {
			log.Printf("error removing firewall rules: %v", err)
		}
	}
}

func run() error {
	c, err := newClient(*address, *username, *password)
	if err != nil {
		return err
	}
	defer c.Close()
	c.revertTrafficRedirection()

	op, err := c.HTTPPort()
	log.Printf("www original port: %d", op)
	if op == 80 {
		log.Print("attempt to modify the HTTP port to a different number")
		np, err := c.ModifyHTTPPort()
		if err != nil {
			return fmt.Errorf("failed to modify HTTP port, you may need change it back to %d: %v", op, err)
		}
		log.Printf("successfully set HTTP port to %d", np)
		defer c.SetHTTPPort(80)
	}

	key, err := getOrCreateAccountKey(*accountKeyFile)
	if err != nil {
		return fmt.Errorf("failed to get or generate account key: %v", err)
	}
	ctx := context.Background()
	client := &acme.Client{Key: key}
	if *staging {
		client.DirectoryURL = "https://acme-staging.api.letsencrypt.org/directory"
	}
	url := getAccountURL(*accountURLFile)
	account, err := getOrCreateAccount(ctx, client, url)
	if err != nil {
		return err
	}
	if url == "" {
		if err := writeAccountURL(*accountURLFile, account.URI); err != nil {
			return err
		}
	}
	auth, err := client.Authorize(ctx, *hostname)
	if err != nil {
		return err
	}
	if auth.Status != acme.StatusValid {
		var chal *acme.Challenge
		for _, c := range auth.Challenges {
			if c.Type == "http-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return errors.New("acme server does not support http-01")
		}
		resp, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return err
		}
		path := client.HTTP01ChallengePath(chal.Token)
		bs := []byte(resp)
		mux := http.NewServeMux()
		mux.HandleFunc(
			path,
			func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Length", strconv.Itoa(len(bs)))
				w.Write(bs)
			})
		// Use a random port
		l, err := net.Listen("tcp", "")
		defer l.Close()
		go http.Serve(l, mux)
		port := l.Addr().(*net.TCPAddr).Port
		ip, err := ip()
		if err != nil {
			return err
		}
		log.Printf("Start serving challenge at http://%s:%d%s", ip, port, path)

		if err := c.redirectHTTPTraffic(ip, strconv.Itoa(port)); err != nil {
			return err
		}
		defer c.revertTrafficRedirection()
		if _, err = client.Accept(ctx, chal); err != nil {
			return err
		}
		if _, err = client.WaitAuthorization(ctx, chal.URI); err != nil {
			return err
		}

		certKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		writeKey(certKey, *rosKeyFile)

		csr := &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: *hostname},
		}

		csrbs, err := x509.CreateCertificateRequest(rand.Reader, csr, certKey)
		if err != nil {
			return err
		}

		ders, url, err := client.CreateCert(ctx, csrbs, 90*24*time.Hour, true)
		if err != nil {
			return err
		}
		log.Printf("Got certificate with URL: %s", url)
		out, err := os.OpenFile(*rosCertFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer out.Close()
		for _, bs := range ders {
			b := &pem.Block{
				Type:  certType,
				Bytes: bs,
			}
			if err := pem.Encode(out, b); err != nil {
				return err
			}
		}
	}
	return nil
}

func main() {
	flag.Parse()
	if err := run(); err != nil {
		log.Fatal(err)
	}

}
