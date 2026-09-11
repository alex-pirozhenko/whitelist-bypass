// Command maxverify live-checks MAX master accounts: it sweeps a pool file for
// token liveness (op6+op19) and can optionally exercise the QR session
// derivation and 2FA-password flows against the real server. It operates only
// on the operator's own accounts and is a verification tool, not part of any
// deployed service.
//
//	maxverify -pool tokens.json                 # liveness sweep only
//	maxverify -pool tokens.json -qr             # + derive a web session from the first live master
//	maxverify -pool tokens.json -set-password   # + set a 2FA password on the first live password-less master
//
// The pool file is a JSON array of {phone, device_id, token, password?}.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/alex-pirozhenko/whitelist-bypass/relay/maxproto"
)

type acct struct {
	Phone    string `json:"phone"`
	DeviceID string `json:"device_id"`
	Token    string `json:"token"`
	Password string `json:"password,omitempty"`
}

func redact(s string) string {
	if len(s) <= 10 {
		return "****"
	}
	return s[:6] + "…" + s[len(s)-4:]
}

func main() {
	poolPath := flag.String("pool", "", "path to a JSON array of {phone,device_id,token,password?}")
	doQR := flag.Bool("qr", false, "derive a web session from the first live master")
	doSetPw := flag.Bool("set-password", false, "set a 2FA password on the first live password-less master")
	addPhone := flag.String("add-phone", "", "op41: resolve+add this phone as a contact of the first live master")
	flag.Parse()
	if *poolPath == "" {
		fmt.Fprintln(os.Stderr, "usage: maxverify -pool tokens.json [-qr] [-set-password]")
		os.Exit(2)
	}

	data, err := os.ReadFile(*poolPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read pool: %v\n", err)
		os.Exit(1)
	}
	var pool []acct
	if err := json.Unmarshal(data, &pool); err != nil {
		fmt.Fprintf(os.Stderr, "parse pool: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("pool: %d accounts from %s\n", len(pool), *poolPath)

	ctx := context.Background()
	var firstLive *acct
	live := 0
	for i := range pool {
		a := &pool[i]
		cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		alive, rotated, err := maxproto.CheckAlive(cctx, a.Token, a.DeviceID, nil)
		cancel()
		status := "DEAD"
		note := ""
		switch {
		case err != nil:
			status = "ERR"
			note = err.Error()
		case alive:
			status = "ALIVE"
			live++
			if firstLive == nil {
				firstLive = a
			}
			if rotated != "" {
				note = "rotated=" + redact(rotated)
				a.Token = rotated
			}
		}
		fmt.Printf("  %-16s pw=%-3v %-5s %s\n", a.Phone, a.Password != "", status, note)
	}
	fmt.Printf("liveness: %d/%d alive\n", live, len(pool))

	if firstLive == nil {
		fmt.Println("no live master — cannot run -qr/-set-password; refresh a token first")
		if *doQR || *doSetPw {
			os.Exit(3)
		}
		return
	}

	if *doQR {
		fmt.Printf("\n[qr] deriving web session from %s ...\n", firstLive.Phone)
		mc := maxproto.New(firstLive.Token, firstLive.DeviceID)
		dctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		if err := mc.Connect(dctx, nil); err != nil {
			fmt.Fprintf(os.Stderr, "  master connect: %v\n", err)
			os.Exit(1)
		}
		if _, err := mc.SessionInit(dctx); err != nil {
			fmt.Fprintf(os.Stderr, "  master session-init: %v\n", err)
			os.Exit(1)
		}
		if _, err := mc.Login(dctx); err != nil {
			fmt.Fprintf(os.Stderr, "  master login: %v\n", err)
			os.Exit(1)
		}
		session, webDev, uid, err := maxproto.DeriveWebSession(dctx, mc, nil)
		mc.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  DeriveWebSession: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("  derived session=%s webDeviceID=%s uid=%d\n", redact(session), webDev, uid)
		// Confirm the derived session is usable, probed WEB-style (a WEB session
		// must be used over a WEB-identified connection, like the web client).
		vctx, vcancel := context.WithTimeout(ctx, 25*time.Second)
		wc := maxproto.NewWeb(session, webDev)
		werr := func() error {
			if err := wc.Connect(vctx, nil); err != nil {
				return fmt.Errorf("connect: %w", err)
			}
			defer wc.Close()
			if _, err := wc.SessionInit(vctx); err != nil {
				return fmt.Errorf("session-init: %w", err)
			}
			if _, err := wc.Login(vctx); err != nil {
				return fmt.Errorf("login: %w", err)
			}
			return nil
		}()
		vcancel()
		fmt.Printf("  derived session usable WEB-style: ok=%v err=%v\n", werr == nil, werr)
	}

	if *addPhone != "" {
		fmt.Printf("\n[add-phone] %s adds contact %s (op41) ...\n", firstLive.Phone, *addPhone)
		mc := maxproto.New(firstLive.Token, firstLive.DeviceID)
		actx, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		if err := mc.Connect(actx, nil); err != nil {
			fmt.Fprintf(os.Stderr, "  connect: %v\n", err)
			os.Exit(1)
		}
		if _, err := mc.SessionInit(actx); err != nil {
			fmt.Fprintf(os.Stderr, "  session-init: %v\n", err)
			os.Exit(1)
		}
		if _, err := mc.Login(actx); err != nil {
			fmt.Fprintf(os.Stderr, "  login: %v\n", err)
			os.Exit(1)
		}
		uid, isNew, err := mc.ContactAddByPhone(actx, *addPhone, "", "")
		mc.Close()
		if err != nil {
			fmt.Printf("  op41 err: %v\n", err)
			return
		}
		fmt.Printf("  op41 OK: contact uid=%d new=%v\n", uid, isNew)
	}

	if *doSetPw {
		var target *acct
		// pick first live password-less account
		for i := range pool {
			a := &pool[i]
			if a.Password == "" {
				aliveCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
				alive, _, _ := maxproto.CheckAlive(aliveCtx, a.Token, a.DeviceID, nil)
				cancel()
				if alive {
					target = a
					break
				}
			}
		}
		if target == nil {
			fmt.Println("\n[set-password] no live password-less master; skipping")
			return
		}
		fmt.Printf("\n[set-password] setting 2FA password on %s ...\n", target.Phone)
		pw, err := maxproto.GenPassword()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  gen password: %v\n", err)
			os.Exit(1)
		}
		mc := maxproto.New(target.Token, target.DeviceID)
		sctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		if err := mc.Connect(sctx, nil); err != nil {
			fmt.Fprintf(os.Stderr, "  connect: %v\n", err)
			os.Exit(1)
		}
		if _, err := mc.SessionInit(sctx); err != nil {
			fmt.Fprintf(os.Stderr, "  session-init: %v\n", err)
			os.Exit(1)
		}
		if _, err := mc.Login(sctx); err != nil {
			fmt.Fprintf(os.Stderr, "  login: %v\n", err)
			os.Exit(1)
		}
		rotated, err := mc.SetAccountPassword(sctx, pw)
		mc.Close()
		if err != nil {
			fmt.Printf("  SetAccountPassword err: %v (ErrSet2FARestricted=%v)\n", err, err == maxproto.ErrSet2FARestricted)
			return
		}
		fmt.Printf("  password set OK (pw=%s), rotatedToken=%s\n", pw, redact(rotated))
	}
}
