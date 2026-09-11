// Command maxverify live-checks MAX master accounts: it sweeps a pool file for
// token liveness (op6+op19) and can optionally exercise the QR session
// derivation and 2FA-password flows against the real server. It operates only
// on the operator's own accounts and is a verification tool, not part of any
// deployed service.
//
//	maxverify -pool tokens.json                 # liveness sweep only
//	maxverify -pool tokens.json -qr             # + derive a web session from the first live master
//	maxverify -pool tokens.json -set-password   # + set a 2FA password on the first live password-less master
//	maxverify -pool tokens.json -derive-phone +7... -out B.json
//	    # derive a WEB session for ONE master (by phone) and write a maxjoin token
//	    # file {token,device_id,phone,platform:"web",uid} (mode 0600). Only that
//	    # account is touched; a rotated master token is persisted back to the pool.
//	maxverify -pool tokens.json -phone +7... -approve-qr https://max.ru/:auth/...
//	    # approve a browser's own web.max.ru login QR (op290) with that pool
//	    # account's ANDROID master; the browser mints its own session, no token
//	    # is ever injected into it. Prints "APPROVED <phone>" on success.
//
// The pool file is a JSON array of {phone, device_id, token, password?}.
// Tokens are never printed: every token that reaches a log line goes through redact.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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

// writeFileAtomic writes data to path via a same-directory temp file + rename,
// so a crash mid-write can never leave a truncated pool/token file behind.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

// savePool persists the pool array back to poolPath atomically, keeping the
// file's existing mode (0600 if it cannot be read).
func savePool(poolPath string, pool []acct) error {
	mode := os.FileMode(0o600)
	if st, err := os.Stat(poolPath); err == nil {
		mode = st.Mode().Perm()
	}
	data, err := json.MarshalIndent(pool, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(poolPath, append(data, '\n'), mode)
}

// webTokenFile is the maxjoin token-file shape for a derived WEB session.
type webTokenFile struct {
	Token    string `json:"token"`
	DeviceID string `json:"device_id"`
	Phone    string `json:"phone"`
	Platform string `json:"platform"`
	UID      int64  `json:"uid"`
}

// loginAs connects, session-inits and logs in a client; the caller closes it.
func loginAs(ctx context.Context, c *maxproto.Client) error {
	if err := c.Connect(ctx, nil); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	if _, err := c.SessionInit(ctx); err != nil {
		return fmt.Errorf("session-init: %w", err)
	}
	if _, err := c.Login(ctx); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	return nil
}

// selectLiveMaster finds phone in the pool, liveness-checks that ONE account
// (nothing else in the pool is touched) and persists a rotated master token
// back to the pool file atomically. Returns the account and a non-zero exit
// code (with the reason already printed) when it cannot be used: 2 = not in
// pool, 3 = token dead, 1 = indeterminate/transport error.
func selectLiveMaster(ctx context.Context, pool []acct, poolPath, phone, tag string) (*acct, int) {
	var target *acct
	for i := range pool {
		if pool[i].Phone == phone {
			target = &pool[i]
			break
		}
	}
	if target == nil {
		fmt.Fprintf(os.Stderr, "%s: %s is not in %s\n", tag, phone, poolPath)
		return nil, 2
	}

	fmt.Printf("[%s] %s: checking master liveness ...\n", tag, phone)
	cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	alive, rotated, err := maxproto.CheckAlive(cctx, target.Token, target.DeviceID, nil)
	cancel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s liveness check failed (indeterminate, not marking dead): %v\n", tag, phone, err)
		return nil, 1
	}
	if !alive {
		fmt.Fprintf(os.Stderr, "%s: %s master token is DEAD (server rejected the login); refresh the token first\n", tag, phone)
		return nil, 3
	}
	if rotated != "" {
		target.Token = rotated
		if err := savePool(poolPath, pool); err != nil {
			fmt.Fprintf(os.Stderr, "%s: master token rotated (%s) but persisting the pool failed: %v\n", tag, redact(rotated), err)
			return nil, 1
		}
		fmt.Printf("[%s] %s: master token rotated -> %s, pool updated\n", tag, phone, redact(rotated))
	}
	fmt.Printf("[%s] %s: master ALIVE\n", tag, phone)
	return target, 0
}

// approveQR implements -phone/-approve-qr: log in the pool account's ANDROID
// master and approve a browser's web.max.ru login QR link (op290). The browser
// then completes its own login and mints its own session — no token is ever
// injected into it. Returns the process exit code.
func approveQR(ctx context.Context, pool []acct, poolPath, phone, qrLink string) int {
	target, code := selectLiveMaster(ctx, pool, poolPath, phone, "approve-qr")
	if code != 0 {
		return code
	}
	actx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	mc := maxproto.New(target.Token, target.DeviceID)
	defer mc.Close()
	if err := loginAs(actx, mc); err != nil {
		fmt.Fprintf(os.Stderr, "approve-qr: master %v\n", err)
		return 1
	}
	if err := mc.QRApprove(actx, qrLink); err != nil {
		fmt.Fprintf(os.Stderr, "approve-qr: op290 rejected: %v\n", err)
		return 1
	}
	fmt.Printf("APPROVED %s\n", phone)
	return 0
}

// derivePhone implements -derive-phone/-out: liveness-check ONE master (by
// phone), persist a rotated token, derive a WEB session from it, prove the
// derived session logs in WEB-style, and write the maxjoin token file. Returns
// the process exit code. Nothing it prints contains a token.
func derivePhone(ctx context.Context, pool []acct, poolPath, phone, outPath string) int {
	target, code := selectLiveMaster(ctx, pool, poolPath, phone, "derive")
	if code != 0 {
		return code
	}

	// Log in the ANDROID master and derive the web session.
	dctx, dcancel := context.WithTimeout(ctx, 45*time.Second)
	defer dcancel()
	mc := maxproto.New(target.Token, target.DeviceID)
	if err := loginAs(dctx, mc); err != nil {
		mc.Close()
		fmt.Fprintf(os.Stderr, "derive-phone: master %v\n", err)
		return 1
	}
	session, webDev, uid, err := maxproto.DeriveWebSession(dctx, mc, nil)
	mc.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "derive-phone: DeriveWebSession: %v\n", err)
		return 1
	}
	fmt.Printf("[derive] %s: derived web session=%s webDeviceID=%s uid=%d\n", phone, redact(session), webDev, uid)

	// Prove the derived session is usable WEB-style before handing it out.
	vctx, vcancel := context.WithTimeout(ctx, 25*time.Second)
	defer vcancel()
	wc := maxproto.NewWeb(session, webDev)
	werr := loginAs(vctx, wc)
	wc.Close()
	if werr != nil {
		fmt.Fprintf(os.Stderr, "derive-phone: derived session failed WEB-style login: %v\n", werr)
		return 1
	}
	fmt.Printf("[derive] %s: derived session logs in WEB-style: ok\n", phone)

	out := webTokenFile{Token: session, DeviceID: webDev, Phone: phone, Platform: "web", UID: uid}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "derive-phone: marshal: %v\n", err)
		return 1
	}
	if err := writeFileAtomic(outPath, append(data, '\n'), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "derive-phone: write %s: %v\n", outPath, err)
		return 1
	}
	fmt.Printf("[derive] wrote %s (mode 0600, platform=web, token=%s)\n", outPath, redact(session))
	return 0
}

func main() {
	poolPath := flag.String("pool", "", "path to a JSON array of {phone,device_id,token,password?}")
	derivePhoneFlag := flag.String("derive-phone", "", "derive a WEB session for this pool phone and write a maxjoin token file to -out (touches only that account)")
	outPath := flag.String("out", "", "with -derive-phone: output token file path (written 0600)")
	phoneFlag := flag.String("phone", "", "pool account selector for -approve-qr")
	approveQRFlag := flag.String("approve-qr", "", "approve this web.max.ru login QR link (https://max.ru/:auth/...) with the -phone account's ANDROID master (op290)")
	doQR := flag.Bool("qr", false, "derive a web session from the first live master")
	doSetPw := flag.Bool("set-password", false, "set a 2FA password on the first live password-less master")
	addPhone := flag.String("add-phone", "", "op41: resolve+add this phone as a contact of the first live master")
	addUID := flag.Int64("add-uid", 0, "op34: add this uid as a contact of the first live master (by uid, no phone directory)")
	injectJSON := flag.Bool("inject-json", false, "derive a web session from the first live master and print localStorage inject JSON (UNREDACTED)")
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

	if *approveQRFlag != "" || *phoneFlag != "" {
		if *approveQRFlag == "" || *phoneFlag == "" {
			fmt.Fprintln(os.Stderr, "usage: maxverify -pool tokens.json -phone <phone> -approve-qr <https://max.ru/:auth/...> (both flags required)")
			os.Exit(2)
		}
		os.Exit(approveQR(ctx, pool, *poolPath, *phoneFlag, *approveQRFlag))
	}

	if *derivePhoneFlag != "" || *outPath != "" {
		if *derivePhoneFlag == "" || *outPath == "" {
			fmt.Fprintln(os.Stderr, "usage: maxverify -pool tokens.json -derive-phone <phone> -out <path> (both flags required)")
			os.Exit(2)
		}
		os.Exit(derivePhone(ctx, pool, *poolPath, *derivePhoneFlag, *outPath))
	}
	var firstLive *acct
	live := 0
	anyRotated := false
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
				anyRotated = true
			}
		}
		fmt.Printf("  %-16s pw=%-3v %-5s %s\n", a.Phone, a.Password != "", status, note)
	}
	fmt.Printf("liveness: %d/%d alive\n", live, len(pool))
	// A successful op19 may rotate a master token; the server keeps accepting
	// the previous one for a while but not forever, so persist every rotation
	// the sweep observed (the per-phone paths already do this).
	if anyRotated {
		if err := savePool(*poolPath, pool); err != nil {
			fmt.Fprintf(os.Stderr, "persisting rotated tokens to %s failed: %v\n", *poolPath, err)
			os.Exit(1)
		}
		fmt.Printf("pool updated with rotated tokens\n")
	}

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

	if *injectJSON {
		mc := maxproto.New(firstLive.Token, firstLive.DeviceID)
		dctx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		if err := mc.Connect(dctx, nil); err != nil {
			fmt.Fprintf(os.Stderr, "connect: %v\n", err)
			os.Exit(1)
		}
		if _, err := mc.SessionInit(dctx); err != nil {
			fmt.Fprintf(os.Stderr, "session-init: %v\n", err)
			os.Exit(1)
		}
		if _, err := mc.Login(dctx); err != nil {
			fmt.Fprintf(os.Stderr, "login: %v\n", err)
			os.Exit(1)
		}
		session, webDev, uid, err := maxproto.DeriveWebSession(dctx, mc, nil)
		mc.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "DeriveWebSession: %v\n", err)
			os.Exit(1)
		}
		inj := map[string]any{
			"phone":             firstLive.Phone,
			"__oneme_auth":      map[string]any{"viewerId": uid, "token": session},
			"__oneme_device_id": webDev,
		}
		b, _ := json.MarshalIndent(inj, "", "  ")
		fmt.Println(string(b))
		return
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

	if *addUID != 0 {
		fmt.Printf("\n[add-uid] %s adds contact uid=%d (op34 CONTACT_ACTION ADD, by uid) ...\n", firstLive.Phone, *addUID)
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
		err := mc.ContactAction(actx, *addUID, "ADD", "PeerByUID", "")
		mc.Close()
		if err != nil {
			fmt.Printf("  op34 err: %v\n", err)
			return
		}
		fmt.Printf("  op34 OK: added uid=%d as a contact (bypassed the phone directory)\n", *addUID)
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
