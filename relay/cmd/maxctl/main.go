package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/alex-pirozhenko/whitelist-bypass/relay/maxproto"
	"github.com/google/uuid"
)

type TokenFile struct {
	Token    string `json:"token"`
	DeviceID string `json:"device_id"`
	Phone    string `json:"phone"`
}

func main() {
	tokenFilePath := flag.String("token-file", "", "Path to the T.json file")
	peerPhone := flag.String("peer-phone", "", "Phone number of the peer to call")
	flag.Parse()

	if *tokenFilePath == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -token-file T.json [-peer-phone +NNN]\n", os.Args[0])
		os.Exit(1)
	}

	// Read token file
	tokenData, err := os.ReadFile(*tokenFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading token file: %v\n", err)
		os.Exit(1)
	}

	var tf TokenFile
	if err := json.Unmarshal(tokenData, &tf); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing token file: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client := maxproto.New(tf.Token, tf.DeviceID)

	fmt.Println("Connecting to api2.oneme.ru:443...")
	if err := client.Connect(ctx, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Connect failed: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	fmt.Println("Initializing session...")
	if _, err := client.SessionInit(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "SessionInit failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Logging in...")
	if _, err := client.Login(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Login failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Resolving self UID for phone: %s...\n", tf.Phone)
	selfUID, err := client.ResolveUID(ctx, tf.Phone)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Resolve self UID failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Self UID resolved: %d\n", selfUID)

	calleeUID := selfUID
	if *peerPhone != "" {
		fmt.Printf("Resolving peer UID for phone: %s...\n", *peerPhone)
		resolvedPeer, err := client.ResolveUID(ctx, *peerPhone)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Resolve peer UID failed: %v\n", err)
			os.Exit(1)
		}
		calleeUID = resolvedPeer
		fmt.Printf("Peer UID resolved: %d\n", calleeUID)
	}

	convID := uuid.NewString()
	fmt.Printf("Starting video chat with UID: %d (conversationId: %s)...\n", calleeUID, convID)
	startResp, err := client.VideoChatStart(ctx, []int64{calleeUID}, convID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "VideoChatStart failed: %v\n", err)
		os.Exit(1)
	}

	joinLinkVal, ok := startResp["joinLink"]
	if !ok {
		fmt.Fprintf(os.Stderr, "VideoChatStart response missing joinLink: %v\n", startResp)
		os.Exit(1)
	}
	joinLink, ok := joinLinkVal.(string)
	if !ok {
		fmt.Fprintf(os.Stderr, "VideoChatStart joinLink is not a string: %T\n", joinLinkVal)
		os.Exit(1)
	}
	fmt.Printf("joinLink: %s\n", joinLink)

	fmt.Println("Joining video chat to retrieve CallInfo...")
	internalParams := maxproto.BuildInternalParams(client.DeviceID())
	joinResp, err := client.VideoChatJoin(ctx, joinLink, internalParams, convID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "VideoChatJoin failed: %v\n", err)
		os.Exit(1)
	}

	ci, err := maxproto.ParseCallInfo(joinResp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ParseCallInfo failed: %v\n", err)
		os.Exit(1)
	}

	ciJSON, err := json.MarshalIndent(ci, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to format CallInfo JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("CallInfo:")
	fmt.Println(string(ciJSON))
}
