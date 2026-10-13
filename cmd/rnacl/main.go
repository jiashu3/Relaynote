// rnacl: read-only dump of Relaynote peers (name, enabled, allowed) and message
// counts by recipient/state. Never prints token hashes or bodies.
// usage: rnacl DB [acl|counts|allowed PEER]
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

type peer struct {
	Name    string   `json:"name"`
	Allowed []string `json:"allowed"`
	Enabled bool     `json:"enabled"`
}
type rec struct {
	Message struct {
		Recipient string   `json:"recipient"`
		Sender    string   `json:"sender"`
		State     string   `json:"state"`
		ID        string   `json:"id"`
		AckedAt   *float64 `json:"acked_at"`
		CreatedAt float64  `json:"created_at"`
	} `json:"message"`
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: rnacl DB acl|counts|allowed PEER")
		os.Exit(2)
	}
	db, err := bolt.Open(os.Args[1], 0600, &bolt.Options{ReadOnly: true, Timeout: time.Second})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer db.Close()
	err = db.View(func(tx *bolt.Tx) error {
		switch os.Args[2] {
		case "acl":
			return tx.Bucket([]byte("peers")).ForEach(func(k, v []byte) error {
				var p peer
				if err := json.Unmarshal(v, &p); err != nil {
					return err
				}
				fmt.Printf("%s|enabled=%v|%s\n", k, p.Enabled, strings.Join(p.Allowed, ","))
				return nil
			})
		case "allowed":
			v := tx.Bucket([]byte("peers")).Get([]byte(os.Args[3]))
			if v == nil {
				return fmt.Errorf("unknown peer")
			}
			var p peer
			if err := json.Unmarshal(v, &p); err != nil {
				return err
			}
			fmt.Println(strings.Join(p.Allowed, ","))
			return nil
		case "ids":
			return tx.Bucket([]byte("messages")).ForEach(func(k, v []byte) error {
				var r rec
				if json.Unmarshal(v, &r) == nil && r.Message.Sender == os.Args[3] && r.Message.Recipient == os.Args[4] {
					fmt.Printf("%.0f %s acked=%v\n", r.Message.CreatedAt, r.Message.ID, r.Message.AckedAt != nil)
				}
				return nil
			})
		case "counts":
			c := map[string]int{}
			err := tx.Bucket([]byte("messages")).ForEach(func(k, v []byte) error {
				var r rec
				if json.Unmarshal(v, &r) != nil {
					c["undecodable"]++
					return nil
				}
				st := "unacked"
				if r.Message.AckedAt != nil {
					st = "acked"
				}
				c[r.Message.Sender+"->"+r.Message.Recipient+" "+st]++
				return nil
			})
			keys := make([]string, 0, len(c))
			for k := range c {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Printf("%s %d\n", k, c[k])
			}
			return err
		}
		return fmt.Errorf("bad mode")
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
