// Package chain maintains the running hash chain over assertion IDs.
//
// The chain serves two purposes:
//   - tamper-evident sequencing of the assertion log (any deletion or
//     reordering of assertions breaks subsequent chain hashes)
//   - cheap "head" tracking: the latest chain_hash summarises the entire log
//
// The chain file is plain text: one line per assertion, tab-separated:
//
//	seq\tprev_chain_hash\tassertion_id\tchain_hash\n
//
// The chain hash is sha256(prev_chain_hash_bytes || assertion_id_bytes)
// where both inputs are the 32 raw bytes of those hashes (NOT their hex
// strings — the hex form is for display only).
//
// The genesis prev_chain_hash is 32 zero bytes (hex: 64 zeros).
package chain

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Genesis is the all-zero prev hash used before the first assertion.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Entry is one row of the chain file.
type Entry struct {
	Seq           uint64
	PrevChainHash string // hex
	AssertionID   string // hex
	ChainHash     string // hex
}

// Append computes the chain hash for assertionID given the prev chain hash
// and returns the resulting hex string.
func Append(prevChainHashHex, assertionIDHex string) (string, error) {
	prev, err := hex.DecodeString(prevChainHashHex)
	if err != nil || len(prev) != 32 {
		return "", fmt.Errorf("invalid prev_chain_hash %q", prevChainHashHex)
	}
	aid, err := hex.DecodeString(assertionIDHex)
	if err != nil || len(aid) != 32 {
		return "", fmt.Errorf("invalid assertion id %q", assertionIDHex)
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(aid)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Head reads the last line of the chain file and returns its chain hash, or
// Genesis if the file does not exist or is empty.
func Head(path string) (prevHash string, seq uint64, err error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Genesis, 0, nil
		}
		return "", 0, err
	}
	defer f.Close()
	// Walk to last line. Chain file is tiny per assertion; for Day-1 scale we
	// scan it linearly. Avoiding seek-from-end keeps the code simple.
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	var last Entry
	for scanner.Scan() {
		e, err := parseEntry(scanner.Text())
		if err != nil {
			return "", 0, err
		}
		last = e
	}
	if err := scanner.Err(); err != nil {
		return "", 0, err
	}
	if last.Seq == 0 && last.ChainHash == "" {
		return Genesis, 0, nil
	}
	return last.ChainHash, last.Seq, nil
}

// AppendEntry writes one entry to the chain file. The caller must compute the
// chain hash beforehand via Append() and provide it.
func AppendEntry(path string, e Entry) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%d\t%s\t%s\t%s\n", e.Seq, e.PrevChainHash, e.AssertionID, e.ChainHash)
	return err
}

// Walk iterates every entry in the chain file in order and verifies that
// each chain hash is correctly derived from its predecessor. Returns the
// final head.
func Walk(path string, visit func(Entry) error) (head string, count uint64, err error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Genesis, 0, nil
		}
		return "", 0, err
	}
	defer f.Close()

	prev := Genesis
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	expectSeq := uint64(1)
	for scanner.Scan() {
		e, err := parseEntry(scanner.Text())
		if err != nil {
			return "", 0, fmt.Errorf("chain line %d: %w", expectSeq, err)
		}
		if e.Seq != expectSeq {
			return "", 0, fmt.Errorf("chain seq jump: expected %d got %d", expectSeq, e.Seq)
		}
		if e.PrevChainHash != prev {
			return "", 0, fmt.Errorf("chain seq %d: prev_chain_hash %s != recomputed %s", e.Seq, e.PrevChainHash, prev)
		}
		want, err := Append(prev, e.AssertionID)
		if err != nil {
			return "", 0, fmt.Errorf("chain seq %d: %w", e.Seq, err)
		}
		if want != e.ChainHash {
			return "", 0, fmt.Errorf("chain seq %d: chain_hash %s != recomputed %s", e.Seq, e.ChainHash, want)
		}
		if visit != nil {
			if err := visit(e); err != nil {
				return "", 0, err
			}
		}
		prev = e.ChainHash
		expectSeq++
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return "", 0, err
	}
	return prev, expectSeq - 1, nil
}

func parseEntry(line string) (Entry, error) {
	parts := strings.Split(line, "\t")
	if len(parts) != 4 {
		return Entry{}, fmt.Errorf("expected 4 tab-separated fields, got %d", len(parts))
	}
	seq, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return Entry{}, fmt.Errorf("seq: %w", err)
	}
	return Entry{
		Seq:           seq,
		PrevChainHash: parts[1],
		AssertionID:   parts[2],
		ChainHash:     parts[3],
	}, nil
}
