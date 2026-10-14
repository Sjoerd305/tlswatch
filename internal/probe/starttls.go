package probe

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// notOffered means the server answered but does not offer TLS upgrade.
type notOffered struct{ msg string }

func (e *notOffered) Error() string { return e.msg }

func startTLS(conn net.Conn, p Protocol) error {
	switch p {
	case TLS, "":
		return nil
	case SMTP:
		return smtpStartTLS(conn)
	case IMAP:
		return imapStartTLS(conn)
	case POP3:
		return pop3StartTLS(conn)
	case FTP:
		return ftpStartTLS(conn)
	case Postgres:
		return postgresStartTLS(conn)
	}
	return fmt.Errorf("unknown protocol %q", p)
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && line == "" {
			return "", errors.New("connection closed by server")
		}
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readReply reads an SMTP/FTP style reply: "123-..." continuation lines up to
// a final "123 ..." line. It returns the code and the text of every line.
func readReply(r *bufio.Reader) (int, []string, error) {
	var lines []string
	first := ""
	for {
		line, err := readLine(r)
		if err != nil {
			return 0, lines, err
		}
		if len(line) >= 3 && first == "" {
			first = line[:3]
		}
		if len(line) >= 3 && line[:3] == first && (len(line) == 3 || line[3] == ' ') {
			code, err := strconv.Atoi(first)
			if err != nil {
				return 0, lines, fmt.Errorf("unexpected reply %q", line)
			}
			lines = append(lines, strings.TrimSpace(line[3:]))
			return code, lines, nil
		}
		if len(line) > 4 && line[:3] == first {
			line = line[4:]
		}
		lines = append(lines, line)
	}
}

func send(conn net.Conn, cmd string) error {
	_, err := io.WriteString(conn, cmd+"\r\n")
	return err
}

func smtpStartTLS(conn net.Conn) error {
	r := bufio.NewReader(conn)
	code, lines, err := readReply(r)
	if err != nil {
		return err
	}
	if code != 220 {
		return fmt.Errorf("SMTP greeting %d %s", code, strings.Join(lines, " "))
	}
	if err := send(conn, "EHLO tlswatch"); err != nil {
		return err
	}
	code, lines, err = readReply(r)
	if err != nil {
		return err
	}
	if code != 250 {
		return &notOffered{fmt.Sprintf("EHLO refused: %d, STARTTLS not available", code)}
	}
	offered := false
	for _, l := range lines {
		if f := strings.Fields(l); len(f) > 0 && strings.EqualFold(f[0], "STARTTLS") {
			offered = true
		}
	}
	if !offered {
		return &notOffered{"server does not offer STARTTLS"}
	}
	if err := send(conn, "STARTTLS"); err != nil {
		return err
	}
	code, lines, err = readReply(r)
	if err != nil {
		return err
	}
	if code != 220 {
		return &notOffered{fmt.Sprintf("STARTTLS refused: %d %s", code, strings.Join(lines, " "))}
	}
	return nil
}

func ftpStartTLS(conn net.Conn) error {
	r := bufio.NewReader(conn)
	code, lines, err := readReply(r)
	if err != nil {
		return err
	}
	if code != 220 {
		return fmt.Errorf("FTP greeting %d %s", code, strings.Join(lines, " "))
	}
	if err := send(conn, "AUTH TLS"); err != nil {
		return err
	}
	code, lines, err = readReply(r)
	if err != nil {
		return err
	}
	if code != 234 {
		return &notOffered{fmt.Sprintf("AUTH TLS refused: %d %s", code, strings.Join(lines, " "))}
	}
	return nil
}

func imapStartTLS(conn net.Conn) error {
	r := bufio.NewReader(conn)
	greet, err := readLine(r)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(greet, "* OK") && !strings.HasPrefix(greet, "* PREAUTH") {
		return fmt.Errorf("IMAP greeting %q", greet)
	}
	// readTagged returns the untagged lines and the tagged completion line.
	readTagged := func(tag string) ([]string, string, error) {
		var untagged []string
		for {
			line, err := readLine(r)
			if err != nil {
				return untagged, "", err
			}
			if strings.HasPrefix(line, tag+" ") {
				return untagged, line, nil
			}
			untagged = append(untagged, line)
		}
	}
	if err := send(conn, "a1 CAPABILITY"); err != nil {
		return err
	}
	untagged, _, err := readTagged("a1")
	if err != nil {
		return err
	}
	offered := false
	for _, l := range untagged {
		if strings.HasPrefix(strings.ToUpper(l), "* CAPABILITY") {
			for _, f := range strings.Fields(l) {
				if strings.EqualFold(f, "STARTTLS") {
					offered = true
				}
			}
		}
	}
	if !offered {
		return &notOffered{"server does not offer STARTTLS"}
	}
	if err := send(conn, "a2 STARTTLS"); err != nil {
		return err
	}
	_, done, err := readTagged("a2")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(strings.ToUpper(done), "A2 OK") {
		return &notOffered{fmt.Sprintf("STARTTLS refused: %s", done)}
	}
	return nil
}

func pop3StartTLS(conn net.Conn) error {
	r := bufio.NewReader(conn)
	greet, err := readLine(r)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(greet, "+OK") {
		return fmt.Errorf("POP3 greeting %q", greet)
	}
	if err := send(conn, "CAPA"); err != nil {
		return err
	}
	line, err := readLine(r)
	if err != nil {
		return err
	}
	if strings.HasPrefix(line, "+OK") {
		offered := false
		for {
			l, err := readLine(r)
			if err != nil {
				return err
			}
			if l == "." {
				break
			}
			if f := strings.Fields(l); len(f) > 0 && strings.EqualFold(f[0], "STLS") {
				offered = true
			}
		}
		if !offered {
			return &notOffered{"server does not offer STLS"}
		}
	}
	if err := send(conn, "STLS"); err != nil {
		return err
	}
	line, err = readLine(r)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "+OK") {
		return &notOffered{fmt.Sprintf("STLS refused: %s", line)}
	}
	return nil
}

func postgresStartTLS(conn net.Conn) error {
	var msg [8]byte
	binary.BigEndian.PutUint32(msg[0:4], 8)
	binary.BigEndian.PutUint32(msg[4:8], 80877103)
	if _, err := conn.Write(msg[:]); err != nil {
		return err
	}
	var reply [1]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return err
	}
	switch reply[0] {
	case 'S':
		return nil
	case 'N':
		return &notOffered{"server does not accept SSL connections"}
	}
	return fmt.Errorf("unexpected reply %q to SSLRequest", reply[0])
}
