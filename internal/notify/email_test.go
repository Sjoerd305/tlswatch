package notify

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"testing"
	"time"
)

func sampleAlert() AlertData {
	six := 6
	return AlertData{Event: EventOpen, Severity: "critical", Kind: "expiring", KindLabel: "Expiring", TargetName: "Portal",
		HostPort: "portal.example.nl:443", Details: "6 days left", DaysLeft: &six, NotAfter: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC),
		SubjectCN: "portal.example.nl", IssuerCN: "Sectigo", Fingerprint: "7f3b92a10c4e5d6f7f3b92a10c4e5d6f", Link: "https://tlswatch.example.nl/targets/3"}
}

func TestRenderHTML(t *testing.T) {
	a := sampleAlert()
	a.Details = `<script>alert("x")</script>`
	m := Render(a)
	for _, want := range []string{"portal.example.nl:443 expires in 6 days", ">crit<", ">6<", "days left", "https://tlswatch.example.nl/targets/3", "&lt;script&gt;"} {
		if !strings.Contains(m.HTML, want) {
			t.Errorf("alert HTML lacks %q", want)
		}
	}
	if strings.Contains(m.HTML, "<script>") {
		t.Fatal("details not escaped")
	}

	r := sampleAlert()
	r.Event = EventRecover
	batch := Combine([]Message{Render(r), Render(sampleAlert())}, "https://tlswatch.example.nl/findings")
	if !strings.Contains(batch.HTML, "2 alerts from tlswatch") || strings.Index(batch.HTML, ">crit<") > strings.Index(batch.HTML, ">resolved<") {
		t.Fatal("batch HTML: missing title or not worst first")
	}

	calm := RenderDigest(DigestData{Date: "Monday 19 October 2026"}, "info")
	if !strings.Contains(calm.HTML, "Nothing needs attention") || !strings.HasPrefix(calm.Subject, "[info] ") {
		t.Fatalf("calm digest: %s", calm.Subject)
	}
	busy := RenderDigest(DigestData{Date: "Monday 19 October 2026", Expiring: []DigestExpiry{{Date: "2026-10-20", Days: 6, Tag: "critical", Name: "Portal", HostPort: "portal.example.nl:443"}}}, "info")
	if !strings.Contains(busy.HTML, "6 d") || !strings.Contains(busy.Body, "2026-10-20     6 d  Portal") {
		t.Fatalf("digest:\n%s", busy.Body)
	}
	if TestMessage("Ops", "").HTML == "" {
		t.Fatal("test message has no HTML")
	}
}

// Mail with an HTML part goes out as multipart/alternative: the plain text
// first, the HTML last.
func TestSMTPMultipart(t *testing.T) {
	cert, pool := testCert(t)
	port, got := fakeSMTP(t, "starttls", "PLAIN", cert)
	snd := &SMTPSender{S: settings(port, "starttls"), RootCAs: pool, Timeout: 5 * time.Second}
	m := Render(sampleAlert())
	if err := snd.Send(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	c := <-got
	msg, err := mail.ReadMessage(strings.NewReader(c.data))
	if err != nil {
		t.Fatal(err)
	}
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		t.Fatalf("content type %q: %v", mt, err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	var types, bodies, raws []string
	for {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(p)
		b, _ := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(raw)))
		raws = append(raws, string(raw))
		types = append(types, p.Header.Get("Content-Type"))
		bodies = append(bodies, strings.ReplaceAll(string(b), "\r\n", "\n"))
	}
	if len(types) != 2 || !strings.HasPrefix(types[0], "text/plain") || !strings.HasPrefix(types[1], "multipart/related") {
		t.Fatalf("parts %q", types)
	}
	if bodies[0] != m.Body {
		t.Fatal("text part differs from the message")
	}
	// The HTML part and the mark it shows inline.
	_, params, _ = mime.ParseMediaType(types[1])
	rel := multipart.NewReader(strings.NewReader(raws[1]), params["boundary"])
	html, err := rel.NextRawPart()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(quotedprintable.NewReader(html))
	if strings.ReplaceAll(string(b), "\r\n", "\n") != m.HTML || !strings.Contains(m.HTML, `src="cid:`+markCID+`"`) {
		t.Fatal("HTML part differs from the message or lacks the mark")
	}
	img, err := rel.NextRawPart()
	if err != nil {
		t.Fatal(err)
	}
	if img.Header.Get("Content-ID") != "<"+markCID+">" || img.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("image part headers %v", img.Header)
	}
	if data, _ := io.ReadAll(base64.NewDecoder(base64.StdEncoding, img)); !bytes.Equal(data, markPNG) {
		t.Fatal("image part is not the mark")
	}
}
