package store

import (
	"testing"
	"time"
)

func (f *fixture) sendRequest(t *testing.T, key string, ttl int) Message {
	t.Helper()
	m, err := f.s.Send(f.a, SendRequest{To: "B", Body: "do thing", ClientID: key, TTL: ttl, Kind: "request", Conv: "conv-1", Hop: 2}, "")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRequestLifecycleNoRerunAfterTimeout(t *testing.T) {
	f := newFixture(t)
	f.s.Lifecycle = true
	m := f.sendRequest(t, "req", 10)
	if m.Kind != "request" || m.Conv != "conv-1" || m.Hop != 2 {
		t.Fatalf("envelope fields not persisted: %+v", m)
	}
	q, err := f.s.GetRequest(f.b, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if q.State != RequestReceived || q.Seq != 1 || q.Deadline != m.ExpiresAt {
		t.Fatalf("unexpected new request: %+v", q)
	}
	f.advance(11 * time.Second)
	if _, err := f.s.StartRequest(f.b, m.ID); err == nil {
		t.Fatal("timed-out request was re-run")
	} else {
		assertStatus(t, 409, err)
	}
	q, err = f.s.GetRequest(f.a, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if q.State != RequestTimedOut || q.Seq != 2 {
		t.Fatalf("timeout transition wrong: %+v", q)
	}
	// Starting a running request is rejected even before the deadline.
	running := f.sendRequest(t, "req2", DefaultTTL)
	if q, err := f.s.StartRequest(f.b, running.ID); err != nil || q.State != RequestRunning || q.Seq != 2 {
		t.Fatalf("start failed: %v %+v", err, q)
	}
	if _, err := f.s.StartRequest(f.b, running.ID); err == nil {
		t.Fatal("running request restarted")
	} else {
		assertStatus(t, 409, err)
	}
}

func TestRequestLateResultMarkedLate(t *testing.T) {
	f := newFixture(t)
	f.s.Lifecycle = true
	m := f.sendRequest(t, "req", 10)
	if _, err := f.s.StartRequest(f.b, m.ID); err != nil {
		t.Fatal(err)
	}
	f.advance(11 * time.Second)
	q, err := f.s.CompleteRequest(f.b, m.ID, "done eventually")
	if err != nil {
		t.Fatal(err)
	}
	if q.State != RequestLate || q.Result != "done eventually" || q.Seq != 4 {
		t.Fatalf("late result not recorded as late: %+v", q)
	}
	got, err := f.s.GetRequest(f.b, m.ID)
	if err != nil || got.State != RequestLate {
		t.Fatalf("late state not persisted: %v %+v", err, got)
	}
	if _, err := f.s.CompleteRequest(f.b, m.ID, "again"); err == nil {
		t.Fatal("concluded request completed again")
	} else {
		assertStatus(t, 409, err)
	}
}

func TestRequestFinalBeforeDeadline(t *testing.T) {
	f := newFixture(t)
	f.s.Lifecycle = true
	m := f.sendRequest(t, "req", 10)
	if _, err := f.s.CompleteRequest(f.b, m.ID, "early"); err == nil {
		t.Fatal("request completed before starting")
	} else {
		assertStatus(t, 409, err)
	}
	if _, err := f.s.StartRequest(f.b, m.ID); err != nil {
		t.Fatal(err)
	}
	q, err := f.s.CompleteRequest(f.b, m.ID, "done")
	if err != nil || q.State != RequestFinal || q.Result != "done" || q.Seq != 3 {
		t.Fatalf("final transition wrong: %v %+v", err, q)
	}
}

func TestAckIndependentFromOutcome(t *testing.T) {
	f := newFixture(t)
	f.s.Lifecycle = true
	m := f.sendRequest(t, "req", DefaultTTL)
	c := claimOne(t, f.s, f.b, 300)
	if _, err := f.s.Ack(f.b, m.ID, c.Receipt); err != nil {
		t.Fatal(err)
	}
	// Delivery ack must not change the lifecycle outcome.
	q, err := f.s.GetRequest(f.b, m.ID)
	if err != nil || q.State != RequestReceived || q.Seq != 1 {
		t.Fatalf("ack changed lifecycle: %v %+v", err, q)
	}
	if _, err := f.s.StartRequest(f.b, m.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.CompleteRequest(f.b, m.ID, "done"); err != nil {
		t.Fatal(err)
	}
	// Lifecycle outcome must not change the delivery ack.
	got, err := f.s.Get(f.a, m.ID)
	if err != nil || got.State != "acknowledged" || got.AckedAt == nil {
		t.Fatalf("lifecycle changed ack: %v %+v", err, got)
	}
	q, err = f.s.GetRequest(f.b, m.ID)
	if err != nil || q.State != RequestFinal {
		t.Fatalf("unexpected lifecycle after completion: %v %+v", err, q)
	}
}

func TestRequestLifecycleDefaultOff(t *testing.T) {
	f := newFixture(t)
	m := f.sendRequest(t, "req", DefaultTTL)
	_, err := f.s.GetRequest(f.b, m.ID)
	assertStatus(t, 400, err)
	_, err = f.s.StartRequest(f.b, m.ID)
	assertStatus(t, 400, err)
	_, err = f.s.CompleteRequest(f.b, m.ID, "done")
	assertStatus(t, 400, err)
}

func TestRequestAccessRules(t *testing.T) {
	f := newFixture(t)
	f.s.Lifecycle = true
	m := f.sendRequest(t, "req", DefaultTTL)
	plain := f.send(t, "plain", DefaultTTL)
	if _, err := f.s.GetRequest(f.b, plain.ID); err == nil {
		t.Fatal("plain message treated as tracked request")
	} else {
		assertStatus(t, 404, err)
	}
	// Only the recipient may drive the lifecycle; the sender may observe.
	_, err := f.s.StartRequest(f.a, m.ID)
	assertStatus(t, 404, err)
	_, err = f.s.GetRequest(f.c, m.ID)
	assertStatus(t, 404, err)
	if _, err := f.s.GetRequest(f.a, m.ID); err != nil {
		t.Fatal(err)
	}
}
