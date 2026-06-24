// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Deployment Theory.

package tpm2

import (
	"bytes"
	"crypto/elliptic"
	"math/big"
	"testing"
)

func curveID256Cmd() []byte {
	var w writer
	w.u16(ECCNistP256)
	return w.bytes()
}

func p256Point(x, y *big.Int) (px, py []byte) {
	return padLeft(x.Bytes(), 32), padLeft(y.Bytes(), 32)
}

func TestECEphemeral(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCECEphemeral, curveID256Cmd())))
	if rc != RCSuccess {
		t.Fatalf("EC_Ephemeral rc = 0x%x", rc)
	}
	r := newReader(p)
	qx, qy := readECCPoint(r)
	counter := r.u16()

	commit := tpm.committed[counter]
	if commit == nil {
		t.Fatal("no committed scalar for the returned counter")
	}
	wx, wy := elliptic.P256().ScalarBaseMult(commit.scalar.Bytes())
	ex, ey := p256Point(wx, wy)
	if !bytes.Equal(qx, ex) || !bytes.Equal(qy, ey) {
		t.Fatal("Q != [r]G")
	}
}

func TestCommit(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate())
	key := createSigningKey(t, tpm, srk, eccSigningTemplate())

	// P1 = the curve generator G, so E should equal [r]G.
	g := elliptic.P256().Params()
	gx, gy := p256Point(g.Gx, g.Gy)
	var body writer
	body.u32(key)
	body.raw(onePasswordAuth())
	writeECCPoint(&body, gx, gy) // P1
	body.tpm2b(nil)              // s2
	body.tpm2b(nil)              // y2
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCCommit, body.bytes())))
	if rc != RCSuccess {
		t.Fatalf("Commit rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u32() // parameterSize
	kx, _ := readECCPoint(r)
	lx, _ := readECCPoint(r)
	ex, ey := readECCPoint(r)
	counter := r.u16()
	if len(kx) != 0 || len(lx) != 0 {
		t.Fatal("K and L should be empty points when s2 is omitted")
	}
	commit := tpm.committed[counter]
	wx, wy := elliptic.P256().ScalarBaseMult(commit.scalar.Bytes())
	wex, wey := p256Point(wx, wy)
	if !bytes.Equal(ex, wex) || !bytes.Equal(ey, wey) {
		t.Fatal("E != [r]P1")
	}
}

func TestZGen2Phase(t *testing.T) {
	tpm := New()
	startup(t, tpm)
	srk, _, _ := createPrimary(t, tpm, RHOwner, eccStorageTemplate()) // keyA (static)
	keyA, _ := tpm.objects.get(srk)
	curve := elliptic.P256()

	// keyA's ephemeral via EC_Ephemeral.
	_, rc, ep := parseResp(t, tpm.Execute(buildCmd(TPMSTNoSessions, CCECEphemeral, curveID256Cmd())))
	if rc != RCSuccess {
		t.Fatalf("EC_Ephemeral rc = 0x%x", rc)
	}
	er := newReader(ep)
	readECCPoint(er)
	counter := er.u16()
	rScalar := tpm.committed[counter].scalar // captured before ZGen_2Phase consumes it

	// Party B's static + ephemeral public points.
	dsB := big.NewInt(0x0123_4567)
	deB := big.NewInt(0x0089_abcd)
	qsbx, qsby := curve.ScalarBaseMult(dsB.Bytes())
	qebx, qeby := curve.ScalarBaseMult(deB.Bytes())

	var body writer
	body.u32(srk)
	body.raw(onePasswordAuth())
	{
		px, py := p256Point(qsbx, qsby)
		writeECCPoint(&body, px, py) // inQsB
	}
	{
		px, py := p256Point(qebx, qeby)
		writeECCPoint(&body, px, py) // inQeB
	}
	body.u16(AlgECDH)
	body.u16(counter)
	_, rc, p := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCZGen2Phase, body.bytes())))
	if rc != RCSuccess {
		t.Fatalf("ZGen_2Phase rc = 0x%x", rc)
	}
	r := newReader(p)
	_ = r.u32()
	z1x, z1y := readECCPoint(r) // Zs = [d_A]·QsB
	z2x, z2y := readECCPoint(r) // Ze = [r]·QeB

	wz1x, wz1y := curve.ScalarMult(qsbx, qsby, keyA.sensitive.Secret)
	wz2x, wz2y := curve.ScalarMult(qebx, qeby, rScalar.Bytes())
	ez1x, ez1y := p256Point(wz1x, wz1y)
	ez2x, ez2y := p256Point(wz2x, wz2y)
	if !bytes.Equal(z1x, ez1x) || !bytes.Equal(z1y, ez1y) {
		t.Fatal("outZ1 (Zs) mismatch")
	}
	if !bytes.Equal(z2x, ez2x) || !bytes.Equal(z2y, ez2y) {
		t.Fatal("outZ2 (Ze) mismatch")
	}

	// The committed value is consumed: reusing the counter fails.
	if _, rc, _ := parseResp(t, tpm.Execute(buildCmd(TPMSTSessions, CCZGen2Phase, body.bytes()))); baseRC(rc) != RCValue {
		t.Fatalf("reused-counter ZGen_2Phase rc = 0x%x, want RC_VALUE", rc)
	}
}
