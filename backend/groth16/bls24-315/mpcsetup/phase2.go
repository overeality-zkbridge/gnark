// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by gnark DO NOT EDIT

package mpcsetup

import (
	"crypto/sha256"
	"errors"
	"math/big"

	curve "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bls24-315"
)

type Phase2Evaluations struct {
	G1 struct {
		A, B, VKK []curve.G1Affine
	}
	G2 struct {
		B []curve.G2Affine
	}
}

type Phase2 struct {
	Parameters struct {
		G1 struct {
			Delta curve.G1Affine
			L, Z  []curve.G1Affine
		}
		G2 struct {
			Delta curve.G2Affine
		}
	}
	PublicKey PublicKey
	Hash      []byte
}

func InitPhase2(r1cs *cs.R1CS, srs1 *Phase1) (Phase2, Phase2Evaluations) {
	srs := srs1.Parameters
	size := len(srs.G1.AlphaTau)
	if size < r1cs.GetNbConstraints() {
		panic("Number of constraints is larger than expected")
	}

	c2 := Phase2{}

	accumulateG1 := func(res *curve.G1Affine, t constraint.Term, value *curve.G1Affine) {
		cID := t.CoeffID()
		switch cID {
		case constraint.CoeffIdZero:
			return
		case constraint.CoeffIdOne:
			res.Add(res, value)
		case constraint.CoeffIdMinusOne:
			res.Sub(res, value)
		case constraint.CoeffIdTwo:
			res.Add(res, value).Add(res, value)
		default:
			var tmp curve.G1Affine
			var vBi big.Int
			r1cs.Coefficients[cID].BigInt(&vBi)
			tmp.ScalarMultiplication(value, &vBi)
			res.Add(res, &tmp)
		}
	}

	accumulateG2 := func(res *curve.G2Affine, t constraint.Term, value *curve.G2Affine) {
		cID := t.CoeffID()
		switch cID {
		case constraint.CoeffIdZero:
			return
		case constraint.CoeffIdOne:
			res.Add(res, value)
		case constraint.CoeffIdMinusOne:
			res.Sub(res, value)
		case constraint.CoeffIdTwo:
			res.Add(res, value).Add(res, value)
		default:
			var tmp curve.G2Affine
			var vBi big.Int
			r1cs.Coefficients[cID].BigInt(&vBi)
			tmp.ScalarMultiplication(value, &vBi)
			res.Add(res, &tmp)
		}
	}

	// Prepare Lagrange coefficients of [τ...]₁, [τ...]₂, [ατ...]₁, [βτ...]₁
	coeffTau1 := lagrangeCoeffsG1(srs.G1.Tau, size)
	coeffTau2 := lagrangeCoeffsG2(srs.G2.Tau, size)
	coeffAlphaTau1 := lagrangeCoeffsG1(srs.G1.AlphaTau, size)
	coeffBetaTau1 := lagrangeCoeffsG1(srs.G1.BetaTau, size)

	internal, secret, public := r1cs.GetNbVariables()
	nWires := internal + secret + public
	var evals Phase2Evaluations
	evals.G1.A = make([]curve.G1Affine, nWires)
	evals.G1.B = make([]curve.G1Affine, nWires)
	evals.G2.B = make([]curve.G2Affine, nWires)
	bA := make([]curve.G1Affine, nWires)
	aB := make([]curve.G1Affine, nWires)
	C := make([]curve.G1Affine, nWires)

	// TODO @gbotrel use constraint iterator when available.

	i := 0
	it := r1cs.GetR1CIterator()
	for c := it.Next(); c != nil; c = it.Next() {
		// A
		for _, t := range c.L {
			accumulateG1(&evals.G1.A[t.WireID()], t, &coeffTau1[i])
			accumulateG1(&bA[t.WireID()], t, &coeffBetaTau1[i])
		}
		// B
		for _, t := range c.R {
			accumulateG1(&evals.G1.B[t.WireID()], t, &coeffTau1[i])
			accumulateG2(&evals.G2.B[t.WireID()], t, &coeffTau2[i])
			accumulateG1(&aB[t.WireID()], t, &coeffAlphaTau1[i])
		}
		// C
		for _, t := range c.O {
			accumulateG1(&C[t.WireID()], t, &coeffTau1[i])
		}
		i++
	}

	// Prepare default contribution
	_, _, g1, g2 := curve.Generators()
	c2.Parameters.G1.Delta = g1
	c2.Parameters.G2.Delta = g2

	// Build Z in PK as τⁱ(τⁿ - 1)  = τ⁽ⁱ⁺ⁿ⁾ - τⁱ  for i ∈ [0, n-2]
	// τⁱ(τⁿ - 1)  = τ⁽ⁱ⁺ⁿ⁾ - τⁱ  for i ∈ [0, n-2]
	n := len(srs.G1.AlphaTau)
	c2.Parameters.G1.Z = make([]curve.G1Affine, n)
	for i := 0; i < n-1; i++ {
		c2.Parameters.G1.Z[i].Sub(&srs.G1.Tau[i+n], &srs.G1.Tau[i])
	}
	bitReverse(c2.Parameters.G1.Z)
	c2.Parameters.G1.Z = c2.Parameters.G1.Z[:n-1]

	// Evaluate L
	nPrivate := internal + secret
	c2.Parameters.G1.L = make([]curve.G1Affine, nPrivate)
	evals.G1.VKK = make([]curve.G1Affine, public)
	offset := public
	for i := 0; i < nWires; i++ {
		var tmp curve.G1Affine
		tmp.Add(&bA[i], &aB[i])
		tmp.Add(&tmp, &C[i])
		if i < public {
			evals.G1.VKK[i].Set(&tmp)
		} else {
			c2.Parameters.G1.L[i-offset].Set(&tmp)
		}
	}
	// Set δ public key
	var delta fr.Element
	delta.SetOne()
	c2.PublicKey = newPublicKey(delta, nil, 1)

	// Hash initial contribution
	c2.Hash = c2.hash()
	return c2, evals
}

func (c *Phase2) Contribute() {
	// Sample toxic δ
	var delta, deltaInv fr.Element
	var deltaBI, deltaInvBI big.Int
	delta.SetRandom()
	deltaInv.Inverse(&delta)

	delta.BigInt(&deltaBI)
	deltaInv.BigInt(&deltaInvBI)

	// Set δ public key
	c.PublicKey = newPublicKey(delta, c.Hash, 1)

	// Update δ
	c.Parameters.G1.Delta.ScalarMultiplication(&c.Parameters.G1.Delta, &deltaBI)
	c.Parameters.G2.Delta.ScalarMultiplication(&c.Parameters.G2.Delta, &deltaBI)

	// Update Z using δ⁻¹
	for i := 0; i < len(c.Parameters.G1.Z); i++ {
		c.Parameters.G1.Z[i].ScalarMultiplication(&c.Parameters.G1.Z[i], &deltaInvBI)
	}

	// Update L using δ⁻¹
	for i := 0; i < len(c.Parameters.G1.L); i++ {
		c.Parameters.G1.L[i].ScalarMultiplication(&c.Parameters.G1.L[i], &deltaInvBI)
	}

	// 4. Hash contribution
	c.Hash = c.hash()
}

func VerifyPhase2(c0, c1 *Phase2, c ...*Phase2) error {
	contribs := append([]*Phase2{c0, c1}, c...)
	for i := 0; i < len(contribs)-1; i++ {
		if err := verifyPhase2(contribs[i], contribs[i+1]); err != nil {
			return err
		}
	}
	return nil
}

func verifyPhase2(current, contribution *Phase2) error {
	// Compute R for δ
	deltaR := genR(contribution.PublicKey.SG, contribution.PublicKey.SXG, current.Hash[:], 1)

	// Check for knowledge of δ
	if !sameRatio(contribution.PublicKey.SG, contribution.PublicKey.SXG, contribution.PublicKey.XR, deltaR) {
		return errors.New("couldn't verify knowledge of δ")
	}

	// Check for valid updates using previous parameters
	if !sameRatio(contribution.Parameters.G1.Delta, current.Parameters.G1.Delta, deltaR, contribution.PublicKey.XR) {
		return errors.New("couldn't verify that [δ]₁ is based on previous contribution")
	}
	if !sameRatio(contribution.PublicKey.SG, contribution.PublicKey.SXG, contribution.Parameters.G2.Delta, current.Parameters.G2.Delta) {
		return errors.New("couldn't verify that [δ]₂ is based on previous contribution")
	}

	// Check for valid updates of L and Z using
	L, prevL := merge(contribution.Parameters.G1.L, current.Parameters.G1.L)
	if !sameRatio(L, prevL, contribution.Parameters.G2.Delta, current.Parameters.G2.Delta) {
		return errors.New("couldn't verify valid updates of L using δ⁻¹")
	}
	Z, prevZ := merge(contribution.Parameters.G1.Z, current.Parameters.G1.Z)
	if !sameRatio(Z, prevZ, contribution.Parameters.G2.Delta, current.Parameters.G2.Delta) {
		return errors.New("couldn't verify valid updates of L using δ⁻¹")
	}

	// Check hash of the contribution
	h := contribution.hash()
	for i := 0; i < len(h); i++ {
		if h[i] != contribution.Hash[i] {
			return errors.New("couldn't verify hash of contribution")
		}
	}

	return nil
}

func (c *Phase2) hash() []byte {
	sha := sha256.New()
	c.writeTo(sha)
	return sha.Sum(nil)
}
