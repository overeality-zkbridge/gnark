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

package groth16

import (
	"os"
	"runtime/pprof"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"

	"github.com/consensys/gnark/internal/backend/bn254/cs"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"

	"fmt"
	"math/big"
	"runtime"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	bn254witness "github.com/consensys/gnark/internal/backend/bn254/witness"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/logger"
)

// Proof represents a Groth16 proof that was encoded with a ProvingKey and can be verified
// with a valid statement and a VerifyingKey
// Notation follows Figure 4. in DIZK paper https://eprint.iacr.org/2018/691.pdf
type Proof struct {
	Ar, Krs curve.G1Affine
	Bs      curve.G2Affine
}

// isValid ensures proof elements are in the correct subgroup
func (proof *Proof) isValid() bool {
	return proof.Ar.IsInSubGroup() && proof.Krs.IsInSubGroup() && proof.Bs.IsInSubGroup()
}

// CurveID returns the curveID
func (proof *Proof) CurveID() ecc.ID {
	return curve.ID
}

// Prove generates the proof of knoweldge of a r1cs with full witness (secret + public part).
func Prove(r1cs *cs.R1CS, pk *ProvingKey, witness bn254witness.Witness, opt backend.ProverConfig) (*Proof, error) {
	if len(witness) != int(r1cs.NbPublicVariables-1+r1cs.NbSecretVariables) {
		return nil, fmt.Errorf("invalid witness size, got %d, expected %d = %d (public) + %d (secret)", len(witness), int(r1cs.NbPublicVariables-1+r1cs.NbSecretVariables), r1cs.NbPublicVariables, r1cs.NbSecretVariables)
	}

	log := logger.Logger().With().Str("curve", r1cs.CurveID().String()).Int("nbConstraints", len(r1cs.Constraints)).Str("backend", "groth16").Logger()

	// solve the R1CS and compute the a, b, c vectors
	a := make([]fr.Element, len(r1cs.Constraints), pk.Domain.Cardinality)
	b := make([]fr.Element, len(r1cs.Constraints), pk.Domain.Cardinality)
	c := make([]fr.Element, len(r1cs.Constraints), pk.Domain.Cardinality)
	var wireValues []fr.Element
	var err error
	if wireValues, err = r1cs.Solve(witness, a, b, c, opt); err != nil {
		if !opt.Force {
			return nil, err
		} else {
			// we need to fill wireValues with random values else multi exps don't do much
			var r fr.Element
			_, _ = r.SetRandom()
			for i := r1cs.NbPublicVariables + r1cs.NbSecretVariables; i < len(wireValues); i++ {
				wireValues[i] = r
				r.Double(&r)
			}
		}
	}

	f, err := os.Create("memprofile2.out")
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not create memory profile: %v\n", err)
		os.Exit(1)
	}

	defer f.Close()
	// Write the memory profile to the file
	if err := pprof.WriteHeapProfile(f); err != nil {
		fmt.Fprintf(os.Stderr, "could not write memory profile: %v\n", err)
		os.Exit(1)
	}
	start := time.Now()

	// set the wire values in regular form
	utils.Parallelize(len(wireValues), func(start, end int) {
		for i := start; i < end; i++ {
			wireValues[i].FromMont()
		}
	})
	// H (witness reduction / FFT part)
	var h []fr.Element
	//chHDone := make(chan struct{}, 1)
	//go func() {
	h = computeH(a, b, c, &pk.Domain)
	a = nil
	b = nil
	c = nil
	runtime.GC()
	//chHDone <- struct{}{}
	//}()

	// we need to copy and filter the wireValues for each multi exp
	// as pk.G1.A, pk.G1.B and pk.G2.B may have (a significant) number of point at infinity
	var wireValuesA, wireValuesB []fr.Element
	chWireValuesA, chWireValuesB := make(chan struct{}, 1), make(chan struct{}, 1)

	go func() {
		wireValuesA = make([]fr.Element, len(wireValues)-int(pk.NbInfinityA))
		fmt.Printf("len(wireValues): %d, memsize: %d Bytes\n", len(wireValues), len(wireValues)*32)
		for i, j := 0, 0; j < len(wireValuesA); i++ {
			if pk.InfinityA[i] {
				continue
			}
			wireValuesA[j] = wireValues[i]
			j++
		}
		close(chWireValuesA)
	}()
	go func() {
		wireValuesB = make([]fr.Element, len(wireValues)-int(pk.NbInfinityB))
		for i, j := 0, 0; j < len(wireValuesB); i++ {
			if pk.InfinityB[i] {
				continue
			}
			wireValuesB[j] = wireValues[i]
			j++
		}
		close(chWireValuesB)
	}()
	f3, err := os.Create("memprofile3.out")
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not create memory profile: %v\n", err)
		os.Exit(1)
	}

	defer f3.Close()
	// Write the memory profile to the file
	if err := pprof.WriteHeapProfile(f3); err != nil {
		fmt.Fprintf(os.Stderr, "could not write memory profile: %v\n", err)
		os.Exit(1)
	}

	// sample random r and s
	var r, s big.Int
	var _r, _s, _kr fr.Element
	if _, err := _r.SetRandom(); err != nil {
		return nil, err
	}
	if _, err := _s.SetRandom(); err != nil {
		return nil, err
	}
	_kr.Mul(&_r, &_s).Neg(&_kr)

	_r.FromMont()
	_s.FromMont()
	_kr.FromMont()
	_r.ToBigInt(&r)
	_s.ToBigInt(&s)

	// computes r[δ], s[δ], kr[δ]
	deltas := curve.BatchScalarMultiplicationG1(&pk.G1.Delta, []fr.Element{_r, _s, _kr})

	proof := &Proof{}
	var bs1, ar curve.G1Jac

	n := runtime.NumCPU()

	chBs1Done := make(chan error, 1)
	computeBS1 := func() {
		<-chWireValuesB
		if _, err := bs1.MultiExp(pk.G1.B, wireValuesB, ecc.MultiExpConfig{NbTasks: n}); err != nil {
			chBs1Done <- err
			close(chBs1Done)
			return
		}
		bs1.AddMixed(&pk.G1.Beta)
		bs1.AddMixed(&deltas[1])
		chBs1Done <- nil
	}

	chArDone := make(chan error, 1)
	computeAR1 := func() {
		<-chWireValuesA
		if _, err := ar.MultiExp(pk.G1.A, wireValuesA, ecc.MultiExpConfig{NbTasks: n}); err != nil {
			chArDone <- err
			close(chArDone)
			return
		}
		ar.AddMixed(&pk.G1.Alpha)
		ar.AddMixed(&deltas[0])
		proof.Ar.FromJacobian(&ar)
		chArDone <- nil
	}

	chKrsDone := make(chan error, 1)
	computeKRS := func() {
		// we could NOT split the Krs multiExp in 2, and just append pk.G1.K and pk.G1.Z
		// however, having similar lengths for our tasks helps with parallelism
		fmt.Println("wtf0")
		var krs, krs2, p1 curve.G1Jac
		chKrs2Done := make(chan error, 1)
		go func() {
			_, err := krs2.MultiExp(pk.G1.Z, h, ecc.MultiExpConfig{NbTasks: n / 2})
			chKrs2Done <- err
		}()
		fmt.Println("wtf1")
		if _, err := krs.MultiExp(pk.G1.K, wireValues[r1cs.NbPublicVariables:], ecc.MultiExpConfig{NbTasks: n / 2}); err != nil {
			chKrsDone <- err
			fmt.Println("wtf3")
			return
		}
		fmt.Println("wtf2")
		krs.AddMixed(&deltas[2])
		n := 3
		for n != 0 {
			select {
			case err := <-chKrs2Done:
				if err != nil {
					chKrsDone <- err
					return
				}
				krs.AddAssign(&krs2)
			case err := <-chArDone:
				if err != nil {
					chKrsDone <- err
					return
				}
				p1.ScalarMultiplication(&ar, &s)
				krs.AddAssign(&p1)
			case err := <-chBs1Done:
				if err != nil {
					chKrsDone <- err
					return
				}
				p1.ScalarMultiplication(&bs1, &r)
				krs.AddAssign(&p1)
			}
			n--
		}
		fmt.Println("wtf4")

		proof.Krs.FromJacobian(&krs)
		chKrsDone <- nil
		fmt.Println("wtf5")
	}

	computeBS2 := func() error {
		// Bs2 (1 multi exp G2 - size = len(wires))
		var Bs, deltaS curve.G2Jac

		nbTasks := n
		if nbTasks <= 16 {
			// if we don't have a lot of CPUs, this may artificially split the MSM
			nbTasks *= 2
		}
		<-chWireValuesB
		if _, err := Bs.MultiExp(pk.G2.B, wireValuesB, ecc.MultiExpConfig{NbTasks: nbTasks}); err != nil {
			return err
		}

		deltaS.FromAffine(&pk.G2.Delta)
		deltaS.ScalarMultiplication(&deltaS, &s)
		Bs.AddAssign(&deltaS)
		Bs.AddMixed(&pk.G2.Beta)

		proof.Bs.FromJacobian(&Bs)
		return nil
	}

	// wait for FFT to end, as it uses all our CPUs
	//<-chHDone

	// schedule our proof part computations
	fmt.Println("computeAR1")
	computeAR1()
	fmt.Println("computeBS1")
	computeBS1()
	fmt.Println("computeKRS")
	computeKRS()
	f4, err := os.Create("memprofile4.out")
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not create memory profile: %v\n", err)
		os.Exit(1)
	}

	defer f4.Close()
	// Write the memory profile to the file
	if err := pprof.WriteHeapProfile(f4); err != nil {
		fmt.Fprintf(os.Stderr, "could not write memory profile: %v\n", err)
		os.Exit(1)
	}
	if err := computeBS2(); err != nil {
		return nil, err
	}

	// wait for all parts of the proof to be computed.
	if err := <-chKrsDone; err != nil {
		return nil, err
	}

	log.Debug().Dur("took", time.Since(start)).Msg("prover done")

	return proof, nil
}

func computeH(a, b, c []fr.Element, domain *fft.Domain) []fr.Element {
	// H part of Krs
	// Compute H (hz=ab-c, where z=-2 on ker X^n+1 (z(x)=x^n-1))
	// 	1 - _a = ifft(a), _b = ifft(b), _c = ifft(c)
	// 	2 - ca = fft_coset(_a), ba = fft_coset(_b), cc = fft_coset(_c)
	// 	3 - h = ifft_coset(ca o cb - cc)

	n := len(a)

	// add padding to ensure input length is domain cardinality
	padding := make([]fr.Element, int(domain.Cardinality)-n)
	a = append(a, padding...)
	b = append(b, padding...)
	c = append(c, padding...)
	n = len(a)

	domain.FFTInverse(a, fft.DIF)
	domain.FFTInverse(b, fft.DIF)
	domain.FFTInverse(c, fft.DIF)

	domain.FFT(a, fft.DIT, true)
	domain.FFT(b, fft.DIT, true)
	domain.FFT(c, fft.DIT, true)

	var den, one fr.Element
	one.SetOne()
	den.Exp(domain.FrMultiplicativeGen, big.NewInt(int64(domain.Cardinality)))
	den.Sub(&den, &one).Inverse(&den)

	// h = ifft_coset(ca o cb - cc)
	// reusing a to avoid unecessary memalloc
	utils.Parallelize(n, func(start, end int) {
		for i := start; i < end; i++ {
			a[i].Mul(&a[i], &b[i]).
				Sub(&a[i], &c[i]).
				Mul(&a[i], &den)
		}
	})

	// ifft_coset
	domain.FFTInverse(a, fft.DIF, true)

	utils.Parallelize(len(a), func(start, end int) {
		for i := start; i < end; i++ {
			a[i].FromMont()
		}
	})

	return a
}
