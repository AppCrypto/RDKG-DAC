package benchfixture

import (
	"EVOLV_DAO/bn256"
	"EVOLV_DAO/crypto/DAC"
	"EVOLV_DAO/crypto/RDKG"
	"EVOLV_DAO/crypto/RDKG/vss"
	"crypto/sha256"
	"math/big"
)

type Fixture struct {
	P       *DAC.Params
	SK      []*RDKG.SecretKey
	VK      []*RDKG.VerifKey
	MPK     *RDKG.AggVerifKey
	Trace   *DAC.TraceCommittee
	Du      *big.Int
	Gamma   *bn256.G1
	ID      *big.Int
	Attrs   []*big.Int
	I       []int
	Par     *vss.Par
	Request *DAC.Commitment
	Blind   []*DAC.BlindSignature
	Sig     *DAC.Signature
}

func New(q int) (*Fixture, error) {
	f := &Fixture{P: DAC.Setup(q + 1), I: []int{1, 3, 4}}
	var e error
	f.SK, f.VK, f.MPK, _, _, e = RDKG.GenPK(f.P.G2, f.P.Order, q+1, 3, 5)
	if e != nil {
		return nil, e
	}
	f.Trace, e = DAC.NewTraceCommittee(f.P, 3, 5)
	if e != nil {
		return nil, e
	}
	DAC.BindContext(f.P, f.MPK, f.Trace.D)
	f.Du, f.Gamma, e = DAC.ElGamalKeyGen(f.P.Order)
	if e != nil {
		return nil, e
	}
	f.Par, _ = vss.Setup(5, 3)
	digest := sha256.Sum256([]byte("authenticated synthetic benchmark user"))
	f.ID = new(big.Int).Mod(new(big.Int).SetBytes(digest[:]), f.P.Order)
	for j := 0; j < q; j++ {
		f.Attrs = append(f.Attrs, big.NewInt(int64(41+j)))
	}
	if e = f.Issue(); e != nil {
		return nil, e
	}
	return f, nil
}
func (f *Fixture) Values() []*big.Int { return append([]*big.Int{f.ID}, f.Attrs...) }
func (f *Fixture) Prepare() error {
	var e error
	f.Request, _, e = DAC.PrepareBlindSign_EDAO(f.P, f.Gamma, f.Du, f.Attrs, f.ID)
	return e
}
func (f *Fixture) Sign() error {
	f.Blind = make([]*DAC.BlindSignature, 5)
	for _, i := range f.I {
		s, e := DAC.BlindSign_EDAO(f.P, f.SK[i], f.Request, f.ID)
		if e != nil {
			return e
		}
		f.Blind[i] = s
	}
	return nil
}
func (f *Fixture) Obtain() error {
	var e error
	f.Sig, e = DAC.ObtainCred(f.I, f.Blind, f.Du, f.Par, f.VK, f.Values())
	return e
}
func (f *Fixture) Issue() error {
	for _, s := range []func() error{f.Prepare, f.Sign, f.Obtain} {
		if e := s(); e != nil {
			return e
		}
	}
	return nil
}
