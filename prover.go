package identity

import (
	"os"

	"github.com/iden3/go-rapidsnark/prover"
	"github.com/iden3/go-rapidsnark/types"
	"github.com/iden3/go-rapidsnark/verifier"
	"github.com/iden3/go-rapidsnark/witness"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

type Prover interface {
	GenerateZKProof(inputs map[string]interface{}) (*types.ZKProof, error)
	VerifyZKProof(proof types.ZKProof) error
}

type zkprover struct {
	calculator      *witness.Circom2WitnessCalculator
	zkey            []byte
	verificationKey []byte
}

func NewProver(wasmFilePath, zkeyFilePath, verificationKeyFilePath string) (Prover, error) {
	var zkProver zkprover
	var err error

	wasmBytes, err := os.ReadFile(wasmFilePath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read WASM file", logan.F{
			"file": wasmFilePath,
		})
	}

	zkProver.calculator, err = witness.NewCircom2WitnessCalculator(wasmBytes, true)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create witness calculator")
	}

	zkProver.zkey, err = os.ReadFile(zkeyFilePath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read zkey file", logan.F{
			"file": zkeyFilePath,
		})
	}

	zkProver.verificationKey, err = os.ReadFile(verificationKeyFilePath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read verification key file", logan.F{
			"file": verificationKeyFilePath,
		})
	}

	return &zkProver, nil
}

func (p *zkprover) GenerateZKProof(inputs map[string]interface{}) (*types.ZKProof, error) {
	binaryWitness, err := p.calculator.CalculateWTNSBin(inputs, false)
	if err != nil {
		return nil, errors.Wrap(err, "failed to calculate binary witness")
	}

	proof, err := prover.Groth16Prover(p.zkey, binaryWitness)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create zk proof")
	}

	if err = p.VerifyZKProof(*proof); err != nil {
		return nil, errors.Wrap(err, "failed to verify zk proof")
	}

	return proof, nil
}

func (p *zkprover) VerifyZKProof(proof types.ZKProof) error {
	if err := verifier.VerifyGroth16(proof, p.verificationKey); err != nil {
		return errors.Wrap(err, "failed to verify groth16 proof")
	}

	return nil
}
