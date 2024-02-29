package identity

import (
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
)

// IBaseVerifierProveIdentityParams is an auto generated low-level Go binding around an user-defined struct.
type IBaseVerifierProveIdentityParams struct {
	StatesMerkleData ILightweightStateStatesMerkleData
	Inputs           []*big.Int
	A                [2]*big.Int
	B                [2][2]*big.Int
	C                [2]*big.Int
}

// IBaseVerifierTransitStateParams is an auto generated low-level Go binding around an user-defined struct.
type IBaseVerifierTransitStateParams struct {
	NewIdentitiesStatesRoot [32]byte
	GistData                ILightweightStateGistRootData
	Proof                   []byte
}

// ILightweightStateGistRootData is an auto generated low-level Go binding around an user-defined struct.
type ILightweightStateGistRootData struct {
	Root               *big.Int
	CreatedAtTimestamp *big.Int
}

// ILightweightStateStatesMerkleData is an auto generated low-level Go binding around an user-defined struct.
type ILightweightStateStatesMerkleData struct {
	IssuerId           *big.Int
	IssuerState        *big.Int
	CreatedAtTimestamp *big.Int
	MerkleProof        [][32]byte
}

// IRegisterVerifierRegisterProofParams is an auto generated low-level Go binding around an user-defined struct.
type IRegisterVerifierRegisterProofParams struct {
	IssuingAuthority  *big.Int
	DocumentNullifier *big.Int
	Commitment        [32]byte
}

// IRegistrationRegistrationCounters is an auto generated low-level Go binding around an user-defined struct.
type IRegistrationRegistrationCounters struct {
	TotalRegistrations *big.Int
}

// IRegistrationRegistrationParams is an auto generated low-level Go binding around an user-defined struct.
type IRegistrationRegistrationParams struct {
	Remark           string
	CommitmentStart  *big.Int
	CommitmentPeriod *big.Int
}

// IRegistrationRegistrationValues is an auto generated low-level Go binding around an user-defined struct.
type IRegistrationRegistrationValues struct {
	CommitmentStartTime *big.Int
	CommitmentEndTime   *big.Int
}

// SparseMerkleTreeProof is an auto generated low-level Go binding around an user-defined struct.
type SparseMerkleTreeProof struct {
	Root         [32]byte
	Siblings     [][32]byte
	Existence    bool
	Key          [32]byte
	Value        [32]byte
	AuxExistence bool
	AuxKey       [32]byte
	AuxValue     [32]byte
}

// RegistrationMetaData contains all meta data concerning the Registration contract.
var RegistrationMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[{\"internalType\":\"address\",\"name\":\"registerVerifier_\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"treeHeight_\",\"type\":\"uint256\"}],\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"proposer\",\"type\":\"address\"},{\"components\":[{\"internalType\":\"string\",\"name\":\"remark\",\"type\":\"string\"},{\"internalType\":\"uint256\",\"name\":\"commitmentStart\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"commitmentPeriod\",\"type\":\"uint256\"}],\"indexed\":false,\"internalType\":\"structIRegistration.RegistrationParams\",\"name\":\"registrationParams\",\"type\":\"tuple\"}],\"name\":\"RegistrationInitialized\",\"type\":\"event\"},{\"anonymous\":false,\"inputs\":[{\"indexed\":true,\"internalType\":\"address\",\"name\":\"user\",\"type\":\"address\"},{\"components\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"issuerId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"issuerState\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"createdAtTimestamp\",\"type\":\"uint256\"},{\"internalType\":\"bytes32[]\",\"name\":\"merkleProof\",\"type\":\"bytes32[]\"}],\"internalType\":\"structILightweightState.StatesMerkleData\",\"name\":\"statesMerkleData\",\"type\":\"tuple\"},{\"internalType\":\"uint256[]\",\"name\":\"inputs\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256[2]\",\"name\":\"a\",\"type\":\"uint256[2]\"},{\"internalType\":\"uint256[2][2]\",\"name\":\"b\",\"type\":\"uint256[2][2]\"},{\"internalType\":\"uint256[2]\",\"name\":\"c\",\"type\":\"uint256[2]\"}],\"indexed\":false,\"internalType\":\"structIBaseVerifier.ProveIdentityParams\",\"name\":\"proveIdentityParams\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"issuingAuthority\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"documentNullifier\",\"type\":\"uint256\"},{\"internalType\":\"bytes32\",\"name\":\"commitment\",\"type\":\"bytes32\"}],\"indexed\":false,\"internalType\":\"structIRegisterVerifier.RegisterProofParams\",\"name\":\"registerProofParams\",\"type\":\"tuple\"}],\"name\":\"UserRegistered\",\"type\":\"event\"},{\"inputs\":[{\"components\":[{\"internalType\":\"string\",\"name\":\"remark\",\"type\":\"string\"},{\"internalType\":\"uint256\",\"name\":\"commitmentStart\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"commitmentPeriod\",\"type\":\"uint256\"}],\"internalType\":\"structIRegistration.RegistrationParams\",\"name\":\"registrationParams_\",\"type\":\"tuple\"}],\"name\":\"__Registration_init\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"commitments\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"key_\",\"type\":\"bytes32\"}],\"name\":\"getProof\",\"outputs\":[{\"components\":[{\"internalType\":\"bytes32\",\"name\":\"root\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32[]\",\"name\":\"siblings\",\"type\":\"bytes32[]\"},{\"internalType\":\"bool\",\"name\":\"existence\",\"type\":\"bool\"},{\"internalType\":\"bytes32\",\"name\":\"key\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"value\",\"type\":\"bytes32\"},{\"internalType\":\"bool\",\"name\":\"auxExistence\",\"type\":\"bool\"},{\"internalType\":\"bytes32\",\"name\":\"auxKey\",\"type\":\"bytes32\"},{\"internalType\":\"bytes32\",\"name\":\"auxValue\",\"type\":\"bytes32\"}],\"internalType\":\"structSparseMerkleTree.Proof\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getRoot\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"root\",\"type\":\"bytes32\"}],\"name\":\"isRootExists\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"components\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"issuerId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"issuerState\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"createdAtTimestamp\",\"type\":\"uint256\"},{\"internalType\":\"bytes32[]\",\"name\":\"merkleProof\",\"type\":\"bytes32[]\"}],\"internalType\":\"structILightweightState.StatesMerkleData\",\"name\":\"statesMerkleData\",\"type\":\"tuple\"},{\"internalType\":\"uint256[]\",\"name\":\"inputs\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256[2]\",\"name\":\"a\",\"type\":\"uint256[2]\"},{\"internalType\":\"uint256[2][2]\",\"name\":\"b\",\"type\":\"uint256[2][2]\"},{\"internalType\":\"uint256[2]\",\"name\":\"c\",\"type\":\"uint256[2]\"}],\"internalType\":\"structIBaseVerifier.ProveIdentityParams\",\"name\":\"proveIdentityParams_\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"issuingAuthority\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"documentNullifier\",\"type\":\"uint256\"},{\"internalType\":\"bytes32\",\"name\":\"commitment\",\"type\":\"bytes32\"}],\"internalType\":\"structIRegisterVerifier.RegisterProofParams\",\"name\":\"registerProofParams_\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"bytes32\",\"name\":\"newIdentitiesStatesRoot\",\"type\":\"bytes32\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"root\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"createdAtTimestamp\",\"type\":\"uint256\"}],\"internalType\":\"structILightweightState.GistRootData\",\"name\":\"gistData\",\"type\":\"tuple\"},{\"internalType\":\"bytes\",\"name\":\"proof\",\"type\":\"bytes\"}],\"internalType\":\"structIBaseVerifier.TransitStateParams\",\"name\":\"transitStateParams_\",\"type\":\"tuple\"},{\"internalType\":\"bool\",\"name\":\"isTransitState_\",\"type\":\"bool\"}],\"name\":\"register\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"registerVerifier\",\"outputs\":[{\"internalType\":\"contractIRegisterVerifier\",\"name\":\"\",\"type\":\"address\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"registrationInfo\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"remark\",\"type\":\"string\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"commitmentStartTime\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"commitmentEndTime\",\"type\":\"uint256\"}],\"internalType\":\"structIRegistration.RegistrationValues\",\"name\":\"values\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"totalRegistrations\",\"type\":\"uint256\"}],\"internalType\":\"structIRegistration.RegistrationCounters\",\"name\":\"counters\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"rootsHistory\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"smtTreeMaxDepth\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
}

func NewRegistrationCoder() (*abi.ABI, error) {
	parsed, err := RegistrationMetaData.GetAbi()
	if err != nil {
		return nil, err
	}

	return parsed, nil
}
