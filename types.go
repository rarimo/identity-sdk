package identity

import (
	"math/big"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-crypto/babyjub"
	merkletree "github.com/rarimo/go-merkletree"
	verifiable "github.com/rarimo/go-schema-processor/verifiable"
)

type CircuitId string

const (
	AtomicQueryMTPV2OnChainVotingCircuit CircuitId = "AtomicQueryMTPV2OnChainVoting"
)

type Operators int

const (
	NOOP Operators = iota
	EQ
	LT
	GT
	IN
	NIN
	NE
)

type QueryWithFieldName struct {
	Query     Query
	FieldName string
}

var QueryOperators = map[string]Operators{
	"$noop": NOOP,
	"$eq":   EQ,
	"$lt":   LT,
	"$gt":   GT,
	"$in":   IN,
	"$nin":  NIN,
	"$ne":   NE,
}

type AuthV2CircuitInputs struct {
	GenesisID    string `json:"genesisID"`
	ProfileNonce string `json:"profileNonce"`

	AuthClaim    *core.Claim        `json:"authClaim"`
	AuthClaimMtp []*merkletree.Hash `json:"authClaimIncMtp"`

	AuthClaimNonRevMtp      []*merkletree.Hash `json:"authClaimNonRevMtp"`
	AuthClaimNonRevMtpAuxHi *merkletree.Hash   `json:"authClaimNonRevMtpAuxHi"`
	AuthClaimNonRevMtpAuxHv *merkletree.Hash   `json:"authClaimNonRevMtpAuxHv"`
	AuthClaimNonRevMtpNoAux string             `json:"authClaimNonRevMtpNoAux"`

	Challenge             string `json:"challenge"`
	ChallengeSignatureR8X string `json:"challengeSignatureR8x"`
	ChallengeSignatureR8Y string `json:"challengeSignatureR8y"`
	ChallengeSignatureS   string `json:"challengeSignatureS"`

	ClaimsTreeRoot *merkletree.Hash `json:"claimsTreeRoot"`
	RevTreeRoot    *merkletree.Hash `json:"revTreeRoot"`
	RootsTreeRoot  *merkletree.Hash `json:"rootsTreeRoot"`
	State          *merkletree.Hash `json:"state"`

	GISTRoot     *merkletree.Hash   `json:"gistRoot"`
	GISTMtp      []*merkletree.Hash `json:"gistMtp"`
	GISTMtpAuxHi *merkletree.Hash   `json:"gistMtpAuxHi"`
	GISTMtpAuxHv *merkletree.Hash   `json:"gistMtpAuxHv"`
	GISTMtpNoAux string             `json:"gistMtpNoAux"`
}

type NodeAuxValue struct {
	key   merkletree.Hash
	value merkletree.Hash
	noAux string
}

type ChainInfo struct {
	Identifier           int64  `json:"id"`
	RpcUrl               string `json:"rpcUrl"`
	StateContractAddress string `json:"stateContractAddress"`
	RarimoNetworkType    string `json:"rarimoNetworkType"`
}

type GISTProofInfo struct {
	Root         *merkletree.Hash     `json:"root"`
	Existence    bool                 `json:"existence"`
	Siblings     [64]*merkletree.Hash `json:"siblings"`
	Index        *merkletree.Hash     `json:"index"`
	Value        *merkletree.Hash     `json:"value"`
	AuxExistence bool                 `json:"aux_existence"`
	AuxIndex     *merkletree.Hash     `json:"aux_index"`
	AuxValue     *merkletree.Hash     `json:"aux_value"`
}

func (p *GISTProofInfo) GetProof() (*GISTProof, error) {
	gistProof := &GISTProof{
		Root: p.Root,
	}

	proof := merkletree.Proof{
		Existence: p.Existence,
	}

	if p.AuxExistence {
		proof.NodeAux = &merkletree.NodeAux{
			Key:   p.AuxIndex,
			Value: p.AuxValue,
		}
	}

	siblings := make([]*merkletree.Hash, 0, 64)
	for _, s := range p.Siblings {
		siblings = append(siblings, s)
	}

	proof.Siblings = siblings

	gistProof.Proof = &proof

	return gistProof, nil
}

type GISTProof struct {
	Root  *merkletree.Hash  `json:"root"`
	Proof *merkletree.Proof `json:"proof"`
}

type StateProvider interface {
	GetGISTProof(userId string, blockNumber string) ([]byte, error)
	ProveAuthV2(inputs []byte) ([]byte, error)
	Fetch(url string, method string, body []byte, headerKey string, headerValue string) ([]byte, error)
	LocalPrinter(msg string)
	ProveCredentialAtomicQueryMTPV2OnChainVoting(inputs []byte) ([]byte, error)
	IsUserRegistered(contract string, documentNullifier []byte) (bool, error)
}

type CredentialStatus struct {
	Identifier      string            `json:"id"`
	InnerType       string            `json:"type"`
	RevocationNonce *big.Int          `json:"revocationNonce,omitempty"`
	StatusIssuer    *CredentialStatus `json:"statusIssuer,omitempty"`
}

type CredentialSchema struct {
	Id        string `json:"id"`
	InnerType string `json:"type"`
}

type VSResponseBody struct {
	Credential verifiable.W3CCredential `json:"credential"`
}

type VSResponse struct {
	Body VSResponseBody `json:"body"`
}

type CredentialRequest struct {
	Description string `json:"description"`
	Identifier  string `json:"id"`
}

func NewCredentialRequest(description string, id string) *CredentialRequest {
	return &CredentialRequest{
		Description: description,
		Identifier:  id,
	}
}

type CredentialsRequestBody struct {
	Credentials []CredentialRequest `json:"Credentials"`
	Url         string              `json:"url"`
}

func NewCredentialsRequestBody(credentials []CredentialRequest, url string) *CredentialsRequestBody {
	return &CredentialsRequestBody{
		Credentials: credentials,
		Url:         url,
	}
}

type ClaimOfferResponse struct {
	Identifier string                 `json:"id"`
	Typ        string                 `json:"typ"`
	ClaimType  string                 `json:"type"`
	ThreadID   string                 `json:"threadID"`
	Body       CredentialsRequestBody `json:"body"`
	From       string                 `json:"from"`
	To         string                 `json:"to"`
}

func NewClaimOfferResponse(
	id string,
	typ string,
	claimType string,
	threadID string,
	body CredentialsRequestBody,
	from string,
	to string,
) *ClaimOfferResponse {
	return &ClaimOfferResponse{
		Identifier: id,
		Typ:        typ,
		ClaimType:  claimType,
		ThreadID:   threadID,
		Body:       body,
		From:       from,
		To:         to,
	}
}

type claimDetailsBody struct {
	Id string `json:"id"`
}

func NewClaimDefailsBody(id string) *claimDetailsBody {
	return &claimDetailsBody{
		Id: id,
	}
}

type ClaimDetails struct {
	Id        string           `json:"id"`
	Typ       string           `json:"typ"`
	ClaimType string           `json:"type"`
	ThreadID  string           `json:"threadID"`
	Body      claimDetailsBody `json:"body"`
	From      string           `json:"from"`
	To        string           `json:"to"`
}

func NewClaimDetails(
	id string,
	typ string,
	claimType string,
	threadID string,
	body claimDetailsBody,
	from string,
	to string,
) *ClaimDetails {
	return &ClaimDetails{
		Id:        id,
		Typ:       typ,
		ClaimType: claimType,
		ThreadID:  threadID,
		Body:      body,
		From:      from,
		To:        to,
	}
}

type ProofData struct {
	A        []string   `json:"pi_a"`
	B        [][]string `json:"pi_b"`
	C        []string   `json:"pi_c"`
	Protocol string     `json:"protocol"`
}

type ZKProof struct {
	Proof      *ProofData `json:"proof"`
	PubSignals []string   `json:"pub_signals"`
}

type AtomicQueryMTPV2OnChainVotingCircuitInputs struct {
	RequestID string `json:"requestID"`

	// user data
	UserGenesisID            string `json:"userGenesisID"`            //
	ProfileNonce             string `json:"profileNonce"`             //
	ClaimSubjectProfileNonce string `json:"claimSubjectProfileNonce"` //

	IssuerID string `json:"issuerID"`
	// Claim
	IssuerClaim *core.Claim `json:"issuerClaim"`
	// Inclusion
	IssuerClaimMtp            []*merkletree.Hash `json:"issuerClaimMtp"`
	IssuerClaimClaimsTreeRoot *merkletree.Hash   `json:"issuerClaimClaimsTreeRoot"`
	IssuerClaimRevTreeRoot    *merkletree.Hash   `json:"issuerClaimRevTreeRoot"`
	IssuerClaimRootsTreeRoot  *merkletree.Hash   `json:"issuerClaimRootsTreeRoot"`
	IssuerClaimIdenState      *merkletree.Hash   `json:"issuerClaimIdenState"`

	IssuerClaimNonRevClaimsTreeRoot *merkletree.Hash   `json:"issuerClaimNonRevClaimsTreeRoot"`
	IssuerClaimNonRevRevTreeRoot    *merkletree.Hash   `json:"issuerClaimNonRevRevTreeRoot"`
	IssuerClaimNonRevRootsTreeRoot  *merkletree.Hash   `json:"issuerClaimNonRevRootsTreeRoot"`
	IssuerClaimNonRevState          *merkletree.Hash   `json:"issuerClaimNonRevState"`
	IssuerClaimNonRevMtp            []*merkletree.Hash `json:"issuerClaimNonRevMtp"`
	IssuerClaimNonRevMtpAuxHi       *merkletree.Hash   `json:"issuerClaimNonRevMtpAuxHi"`
	IssuerClaimNonRevMtpAuxHv       *merkletree.Hash   `json:"issuerClaimNonRevMtpAuxHv"`
	IssuerClaimNonRevMtpNoAux       string             `json:"issuerClaimNonRevMtpNoAux"`

	IsRevocationChecked int `json:"isRevocationChecked"`

	ClaimSchema string `json:"claimSchema"`

	// Query
	// JSON path
	ClaimPathNotExists int                `json:"claimPathNotExists"` // 0 for inclusion, 1 for non-inclusion
	ClaimPathMtp       []*merkletree.Hash `json:"claimPathMtp"`
	ClaimPathMtpNoAux  string             `json:"claimPathMtpNoAux"` // 1 if aux node is empty,
	// 0 if non-empty or for inclusion proofs
	ClaimPathMtpAuxHi *merkletree.Hash `json:"claimPathMtpAuxHi"` // 0 for inclusion proof
	ClaimPathMtpAuxHv *merkletree.Hash `json:"claimPathMtpAuxHv"` // 0 for inclusion proof
	ClaimPathKey      string           `json:"claimPathKey"`      // hash of path in merklized json-ld document
	ClaimPathValue    string           `json:"claimPathValue"`    // value in this path in merklized json-ld document

	Operator  int      `json:"operator"`
	SlotIndex int      `json:"slotIndex"`
	Timestamp int64    `json:"timestamp"`
	Value     []string `json:"value"`

	// AuthClaim proof of inclusion
	AuthClaim    *core.Claim        `json:"authClaim"`
	AuthClaimMtp []*merkletree.Hash `json:"authClaimIncMtp"`

	// AuthClaim non revocation proof
	AuthClaimNonRevMtp      []*merkletree.Hash `json:"authClaimNonRevMtp"`
	AuthClaimNonRevMtpAuxHi *merkletree.Hash   `json:"authClaimNonRevMtpAuxHi"`
	AuthClaimNonRevMtpAuxHv *merkletree.Hash   `json:"authClaimNonRevMtpAuxHv"`
	AuthClaimNonRevMtpNoAux string             `json:"authClaimNonRevMtpNoAux"`

	Challenge             string `json:"challenge"`
	ChallengeSignatureR8X string `json:"challengeSignatureR8x"`
	ChallengeSignatureR8Y string `json:"challengeSignatureR8y"`
	ChallengeSignatureS   string `json:"challengeSignatureS"`

	// User State
	ClaimsTreeRoot *merkletree.Hash `json:"userClaimsTreeRoot"`
	RevTreeRoot    *merkletree.Hash `json:"userRevTreeRoot"`
	RootsTreeRoot  *merkletree.Hash `json:"userRootsTreeRoot"`
	State          *merkletree.Hash `json:"userState"`

	// Global on-chain state
	GISTRoot     *merkletree.Hash   `json:"gistRoot"`
	GISTMtp      []*merkletree.Hash `json:"gistMtp"`
	GISTMtpAuxHi *merkletree.Hash   `json:"gistMtpAuxHi"`
	GISTMtpAuxHv *merkletree.Hash   `json:"gistMtpAuxHv"`
	GISTMtpNoAux string             `json:"gistMtpNoAux"`

	VotingAddress string `json:"votingAddress"`
	Commitment    string `json:"commitment"`
}

type Issuer struct {
	State          string `json:"state"`
	RootOfRoots    string `json:"rootOfRoots"`
	ClaimsTreeRoot string `json:"claimsTreeRoot"`
	RevTreeRoot    string `json:"revocationTreeRoot"`
}

func (i *Issuer) GetIssuerPreparedState() (*TreeState, error) {
	state, err := merkletree.NewHashFromHex(i.State)
	if err != nil {
		return nil, err
	}

	rootOfRoots, err := merkletree.NewHashFromHex(i.RootOfRoots)
	if err != nil {
		return nil, err
	}

	claimsTreeRoot, err := merkletree.NewHashFromHex(i.ClaimsTreeRoot)
	if err != nil {
		return nil, err
	}

	revTreeRoot, err := merkletree.NewHashFromHex(i.RevTreeRoot)
	if err != nil {
		return nil, err
	}

	return &TreeState{
		State:           state,
		RootsRoot:       rootOfRoots,
		ClaimsRoot:      claimsTreeRoot,
		RevocationsRoot: revTreeRoot,
	}, nil
}

type TreeStateIssuerPreparedState struct {
	State          *merkletree.Hash
	RootOfRoots    *merkletree.Hash
	ClaimsTreeRoot *merkletree.Hash
	RevTreeRoot    *merkletree.Hash
}

type ProofStatus struct {
	Mtp    *merkletree.Proof `json:"mtp"`
	Issuer *Issuer           `json:"issuer"`
}

type ProofState struct {
	TxID               string `json:"txID,omitempty"`
	BlockTimestamp     int64  `json:"blockTimestamp,omitempty"`
	BlockNumber        int64  `json:"blockNumber,omitempty"`
	RootOfRoots        string `json:"rootOfRoot"`
	ClaimsTreeRoot     string `json:"claimsTreeRoot"`
	RevocationTreeRoot string `json:"revocationTreeRoot"`
	Value              string `json:"value"`
	Status             string `json:"status,omitempty"`
}

type IssuerData struct {
	Identifier       string            `json:"identifier"`
	State            ProofState        `json:"state"`
	AuthCoreClaim    *core.Claim       `json:"authCoreClaim,omitempty"`
	Mtp              *merkletree.Proof `json:"mtp,omitempty"`
	CredentialStatus *CredentialStatus `json:"credentialStatus,omitempty"`
	UpdateURL        string            `json:"updateURL"`
}

type Iden3SparseMerkleTreeProof struct {
	Type       string            `json:"type"`
	IssuerData *IssuerData       `json:"issuerData"`
	Mtp        *merkletree.Proof `json:"mtp"`
	CoreClaim  string            `json:"coreClaim"`
	Identifier string            `json:"id"`
}

func (p *Iden3SparseMerkleTreeProof) GetCoreClaim() (*core.Claim, error) {
	var claim core.Claim
	if err := claim.FromHex(p.CoreClaim); err != nil {
		return nil, err
	}

	return &claim, nil
}

func (p *Iden3SparseMerkleTreeProof) ProofType() verifiable.ProofType {
	return verifiable.Iden3SparseMerkleTreeProofType
}

type BJJSignatureProof2021 struct {
	ProofType  string      `json:"type"`
	IssuerData *IssuerData `json:"issuerData"`
	Signature  string      `json:"signature"`
	CoreClaim  string      `json:"coreClaim"`
}

type CircuitClaim struct {
	IssuerId       string
	Claim          *core.Claim
	SignatureProof *BJJSignatureProof
	Status         *ProofStatus
}

type MTP struct {
	Proof     *merkletree.Proof `json:"proof"`
	TreeState *TreeState        `json:"treeState,omitempty"`
}

type BJJSignatureProof struct {
	Signature             *babyjub.Signature `json:"signature"`
	IssuerAuthClaim       *core.Claim        `json:"issuerAuthClaim,omitempty"`
	IssuerAuthIncProof    *MTP               `json:"issuerAuthIncProof"`
	IssuerAuthNonRevProof *MTP               `json:"issuerAuthNonRevProof"`
}

type CreateProofRequest struct {
	AccountAddress string      `json:"accountAddress"`
	CircuitId      CircuitId   `json:"circuitId"`
	Query          *ProofQuery `json:"query"`
}

type ProofQuery struct {
	AllowedIssuers      []string                     `json:"allowedIssuers,omitempty"`
	CredentialSubject   *ProofQueryCredentialSubject `json:"credentialSubject,omitempty"`
	CredentialSubjectId string                       `json:"credentialSubjectId,omitempty"`
	Type                []string                     `json:"type,omitempty"`
}

type ProofQueryCredentialSubject struct {
	CredentialHash *CredentialHash `json:"credentialHash"`
}

type CredentialHash struct {
	Eq string `json:"$eq"`
}

type Query struct {
	SlotIndex  int         `json:"slotIndex"`
	Values     []*big.Int  `json:"values"`
	Operator   Operators   `json:"operator"`
	ValueProof *ValueProof `json:"valueProof,omitempty"`
}

type ValueProof struct {
	Path  *big.Int          `json:"path"`
	Value *big.Int          `json:"value"`
	Mtp   *merkletree.Proof `json:"mtp"`
}

type SerializationSchema struct {
	IndexDataSlotA string `json:"indexDataSlotA"`
	IndexDataSlotB string `json:"indexDataSlotB"`
	ValueDataSlotA string `json:"valueDataSlotA"`
	ValueDataSlotB string `json:"valueDataSlotB"`
}

type SchemaMetadata struct {
	Uris          map[string]string    `json:"uris"`
	Serialization *SerializationSchema `json:"serialization,omitempty"`
}

type JSONSchema struct {
	Metadata SchemaMetadata `json:"$metadata"`
	Schema   string         `json:"$schema"`
	Type     string         `json:"type"`
}

type OperationProof struct {
	Path      []string `json:"path"`
	Signature string   `json:"signature"`
}

type StateInfo struct {
	Index                  string `json:"index"`
	Hash                   string `json:"hash"`
	CreatedAtTimestamp     string `json:"createdAtTimestamp"`
	CreatedAtBlock         string `json:"createdAtBlock"`
	LastUpdateOperationIdx string `json:"lastUpdateOperationIndex"`
}

type GetStateInfoResponse struct {
	State StateInfo `json:"state"`
}

type CoreMTP struct {
	Proof []string `json:"proof"`
}

type OperationData struct {
	Operation Operation `json:"operation"`
}

type Operation struct {
	Index         string           `json:"index"`
	OperationType string           `json:"operationType"`
	Details       OperationDetails `json:"details"`
	Status        string           `json:"status"`
	Creator       string           `json:"creator"`
	Timestamp     string           `json:"timestamp"`
}

type OperationDetails struct {
	Type          string `json:"@type"`
	Contract      string `json:"contract"`
	Chain         string `json:"chain"`
	GISTHash      string `json:"GISTHash"`
	StateRootHash string `json:"stateRootHash"`
	Timestamp     string `json:"timestamp"`
}
