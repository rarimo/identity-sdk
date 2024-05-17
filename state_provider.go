package identity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/iden3/go-rapidsnark/witness/v2"
	"github.com/rarimo/passport-identity-provider/resources"
	"gitlab.com/distributed_lab/logan/v3"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

type stateProvider struct {
	identityProviderURL *url.URL
}

func NewStateProvider(identityProviderURL string) (StateProvider, error) {
	parsedIdentityProviderURL, err := url.Parse(identityProviderURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse identity provider URL", logan.F{
			"url": identityProviderURL,
		})
	}

	return &stateProvider{
		identityProviderURL: parsedIdentityProviderURL,
	}, nil
}

func (s stateProvider) GetGISTProof(userId string, blockNumber string) ([]byte, error) {
	providerURL := s.identityProviderURL.JoinPath("/integrations/identity-provider-service/v1/gist-data")
	// sometimes blockNumber is empty
	if userId == "" {
		return nil, fmt.Errorf("user identifier is empty")
	}

	query := providerURL.Query()
	query.Set("user_did", userId)
	query.Set("block_number", blockNumber)
	providerURL.RawQuery = query.Encode()

	resp, err := http.Get(providerURL.String())
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch identity provider gist data", logan.F{
			"url": providerURL.String(),
		})
	}

	var gistData resources.GistDataResponse
	if err = json.NewDecoder(resp.Body).Decode(&gistData); err != nil {
		return nil, errors.Wrap(err, "failed to parse identity provider gist data")
	}

	rawProof, err := json.Marshal(gistData.Data.Attributes.GistProof)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode gist proof")
	}

	return rawProof, nil
}

func (s stateProvider) ProveAuthV2(inputs []byte) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (s stateProvider) Fetch(url string, method string, body []byte, headerKey string, headerValue string) ([]byte, error) {
	if len(body) == 0 || url == "" || method == "" || headerKey == "" || headerValue == "" {
		return nil, errors.From(errors.New("Fetch: some input is empty"), logan.F{
			"url": url, "method": method, "body": string(body), "headerKey": headerKey, "headerValue": headerValue,
		})
	}

	request, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build request")
	}

	request.Header.Set(headerKey, headerValue)

	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, errors.Wrap(err, "failed to make request")
	}

	defer resp.Body.Close()

	var rawBody []byte
	if err = json.NewDecoder(resp.Body).Decode(&rawBody); err != nil {
		return nil, errors.Wrap(err, "failed to parse body")
	}

	return rawBody, nil
}

func (s stateProvider) LocalPrinter(msg string) {
	//TODO implement me
	panic("implement me")
}

func (s stateProvider) ProveCredentialAtomicQueryMTPV2OnChainVoting(inputs []byte) ([]byte, error) {
	const (
		wasmFilePath            = "assets/voting/voting.wasm"
		zkeyFilePath            = "assets/voting/voting.zkey"
		verificationKeyFilePath = "assets/voting/voting.json"
	)

	if len(inputs) == 0 {
		return nil, errors.New("input bytes are empty")
	}

	parsedInputs, err := witness.ParseInputs(inputs)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse inputs")
	}

	votingProver, err := NewProver(wasmFilePath, zkeyFilePath, verificationKeyFilePath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create voting prover")
	}

	proof, err := votingProver.GenerateZKProof(parsedInputs)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate voting proof")
	}

	rawProof, err := json.Marshal(proof)
	if err != nil {
		return nil, errors.Wrap(err, "failed to encode voting proof")
	}

	return rawProof, nil
}

func (s stateProvider) IsUserRegistered(contract string, documentNullifier []byte) (bool, error) {
	//TODO implement me
	panic("implement me")
}
