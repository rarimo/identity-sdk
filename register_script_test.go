package identity_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/rarimo/registration-relayer/resources"
	"github.com/rarimovoting/identity"
)

func TestCreateAndRegister(t *testing.T) {
	// TODO impl and set, get from env
	var provider identity.StateProvider
	var relayerURL string
	var baseArgs = registerArgs{}

	testCases := []struct {
		identityArgs
		registerArgs
	}{
		{
			identityArgs{provider: provider},
			baseArgs,
		},
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("identity_%d", i), func(t *testing.T) {
			t.Logf("=== START OF RUN %d ===", i)
			cd, err := generateCalldata(tc.identityArgs, tc.registerArgs)
			if err != nil {
				t.Fatal(err)
			}

			txHash, err := postCalldata(relayerURL, cd)
			if err != nil {
				t.Fatal(fmt.Errorf("failed to post calldata: %v", err))
			}

			t.Logf("txHash: %s\n=== END OF RUN %d ===", txHash, i)
		})
	}
}

type identityArgs struct {
	secretKeyHex string
	secretHex    string
	nullifierHex string
	provider     identity.StateProvider
}

type registerArgs struct {
	rarimoCoreURL        string
	issuerDid            string
	votingAddress        string
	schemaJsonLd         []byte
	issuingAuthorityCode string
	stateInfoJSON        []byte
}

func generateCalldata(i identityArgs, r registerArgs) ([]byte, error) {
	id, err := identity.NewIdentityWithData(i.secretKeyHex, i.secretHex, i.nullifierHex, i.provider)
	if err != nil {
		return nil, err
	}

	cd, err := id.Register(
		r.rarimoCoreURL,
		r.issuerDid,
		r.votingAddress,
		r.schemaJsonLd,
		r.issuingAuthorityCode,
		r.stateInfoJSON,
	)
	return cd, err
}

type RegistrationRequestData struct {
	TxData string `json:"tx_data"`
}

type RegistrationRequest struct {
	Data RegistrationRequestData `json:"data"`
}

func postCalldata(u string, cd []byte) (string, error) {
	req := RegistrationRequest{
		Data: RegistrationRequestData{
			TxData: hexutil.Encode(cd), // must be with 0x prefix
		},
	}

	bb, err := json.Marshal(req)
	if err != nil {
		return "", err
	}

	r, err := http.Post(u, "application/json", bytes.NewReader(bb))
	if err != nil {
		return "", err
	}

	var resp resources.TxResponse
	if err = json.NewDecoder(r.Body).Decode(&resp); err != nil {
		return "", err
	}

	return resp.Data.Attributes.TxHash, nil
}
