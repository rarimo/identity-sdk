package identity_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/rarimo/registration-relayer/resources"
	"github.com/rarimovoting/identity"
)

const keysCount = 3

func TestGenerateCrypto(t *testing.T) {
	for j := 0; j < keysCount; j++ {
		key := babyjub.NewRandPrivKey()

		i, e := big.NewInt(2), big.NewInt(248)
		maxKeySize := i.Exp(i, e, nil)

		secret, err := rand.Int(rand.Reader, maxKeySize)
		if err != nil {
			t.Fatal(fmt.Errorf("error generating secret: %v", err))
		}

		nullifier, err := rand.Int(rand.Reader, maxKeySize)
		if err != nil {
			t.Fatal(fmt.Errorf("error generating nullifier: %v", err))
		}

		var comma string
		if j < keysCount-1 {
			comma = ","
		}

		fmt.Printf(`
		{
			identityArgs: identityArgs{
				secretKeyHex: "0x%s",
				secretHex:    "0x%s",
				nullifierHex: "0x%s",
			},
		}%s
`, hex.EncodeToString(key[:]), secret.Text(16), nullifier.Text(16), comma)
	}
}

func TestCreateAndRegister(t *testing.T) {
	env := fromEnv()
	provider, err := identity.NewStateProvider(env.identityProviderURL)
	if err != nil {
		t.Fatal(err)
	}

	// generate in TestGenerateCrypto and paste here
	testCases := []struct {
		identityArgs
		registerArgs
	}{
		{
			identityArgs: identityArgs{
				secretKeyHex: "0xb34c4f6ef68d95d72b49c7bec5b8ecba55d2e0a82b81b55d8e6dd292107ea51d",
				secretHex:    "0x264cc18cef255b00af5188b5ecd96c88e10fff05f27a3b116f4cdca9f02439",
				nullifierHex: "0x94ce952a70c516d4415869e6ea76ddc9a87ca9de412dcc0d3ce5975ed14303",
			},
		},

		{
			identityArgs: identityArgs{
				secretKeyHex: "0xf361688e574840b2d1b1bf4af15b548e048fccba581eec95b9b4bda6844a85c1",
				secretHex:    "0x1efe93dce05281b56be7653ea585dc8cba94eec80286da4e7458542fc2d224",
				nullifierHex: "0xf1ed6b705caf03e7cad9c488e5f3517c2b0a7c59426a440e467d5d707cb6f6",
			},
		},

		{
			identityArgs: identityArgs{
				secretKeyHex: "0xfc83355e0327740b200467e63bbda96b551a617be7d16c91ced7107fa53f9304",
				secretHex:    "0xd76d8f806a8afee1fe85a9971b98814f045ca89cf2d0c1f7801cfb8ebe8016",
				nullifierHex: "0x670add141d23ecb75e0644ef1d621300c7fa2178b756719c4320f9d85d71d7",
			},
		},
	}

	for i := range testCases {
		testCases[i].provider = provider
		testCases[i].registerArgs = env.registerArgs
	}

	for i, tc := range testCases {
		t.Run(fmt.Sprintf("identity_%d", i), func(t *testing.T) {
			t.Logf("=== START OF RUN %d ===", i)
			cd, err := generateCalldata(tc.identityArgs, tc.registerArgs)
			if err != nil {
				t.Fatal(err)
			}

			txHash, err := postCalldata(env.relayerURL, cd)
			if err != nil {
				t.Fatal(fmt.Errorf("failed to post calldata: %v", err))
			}

			t.Logf("txHash: %s\n=== END OF RUN %d ===", txHash, i)
		})
	}
}

type envArgs struct {
	relayerURL          string
	identityProviderURL string
	registerArgs
}

func fromEnv() envArgs {
	mustEnv := func(k string) string {
		v := os.Getenv(k)
		if v == "" {
			panic(fmt.Sprintf("env var %s must be set", k))
		}
		return v
	}

	schemaString := mustEnv("SCHEMA_JSON_LD")
	stateString := mustEnv("STATE_INFO_JSON")

	schema, err := hex.DecodeString(schemaString)
	if err != nil {
		panic(fmt.Sprintf("error decoding SCHEMA_JSON_LD value: %v", err))
	}

	state, err := hex.DecodeString(stateString)
	if err != nil {
		panic(fmt.Sprintf("error decoding STATE_INFO_JSON value: %v", err))
	}

	return envArgs{
		relayerURL:          mustEnv("RELAYER_URL"),
		identityProviderURL: mustEnv("IDENTITY_PROVIDER_URL"),
		registerArgs: registerArgs{
			rarimoCoreURL:        mustEnv("RARIMO_CORE_URL"),
			issuerDid:            mustEnv("ISSUER_DID"),
			votingAddress:        mustEnv("VOTING_ADDRESS"),
			issuingAuthorityCode: mustEnv("ISSUING_AUTHORITY_CODE"),
			schemaJsonLd:         schema,
			stateInfoJSON:        state,
		},
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
	issuingAuthorityCode string
	schemaJsonLd         []byte
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
