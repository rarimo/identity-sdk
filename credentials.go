package identity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/iden3/go-iden3-core/v2/w3c"
	"gitlab.com/distributed_lab/logan/v3/errors"
)

type CreateIdentityRequestData struct {
	ID          *w3c.DID `json:"id"`
	ZKProof     ZKProof  `json:"zkproof"`
	DocumentSOD struct {
		SignedAttributes    string `json:"signed_attributes"`
		Algorithm           string `json:"algorithm"`
		Signature           string `json:"signature"`
		PemFile             string `json:"pem_file"`
		EncapsulatedContent string `json:"encapsulated_content"`
	} `json:"document_sod"`
}

type ClaimResponse struct {
	Data struct {
		Key struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		} `json:"key"`
		Attributes struct {
			ClaimId   string `json:"claim_id"`
			IssuerDid string `json:"issuer_did"`
		} `json:"attributes"`
	} `json:"data"`
}

func createCredential(userDID *w3c.DID) (*ClaimResponse, error) {
	var createIdentityRequest struct {
		Data CreateIdentityRequestData `json:"data"`
	}
	if err := json.Unmarshal([]byte(createCredRawReq), &createIdentityRequest); err != nil {
		return nil, err
	}
	createIdentityRequest.Data.ID = userDID

	rawCreateIdentityRequest, err := json.Marshal(createIdentityRequest)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8000/integrations/identity-provider-service/v1/create-identity", bytes.NewReader(rawCreateIdentityRequest))
	if err != nil {
		return nil, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	var claimResp ClaimResponse
	if err = json.NewDecoder(res.Body).Decode(&claimResp); err != nil {
		return nil, err
	}

	return &claimResp, nil
}

func (i *Identity) SetCredentials(rarimoCoreUrl string, rawStateInfo []byte) error {
	cred, err := createCredential(i.did)
	if err != nil {
		return err
	}

	createdAt := time.Now().Unix()
	finalised := false
	for !finalised {
		finalised, _, err = i.IsFinalized(rarimoCoreUrl, cred.Data.Attributes.IssuerDid, createdAt, nil)
		if err != nil {
			return nil
		}
	}

	// Sleep 10 seconds
	time.Sleep(10 * time.Second)

	claimOffer, err := getClaimOffer(cred.Data.Attributes.ClaimId)
	if err != nil {
		return errors.Wrap(err, "failed to get claim offer")
	}

	rawOfferResp, err := json.Marshal(claimOffer)
	if err != nil {
		return errors.Wrap(err, "failed to marshal claim offer")
	}

	if err = i.InitVerifiableCredentials(rawOfferResp); err != nil {
		return errors.Wrap(err, "failed to init verifiable credentials")
	}

	return nil
}

func getClaimOffer(claimID string) (*ClaimOfferResponse, error) {
	var issuerURL = fmt.Sprintf("https://issuer.polygon.robotornot.mainnet-beta.rarimo.com/v1/offer/%s", claimID)
	resp, err := http.Get(issuerURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed to fetch claim offer")
	}

	var claimOffer ClaimOfferResponse
	if err = json.NewDecoder(resp.Body).Decode(&claimOffer); err != nil {
		return nil, errors.Wrap(err, "failed to decode claim offer")
	}

	return &claimOffer, nil
}

const createCredRawReq = `{
    "data": {
        "id": "did:iden3:readonly:tVdHmzLBuQxhVDjmMX548BZ7FnSjpmAyk6aqfaA7d",
        "document_sod": {
            "algorithm": "SHA256withRSA",
            "signed_attributes": "3148301506092a864886f70d01090331080606678108010101302f06092a864886f70d01090431220420bbdf9e5addbf041991e52f2d044149e00b6caf4471850da8b72f287968462a56",
            "pem_file": "-----BEGIN CERTIFICATE-----\nMIIGKTCCBBGgAwIBAgIDGGzxMA0GCSqGSIb3DQEBCwUAMIGQMQswCQYDVQQGEwJV\nQTEZMBcGA1UEBRMQVUEtMTYyODY0NDEtMDAwMTE8MDoGA1UECgwzUG9seWdyYXBo\nIGNvbWJpbmUgVUtSQUlOQSBmb3Igc2VjdXJpdGllcyBwcm9kdWN0aW9uMREwDwYD\nVQQLDAhTQ1BEIFBDVTEVMBMGA1UEAwwMQ1NDQS1VS1JBSU5FMB4XDTE4MDYyMjEz\nNDMxNloXDTI4MDkyMjEzNDMxNlowgcgxCzAJBgNVBAYTAlVBMT8wPQYDVQQDDDZT\nRSBQb2x5Z3JhcGggY29tYmluZSBVS1JBSU5BIGZvciBzZWN1cml0aWVzIHByb2R1\nY3Rpb24xGTAXBgNVBAUTEFVBLTE2Mjg2NDQxLTAwMDIxPzA9BgNVBAoMNlNFIFBv\nbHlncmFwaCBjb21iaW5lIFVLUkFJTkEgZm9yIHNlY3VyaXRpZXMgcHJvZHVjdGlv\nbjENMAsGA1UECwwEU0NQRDENMAsGA1UEBwwES3lpdjCCAiIwDQYJKoZIhvcNAQEB\nBQADggIPADCCAgoCggIBAOXaU9kqZCzMXuzxoxxxQ4NiU6SBX8dfO4urkWWlaV4y\nOBG4JcWVFavrOv+wqF1\/KcgGrLf8f8VrwPNoj9RoTjyPGnCkVsdrvuxiG0TFIo00\nPY7EWcsBqgFlE0puaWvFGtHl0PunV9troBgOn9b7ZkA\/ubYDv0S0Usptms72FJVi\nvvXpVoGA\/DLNmptwjBqlgZ+k0uqOrfLFW5IwgiMtZN4ijKymnyAUTRu7HI5vIEFu\nTz\/Fu+bx7xwTC3tq+JkyeYB9RRZf3q7OQvZNp9mTDseQkBhv1L3IpWqfimwrN+Lj\nZoLbelXkTrMYFNvE5jLuXxUjNC67aqbJB50+LZWSMilf6CNqubx4kSVyRcBv0yRo\nVUycUIvA3Adx26fvr4NHmkkmEjnHwmp5vyom\/yL+Se7XCtdfYELJ21qWKG8zvkel\n3CMVOwNOXzUcwidB7FX43LsNVJwyFYhbv4iQ8pNR0KEOZn5edC5TxYQfcNFHxS11\nkRbo0aAwVySyX\/wLCW8jJVccK0kwnR\/2R8erfk1068cLg1AlsTFcIpaoqnVgOiKR\nOylyOeypgA1S5fUHZHU+RSqC2ByKC9hgwNHji7\/K\/qM0FI3pThBMOFhy5J0ivXl\/\nzM7tkRVxoj\/IY\/JJ\/bEtln6uOEoMiyLWfLPkdGNXW8N\/zeHvsrkw4+NDriB2ox2f\nAgMBAAGjUjBQMB0GA1UdDgQWBBRSvkbOL+R\/Zsg3DidoL+8qoaoT4DAfBgNVHSME\nGDAWgBRgNP\/WOOYC4wrv2JxxON7M0G0g9DAOBgNVHQ8BAf8EBAMCB4AwDQYJKoZI\nhvcNAQELBQADggIBAE9GuvQgyqIbBqE1jVliy8PkLuAUQ1N8w7T7f87gTPjFbAw9\ndicNnbpl5BcNSgpCHLrZrHWjtAC9DiVUBL33mpKyi0mDx96FUmU0G4mqVtazl\/Uu\nlQX+8h87Cnqsw7NMW759hn5CsxZFGCqduwsmTY2cA9Pek9WE1PsGlcMZ4x4KXue8\noa738sON3mXtXVcP05o+joJbWEhwKkz3ATmYb8\/qlzDVmn1Ex1C5DAEbfspJveZo\nTPFOOSZZ1bHBvGjkmeKT1tX9VP2UjgVPnKS6nQADTNOVxeX2U5QfwoTOJv\/EO6T\/\nZlofIKvuSnSYmPMid79dHnrpW5imAn2tw26C7hxck7IT52BFx+Z9dLoLpCGeAifi\nRN72Lf9\/wbVgbhl4gsJQ7EpWVZDzY5pmiUh5y9npzK49tbOU6VWH4gatY4mCT9Ja\noTdaTLLilO6CDx+Jab2aDvea4bjUTdkmJM2cdG2kWJXmCXGCI3j31HyYlaD9tMn4\n3wS\/H+RE2WZviZhkh8hXht6zsDhWxlOzN0UlEzGNy4SZwJu8sOykyfVNYib9Af0o\nqd451ohTgRczL9oGLzrVZkXFshMiElk0MQ1CAEegp1O0IG0ewADO2\/uasHGsA\/fI\nEn4hC8BJ2pmFjVmaa1uRx28+0PaxPEnzreIpCgR3F78ChAZcqX+3Cvyl6YqR\n-----END CERTIFICATE-----\n",
            "signature": "c7fdd2d014ea7530f3ece142e15bab74ee3a135ac8f05fc194f8ab9ab667bd2d8c1322d89c6e6dc0c54a12d14b82a86e3a2cd38c32a21426289c50efd0ff5c480869a8721635b56f5bea1c809c2c4a2ff9322d89e4e96770363b8674c97f9333a004850d68726dabefb63f0706241cd0081c16f631dc094b54805923417e246aa1a4d50324c5b5be7e5d2a16d2981af4001f20cd42c2c9727d76fd81056482014c8aeebed41c63fbce9b13ab65afa5c5bd28886978a27cd402b7a7b81c47cc07a689e28c5c6ad919dc7c8a9b1858f9283080da1db85ea3dd035825f4bfa768a065ce86fcacff64f4b843095d551af89bb1010376bdac1d25921fd9a5f4724e5ece009c78f30755e213f402b61de94b51cc6ec911786edd940eca5ac87d560204e61705346752164b14da605dd80a20e77c72ac5f2595a7ab409e228e25ef59a5b69a0b9a4979a7ed6cde7e932a60ec127bcb2c879f6c8e341f6f20653daec2f8f2a31ed1f839155c16c7e219700f305f5f70ace0ad48f2b662d9966d2cbe9378d1378a35066e81a4724f680e74c66037d4598858839f06725516ebe378d4e3c7ca5e473c2e303a4e6d2ef01d75c5c165ad86e56e11f764b9705844aee52c1784919d369548c2f67f1864954b3009d7b7fcad98051cf1a19bd77417da4930d5e098307fb8ee2392871dde12454e5ffb144677466deaba896962663a3e17688d89",
            "encapsulated_content": "3082014c020100300b0609608648016503040201308201383025020101042074a48d6361ac698d5261e18b368a96c6f399ff4d05a3676793bb1ef668364daa30250201020420c90aec41a338fb8a21a7ca26646d73b27598c6774d3ad176d561cfc4d1443f5c30250201030420c0f214e1e5c30c34e64ad49f4dd149e604a7543b39c6f3a41b19cc90bda20136302502010504206071e79f8f69c5f8e3f29e9bc5566a39a6ecf90e6268b2844db85d5caa24c6ec3025020107042081f6e976e2d8e5d9dea9d73a8bbe64f964f487d8dd498ff73e7b11d50bc0d0d8302502010d04200cc25db3c0fb4f893f35ba9f5649424c3e45b17ed730c70410694466c5be1b7c302502010e042092547f46705bb3c4acde31ce115423f5733ceae755230a24b5692d96e2cc42ee302502010f0420ec0806b894dd53fe9d7253e0ca0e81d2ff5fb4302beed4bc17ce18ff1ea4ab53"
        },
        "zkproof": {
            "pub_signals": [
                "155044851889420636434671896075824699078",
                "323802002511852798789213804090977832362",
                "4903594",
                "24",
                "5",
                "20",
                "25",
                "5",
                "20",
                "18"
            ],
            "proof": {
                "pi_b": [
                    [
                        "21598848726121200795857046178244931637813185780454081972885746152733530287731",
                        "19951032558743117731587499466680465362389200075789012079201209805195414679944"
                    ],
                    [
                        "19445351635267901810640634819612963343797020012476992895186793496958814563579",
                        "20005992294382347680973857778282490268839260636995737513930522988613906253281"
                    ],
                    [
                        "1",
                        "0"
                    ]
                ],
                "pi_c": [
                    "2998221255663212560465655275538779033180921314552111584743187788503501390518",
                    "13161532540790410017736457961441056328046597925961677430806225239007643058519",
                    "1"
                ],
                "pi_a": [
                    "20854290578031842053682424033156605362925800183906995285452104215978827146141",
                    "12059053090673738555419115480754252521883243838903602282091813361503137836642",
                    "1"
                ],
                "protocol": "groth16"
            }
        }
    }
}`
