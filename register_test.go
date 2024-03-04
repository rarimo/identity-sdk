package identity_test

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

var PRIVATE_KEY = ""
var RPC = ""
var CONTRACT_ADDRESS = ""
var CALLDATA = ""

func TestCalldata(t *testing.T) {
	client, err := ethclient.Dial(RPC)
	if err != nil {
		log.Fatal(err)
	}

	privateKey, err := crypto.HexToECDSA(PRIVATE_KEY)
	if err != nil {
		log.Fatal(err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(fromAddress)

	gasLimit := uint64(5_000_000)
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	toAddress := common.HexToAddress(CONTRACT_ADDRESS)

	rawCalldata, err := hex.DecodeString(CALLDATA)
	if err != nil {
		log.Fatal(err)
	}

	tx := types.NewTransaction(nonce, toAddress, big.NewInt(0), gasLimit, gasPrice, rawCalldata)

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatal(err)
	}

	if err := client.SendTransaction(context.Background(), signedTx); err != nil {
		log.Fatal(err)
	}

	t.Log("tx sent: ", signedTx.Hash().Hex())
}

// func TestGetTX(t *testing.T) {
// 	txHash := common.HexToHash("0x5e29513ba6e502fe0c46017978728fb65bd1033334cb640e1b80c2f3b32f84b1")

// 	client, err := ethclient.Dial(RPC)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	reason, err := GetFailingMessage(*client, txHash)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	log.Fatal(reason)
// }

// func GetFailingMessage(client ethclient.Client, hash common.Hash) (string, error) {
// 	tx, _, err := client.TransactionByHash(context.Background(), hash)
// 	if err != nil {
// 		return "", err
// 	}

// 	from, err := types.Sender(types.NewEIP155Signer(tx.ChainId()), tx)
// 	if err != nil {
// 		return "", err
// 	}

// 	msg := ethereum.CallMsg{
// 		From:     from,
// 		To:       tx.To(),
// 		Gas:      tx.Gas(),
// 		GasPrice: tx.GasPrice(),
// 		Value:    tx.Value(),
// 		Data:     tx.Data(),
// 	}

// 	res, err := client.CallContract(context.Background(), msg, nil)
// 	if err != nil {
// 		return "", err
// 	}

// 	return string(res), nil
// }
