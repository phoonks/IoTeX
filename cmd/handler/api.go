package handler

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/iotexproject/go-pkgs/hash"
	"github.com/iotexproject/iotex-address/address"
	"github.com/iotexproject/iotex-antenna-go/v2/account"
	"github.com/iotexproject/iotex-antenna-go/v2/iotex"
	"github.com/iotexproject/iotex-proto/golang/iotexapi"
	"github.com/iotexproject/iotex-proto/golang/iotextypes"
	cf "github.com/kahsengphoon/IoTeX/config"
	"google.golang.org/protobuf/proto"

	"github.com/urfave/cli/v2"
)

func (h *HttpServer) StartApiServer(c *cli.Context) error {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	if h.isStarted {
		return errors.New("Server already started")
	}

	r := gin.New()
	r.Use(gin.Recovery())
	h.isStarted = true
	h.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", h.port),
		Handler: r,
	}

	rawTx := SignWithRawTransaction()
	SignSerializedTransaction("3c6069d8b5d1a63eeb0a4247c40660c90d8001a26979fc3e339c59c41ce5ec70", rawTx)

	// SendSignedTransaction2("3c6069d8b5d1a63eeb0a4247c40660c90d8001a26979fc3e339c59c41ce5ec70")

	// CreateAddress()
	// Withdraw()
	if err := r.Run(fmt.Sprintf(":%v", cf.Enviroment().AppServerPort)); err != nil {
		return err
	}

	return nil
}

func CreateAddress() {
	acc, err := account.NewAccount()
	if err != nil {
		fmt.Println("Error creating account:", err)
		return
	}
	fmt.Printf("Testnet Wallet: %+v\n", acc)
	fmt.Printf("Testnet Wallet Address: %s\n", acc.Address().String())

	// Get the private key
	privateKey := acc.PrivateKey()
	publicKey := privateKey.PublicKey().Hash()
	fmt.Printf("Private Key: %x\n", privateKey.Bytes())
	fmt.Printf("Public Key: %x\n", publicKey)

	// Get the Ethereum address
	ethAddress, err := address.FromBytes(publicKey)
	if err != nil {
		fmt.Printf("Error getting Ethereum address: %v", err)
	}
	fmt.Printf("Ethereum Address: %s\n", ethAddress.Hex())

	// Testnet Wallet: &{private:0x1400011e6f8 address:0x14000036138}
	// Testnet Wallet Address: io16n6cz7u6956n90e6fw7reng5tnr2m7x89vkekz
	// Private Key: 3c6069d8b5d1a63eeb0a4247c40660c90d8001a26979fc3e339c59c41ce5ec70
	// Public Key: d4f5817b9a2d3532bf3a4bbc3ccd145cc6adf8c7
	// Ethereum Address: 0xd4f5817b9a2d3532bf3a4bbc3ccd145cc6adf8c7

	// Testnet Wallet: &{private:0x1400012aea0 address:0x1400045cd38}
	// Testnet Wallet Address: io1d6gajpq9j06u45dpz6z3l2ty95l8scwal2azul
	// Private Key: 745dd5b4f644c8f7e46a40804d9d503f7a5453019868f7e7b88627fdff633ed6
	// Public Key: 6e91d9040593f5cad1a116851fa9642d3e7861dd
	// Ethereum Address: 0x6e91d9040593f5cad1a116851fa9642d3e7861dd
}

func Withdraw() {
	conn, err := iotex.NewDefaultGRPCConn(testnetRPC)
	if err != nil {
		log.Fatalf("connection error : %v", err)
	}
	defer conn.Close()

	acc, err := account.HexStringToAccount("3c6069d8b5d1a63eeb0a4247c40660c90d8001a26979fc3e339c59c41ce5ec70")
	if err != nil {
		log.Fatalf("create account from private key error : %v", err)
	}
	c := iotex.NewAuthedClient(iotexapi.NewAPIServiceClient(conn), testnetChainID, acc)

	to, err := address.FromString("io1d6gajpq9j06u45dpz6z3l2ty95l8scwal2azul")
	if err != nil {
		log.Fatalf("invalid recipient address: %v", err)
	}

	// Amount to transfer (in Rau)
	amount := big.NewInt(100000000000000000) // 0.1 IOTX

	// Gas limit and gas price
	gasLimit := uint64(21000)
	gasPrice := big.NewInt(2200000000000) // 0.002 Qev

	resp, err := c.Transfer(to, amount).SetGasPrice(gasPrice).SetGasLimit(gasLimit).Call(context.Background())
	if err != nil {
		log.Fatalf("transfer error %v", err)
	}

	txHashHex := hex.EncodeToString(resp[:])
	fmt.Println("Transfer successful, transaction hash:", txHashHex)
	// [137 236 104 171 82 248 15 1 12 173 64 36 200 107 4 55 102 192 21 71 160 56 189 67 65 42 9 156 34 81 215 92]
	// 822c81514700e43b0f434760c0a45b709ec069b51de2ea9559ee537ea7b1ae72
	// 945b0147413a3713f7028a649f353c2a6f8ea5468cf425db6b16f289490a2daf
	// 2b08e568f83ca6d2e6e44c19a1768ee3610860210a4ebe226b155cd90fa8b3c9
	// 046b8fd1753fb5705a8056d2aa2e96b79226023bf7490d5f4ff094088705f408
	// 689e07be0aef2017036f8ce90f39a2be2c4c9e310b9e4ba76239c01d20fd1e61
}

func SignWithRawTransaction() string {
	// Recipient address
	recipientAddress := "io1d6gajpq9j06u45dpz6z3l2ty95l8scwal2azul"
	senderAddr := "io16n6cz7u6956n90e6fw7reng5tnr2m7x89vkekz"

	// Amount to transfer (in Rau)
	amount := big.NewInt(100000000000000000) // 0.1 IOTX

	// Gas limit and gas price
	gasLimit := uint64(21000)
	gasPrice := "2200000000000" // 2 Qev

	conn, err := iotex.NewDefaultGRPCConn(testnetRPC)
	if err != nil {
		log.Fatalf("connection error : %v", err)
	}
	defer conn.Close()

	client := iotexapi.NewAPIServiceClient(conn)

	// Fetch current nonce for sender's address
	senderAcc, err := client.GetAccount(context.Background(), &iotexapi.GetAccountRequest{
		Address: senderAddr,
	})
	if err != nil {
		log.Fatalf("GetAccount error : %v", err)
	}

	to, err := address.FromString(recipientAddress)
	if err != nil {
		log.Fatalf("invalid recipient address: %v", err)
	}
	// Create a transfer action
	transfer := &iotextypes.Transfer{
		Amount:    amount.String(),
		Recipient: to.String(),
	}

	// Create the ActionCore (the action details including nonce, gas, and the transfer action)
	// You should fetch the actual nonce for the sender. Here, it's set as 1 for simplicity.
	nonce := senderAcc.GetAccountMeta().GetPendingNonce()

	actionCore := &iotextypes.ActionCore{
		Nonce:    nonce,
		GasLimit: gasLimit,
		GasPrice: gasPrice,
		ChainID:  testnetChainID,
		Action: &iotextypes.ActionCore_Transfer{
			Transfer: transfer,
		},
	}

	// Convert the action to bytes (serialize it)
	rawTxBytes, err := proto.Marshal(actionCore)
	if err != nil {
		log.Fatalf("Error serializing action: %v", err)
	}

	// Convert the serialized transaction to a hexadecimal string
	rawTxHex := hex.EncodeToString(rawTxBytes)

	fmt.Println("Raw transaction (hex):", rawTxHex)

	// The rawTxHex can now be provided to another party for signing with their private key
	return rawTxHex
}

func SignSerializedTransaction(privateKeyHex, rawTxHex string) string {
	// The raw transaction (hexadecimal string) provided by the creator
	// Convert the hexadecimal string back to bytes
	rawTxBytes, err := hex.DecodeString(rawTxHex)
	if err != nil {
		log.Fatalf("Error decoding raw transaction hex: %v", err)
	}

	// Your private key (for signing the transaction)
	// Create an account from the private key
	acc, err := account.HexStringToAccount(privateKeyHex)
	if err != nil {
		log.Fatalf("create account from private key error : %v", err)
	}

	// Convert the bytes to action
	var actionCore iotextypes.ActionCore
	err = proto.Unmarshal(rawTxBytes, &actionCore)
	if err != nil {
		log.Fatalf("Error serializing action: %v", err)
	}

	// Hash the raw transaction using sha256
	rawTxsha256 := hash.Hash256b(rawTxBytes) // Produces a 32-byte hash

	// Sign the transfer action
	signedTx, err := acc.PrivateKey().Sign(rawTxsha256[:])
	if err != nil {
		log.Fatalf("Error signing transfer action: %v", err)
	}

	// Create the full action
	signedAction := &iotextypes.Action{
		Core:         &actionCore,
		SenderPubKey: acc.PublicKey().Bytes(),
		Signature:    signedTx,
	}

	conn, err := iotex.NewDefaultGRPCConn(testnetRPC)
	if err != nil {
		log.Fatalf("connection error : %v", err)
	}
	defer conn.Close()

	client := iotexapi.NewAPIServiceClient(conn)

	// Send the action
	resp, err := client.SendAction(context.Background(), &iotexapi.SendActionRequest{
		Action: signedAction,
	})
	if err != nil {
		log.Fatalf("Error sending signed transaction: %v", err)
	}

	fmt.Println("Transaction sent successfully, action hash:", resp.ActionHash)

	// The signedTxHex can now be sent to the IoTeX network
	return resp.ActionHash
}

func SendSignedTransaction2(privateKeyHex string) {
	// Recipient address
	recipientAddress := "io1d6gajpq9j06u45dpz6z3l2ty95l8scwal2azul"

	// Amount to transfer (in Rau)
	amount := big.NewInt(100000000000000000) // 0.1 IOTX

	// Gas limit and gas price
	gasLimit := uint64(21000)
	gasPrice := "2200000000000" // 2.2 Qev

	conn, err := iotex.NewDefaultGRPCConn(testnetRPC)
	if err != nil {
		log.Fatalf("connection error : %v", err)
	}
	defer conn.Close()

	client := iotexapi.NewAPIServiceClient(conn)

	// Your private key (for signing the transaction)
	// Create an account from the private key
	acc, err := account.HexStringToAccount(privateKeyHex)
	if err != nil {
		log.Fatalf("create account from private key error : %v", err)
	}

	senderAddress := acc.Address().String()
	// Fetch nonce for the sender
	accountResp, err := client.GetAccount(context.Background(), &iotexapi.GetAccountRequest{
		Address: senderAddress,
	})
	if err != nil {
		log.Fatalf("Failed to fetch account details: %v", err)
	}

	nonce := accountResp.GetAccountMeta().GetPendingNonce()

	// Create transfer action
	transfer := &iotextypes.Transfer{
		Amount:    amount.String(),
		Recipient: recipientAddress,
	}

	actionCore := &iotextypes.ActionCore{
		Nonce:    nonce,
		GasLimit: gasLimit,
		GasPrice: gasPrice,
		ChainID:  testnetChainID, // Testnet
		Action: &iotextypes.ActionCore_Transfer{
			Transfer: transfer,
		},
	}

	// Serialize the ActionCore and sign it
	rawTxBytes, err := proto.Marshal(actionCore)
	if err != nil {
		log.Fatalf("Error serializing action core: %v", err)
	}
	rawTxHash := hash.Hash256b(rawTxBytes)
	// rawTxHash := sha256.Sum256(rawTxBytes)
	signedTx, err := acc.PrivateKey().Sign(rawTxHash[:])
	if err != nil {
		log.Fatalf("Error signing transaction: %v", err)
	}

	// Create the full action
	action := &iotextypes.Action{
		Core:         actionCore,
		SenderPubKey: acc.PublicKey().Bytes(),
		Signature:    signedTx,
	}

	fmt.Printf("Sender Address: %s\n", acc.Address().String())
	fmt.Printf("Public Key: %x\n", acc.PublicKey().Hash())
	fmt.Printf("Serialized ActionCore: %x\n", rawTxBytes)
	fmt.Printf("ActionCore Hash: %x\n", rawTxHash)
	fmt.Printf("Signature: %x\n", signedTx)
	fmt.Printf("Account Meta: %+v\n", accountResp.GetAccountMeta())
	fmt.Printf("Action: %+v\n", action)

	// Send the action
	resp, err := client.SendAction(context.Background(), &iotexapi.SendActionRequest{
		Action: action,
	})
	if err != nil {
		log.Fatalf("Error sending signed transaction: %v", err)
	}

	fmt.Println("Transaction sent successfully, action hash:", resp.ActionHash)

	// c1b18458a1be0433958d53d090ffae1d53a0fc91e53415cad6fd00969e93dabc
}
