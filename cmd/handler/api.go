package handler

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	// base58 "github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/gin-gonic/gin"
	"github.com/iotexproject/go-pkgs/hash"
	"github.com/iotexproject/iotex-address/address"
	"github.com/iotexproject/iotex-antenna-go/v2/account"
	"github.com/iotexproject/iotex-antenna-go/v2/iotex"
	"github.com/iotexproject/iotex-proto/golang/iotexapi"
	"github.com/iotexproject/iotex-proto/golang/iotextypes"
	cf "github.com/kahsengphoon/IoTeX/config"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
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

	// SignWithRawTransaction()
	// SignWithRawTransactionXrc20()
	SignSerializedTransaction("3c6069d8b5d1a63eeb0a4247c40660c90d8001a26979fc3e339c59c41ce5ec70", "100218d08603220d31303030303030303030303030280262740a01301229696f3174656c68303963633373756c6a73776a77677a763774727a6a3679686d6879336e72746530371a44a9059cbb0000000000000000000000001686c628eddd1cb769ef50362b27c4dff2a3d3990000000000000000000000000000000000000000000000000de0b6b3a7640000")

	// SendSignedTransaction2("3c6069d8b5d1a63eeb0a4247c40660c90d8001a26979fc3e339 c59c41ce5ec70")

	// xpub := "038d6b0504d8ad24f9386c3a80cc27a8f74135c0cbae232ba9c36a0fe64408111b"
	// uncpub := "048d6b0504d8ad24f9386c3a80cc27a8f74135c0cbae232ba9c36a0fe64408111b1a0988204632f0faf98eb5b8e97ddbc860a4cdc6e1fd2e6cf40dc6ebc115dc4b"
	// uncpub := "04b55d441da8d54bb35dc8eb11a4100fb9f4bc062ca156e67a9065e29a107a7ab50cfd74b1909dfce1e127906e47cca1412d55f2d0ec3869d22ef5f77688c407ac"
	// ConvertCompressedToUncompressed(xpub)
	// ValidateUncompressedPublicKey(uncpub)

	// pub generate: io1627w7kvlwkj72xheyhknrf69chdvjqwgzz0y5r / 0xd2bcef599f75a5e51af925ed31a745c5dac901c8
	// GenerateUncompressedToAddress(uncpub)
	// EthToIoTeXAddress("0xd2bcef599f75a5e51af925ed31a745c5dac901c8")

	// path := []uint32{
	// 	44 + hdkeychain.HardenedKeyStart,  // 44'
	// 	304 + hdkeychain.HardenedKeyStart, // 304'
	// 	0 + hdkeychain.HardenedKeyStart,   // 0'
	// 	0,                                 // Normal index
	// 	0,                                 // First account
	// }
	// // Derive the child public key
	// compressedPubKey, err := DeriveChildPublicKey(xpub, path)
	// if err != nil {
	// 	log.Fatalf("Error deriving child public key: %v", err)
	// }
	// fmt.Printf("Derived Compressed Public Key: %s\n", compressedPubKey)
	// // Generate the IoTeX address
	// iotexAddress, err := GenerateIoTeXAddress(compressedPubKey)
	// if err != nil {
	// 	log.Fatalf("Error generating IoTeX address: %v", err)
	// }
	// fmt.Printf("IoTeX Address: %s\n", iotexAddress)

	// GenerateIoTeXAddress(xpub)

	// publicKey, err := DecompressPublicKey("d4f5817b9a2d3532bf3a4bbc3ccd145cc6adf8c7")
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// GenerateIoTeXAddress(publicKey)

	// CreateAddress()
	// Withdraw()
	if err := r.Run(fmt.Sprintf(":%v", cf.Enviroment().AppServerPort)); err != nil {
		return err
	}

	return nil
}

func keccak256(data []byte) []byte {
	hash := sha3.NewLegacyKeccak256() // Keccak-256
	hash.Write(data)
	return hash.Sum(nil)
}

func GenerateUncompressedToAddress(uncompressedPubKey string) (string, error) {
	// Decode the uncompressed public key from hex
	pubKeyBytes, err := hex.DecodeString(uncompressedPubKey)
	if err != nil {
		fmt.Println("Error decoding public key:", err)
		return "", err
	}

	// Compress the public key
	if len(pubKeyBytes) != 65 || pubKeyBytes[0] != 0x04 {
		log.Fatalf("Invalid uncompressed public key format")
	}

	// Convert the raw public key into an ECDSA public key (skip the 0x04 prefix)
	publicKey, err := crypto.UnmarshalPubkey(pubKeyBytes)

	// Compress the public key
	compressed := crypto.CompressPubkey(publicKey)
	fmt.Printf("compressed: %x \n", compressed)

	// Ensure the uncompressed key is valid (starts with 0x04)
	if pubKeyBytes[0] != 0x04 {
		fmt.Println("Invalid uncompressed public key format.")
		return "", err
	}

	// Extract the 64-byte compressed public key (after the 0x04 prefix)
	compressedPubKey := pubKeyBytes[1:]

	if len(compressedPubKey) != 64 {
		return "", errors.New("invalid compressed public key length")
	}
	// Hash the compressed public key using Keccak-256
	hashedPubKey := keccak256(compressedPubKey)
	h := hash.Hash160b(hashedPubKey[1:])

	// Convert the address to hex and prepend "0x" prefix
	address := "0x" + hex.EncodeToString(h[:])

	// Step 5: Return the address in lowercase
	fmt.Printf("Generated ETH IoTeX Address: %s\n", address)
	return address, nil
}

func EthToIoTeXAddress(ethAddress string) string {
	// Remove the "0x" prefix
	if len(ethAddress) > 2 && ethAddress[:2] == "0x" {
		ethAddress = ethAddress[2:]
	}

	// Convert to bytes
	addressBytes, err := hex.DecodeString(ethAddress)
	if err != nil {
		log.Fatalf("Failed to decode Ethereum address: %v", err)
	}

	// Convert to IoTeX bech32 address
	bech32Address, err := convertToBech32("io", addressBytes)
	if err != nil {
		log.Fatalf("Failed to convert to IoTeX address: %v", err)
	}

	fmt.Printf("Generated IO IoTeX Address: %s\n", bech32Address)

	return bech32Address
}

// convertToBech32 converts bytes to a Bech32 address with the given human-readable part (HRP)
func convertToBech32(hrp string, data []byte) (string, error) {
	// Convert the bytes to the 5-bit groups required by Bech32
	convertedData, err := bech32.ConvertBits(data, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("failed to convert bits: %v", err)
	}

	// Encode into Bech32 format
	bech32Addr, err := bech32.Encode(hrp, convertedData)
	if err != nil {
		return "", fmt.Errorf("failed to encode Bech32: %v", err)
	}

	return bech32Addr, nil
}

func ValidateUncompressedPublicKey(uncompressedKey string) error {
	// Step 1: Decode the hex string
	pubKeyBytes, err := hex.DecodeString(uncompressedKey)
	if err != nil {
		return fmt.Errorf("invalid hex string: %v", err)
	}

	// Step 2: Check the length and prefix
	if len(pubKeyBytes) != 65 {
		return fmt.Errorf("invalid length: expected 65 bytes, got %d", len(pubKeyBytes))
	}
	if pubKeyBytes[0] != 0x04 {
		return fmt.Errorf("invalid prefix: expected 0x04, got 0x%x", pubKeyBytes[0])
	}

	// Step 3: Parse the public key using the btcec package
	_, err = btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid public key: %v", err)
	}

	fmt.Println("The uncompressed public key is valid!")
	return nil
}

func GenerateIoTeXAddress(compressedPubKey string) (string, error) {
	// Step 1: Decode the hex compressed public key
	pubKeyBytes, err := hex.DecodeString(compressedPubKey)
	if err != nil {
		return "", fmt.Errorf("invalid public key hex: %v", err)
	}
	fmt.Printf("Decoded Public Key Bytes: %x\n", pubKeyBytes)

	// Step 2: Perform Keccak-256 hash on the public key bytes
	hash := sha3.NewLegacyKeccak256()
	hash.Write(pubKeyBytes)
	hashed := hash.Sum(nil)
	fmt.Printf("Keccak-256 Hash: %x\n", hashed)

	// Step 3: Take the last 20 bytes of the Keccak-256 hash
	addressBytes := hashed[len(hashed)-20:]
	fmt.Printf("Last 20 Bytes: %x\n", addressBytes)

	// Step 4: Prefix with "io" to form the IoTeX address
	address := strings.ToLower(fmt.Sprintf("io%s", hex.EncodeToString(addressBytes)))
	fmt.Printf("Generated IoTeX Address: %s\n", address)

	// Step 5: Return the address
	return address, nil
}

func ConvertCompressedToUncompressed(compressedKey string) (string, error) {
	// Step 1: Decode the compressed public key
	compressedBytes, err := hex.DecodeString(compressedKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode compressed key: %v", err)
	}

	// Step 2: Parse the compressed key into a public key using btcec
	pubKey, err := btcec.ParsePubKey(compressedBytes)
	if err != nil {
		return "", fmt.Errorf("invalid compressed public key: %v", err)
	}

	// Step 3: Serialize the key in uncompressed format
	uncompressedBytes := pubKey.SerializeUncompressed()

	// Step 4: Return the uncompressed key as a hex string
	uncompressedKey := hex.EncodeToString(uncompressedBytes)

	fmt.Printf("uncompressedKey: %v \n", uncompressedKey)
	return uncompressedKey, nil
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
	recipientAddress := "io1z6rvv28dm5wtw6002qmzkf7ymle285uem4pk80"
	senderAddr := "io1627w7kvlwkj72xheyhknrf69chdvjqwgzz0y5r"

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

	// Hash the raw transaction using sha256
	rawTxsha256 := hash.Hash256b(rawTxBytes) // Produces a 32-byte hash
	fmt.Println("Raw transaction (hex256):", hex.EncodeToString(rawTxsha256[:]))

	// The rawTxHex can now be provided to another party for signing with their private key
	return rawTxHex
}

func SignWithRawTransactionXrc20() string {
	// Recipient address
	recipientAddress := "io1z6rvv28dm5wtw6002qmzkf7ymle285uem4pk80"
	senderAddr := "io1627w7kvlwkj72xheyhknrf69chdvjqwgzz0y5r"
	contractAddress := "io1telh09cc3suljswjwgzv7trzj6yhmhy3nrte07"

	// Amount to transfer (in Rau)
	amount := big.NewInt(1000000000000000000) // 1 WCC

	// Gas limit and gas price
	gasLimit := uint64(50000)
	gasPrice := "1000000000000" // 2 Qev

	conn, err := iotex.NewDefaultGRPCConn(testnetRPC)
	if err != nil {
		log.Fatalf("connection error : %v", err)
	}
	defer conn.Close()

	client := iotexapi.NewAPIServiceClient(conn)

	// Convert recipient IoTeX address to Ethereum-compatible address
	recipientEthAddr, err := address.FromString(recipientAddress)
	if err != nil {
		panic(err)
	}

	recipientAddr := common.BytesToAddress(recipientEthAddr.Bytes())

	// ABI encode the `transfer` function call
	erc20ABI, _ := abi.JSON(strings.NewReader(`[{"constant":false,"inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"}]`))
	payload, err := erc20ABI.Pack("transfer", recipientAddr, amount)
	if err != nil {
		panic(err)
	}

	// Fetch current nonce for sender's address
	senderAcc, err := client.GetAccount(context.Background(), &iotexapi.GetAccountRequest{
		Address: senderAddr,
	})
	if err != nil {
		log.Fatalf("GetAccount error : %v", err)
	}

	// Create the ActionCore (the action details including nonce, gas, and the transfer action)
	// You should fetch the actual nonce for the sender. Here, it's set as 1 for simplicity.
	nonce := senderAcc.GetAccountMeta().GetPendingNonce()

	actionCore := &iotextypes.ActionCore{
		Nonce:    nonce,
		GasLimit: gasLimit,
		GasPrice: gasPrice,
		ChainID:  testnetChainID,
		Action: &iotextypes.ActionCore_Execution{
			Execution: &iotextypes.Execution{
				Amount:   "0",             // No native IOTX transfer, only token transfer
				Contract: contractAddress, // The XRC20 contract address
				Data:     payload,         // Encoded transfer function call
			},
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

	// Hash the raw transaction using sha256
	rawTxsha256 := hash.Hash256b(rawTxBytes) // Produces a 32-byte hash
	fmt.Println("Raw transaction (hex256):", hex.EncodeToString(rawTxsha256[:]))

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

	// // Your private key (for signing the transaction)
	// // Create an account from the private key
	// acc, err := account.HexStringToAccount(privateKeyHex)
	// if err != nil {
	// 	log.Fatalf("create account from private key error : %v", err)
	// }

	// Convert the bytes to action
	var actionCore iotextypes.ActionCore
	err = proto.Unmarshal(rawTxBytes, &actionCore)
	if err != nil {
		log.Fatalf("Error serializing action: %v", err)
	}

	conn, err := iotex.NewDefaultGRPCConn(testnetRPC)
	if err != nil {
		log.Fatalf("connection error : %v", err)
	}
	defer conn.Close()

	client := iotexapi.NewAPIServiceClient(conn)

	// // Hash the raw transaction using sha256
	rawTxsha256 := hash.Hash256b(rawTxBytes) // Produces a 32-byte hash

	// // Sign the transfer action
	// signedTxOri, err := acc.PrivateKey().Sign(rawTxsha256[:])
	// if err != nil {
	// 	log.Fatalf("Error signing transfer action: %v", err)
	// }
	// fmt.Printf("signedTxOri: %v\n", hex.EncodeToString(signedTxOri))

	// Step 2: Create r, s, v from the signature
	// manual step
	rHex := "0c7ca220469353c50cd18d36f23dca794c5cc568c95841aa008f6baf85525303"
	sHex := "5757aa0628afd9e799b9f8f00b0f40af0b9810f2b811e0baf99f002ecfca2b82"
	vHex := "01"

	signedTx, err := rsvToSignature(rHex, sHex, vHex)
	if err != nil {
		log.Fatalf("rsvToSignature error : %v", err)
	}

	signedTxStr := hex.EncodeToString(signedTx)
	fmt.Printf("signedTxStr: %v\n", signedTxStr)

	publicKey, err := crypto.SigToPub(rawTxsha256[:], signedTx)
	if err != nil {
		log.Fatalf("Failed to recover public key: %v", err)
	}
	// Convert the public key to bytes
	publicKeyBytes := crypto.FromECDSAPub(publicKey)
	publicKeyHex := hex.EncodeToString(publicKeyBytes)

	// Print the recovered public key in hex format
	fmt.Printf("Decoded Bytes: %x\n", publicKeyBytes)
	fmt.Printf("Length of Decoded Data: %d bytes\n", len(publicKeyBytes))
	fmt.Printf("publicKeyHex: %x\n", publicKeyHex)

	// Create the full action
	signedAction := &iotextypes.Action{
		Core:         &actionCore,
		SenderPubKey: publicKeyBytes,
		Signature:    signedTx,
	}

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

func rsvToSignature(rHex, sHex, vHex string) ([]byte, error) {
	// Decode r, s, and v from hex to bytes
	r, err := hex.DecodeString(rHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode r: %v", err)
	}

	s, err := hex.DecodeString(sHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode s: %v", err)
	}

	v, err := hex.DecodeString(vHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode v: %v", err)
	}
	if len(v) != 1 {
		return nil, fmt.Errorf("v must be a single byte")
	}

	// Concatenate r, s, and v into a single signature
	signature := append(r, append(s, v[0])...)
	return signature, nil
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
