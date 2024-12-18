package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/gin-gonic/gin"
	cf "github.com/kahsengphoon/IoTeX/config"
	"github.com/urfave/cli/v2"
)

const ZeroQuote uint32 = 0x80000000

// Base58 extended pubkey: xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6T6L3CZGkXPvU8KGPYua1xbGuevSAoxji4t1GHbP5DR7tEaNYjm
// Child key for path  m/44/304/0/0/0 : 025ce33622586a356b81462e00137af73e12c4c9a673f755b7a5f26356d03fe535
// Ethereum Address: 0xd2BCeF599f75A5E51af925ED31A745c5daC901C8
// Child address for path  m/44/304/0/0/0 : 0xd2BCeF599f75A5E51af925ED31A745c5daC901C8

var masterPubKey = "038d6b0504d8ad24f9386c3a80cc27a8f74135c0cbae232ba9c36a0fe64408111b"
var addrPath string = "m/44/304/0/0/0"

// var trxaddrPath string = "m/44/195/0/0/0"

var toAddr string = "0x2808D3C5BC00822662bd51f831205510139EfFc0"
var pubKey string = "03a40f0537b5772a2c475afefe6208dd5d928e5a0b3b24034fccfca20c3631250c"
var gasPrice string = "5000000000"
var amount string = "1000"
var sepoliaChainId string = "11155111"

var nonce uint64 = 2
var gasLimit uint64 = 21000

var rStr string = "cae220b79393642a170916d4504e261c94ef77e6618b9ad9b89eb11ba75a3c77"
var sStr string = "08cbaeacf6a9997cae6d93488ed933ff1d6d46f5a176ac3d19ff5510efc3fa96"
var vStr string = "0"

func (h *HttpServer) StartCwServer(c *cli.Context) error {
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

	DeriveChildPublicKey()
	if err := r.Run(fmt.Sprintf(":%v", cf.Enviroment().AppServerPort)); err != nil {
		return err
	}

	return nil
}

func StartCw() {
	if len(os.Args) < 2 {
		fmt.Println("please provide function")
		fmt.Println("os.Args[0]", os.Args[0])
	} else {
		switch os.Args[1] {
		case "getaddr":
			publicKeyBytes, err := hex.DecodeString(pubKey)
			if err != nil {
				fmt.Println("decodestring error:", err)
			}
			fmt.Println(PublicKeyBytesToAddress(publicKeyBytes))
		case "createethtx":
			GetTransactionRawHex()
		// case "getraw":
		// 	GetSig()
		case "verify":
			hash := "e102d7562d1d8aade875d884422372c777be7d1de48647b78b44db182463cef7"
			VerifyECDSA(hash)
		// case "recover":
		// 	RecoverPubKey()
		case "derive":
			DeriveChildPublicKey()
		case "encode":
			EncodeBase58PubKey()
			// case "gettrxaddr":
			// 	GetTronAddress()
			// case "createtrxtx":
			// 	CreateTronTransaction()
			// case "verifytron":
			// 	VerifyTronPubkey()
		}
	}
}

func GetTransactionRawHex() string {
	publicKeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		fmt.Println("decodestring error:", err)
		return ""
	}

	addr := PublicKeyBytesToAddress(publicKeyBytes)
	fmt.Println("addr:", addr)
	tx, err := CreateLegacyEthTransaction(toAddr, amount, gasPrice)
	if err != nil {
		fmt.Println("createLegacyEthTransaction error:", err)
		return ""
	}

	rawTxHex := ConvertTransactionToHex(tx)

	fmt.Println("ETH Raw TxHex ", rawTxHex)

	var R string
	var S string

	for {
		fmt.Println("Please enter R value and press Enter:")
		// Wait for user input
		fmt.Scanln(&R)

		rbytes, _ := hex.DecodeString(R)
		rBig := big.NewInt(0).SetBytes(rbytes)
		// Check if 'r' is negative
		if rBig.Sign() == -1 {
			fmt.Println("'r' value is negative")
		} else {
			break
		}
	}

	fmt.Println("Please enter S value and press Enter:")
	// Wait for user input
	fmt.Scanln(&S)

	signature := ConvertRSVToSignatureByte(R, S, "0")
	recaddr := RecoverPubKey(rawTxHex, signature)

	if addr.String() != recaddr {
		fmt.Println("from address:", addr.String(), " | recovered address:", recaddr)
		fmt.Println("Sig not valid")
		signature = ConvertRSVToSignatureByte(R, S, "1")
	}

	GetSig(signature)

	return rawTxHex
}

func ConvertTransactionToHex(trx *types.Transaction) string {
	bigChainId, _ := big.NewInt(0).SetString(sepoliaChainId, 10)
	signer := types.LatestSignerForChainID(bigChainId)
	trxHash := signer.Hash(trx)
	rawTrx := hex.EncodeToString(trxHash.Bytes())
	return rawTrx
}

func CreateLegacyEthTransaction(to, amount, gasPrice string) (*types.Transaction, error) {
	bigAmount, _ := big.NewInt(0).SetString(amount, 10)
	biggasPrice, _ := big.NewInt(0).SetString(gasPrice, 10)

	toAddr := common.HexToAddress(to)

	txData := types.LegacyTx{
		Nonce:    nonce,
		Value:    bigAmount,
		GasPrice: biggasPrice,
		Gas:      gasLimit,
		To:       &toAddr,
	}

	trx := types.NewTx(&txData)

	return trx, nil
}

func PublicKeyBytesToAddress(publicKey []byte) *common.Address {
	// Parse the public key hexadecimal string into bytes
	ecdsaPubKey, err := crypto.DecompressPubkey(publicKey)
	if err != nil {
		fmt.Println("UnmarshalPubkey error:", err)
		return nil
	}

	// Convert the public key to an Ethereum address
	address := crypto.PubkeyToAddress(*ecdsaPubKey)

	// Print the Ethereum address
	fmt.Println("Ethereum Address:", address.Hex())

	return &address
}

func RecoverPlain(R, S, Vs string, homestead bool) ([]byte, error) {
	rBig := new(big.Int)
	sBig := new(big.Int)
	vBig := new(big.Int)
	rBig.SetString(R, 10)  // Assuming decimal base
	sBig.SetString(S, 10)  // Assuming decimal base
	vBig.SetString(Vs, 10) // Assuming decimal base

	if vBig.BitLen() > 8 {
		fmt.Println("ErrInvalidSig-BitLen")
		return nil, errors.New("ErrInvalidSig")
	}
	V := byte(vBig.Uint64() - 27)
	if !crypto.ValidateSignatureValues(V, rBig, sBig, homestead) {
		fmt.Println("ErrInvalidSig-ValidateSignatureValues-V", vBig.Uint64())
		fmt.Println("ErrInvalidSig-ValidateSignatureValues-vBytes", vBig.Bytes())
		fmt.Println("ErrInvalidSig-ValidateSignatureValues")
		return nil, errors.New("ErrInvalidSig")
	}
	// encode the snature in uncompressed format
	r, s := rBig.Bytes(), sBig.Bytes()
	sig := make([]byte, 65)
	copy(sig[32-len(r):32], r)
	copy(sig[64-len(s):64], s)
	sig[64] = V

	fmt.Println("signature: ", sig)

	return sig, nil
}

func GetSig(signature []byte) {
	// signature := ConvertRSVToSignatureByte()

	// Print the signature bytes
	fmt.Printf("Signature bytes: %x\n", signature)

	tx, err := CreateLegacyEthTransaction(toAddr, amount, gasPrice)
	if err != nil {
		fmt.Println("GetSig-createLegacyEthTransaction error:", err)
		return
	}

	pre, _ := tx.MarshalBinary()
	rawTxHexWithoutSig := hexutil.Encode(pre)
	fmt.Println("rawTxHexWithoutSig:", rawTxHexWithoutSig)

	bigChainId, _ := big.NewInt(0).SetString(sepoliaChainId, 10)
	signer := types.LatestSignerForChainID(bigChainId)

	signedTx, err := tx.WithSignature(signer, signature)
	if err != nil {
		fmt.Println("GetSig-WithSignature error:", err)
		return
	}

	txBinary, err := signedTx.MarshalBinary()
	if err != nil {
		fmt.Println("GetSig-MarshalBinary error:", err)
		return
	}

	rawTxHexWithSig := hexutil.Encode(txBinary)
	fmt.Println("rawTxHexWithSig:", rawTxHexWithSig)

}

func VerifyECDSA(hashStr string) {
	hash, _ := hex.DecodeString(hashStr)
	rByte, _ := hex.DecodeString(rStr)
	sByte, _ := hex.DecodeString(sStr)
	r := new(big.Int)
	s := new(big.Int)

	r.SetBytes(rByte)
	s.SetBytes(sByte)

	publicKeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		fmt.Println("decodestring error:", err)
	}

	// Parse the public key hexadecimal string into bytes
	ecdsaPubKey, err := crypto.DecompressPubkey(publicKeyBytes)
	if err != nil {
		fmt.Println("UnmarshalPubkey error:", err)
	}

	// Verify the signature
	valid := ecdsa.Verify(ecdsaPubKey, hash, r, s)
	if valid {
		fmt.Println("Signature is valid")
	} else {
		fmt.Println("Signature is not valid")
	}
}

func RecoverPubKey(hash string, signature []byte) string {
	hashStr, _ := hex.DecodeString(hash)
	// signature := ConvertRSVToSignatureByte()

	// Recover the public key from the signature
	publicKey, err := crypto.SigToPub(hashStr[:], signature)
	if err != nil {
		fmt.Println("Error recovering public key:", err)
		return ""
	}

	// Print the recovered public key
	fmt.Println("Recovered Public Key:", publicKey)
	// fmt.Println("Recovered Address:", crypto.PubkeyToAddress(*publicKey))

	// Serialize the public key into compressed form
	compressedBytes := elliptic.MarshalCompressed(publicKey.Curve, publicKey.X, publicKey.Y)

	// Convert the compressed bytes to hexadecimal string
	compressedHex := hex.EncodeToString(compressedBytes)

	// Print the compressed public key in hexadecimal format
	fmt.Println("Compressed Public Key (Hex):", compressedHex)
	addr := crypto.PubkeyToAddress(*publicKey)
	return addr.String()
}

func ConvertRSVToSignatureByte(rstr, sstr, vstr string) []byte {
	rByte, _ := hex.DecodeString(rstr)
	sByte, _ := hex.DecodeString(sstr)

	// Convert signature components to big integers
	r := new(big.Int).SetBytes(rByte)        // Assuming decimal base
	s := new(big.Int).SetBytes(sByte)        // Assuming decimal base
	v, _ := new(big.Int).SetString(vstr, 10) // Assuming decimal base

	// Convert `v` value to a single byte
	vByte := byte(v.Uint64())

	// Convert `r` and `s` components to fixed-length byte slices
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	// Ensure that `r` and `s` are each 32 bytes long
	if len(rBytes) < 32 {
		padding := make([]byte, 32-len(rBytes))
		rBytes = append(padding, rBytes...)
	}
	if len(sBytes) < 32 {
		padding := make([]byte, 32-len(sBytes))
		sBytes = append(padding, sBytes...)
	}

	// Concatenate `r`, `s`, and `v` into a single byte slice
	signature := append(rBytes, sBytes...)
	signature = append(signature, vByte)

	return signature
}

// xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Reb4JMGv59umJFUp9mAoNbFEqzN5hHXERW1xg4FXEFSpHS5zcA
// 0x9B75738f570C418508f0dce0f508668B5a23396b /0
// 0x6b391CAb6e5423e9CA7feB42640A70AACFcEE197 /1

// Function to derive a child public key from a master public key using a given path
func DeriveChildPublicKey() ([]byte, *common.Address) {
	// masterB58PubKey := EncodeBase58PubKey()
	// Derive the child extended key from the master public key and path
	// extendedKey, err := hdkeychain.NewKeyFromString(masterB58PubKey)
	b58hexStr, _ := GenerateExtendedPublicKey()
	extendedKey, err := hdkeychain.NewKeyFromString(b58hexStr)
	if err != nil {
		fmt.Println("hdkeychain.NewKeyFromString", err)
		return nil, nil
	}

	derivationPath, err := parseDerivationPath()
	if err != nil {
		fmt.Println("parseDerivationPath", err)
		return nil, nil
	}

	// Derive the child extended key from the master public key and path
	childExtendedKey := extendedKey
	for _, index := range derivationPath {
		childExtendedKey, err = childExtendedKey.Derive(index)
		if err != nil {
			fmt.Println("childExtendedKey.Derive", err)
			return nil, nil
		}
	}

	childPubKey, _ := childExtendedKey.ECPubKey()

	childPubKeyCompressed := hex.EncodeToString(childPubKey.SerializeCompressed())
	fmt.Println("Child key for path ", addrPath, ":", childPubKeyCompressed)
	childaddress := PublicKeyBytesToAddress(childPubKey.SerializeCompressed())
	fmt.Println("Child address for path ", addrPath, ":", childaddress)

	return childPubKey.SerializeCompressed(), childaddress
}

func GenerateExtendedPublicKey() (string, error) {
	// Decode compressed public key from hex
	compressedPubKeyBytes, err := hex.DecodeString(masterPubKey)
	if err != nil {
		return "", fmt.Errorf("error decoding compressed public key hex: %v", err)
	}

	// chainCodeHex, err := hex.DecodeString(chainCode)
	// if err != nil {
	// 	return "", fmt.Errorf("error decoding compressed chainCodehex: %v", err)
	// }

	// Construct the extended public key bytes
	extendedPubKeyBytes := append([]byte{0x04, 0x88, 0xB2, 0x1E}, byte(0x00))
	extendedPubKeyBytes = append(extendedPubKeyBytes, make([]byte, 4)...)
	extendedPubKeyBytes = append(extendedPubKeyBytes, make([]byte, 4)...)
	extendedPubKeyBytes = append(extendedPubKeyBytes, make([]byte, 32)...)
	extendedPubKeyBytes = append(extendedPubKeyBytes, compressedPubKeyBytes...)

	// Calculate checksum
	checksum := doubleSHA256(extendedPubKeyBytes)[:4]

	// Append checksum to extended public key bytes
	extendedPubKeyBytes = append(extendedPubKeyBytes, checksum...)

	// Base58 encode extended public key
	extendedPubKey := base58.Encode(extendedPubKeyBytes)

	fmt.Println("Base58 extended pubkey:", extendedPubKey)

	return extendedPubKey, nil
}

// doubleSHA256 calculates the double SHA256 hash of data
func doubleSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	hash = sha256.Sum256(hash[:])
	return hash[:]
}

// Function to parse a derivation path string into an array of uint32
func parseDerivationPath_() ([]uint32, error) {
	path := addrPath
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] != "m" {
		return nil, fmt.Errorf("invalid derivation path")
	}

	derivationPath := make([]uint32, 0, len(parts)-1)
	for _, part := range parts[1:] {
		// Parse part as uint32
		index, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid derivation path: %v", err)
		}

		// Convert to uint32
		derivationPath = append(derivationPath, uint32(index))
	}

	return derivationPath, nil
}

// Function to parse a derivation path string into an array of uint32
func parseDerivationPath() ([]uint32, error) {
	path := addrPath
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] != "m" {
		return nil, fmt.Errorf("invalid derivation path")
	}

	derivationPath := make([]uint32, 0, len(parts)-1)
	for _, part := range parts[1:] {
		// Check if part ends with '
		hardened := false
		if strings.HasSuffix(part, "'") {
			part = strings.TrimSuffix(part, "'")
			hardened = true
		}

		// Parse part as uint32
		index, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid derivation path: %v", err)
		}

		// Convert to uint32 and adjust if hardened
		if hardened {
			index += hdkeychain.HardenedKeyStart
		}

		derivationPath = append(derivationPath, uint32(index))
	}

	return derivationPath, nil
}

func EncodeBase58PubKey() string {
	publicKeyBytes, err := hex.DecodeString(masterPubKey)
	if err != nil {
		fmt.Println("decodestring error:", err)
	}

	// Parse the public key hexadecimal string into bytes
	ecdsaPubKey, err := crypto.DecompressPubkey(publicKeyBytes)
	if err != nil {
		fmt.Println("UnmarshalPubkey error:", err)
	}

	// Serialize the public key into a byte array
	pubKeyBytes := crypto.FromECDSAPub(ecdsaPubKey)
	if err != nil {
		fmt.Println("Error serializing public key:", err)
		return ""
	}

	// Hash the public key bytes using SHA-256
	// pubkeyhash := sha256.Sum256(pubKeyBytes)

	pubKeyB58 := base58.Encode(pubKeyBytes)
	if err != nil {
		fmt.Println("Error pubKeyB58 public key:", err)
		return ""
	}
	fmt.Println("Base58 PubKey:", pubKeyB58)

	return pubKeyB58

	// pubKeyHex := hex.EncodeToString(pubKeyBytes)
	// if err != nil {
	// 	fmt.Println("Error DecodeString public key:", err)
	// 	return
	// }
	// fmt.Println(pubKeyHex)
}
