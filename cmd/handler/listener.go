package handler

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"log"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/gin-gonic/gin"
	"github.com/iotexproject/iotex-antenna-go/v2/iotex"
	"github.com/iotexproject/iotex-proto/golang/iotexapi"
	cf "github.com/kahsengphoon/IoTeX/config"
	"github.com/urfave/cli/v2"
)

const (
	mainnetRPC     = "api.iotex.one:443"
	testnetRPC     = "api.testnet.iotex.one:443"
	mainnetChainID = 1
	testnetChainID = 2
	customBlock    = 29528584
	myContractABI  = `[
		{
			"inputs": [
				{
					"internalType": "uint256",
					"name": "initialSupply",
					"type": "uint256"
				}
			],
			"stateMutability": "nonpayable",
			"type": "constructor"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "spender",
					"type": "address"
				},
				{
					"internalType": "uint256",
					"name": "allowance",
					"type": "uint256"
				},
				{
					"internalType": "uint256",
					"name": "needed",
					"type": "uint256"
				}
			],
			"name": "ERC20InsufficientAllowance",
			"type": "error"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "sender",
					"type": "address"
				},
				{
					"internalType": "uint256",
					"name": "balance",
					"type": "uint256"
				},
				{
					"internalType": "uint256",
					"name": "needed",
					"type": "uint256"
				}
			],
			"name": "ERC20InsufficientBalance",
			"type": "error"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "approver",
					"type": "address"
				}
			],
			"name": "ERC20InvalidApprover",
			"type": "error"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "receiver",
					"type": "address"
				}
			],
			"name": "ERC20InvalidReceiver",
			"type": "error"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "sender",
					"type": "address"
				}
			],
			"name": "ERC20InvalidSender",
			"type": "error"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "spender",
					"type": "address"
				}
			],
			"name": "ERC20InvalidSpender",
			"type": "error"
		},
		{
			"anonymous": false,
			"inputs": [
				{
					"indexed": true,
					"internalType": "address",
					"name": "owner",
					"type": "address"
				},
				{
					"indexed": true,
					"internalType": "address",
					"name": "spender",
					"type": "address"
				},
				{
					"indexed": false,
					"internalType": "uint256",
					"name": "value",
					"type": "uint256"
				}
			],
			"name": "Approval",
			"type": "event"
		},
		{
			"anonymous": false,
			"inputs": [
				{
					"indexed": true,
					"internalType": "address",
					"name": "from",
					"type": "address"
				},
				{
					"indexed": true,
					"internalType": "address",
					"name": "to",
					"type": "address"
				},
				{
					"indexed": false,
					"internalType": "uint256",
					"name": "value",
					"type": "uint256"
				}
			],
			"name": "Transfer",
			"type": "event"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "owner",
					"type": "address"
				},
				{
					"internalType": "address",
					"name": "spender",
					"type": "address"
				}
			],
			"name": "allowance",
			"outputs": [
				{
					"internalType": "uint256",
					"name": "",
					"type": "uint256"
				}
			],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "spender",
					"type": "address"
				},
				{
					"internalType": "uint256",
					"name": "value",
					"type": "uint256"
				}
			],
			"name": "approve",
			"outputs": [
				{
					"internalType": "bool",
					"name": "",
					"type": "bool"
				}
			],
			"stateMutability": "nonpayable",
			"type": "function"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "account",
					"type": "address"
				}
			],
			"name": "balanceOf",
			"outputs": [
				{
					"internalType": "uint256",
					"name": "",
					"type": "uint256"
				}
			],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [],
			"name": "decimals",
			"outputs": [
				{
					"internalType": "uint8",
					"name": "",
					"type": "uint8"
				}
			],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [],
			"name": "name",
			"outputs": [
				{
					"internalType": "string",
					"name": "",
					"type": "string"
				}
			],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [],
			"name": "symbol",
			"outputs": [
				{
					"internalType": "string",
					"name": "",
					"type": "string"
				}
			],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [],
			"name": "totalSupply",
			"outputs": [
				{
					"internalType": "uint256",
					"name": "",
					"type": "uint256"
				}
			],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "to",
					"type": "address"
				},
				{
					"internalType": "uint256",
					"name": "value",
					"type": "uint256"
				}
			],
			"name": "transfer",
			"outputs": [
				{
					"internalType": "bool",
					"name": "",
					"type": "bool"
				}
			],
			"stateMutability": "nonpayable",
			"type": "function"
		},
		{
			"inputs": [
				{
					"internalType": "address",
					"name": "from",
					"type": "address"
				},
				{
					"internalType": "address",
					"name": "to",
					"type": "address"
				},
				{
					"internalType": "uint256",
					"name": "value",
					"type": "uint256"
				}
			],
			"name": "transferFrom",
			"outputs": [
				{
					"internalType": "bool",
					"name": "",
					"type": "bool"
				}
			],
			"stateMutability": "nonpayable",
			"type": "function"
		}
	]`
)

// For high-value transactions, wait for 12 confirmations.
// For everyday transactions, 3 confirmations are typically sufficient.

func (h *HttpServer) StartListenerServer(c *cli.Context) error {
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

	ConnectIoTeX2()
	if err := r.Run(fmt.Sprintf(":%v", cf.Enviroment().AppServerPort)); err != nil {
		return err
	}

	return nil
}

func ConnectIoTeX2() {
	// Create grpc connection
	conn, err := iotex.NewDefaultGRPCConn(testnetRPC)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	client := iotexapi.NewAPIServiceClient(conn)

	contractABI, err := abi.JSON(strings.NewReader(myContractABI))
	if err != nil {
		log.Fatalf("Failed to parse contract ABI: %v", err)
	}

	// Get the latest block height
	chainMeta, err := client.GetChainMeta(context.Background(), &iotexapi.GetChainMetaRequest{})
	if err != nil {
		fmt.Println("Error fetching chain meta:", err)
		return
	}
	latestBlockHeight := chainMeta.ChainMeta.Height
	if customBlock > 0 {
		latestBlockHeight = uint64(customBlock)
	}
	fmt.Printf("Latest Block Height: %d\n", latestBlockHeight)

	// Get block details for the latest block
	blockMeta, err := client.GetBlockMetas(context.Background(), &iotexapi.GetBlockMetasRequest{
		Lookup: &iotexapi.GetBlockMetasRequest_ByIndex{
			ByIndex: &iotexapi.GetBlockMetasByIndexRequest{
				Start: latestBlockHeight,
				Count: 1,
			},
		},
	})
	if err != nil {
		fmt.Println("Error fetching block meta:", err)
		return
	}

	for _, meta := range blockMeta.BlkMetas {
		fmt.Printf("Block Height: %d\n", meta.Height)
		fmt.Printf("Block Hash: %s\n", meta.Hash)
		fmt.Printf("Number of Actions: %d\n", meta.NumActions)
		fmt.Printf("Producer Address: %s\n", meta.ProducerAddress)
		fmt.Println("------")

		// Get actions (transactions) from the block
		actions, err := client.GetActions(context.Background(), &iotexapi.GetActionsRequest{
			Lookup: &iotexapi.GetActionsRequest_ByBlk{
				ByBlk: &iotexapi.GetActionsByBlockRequest{
					BlkHash: meta.Hash,
					Start:   0,
					Count:   uint64(meta.NumActions), // Number of actions to fetch
				},
			},
		})
		if err != nil {
			fmt.Println("Error fetching actions:", err)
			return
		}

		for _, action := range actions.ActionInfo {
			fmt.Printf("Action Hash: %s\n", action.ActHash)
			fmt.Printf("Sender: %s\n", action.Sender)

			// Check if the action is a transfer
			if transfer := action.Action.Core.GetTransfer(); transfer != nil {
				// Convert Rau to IOTX
				amountFloat, _ := new(big.Float).SetString(transfer.Amount)
				amountInIOTX := new(big.Float).Quo(amountFloat, big.NewFloat(1e18))

				fmt.Printf("Recipient: %s\n", transfer.Recipient)
				fmt.Printf("Amount (in Rau): %s\n", transfer.Amount)
				fmt.Printf("Amount (in IOTX): %s\n", amountInIOTX.String())
				fmt.Printf("Transaction Type: Transfer\n")
			} else if execution := action.Action.Core.GetExecution(); execution != nil {
				fmt.Printf("Transaction Type: Contract Execution\n")
			} else {
				fmt.Printf("Transaction Type: Not a Transfer\n")
			}

			// Get the transaction receipt to check the status
			receipt, err := client.GetReceiptByAction(context.Background(), &iotexapi.GetReceiptByActionRequest{
				ActionHash: action.ActHash,
			})
			if err != nil {
				fmt.Println("Error fetching receipt:", err)
				continue
			}

			// Calculate the gas fee
			gasUsed := new(big.Int).SetUint64(receipt.ReceiptInfo.Receipt.GasConsumed)
			gasFee := new(big.Int)
			gasFee.SetString(action.GetGasFee(), 10)

			// Calculate the gas price
			gasPrice := big.NewInt(0)
			if gasUsed.Cmp(big.NewInt(0)) > 0 {
				gasPrice = new(big.Int).Div(gasFee, gasUsed)
			}
			// Convert gas fee from Rau to IOTX
			gasFeeInIOTX := new(big.Float).Quo(new(big.Float).SetInt(gasFee), big.NewFloat(1e18))
			// Convert Rau to IOTX
			priceInQev := new(big.Float).Quo(new(big.Float).SetInt(gasPrice), big.NewFloat(1e15))

			if execution := action.Action.Core.GetExecution(); execution != nil {
				fmt.Printf("Contract: %s\n", execution.Contract)

				// Decode the execution data
				data := execution.Data
				if len(data) > 0 {
					method, err := contractABI.MethodById(data[:4])
					if err != nil {
						fmt.Println("Error finding method by ID:", err)
					}
					fmt.Printf("Method: %s\n", method.Name)

					args, err := method.Inputs.Unpack(data[4:])
					if err != nil {
						fmt.Println("Error unpacking method inputs:", err)
					}
					fmt.Printf("Arguments: %v\n", args)
					// Convert Rau to IOTX
					amountFloat, _ := new(big.Float).SetString(fmt.Sprintf("%s", args[1]))
					amountInIOTX := new(big.Float).Quo(amountFloat, big.NewFloat(1e18))

					fmt.Printf("Recipient: %s\n", args[0])
					fmt.Printf("Amount (in Rau): %s\n", args[1])
					fmt.Printf("Amount (in IOTX): %s\n", amountInIOTX.String())
				}
			}
			// Print additional details
			fmt.Printf("Status: %d\n", receipt.ReceiptInfo.Receipt.Status) // 0 - failed, 1 - success
			fmt.Printf("Timestamp: %d\n", action.Timestamp.Seconds)
			fmt.Printf("Gas Used: %s\n", gasUsed)
			fmt.Printf("Gas Fee (in Rau): %s\n", gasFee)
			fmt.Printf("Gas Fee (in IOTX): %s\n", gasFeeInIOTX.String())

			fmt.Printf("Gas Limit: %d\n", action.Action.Core.GasLimit)
			fmt.Printf("Gas Price (in Rau): %s\n", gasPrice)
			fmt.Printf("Gas Price (in Qev): %s\n", priceInQev.String())
			fmt.Printf("Nonce: %d\n", action.Action.Core.Nonce)
			fmt.Printf("Chain ID: %d\n", action.Action.Core.ChainID)
			fmt.Println("------")
		}
	}
}
