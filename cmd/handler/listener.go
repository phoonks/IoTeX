package handler

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/http"

	"log"

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
	customBlock    = 29402536
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
