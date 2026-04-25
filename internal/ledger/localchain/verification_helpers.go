package localchain

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

func (chain *Chain) rollbackAppendLocked(node *Node) {
	if node.prev != nil {
		node.prev.next = nil
	} else {
		chain.head = nil
	}

	chain.tail = node.prev
	chain.length--
}

func verifyNodeLink(previousNode, currentNode *Node) error {
	if previousNode == nil {
		return verifyGenesisNode(currentNode)
	}

	if currentNode.prev != previousNode || previousNode.next != currentNode {
		return fmt.Errorf("%w: linked list pointers are inconsistent at block %d", ErrVerificationFailed, currentNode.Block.Index)
	}

	if currentNode.Block.Index != previousNode.Block.Index+1 {
		return fmt.Errorf("%w: invalid index progression at block %d", ErrVerificationFailed, currentNode.Block.Index)
	}

	if currentNode.Block.PrevHash != previousNode.Block.BlockHash {
		return fmt.Errorf("%w: prev hash mismatch at block %d", ErrVerificationFailed, currentNode.Block.Index)
	}

	return nil
}

func verifyGenesisNode(node *Node) error {
	if node.prev != nil {
		return fmt.Errorf("%w: genesis prev pointer must be nil", ErrVerificationFailed)
	}

	if node.Block.Index != 0 {
		return fmt.Errorf("%w: genesis index must be zero", ErrVerificationFailed)
	}

	if node.Block.PrevHash != "" {
		return fmt.Errorf("%w: genesis prev hash must be empty", ErrVerificationFailed)
	}

	return nil
}

func (chain *Chain) verifyNodeIntegrity(node *Node) error {
	block := node.Block

	if actualPayloadHash := hashPayload(block.Payload); actualPayloadHash != block.PayloadHash {
		return fmt.Errorf("%w: payload hash mismatch at block %d", ErrVerificationFailed, block.Index)
	}

	if actualBlockHash := computeBlockHash(block); actualBlockHash != block.BlockHash {
		return fmt.Errorf("%w: block hash mismatch at block %d", ErrVerificationFailed, block.Index)
	}

	ledgerSignature, err := base64.StdEncoding.DecodeString(block.LedgerSignature)
	if err != nil {
		return fmt.Errorf("%w: invalid block signature encoding at block %d", ErrVerificationFailed, block.Index)
	}

	if !verifyLedgerSignature(chain.verifyKey, block.BlockHash, ledgerSignature) {
		return fmt.Errorf("%w: invalid block signature at block %d", ErrVerificationFailed, block.Index)
	}

	return nil
}

func verifyLedgerSignature(verifyKey []byte, blockHash string, ledgerSignature []byte) bool {
	return ed25519.Verify(verifyKey, []byte(blockHash), ledgerSignature)
}
