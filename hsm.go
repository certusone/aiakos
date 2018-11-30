package aiakos

import (
	"errors"

	"github.com/certusone/yubihsm-go"
	"github.com/certusone/yubihsm-go/commands"
	"github.com/certusone/yubihsm-go/connector"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/ed25519"
	cmn "github.com/tendermint/tendermint/libs/common"
	"github.com/tendermint/tendermint/libs/log"
	"github.com/tendermint/tendermint/types"
)

type (
	// AiakosPV implements PrivValidator using Aiakos
	AiakosPV struct {
		hsmSessionManager *yubihsm.SessionManager

		hsmURL       string
		authKeyID    uint16
		password     string
		signingKeyID uint16

		cachedPubKey crypto.PubKey

		cmn.BaseService
	}
)

// NewAiakosPV returns a new instance of AiakosPV
func NewAiakosPV(hsmURL string, signingKeyID uint16, authKeyID uint16, password string, logger log.Logger) (*AiakosPV, error) {

	pv := &AiakosPV{
		hsmURL:       hsmURL,
		authKeyID:    authKeyID,
		password:     password,
		signingKeyID: signingKeyID,
	}
	pv.BaseService = *cmn.NewBaseService(logger, "AiakosPV", pv)

	return pv, nil
}

// OnStart implements cmn.Service.
func (a *AiakosPV) OnStart() error {
	sessionManager, err := yubihsm.NewSessionManager(connector.NewHTTPConnector(a.hsmURL), a.authKeyID, a.password)
	if err != nil {
		return err
	}

	a.hsmSessionManager = sessionManager

	return nil
}

// OnStop implements cmn.Service.
func (a *AiakosPV) OnStop() {
	a.hsmSessionManager.Destroy()
}

// GetAddress returns the address of the validator.
// Implements PrivValidator.
func (a *AiakosPV) GetAddress() types.Address {
	pubKey := a.GetPubKey()
	return pubKey.Address()
}

// GetPubKey returns the public key of the validator.
// Implements PrivValidator.
func (a *AiakosPV) GetPubKey() crypto.PubKey {
	if a.cachedPubKey != nil {
		return a.cachedPubKey
	}

	command, err := commands.CreateGetPubKeyCommand(a.signingKeyID)
	if err != nil {
		panic(err)
	}
	resp, err := a.hsmSessionManager.SendEncryptedCommand(command)
	if err != nil {
		panic(err)
	}

	parsedResp, matched := resp.(*commands.GetPubKeyResponse)
	if !matched {
		a.Logger.Error("invalid response type")
		panic(errors.New("invalid response type"))
	}

	if parsedResp.Algorithm != commands.AlgorighmED25519 {
		a.Logger.Error("invalid response type", "algorithm", parsedResp.Algorithm)
		panic(errors.New("invalid pubKey algorithm"))
	}

	if len(parsedResp.KeyData) != ed25519.PubKeyEd25519Size {
		a.Logger.Error("invalid pubKey size", "size", len(parsedResp.KeyData))
		panic(errors.New("invalid pubKey size"))
	}

	// Convert raw key data to tendermint PubKey type
	publicKey := new(ed25519.PubKeyEd25519)
	copy(publicKey[:], parsedResp.KeyData[:])

	// Cache publicKey
	a.cachedPubKey = publicKey

	return publicKey
}

// SignVote signs a canonical representation of the vote, along with the
// chainID. Implements PrivValidator.
func (a *AiakosPV) SignVote(chainID string, vote *types.Vote) error {
	signature, err := a.signBytes(vote.SignBytes(chainID))
	if err != nil {
		return err
	}

	vote.Signature = signature

	return nil
}

// SignProposal signs a canonical representation of the proposal, along with
// the chainID. Implements PrivValidator.
func (a *AiakosPV) SignProposal(chainID string, proposal *types.Proposal) error {
	signature, err := a.signBytes(proposal.SignBytes(chainID))
	if err != nil {
		return err
	}

	proposal.Signature = signature

	return nil
}

// ImportKey imports a Eddsa private key to the specified key slot on the HSM.
// This fails if the key slot already contains a key.
// This should be used for testing purposes only. Wrap and import keys in production.
func (a *AiakosPV) ImportKey(keyID uint16, key []byte) error {
	command, err := commands.CreatePutAsymmetricKeyCommand(keyID, []byte("imported"), commands.Domain1, commands.CapabilityAsymmetricSignEddsa, commands.AlgorighmED25519, key, []byte{})
	if err != nil {
		return err
	}
	resp, err := a.hsmSessionManager.SendEncryptedCommand(command)
	if err != nil {
		return err
	}

	parsedResp, matched := resp.(*commands.PutAsymmetricKeyResponse)
	if !matched {
		a.Logger.Error("invalid response type")
		return errors.New("invalid response type")
	}

	if parsedResp.KeyID != keyID {
		a.Logger.Error("imported KeyID mismatch")
		return errors.New("imported KeyID mismatch")
	}

	return nil
}

func (a *AiakosPV) signBytes(data []byte) ([]byte, error) {
	command, err := commands.CreateSignDataEddsaCommand(a.signingKeyID, data)
	if err != nil {
		return nil, err
	}
	resp, err := a.hsmSessionManager.SendEncryptedCommand(command)
	if err != nil {
		return nil, err
	}

	parsedResp, matched := resp.(*commands.SignDataEddsaResponse)
	if !matched {
		a.Logger.Error("invalid response type")
		return nil, errors.New("invalid response type")
	}

	// TODO replace with ed25519.SignatureSize once tendermint is upgraded to >=v0.24.0
	if len(parsedResp.Signature) != 64 {
		a.Logger.Error("invalid signature length", "size", len(parsedResp.Signature))
		return nil, errors.New("invalid signature length")
	}

	return parsedResp.Signature, nil
}
