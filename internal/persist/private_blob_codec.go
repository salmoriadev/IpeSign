package persist

import "ipesign/internal/cryptoutil"

type PrivateBlobCodec interface {
	Seal(plaintext []byte) ([]byte, error)
	Open(sealedBlob []byte) ([]byte, error)
	IsSealed(raw []byte) bool
}

type PassphrasePrivateBlobCodec struct {
	passphrase string
}

func NewPassphrasePrivateBlobCodec(passphrase string) *PassphrasePrivateBlobCodec {
	return &PassphrasePrivateBlobCodec{
		passphrase: passphrase,
	}
}

func (codec *PassphrasePrivateBlobCodec) Seal(plaintext []byte) ([]byte, error) {
	return cryptoutil.SealWithPassphrase(plaintext, codec.passphrase)
}

func (codec *PassphrasePrivateBlobCodec) Open(sealedBlob []byte) ([]byte, error) {
	return cryptoutil.OpenWithPassphrase(sealedBlob, codec.passphrase)
}

func (codec *PassphrasePrivateBlobCodec) IsSealed(raw []byte) bool {
	return cryptoutil.LooksLikeSealedBlob(raw)
}
