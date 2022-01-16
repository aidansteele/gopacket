package pcapgo

import (
	"encoding/binary"
)

// NgDecryptionSecrets hold the statistic for an interface at a single point in time. These values are already supposed to be accumulated. Most pcapng files contain this information at the end of the file/section.
type NgDecryptionSecrets struct {
	Type NgDecryptionSecretType
	Data []byte
}

type NgDecryptionSecretType uint32

const (
	NgDecryptionSecretTypeTLSKeyLog       = NgDecryptionSecretType(0x544c534b)
	NgDecryptionSecretTypeWireGuardKeyLog = NgDecryptionSecretType(0x57474b4c)
	NgDecryptionSecretTypeZigBeeNWK       = NgDecryptionSecretType(0x5a4e574b)
	NgDecryptionSecretTypeZigBeeAPS       = NgDecryptionSecretType(0x5a415053)
)

// WriteDecryptionSecrets writes TLS secrets to the file
func (w *NgWriter) WriteDecryptionSecrets(secrets NgDecryptionSecrets) error {
	length := uint32(len(secrets.Data)) + 20
	padding := (4 - length&3) & 3
	length += padding

	le := binary.LittleEndian
	le.PutUint32(w.buf[:4], uint32(ngBlockTypeDecryptionSecrets))
	le.PutUint32(w.buf[4:8], length)
	le.PutUint32(w.buf[8:12], uint32(secrets.Type))
	le.PutUint32(w.buf[12:16], uint32(len(secrets.Data)))
	if _, err := w.w.Write(w.buf[:16]); err != nil {
		return err
	}

	if _, err := w.w.Write(secrets.Data); err != nil {
		return err
	}

	binary.LittleEndian.PutUint32(w.buf[:4], 0)
	_, err := w.w.Write(w.buf[4-padding : 8]) // padding + length
	return err
}
