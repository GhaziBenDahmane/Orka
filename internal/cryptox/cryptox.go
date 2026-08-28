package cryptox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var streamMagic = []byte("DYENC01\x00")

const streamChunkSize = 64 * 1024

type Box struct{ aead cipher.AEAD }

func New(key []byte) (*Box, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return &Box{aead: aead}, nil
}

func (b *Box) Encrypt(plaintext []byte, context string) (string, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("create nonce: %w", err)
	}
	sealed := b.aead.Seal(nonce, nonce, plaintext, []byte(context))
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

func (b *Box) Decrypt(encoded, context string) ([]byte, error) {
	payload, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	if len(payload) < b.aead.NonceSize() {
		return nil, fmt.Errorf("ciphertext is too short")
	}
	nonce, ciphertext := payload[:b.aead.NonceSize()], payload[b.aead.NonceSize():]
	plaintext, err := b.aead.Open(nil, nonce, ciphertext, []byte(context))
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// EncryptStream writes a framed AES-GCM stream. Each chunk and the terminal
// frame is authenticated independently, allowing large artifacts to be
// encrypted without buffering them in memory while detecting truncation.
func (b *Box) EncryptStream(dst io.Writer, src io.Reader, context string) error {
	prefix := make([]byte, b.aead.NonceSize()-4)
	if _, err := io.ReadFull(rand.Reader, prefix); err != nil {
		return fmt.Errorf("create stream nonce: %w", err)
	}
	if _, err := dst.Write(append(append([]byte{}, streamMagic...), prefix...)); err != nil {
		return err
	}
	buffer := make([]byte, streamChunkSize)
	for counter := uint32(0); ; counter++ {
		n, readErr := io.ReadFull(src, buffer)
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return readErr
		}
		if err := b.writeStreamFrame(dst, prefix, context, counter, buffer[:n]); err != nil {
			return err
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr == io.ErrUnexpectedEOF {
			if counter == ^uint32(0) {
				return errors.New("encrypted stream is too large")
			}
			return b.writeStreamFrame(dst, prefix, context, counter+1, nil)
		}
		if counter == ^uint32(0) {
			return errors.New("encrypted stream is too large")
		}
	}
}

func (b *Box) writeStreamFrame(dst io.Writer, prefix []byte, context string, counter uint32, plaintext []byte) error {
	nonce := append(append([]byte{}, prefix...), make([]byte, 4)...)
	binary.BigEndian.PutUint32(nonce[len(prefix):], counter)
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(plaintext)))
	aad := append(append([]byte(context), header...), nonce...)
	sealed := b.aead.Seal(nil, nonce, plaintext, aad)
	if _, err := dst.Write(header); err != nil {
		return err
	}
	_, err := dst.Write(sealed)
	return err
}

func (b *Box) DecryptStream(dst io.Writer, src io.Reader, context string) error {
	header := make([]byte, len(streamMagic)+b.aead.NonceSize()-4)
	if _, err := io.ReadFull(src, header); err != nil {
		return fmt.Errorf("read encrypted stream header: %w", err)
	}
	if !bytes.Equal(header[:len(streamMagic)], streamMagic) {
		return errors.New("invalid encrypted stream header")
	}
	prefix := header[len(streamMagic):]
	for counter := uint32(0); ; counter++ {
		lengthBytes := make([]byte, 4)
		if _, err := io.ReadFull(src, lengthBytes); err != nil {
			return fmt.Errorf("encrypted stream is truncated: %w", err)
		}
		plainLength := binary.BigEndian.Uint32(lengthBytes)
		if plainLength > streamChunkSize {
			return errors.New("invalid encrypted stream frame")
		}
		sealed := make([]byte, int(plainLength)+b.aead.Overhead())
		if _, err := io.ReadFull(src, sealed); err != nil {
			return fmt.Errorf("encrypted stream is truncated: %w", err)
		}
		nonce := append(append([]byte{}, prefix...), make([]byte, 4)...)
		binary.BigEndian.PutUint32(nonce[len(prefix):], counter)
		aad := append(append([]byte(context), lengthBytes...), nonce...)
		plain, err := b.aead.Open(nil, nonce, sealed, aad)
		if err != nil {
			return fmt.Errorf("decrypt stream frame: %w", err)
		}
		if plainLength == 0 {
			var extra [1]byte
			if n, err := src.Read(extra[:]); n != 0 || err != io.EOF {
				return errors.New("encrypted stream has trailing data")
			}
			return nil
		}
		if _, err = dst.Write(plain); err != nil {
			return err
		}
		if counter == ^uint32(0) {
			return errors.New("encrypted stream is too large")
		}
	}
}

func Digest(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}
