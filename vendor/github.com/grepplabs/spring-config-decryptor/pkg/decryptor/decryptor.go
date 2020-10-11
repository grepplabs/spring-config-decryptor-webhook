package decryptor

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	merror "github.com/grepplabs/spring-config-decryptor/pkg/errors"
	"io"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
)

const (
	cipherPrefix = "{cipher}"
	defaultSalt  = "deadbeef"
)

var (
	cipherPattern = regexp.MustCompile(`{cipher}([A-Za-z0-9+/=]*)`)
)

type ValueDecryptorOption func(decryptor *ValueDecryptor) error

type ValueDecryptor struct {
	privateKey *rsa.PrivateKey
	salt       []byte
}

func NewValueDecryptor(key []byte, options ...ValueDecryptorOption) (*ValueDecryptor, error) {
	privateKey, err := ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	result := &ValueDecryptor{privateKey: privateKey}
	if err := WithSalt(defaultSalt)(result); err != nil {
		return nil, err
	}
	for _, option := range options {
		if err = option(result); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func ParsePrivateKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block != nil {
		key = block.Bytes
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("private key should be a PEM or plain PKCS1 or PKCS8; parse error: %v", err)
		}
	}
	parsed, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is invalid")
	}
	return parsed, nil
}

func WithSalt(salt string) ValueDecryptorOption {
	return func(decryptor *ValueDecryptor) error {
		if saltBytes, err := hex.DecodeString(salt); err != nil {
			return fmt.Errorf("salt '%s' cannot be hex decoded: %v", salt, err)
		} else {
			decryptor.salt = saltBytes
		}
		return nil
	}
}

func (d ValueDecryptor) DecryptValue(value string) (string, error) {
	if !strings.HasPrefix(value, cipherPrefix) {
		return value, nil
	}
	value = strings.TrimPrefix(value, cipherPrefix)
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("value '%s' cannot be base64 decoded: %v", value, err)
	}
	return d.decryptData(data)
}

func (d ValueDecryptor) decryptData(data []byte) (string, error) {
	if len(data) < 2 {
		return "", errors.New("data too short to read session key length")
	}
	length := binary.BigEndian.Uint16(data[0:2])

	if len(data) < int(length+2) {
		return "", errors.New("data too short to read session key cipher text")
	}
	ciphertext := data[2 : length+2]

	iv, err := rsa.DecryptPKCS1v15(rand.Reader, d.privateKey, ciphertext)
	if err != nil {
		return "", err
	}
	key := pbkdf2.Key([]byte(hex.EncodeToString(iv)), d.salt, 1024, 32, sha1.New)

	plaintext, err := d.decryptCBC(key, data[2+length:])
	if err != nil {
		return "", err
	}
	return string(d.unpad(plaintext)), nil
}

func (d ValueDecryptor) decryptCBC(key, ciphertext []byte) (plaintext []byte, err error) {
	var block cipher.Block

	if block, err = aes.NewCipher(key); err != nil {
		return
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("cipher text length shorter than AES block size")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(ciphertext, ciphertext)

	plaintext = ciphertext

	return
}

func (d ValueDecryptor) unpad(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

type ConfigDecryptor struct {
	valueDecryptor *ValueDecryptor
}

func NewConfigDecryptor(valueDecryptor *ValueDecryptor) *ConfigDecryptor {
	return &ConfigDecryptor{
		valueDecryptor: valueDecryptor,
	}
}

func (c ConfigDecryptor) Decrypt(output io.Writer, input io.Reader) (err error) {
	var (
		line string
	)
	rd := bufio.NewReader(input)
	wr := bufio.NewWriter(output)
	defer func() {
		merr := merror.MultiError{}
		merr.Add(err)
		merr.Add(errors.Wrap(wr.Flush(), "writing flush error"))
		err = merr.Err()
	}()
	for {
		if line, err = rd.ReadString('\n'); err != nil {
			if err == io.EOF {
				if err = c.decryptLine(wr, line); err != nil {
					return err
				}
				break
			}
			return fmt.Errorf("read file line error: %v", err)
		}
		if err = c.decryptLine(wr, line); err != nil {
			return err
		}
	}
	return nil
}

func (c ConfigDecryptor) decryptLine(wr *bufio.Writer, line string) (err error) {
	line, err = c.processLine(line)
	if err != nil {
		return fmt.Errorf("line processing error: %v", err)
	}
	_, err = wr.WriteString(line)
	if err != nil {
		return fmt.Errorf("line writing error: %v", err)
	}
	return nil
}

func (c ConfigDecryptor) processLine(line string) (string, error) {
	var sb strings.Builder

	for {
		ns := cipherPattern.FindStringIndex(line)
		if ns == nil {
			sb.WriteString(line)
			break
		}
		sb.WriteString(line[:ns[0]])
		value := line[ns[0]:ns[1]]
		plainText, err := c.valueDecryptor.DecryptValue(value)
		if err != nil {
			return "", err
		}
		sb.WriteString(plainText)
		line = line[ns[1]:]
	}
	return sb.String(), nil
}

type Decryptor interface {
	Decrypt(output io.Writer, input io.Reader) (err error)
}

func NewDecryptor(key []byte) (Decryptor, error) {
	valueDecryptor, err := NewValueDecryptor(key)
	if err != nil {
		return nil, errors.Wrap(err, "create value decryptor error")
	}
	configDecryptor := NewConfigDecryptor(valueDecryptor)
	return configDecryptor, nil
}
