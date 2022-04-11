package simplersa

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"regexp"
	"strings"
)

var (
	ErrBlankValues                      = errors.New("message and/or PublicKey is blank")
	ErrEncryptMessageConvertingKey      = errors.New("cannot convert key PEM decode failed")
	ErrEncryptMessageX509Parsing        = errors.New("parsing x509 data")
	ErrEncryptMessagePCS1Encrypting     = errors.New("encrypting Message with PKCS1v5")
	ErrDecryptMessageRegExMatchFailed   = errors.New("regular expression Match() failed")
	ErrDecryptMessageDecodeStringFailed = errors.New("base 64 decoding of message failed")
	ErrDecryptMessagePemDecoding        = errors.New("private Key pem decoding failed")
	ErrDecryptMessageX509Decoding       = errors.New("x509 private key decoding failed")
	ErrDecryptionFailed                 = errors.New("message decryption failed")
	ErrInvalidKeyLen                    = errors.New("invalid Key length")
)

// ValidKeyLengths - In my brief search, these are the de facto or "commonly
// accepted" key lengths.
var ValidKeyLengths = []int{512, 1024, 2048, 3072, 4096, 7680, 15360}

type RsaKeyPairType struct {
	PublicKey  string
	PrivateKey string
}

// badLength validates if KeyLen is in the ValidKeyLengths array
func badKeyLength(keyLen int) bool {
	// Check for valid length
	rtn := true
	for _, v := range ValidKeyLengths {
		if keyLen == v {
			rtn = false
			break
		}
	}
	return rtn
}

//NewRSAKeyPair creates PEM encoded X509 RSA public and private key certificates
func NewRSAKeyPair(rsaKeyLength int) (RsaKeyPairType, error) {

	var rsaKeyPair RsaKeyPairType

	// check for valid RSA key Length
	if badKeyLength(rsaKeyLength) {
		return rsaKeyPair, ErrInvalidKeyLen
	}

	//The GenerateKey function uses the random data generator random to generate a
	//pair of RSA keys with a specified number of words rand.Reader is a global,
	//shared strong random number generator for passwords.

	privateKey, _ := rsa.GenerateKey(rand.Reader, rsaKeyLength)

	// create a x509 PEM encoded "Private Key" string that you
	//could store in a file if you wanted to :)

	rsaKeyPair.PrivateKey = string(
		pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA Private Key",
				Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
			}))

	// create a x509 PEM encoded "Public Key" string that you
	//could store in a file if you wanted to :)
	rsaKeyPair.PublicKey = string(
		pem.EncodeToMemory(
			&pem.Block{
				Type: "RSA Public Key",
				Bytes: func(pubKey *rsa.PublicKey) []byte {
					pk, _ := x509.MarshalPKIXPublicKey(pubKey)
					return pk
				}(&privateKey.PublicKey),
			}))

	return rsaKeyPair, nil
}

// SaveRSAKeyPair saves a key pair to disk, the key pairs will
//be written as fileName.pvt and fileName.pub
func SaveRSAKeyPair(keys *RsaKeyPairType, fileName string) error {
	err := os.WriteFile(fileName+".pvt", []byte(keys.PrivateKey), 0700)
	if err != nil {
		return err
	}
	err = os.WriteFile(fileName+".pub", []byte(keys.PublicKey), 0700)
	if err != nil {
		return err
	}
	return nil
}

//LoadRsaKeys attempts to load both the private and public keys from disk
// Pay attention the "Warning" integer returned. it will be
//  0 - Both keys loaded
//	1 - if the private key wasn't found
//  2 - if the public  key wasn't found
//  3 - if both keys weren't found.
//  cut bait and run accordingly
// if it's 0 you have both keys and can encrypt and decrypt
// if it's 1 you can't decrypt
// if it's 2 you can't encrypt
// if it's 3 you can't do anything
// in addition file path is stored in the strings on warnings
func LoadRsaKeys(fileName string) (*RsaKeyPairType, int) {
	var kp RsaKeyPairType
	var warning = 0
	privateKeyNotfound := 1
	publicKeyNotFound := 2

	pub, err := os.ReadFile(fileName + ".pub")
	if err == nil {
		kp.PublicKey = string(pub)
	} else {
		kp.PublicKey = "WARNING: " + "fileName" + ".pub wasn't found"
		warning += publicKeyNotFound
	}
	pvt, err := os.ReadFile(fileName + ".pvt")
	if err == nil {
		kp.PrivateKey = string(pvt)
	} else {
		kp.PrivateKey = "WARNING: " + "fileName" + ".pvt wasn't found"
		warning += privateKeyNotfound
	}
	return &kp, warning
}

//EncryptMessage encrypts a plainText byte array with the RSA PublicKey
//string passed in. RSA is one way encryption Use the Public key to
//encrypt and the private key to decrypt.
//Returns the encrypted text as a base64 encoded string.
func EncryptMessage(message string, publicKey string) (string, error) {
	// scrub input
	if message == "" || publicKey == "" {
		return "", ErrBlankValues
	}
	// convert the message to a byte array
	plainText := []byte(message)

	//convert PublicKey to an array
	block, _ := pem.Decode([]byte(publicKey))

	//X509 decoding
	publicKeyInterface, err1 := x509.ParsePKIXPublicKey(block.Bytes)
	if err1 != nil {
		return "", ErrEncryptMessageX509Parsing
	}

	//Type assertion
	pubKey := publicKeyInterface.(*rsa.PublicKey)
	//Encrypt plaintext
	cipherText, _ := rsa.EncryptPKCS1v15(rand.Reader, pubKey, plainText)

	//Return ciphertext
	ctxt := base64.StdEncoding.EncodeToString(cipherText)

	return lineWrapString(ctxt, 40, true), nil
}

// reformat string "text" by adding a newline at "lineLen".
// Encoded text is a long string of characters, and sometimes it's
// easier to work with something formatted. This is for that.
func lineWrapString(text string, lineLen int, withHeaders bool) string {
	rtn := ""
	if withHeaders {
		rtn = "-----BEGIN ENCODED MESSAGE-----\n"
	}

	for i, r := range text {
		if i > 0 && (i%lineLen) == 0 {
			rtn += "\n"
		}
		rtn += string(r)
	}

	if withHeaders {
		rtn += "\n-----END ENCODED MESSAGE-----\n"
	}
	return rtn
}

//DecryptMessage Decrypts the message string using a passed in
//private key.
func DecryptMessage(message string, privateKey string) (string, error) {
	// scrub input
	if message == "" || privateKey == "" {
		return "", ErrBlankValues
	}

	// clean up the message string and convert it to bytes for
	// decryption.
	b64Lines := strings.Split(message, "\n")
	b64ctx := ""
	for _, line := range b64Lines {
		lineIsComment, _ := regexp.MatchString("-", line)

		if lineIsComment == false {
			b64ctx += line
		}
	}
	cipherText, err := base64.StdEncoding.DecodeString(b64ctx)
	if err != nil {
		return "", ErrDecryptMessageDecodeStringFailed
	}

	//PEM decoding
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil {
		return "", ErrDecryptMessagePemDecoding
	}

	//X509 decoding
	pvtKey, err3 := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err3 != nil {
		return "", ErrDecryptMessageX509Decoding
	}

	//Decrypt the ciphertext
	plainText, err4 := rsa.DecryptPKCS1v15(rand.Reader, pvtKey, cipherText)
	if err4 != nil {
		return "", ErrDecryptionFailed
	}

	//Return plaintext
	return string(plainText), nil
}
