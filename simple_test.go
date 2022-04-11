package simplersa

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

var TestKeyLen int = 3072

func TestNewRSAKeyPair(t *testing.T) {
	//Normal Ops
	kp, keyErr := NewRSAKeyPair(TestKeyLen)
	if keyErr != nil {
		t.Errorf("expected success received %s", keyErr)
	}
	if kp.publicKey == "" || kp.privateKey == "" {
		t.Errorf("NewRSAKeyPair() failed to return a valid key pair.")
	}

	//Edge cases
	kp, err := NewRSAKeyPair(-8)
	if err != ErrInvalidKeyLen {
		t.Errorf("expected ErrInvalidKeyLen received %s", err)
	}
}

func PrepTestDirectory(t *testing.T) error {
	var rtn error

	if _, err := os.Stat("./testCerts"); os.IsNotExist(err) {
		//create directory for test
		err := os.Mkdir("./testCerts", 0755)
		if err != nil {
			rtn = errors.New("Can't create test directory")
		}
	} else {
		//remove test files if they exist
		if _, err := os.Stat("./testCerts/testKey.pvt"); os.IsExist(err) {
			err := os.Remove("./testCerts/testKey.pvt")
			if err != nil {
				rtn = errors.New("cannot remove previous testKey.pvt")
			}
		}
		if _, err := os.Stat("./testCerts/testKey.pub"); os.IsExist(err) {
			err = os.Remove("./testCerts/testKey.pub")
			if err != nil {
				rtn = errors.New("cannot remove previous testKey.pub")
			}
		}
	}
	return rtn
}

func TestSaveRSAKeyPair(t *testing.T) {
	e := PrepTestDirectory(t)
	if e != nil {
		t.Errorf("expected success received %s", e)
	}

	kp, keyErr := NewRSAKeyPair(TestKeyLen)
	if keyErr != nil {
		t.Errorf("expected success received %s", keyErr)
	}

	//Normal ops
	//Attempt to create keyfiles
	err := SaveRSAKeyPair(&kp, "./testCerts/testKey")
	if err != nil {
		t.Errorf("Cannot save Test Certs")
	}
	if _, err := os.Stat("./testCerts/testKey.pvt"); os.IsNotExist(err) {
		t.Errorf("private key not created")
	}
	if _, err := os.Stat("./testCerts/testKey.pub"); os.IsNotExist(err) {
		t.Errorf("public key not created")
	}

	// see what happens if file permissions are wrong on the pvt file
	os.Chmod("./testCerts/testKey.pvt", 0444)
	pvterr := SaveRSAKeyPair(&kp, "./testCerts/testKey")
	if pvterr != nil {
		eStr := fmt.Sprintf("%s", pvterr)
		if !strings.Contains(eStr, "permission denied") {
			t.Errorf("Err was: %s expected permission denied", eStr)
		}
	} else {
		t.Errorf("expected permission denied error, none encountered")
	}

	// reset permissions
	os.Chmod("./testCerts/testKey.pvt", 0744)

	// see what happens if permission is denied to the public file
	os.Chmod("./testCerts/testKey.pub", 0444)
	pubErr := SaveRSAKeyPair(&kp, "./testCerts/testKey")
	if pubErr != nil {
		eStr := fmt.Sprintf("%s", pubErr)
		if !strings.Contains(eStr, "permission denied") {
			t.Errorf("Err was: %s expected permission denied", eStr)
		}
	} else {
		t.Errorf("expected permission denied error, none encountered")
	}

	// reset permissions
	os.Chmod("./testCerts/testKey.pub", 0744)

}

func TestLoadRsaKeys(t *testing.T) {
	//Assumes the TestCerts have been created and are available for loading

	//Test with all keys present
	_ = func() int {
		_, warning := LoadRsaKeys("./testCerts/testKey")
		if warning != 0 {
			t.Errorf("A key is missing and should not be")
		}
		return warning
	}()

	//Test with pvt Key missing
	err := os.Rename("./testCerts/testKey.pvt", "./testCerts/testKey.pvt.temp")
	if err != nil {
		t.Errorf("Can't rename Private Key")
	}
	_ = func() int {
		_, warning := LoadRsaKeys("./testCerts/testKey")
		if warning != 1 {
			t.Errorf("A key is missing and should not be")
		}
		return warning
	}()

	//Test with Both Keys missing
	err = os.Rename("./testCerts/testKey.pub", "./testCerts/testKey.pub.temp")
	if err != nil {
		t.Errorf("Can't rename Public Key")
	}
	_ = func() int {
		_, warning := LoadRsaKeys("./testCerts/testKey")
		if warning != 3 {
			t.Errorf("both keys should be missing")
		}
		return warning
	}()

	//Test with public Key missing
	err = os.Rename("./testCerts/testKey.pvt.temp", "./testCerts/testKey.pvt")
	if err != nil {
		t.Errorf("Can't rename Public Key")
	}
	_ = func() int {
		_, warning := LoadRsaKeys("./testCerts/testKey")
		if warning != 2 {
			t.Errorf("only the public key should be missing")
		}
		return warning
	}()

	//reset public key
	err = os.Rename("./testCerts/testKey.pub.temp", "./testCerts/testKey.pub")
	if err != nil {
		t.Errorf("Can't rename Public Key")
	}
}

func TestEncryptMessage(t *testing.T) {

	keys, keyErr := NewRSAKeyPair(TestKeyLen)
	if keyErr != nil {
		t.Errorf("expected success received %s", keyErr)
	}
	plainText := "Hello this is a test message with runes♡♡♡♡"

	//normal ops
	cipherText, err10 := EncryptMessage(plainText, keys.publicKey)
	if err10 != nil {
		t.Errorf("Message Encryption Failed: %s", err10)
	}
	decryptedText, err11 := DecryptMessage(cipherText, keys.privateKey)
	if err11 != nil {
		t.Errorf("Message Decryption Failed: %s", err11)
	}

	if plainText != decryptedText {
		t.Errorf("ecrypted text not equal to decrypted text \n\tExpected:\t\"%s\"\n\tDecrypted:\t\"%s\"", plainText, decryptedText)
	}

	//validate error returns when stuff is missing or bad

	//Blank message and/or blank key passed
	_, err := EncryptMessage("", "")
	if err == nil && err != ErrBlankValues {
		t.Errorf("blank message and publicKey were not detected")
	}

	//Added the "BadBytes" sticking out on the right side of the key
	//to make it a "Bad Key"
	badPublicKey := `-----BEGIN RSA Public Key-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3vKgvXw9GoIXkSuP5dCD
mQ0yN2GuswZ9OtKwmRyeVYu7yP6abulVyrGZX8vtORGP4RbUvX73p08VN+3n/Ks1
8/iIS/iwGSjN17pHRObrul9up5xbsRZGJSLhjRdwR0wvldz1T+fcuEN6PxwXqWEq
0AaFbphiheUTC0FMTthpQDtkXHsyD9bi4r4NISxq3HS0/pM2K7GL1+03WD/uJls6BadBytes
JJxnNJbUiPXsDJxGB3z4RClKNXzGqZs/TVLeijD19h2ZE2YS7ACJEIuuh7swoP3P
owxIOcNYViHU2mCysm7TeKUSoxUBXRoZwjSSSG3dyLzDdSn3lWUI2q+j3X7Ffub/
23z+TmZh4efkf74iG9S1Iz5gLupjyIcWAKWL8HkoaW5h5y48Z9B9vvzI4NrFaz+/
lst3Z2psGSI8YTqgWNg1o0ynSnuxA46d6YTwY+3DoI32yLPqifPudSG5P0nEcWlz
jyGd5OFcpON540andqvyxGiEMaTJjIl0+zyPjMlLHBKFC4MSXX0XT9Av2/RLzFw1
Q9UFJlbzz0d6arI1cxou6KVnuddjAcEvanryl7ROUt0oDZ91p474vQCVL8qnz9DH
3aVY4LjnSyv6hdyQWFO0pLOaU+KeF44fsMJB+ex6StEjNTGkNG1JdjW69h+H4DMP
Yaj0FM0G8awAoYfk0iG1AC8CAwEAAQ==
-----END RSA Public Key-----
`

	//Test a Malformed Public key
	_, err3 := EncryptMessage("Test Message", badPublicKey)
	if err3 == nil {
		t.Errorf("malforomed publicKey not detected")
	}
	if err3 != ErrEncryptMessageX509Parsing {
		t.Errorf("expected ErrEncryptMessageX509Parsing but found error \"%s\"", err3)
	}
}

func TestDecryptMessage(t *testing.T) {

	//normal ops
	keys, keyErr := NewRSAKeyPair(TestKeyLen)
	if keyErr != nil {
		t.Errorf("expected success received %s", keyErr)
	}
	plainText := "Hello this is a test message with runes♡♡♡♡"

	cipherText, err1 := EncryptMessage(plainText, keys.publicKey)
	if err1 != nil {
		t.Errorf("message encryption Failed: %s", err1)
	}
	decryptedText, err2 := DecryptMessage(cipherText, keys.privateKey)
	if err2 != nil {
		t.Errorf("message eecryption Failed: %s", err2)
	}

	if plainText != decryptedText {
		t.Errorf("decrypted text not equal to encrypted text \n\tExpected:\t\"%s\"\n\tDecrypted:\t\"%s\"", plainText, decryptedText)
	}

	//Error testing (seriously short)
	badPrivateKey := `-----BEGIN RSA Private Key-----
MIILJAIBAAKCAnIAqLM3qtQKSXBl8pKcT1C6XhC1YZxL7mMZVdCNXsfc2SLYlGnG
j/b3lAXNi1iuZCBZLAm0+sUkQBztA8ZkctceOJHRQqIrT8vO0YDp9PhziWv6V2HV
+z+vsXvuHP29tRuAu+bYoxvUJJ/L2EeJSHHv2C8KD1mhksmdbaUmf2GDcjOCGxpV
mUWwPHh55twRwwuLcrBhc7TOmglW26RHCzroJFy6CpXgeSuiCMQ33RstxwOIFmTp
rbl3kT8jztwf9FKEpu/RL7gXEAz1zlUXkJT6uq0EZPEa7rM/UeI1Y68A2naGSIpN
iDtK1uu5aAoBIL+hEaR8JJ9EGVEdYsHWzI+iK7sN2mClPDaPR72mwPTY6Tk5oOpb
k36fBTteLcUQA1HZ+dh7j3B1RSk2plb74uFZZweMGbFRs2LHDzSvMl2xy06X02H8
jiG5rH7gqLjfuJI2TKhEhZJMYh+xx9HgSiREO2zwMeEwhlgDWIGnc92oc5ZpThnH
D3s17ap+VFL4bAJQshMq2U5vzxIM6t3F
-----END RSA Private Key-----
`
	//Test a malformed private key
	_, err3 := DecryptMessage("Test Message", badPrivateKey)
	if err3 == nil {
		t.Errorf("malforomed privateKey not detected")
	}
	if err3 != ErrDecryptMessageDecodeStringFailed {
		t.Errorf("expected ErrDecryptMessageDecodeStringFailed but found error \"%s\"", err3)
	}

	_, err4 := DecryptMessage("", "")
	if err4 != ErrBlankValues {
		t.Errorf("expected ErrBlankValues but received error \"%s\"", err3)
	}
}

func TestWrongKeyUsed(t *testing.T) {
	k1, _ := NewRSAKeyPair(TestKeyLen)
	k2, _ := NewRSAKeyPair(TestKeyLen)
	plainText := "Hello this is a test message with runes♡♡♡♡"
	cipherText, _ := EncryptMessage(plainText, k1.publicKey)

	decryptedMsg, err := DecryptMessage(cipherText, k2.privateKey)
	if err != nil && err != ErrDecryptionFailed {
		t.Errorf("Expected ErrDecryptionFailed, received:\nDecrypted Message: %s\n Error: %s", decryptedMsg, err)
	}
}

func TestBadPEMFormattingOnKey(t *testing.T) {
	key, _ := NewRSAKeyPair(TestKeyLen)
	plainText := "Hello this is a test message with runes♡♡♡♡"
	cipherText, _ := EncryptMessage(plainText, key.publicKey)
	//create a bad PEM packet by removing headers from PrivateKey
	var badKey string = ""
	for _, ln := range strings.Split(key.privateKey, "\n") {
		if !strings.Contains(ln, "-") {
			badKey += ln
		}
	}

	msg, err := DecryptMessage(cipherText, badKey)
	if err != nil {
		if err != ErrDecryptMessagePemDecoding {
			t.Errorf("Expected ErrDecryptMessagePemDecoding, received:\nDecrypted Message: %s\n Error: %s", msg, err)
		}
	}
}

func TestBadX509DecodingOnKey(t *testing.T) {
	key, _ := NewRSAKeyPair(TestKeyLen)
	plainText := "Hello this is a test message with runes♡♡♡♡"
	cipherText, _ := EncryptMessage(plainText, key.publicKey)

	// making a wee change to a good private key, so it won't parse correctly in x509
	// decryption phase.
	var badKey string = ""
	for i, ln := range strings.Split(key.privateKey, "\n") {
		if i == 4 {
			badKey += "BadKEY"
			for i, r := range []rune(ln) {
				if i > 5 {
					badKey += string(r)
				}
			}
			badKey += "\n"
		} else {
			badKey += ln + "\n"
		}
	}

	msg, err := DecryptMessage(cipherText, badKey)
	if err != nil {
		if err != ErrDecryptMessageX509Decoding {
			t.Errorf("Expected ErrDecryptMessageX509Decoding, received:\nDecrypted Message: %s\n Error: %s", msg, err)
		}
	}
}
