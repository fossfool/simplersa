[![test](https://github.com/fossfool/simplersa/actions/workflows/test.yaml/badge.svg?branch=master)](https://github.com/fossfool/simplersa/actions/workflows/test.yaml)
# simplersa
A Wrapper for RSA Encryption in Go (go or golang for search)

Okay when I started working with RSA encryption, I spent a bunch of time banging my head against my monitor just trying to get something to work. RSA isn't something you're just going to pick up in a few minutes. It's convoluted. Sorry, it just is, compared to MD5 AES or some other encryption algorithms you might have already been working with. But that's enough complaining. ONCE I GOT MY BRAIN AROUND IT, it's not that bad.
### WHAT IS RSA?
It's an asymmetric encryption algorithm used to help secure the internet. It takes a Public key to encrypt a message and a private key to decrypt it back into readable text. It's meant to pass messages less than a few hundered characters in length from one person to another. checkout https://en.wikipedia.org/wiki/RSA_(cryptosystem) for more in depth info.

The long and short of it is when you're really dealing with RSA, you are actually dealing with RSA, Base64 encoding, PEM Encoding, and x509 certificates too. You'll go bald starting from scratch. SimpleRsa wraps this up nice and neat for you. It's 100% GO code too, check this out.

```go
    package main
    
    import (
        "fmt"
        srsa "github.com/fossfool/simplersa"
    )
    
    func main() {
        fmt.Println("Testing simplersa")
    
        //Make and RSA Key Pair using a 1024 bit length
        //(I'm using short key lengths here to make things
        //readable. We support up to 16k bit lengths.)
        rsaKeys, _ := srsa.NewRSAKeyPair(1024)
    
        //this returns PEM Encoded x509 RSA Certificates
        //they're in memory and ready to work
        fmt.Println(rsaKeys.PublicKey)
        fmt.Println(rsaKeys.PrivateKey)
    
        plainText := "A test message with runes ♡♡♡♡ in it."
        cipherText, _ := srsa.EncryptMessage(plainText, rsaKeys.PublicKey)
        fmt.Println(cipherText)
        decryptedText, _ := srsa.DecryptMessage(cipherText, rsaKeys.PrivateKey)
        fmt.Println(decryptedText)
        
        //Want to save the keys to disk?
        
        srsa.SaveRSAKeyPair(&rsaKeys, "MyRSAKey")
        
        // loading is just as easy it will attempt to load both keys.
        
        keys, _ := srsa.LoadRsaKeys("MyRSAKey")
        
        // this creates MyRSAKey.pvt and MyRSAKey.pub in the working directory
    }
    
    /* Example output (your keys will be different) 
    Testing simplersa
    -----BEGIN RSA Public Key-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmxqY8auDTvn0WnYyy+eBNTaX9
    GJ9OCuM20apOqE+yxgsK078fHRn/o+TMtUJgol6oAIfqcjT15cum31HmAOrdX9qL
    GHHH5xKugu6Kan78OpQGlugrOKoRawt9BiZxB/uZQ4iZjHB2MubnY2FT+OuU/KPW
    DjX5ws9Fnwoir+uq2QIDAQAB
    -----END RSA Public Key-----
    
    -----BEGIN RSA Private Key-----
    MIICXQIBAAKBgQCmxqY8auDTvn0WnYyy+eBNTaX9GJ9OCuM20apOqE+yxgsK078f
    HRn/o+TMtUJgol6oAIfqcjT15cum31HmAOrdX9qLGHHH5xKugu6Kan78OpQGlugr
    OKoRawt9BiZxB/uZQ4iZjHB2MubnY2FT+OuU/KPWDjX5ws9Fnwoir+uq2QIDAQAB
    AoGAF/BFpkB1Gw+ppthgfMQvNQljPQwOucYITTMVLgssvW194kT4lv+3XqFo0xVl
    fLdxvM2utLFF9tHQRJijic8x5u9Gsz5DTGHKxKfhecEH9sJsQUeI+k6shHx6Wn1f
    gI1dE5FqIWFOhZHat/av2Aer4SCpSMfARfv5WlcCVe3W5R0CQQDdzYR8JTUomnQp
    yX0lIAJyDeIoCK2aVoQ9nOO/MpHuzwGYD36lNLR4kiouDjPQKKlYIbjXTaDLfEnZ
    P95onQxDAkEAwH09xhyoz9rri/MEASdbQKUsk2ML39Wu8yvz/PVlwXlrN2MmL2E7
    xXsWmDKV7SprgWQqvR/e7swMjb0R2L4IswJBANmnTmXgwTx57JoA7fxbX+r6Mr6k
    XW9BjP1FErxR7KCSpHbKZbXKdXqHvDp7l16iOCOS2+bzd2GXMoSsxxyTWC8CQQCo
    LQRK0gFf0SqZFJK8G1Gr8mQ2xYO7Zeu7w/whV5o25smZE8RqAu8BBCDiitfY5YYV
    /5kjsfPJ+XdCYx1zm9znAkBLMScBbWB3gJLYK5CpOTgl3N/+JkrpQMiWTsbf9vbH
    dlDBgksGhnQmMCiIEYeExrVbucRBqGDkU1xdZQKkrpx5
    -----END RSA Private Key-----
    
    -----BEGIN ENCODED MESSAGE-----
    ULc00gCsAEZE09QD7liUqQhxFXdl78TEdyfr9UV0
    HV6qbx90+GBoIfn5qu3dpFZT+ReJurM56vFQvC5S
    bJYHqoW4O1RuYicpuqFAIzl/kzC1DU2BUkacMsq3
    R/TAr3xaUTPrHLqPHf8seZH20EnP4VPIZy/mESet
    iHUAUAv+BHE=
    -----END ENCODED MESSAGE-----
    
    A test message with runes ♡♡♡♡ in it.
    
    Process finished with the exit code 0
    
     */

```

So this is the first release... I'll keep working on the docs if you have any questions, please let me know.

-james
(fossfool)

