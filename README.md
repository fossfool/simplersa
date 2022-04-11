# simplersa
A Wrapper for RSA Encryption in Go (go or golang for search)

Okay when I started working with RSA encryption, I spent a bunch of time banging my head against my monitor just trying to get something to work. RSA isn't something you're just going to pick up in a few minutes. It's convoluted. Sorry, it just is, compared to MD5 AES or some other encryption algorithms you might have already been working with. But that's enough complaining. ONCE I GOT MY BRAIN AROUND IT, it's not that bad.
### WHAT IS RSA?
It's an asymmetric encryption algorithm used to help secure the internet. It takes a Public key to encrypt a message and a private key to decrypt it back into readable text. It's meant to pass messages less than a few hundered characters in length from one person to another. checkout https://en.wikipedia.org/wiki/RSA_(cryptosystem) for more in depth info.

The long and short of it is when you're really dealing with RSA, you are actually dealing with RSA, Base64 encoding, PEM Encoding, and x509 certificates too. You'll go bald starting from scratch. SimpleRsa wraps this up nice and neat for you. It's 100% GO code too, check this out.

```go
    package main

    
```
testing staging areas
