# Experiment with FROST signatures for iroh ed keypairs

## Splitting a keypair

Split the keypair in ~/.iroh/keypair into subdirectories a, b, c

```
cargo run split --key ~/.iroh/keypair a b c 
```

Minimum number of parts is 3. Default threshold is n-1.

This is just a toy. The original keypair is kept in place. In a real application
you would delete the keypair.

## Signing using the fragments

```
cargo run sign a c --key 25mzjgjlrcrma7wkm4l3fjv2afcs53cvmmyw3v2uwwt2dczsinaa --message test
Reconstructed a signing key from ["a/25mzjgjlrcrma7wkm4l3fjv2afcs53cvmmyw3v2uwwt2dczsinaa.secret", "c/25mzjgjlrcrma7wkm4l3fjv2afcs53cvmmyw3v2uwwt2dczsinaa.secret"]
Signature: daec0537cd6f080cce1ae7150684ac3147e576c9bde9a74d27e914bcfa834cef2d204ff9295379784fcca3eaa95e4b196b4fb8b60ec316840b5e649844db880e
```