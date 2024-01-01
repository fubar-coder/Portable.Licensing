#if NET6_0_OR_GREATER
using System;
using System.Security.Cryptography;

namespace Portable.Licensing.Security.Cryptography
{
    internal class NativeSigner : Signer
    {
        public override byte[] Sign(byte[] documentToSign, string privateKey, string passPhrase)
        {
            var ecdsa = ECDsa.Create();
            ecdsa.ImportEncryptedPkcs8PrivateKey(passPhrase, Convert.FromBase64String(privateKey), out int _);
            return ecdsa.SignData(documentToSign, HashAlgorithmName.SHA512, DSASignatureFormat.Rfc3279DerSequence);
        }

        public override bool VerifySignature(byte[] documentToSign, byte[] signature, string publicKey)
        {
            var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKey), out int read);
            return ecdsa.VerifyData(documentToSign, signature, HashAlgorithmName.SHA512, DSASignatureFormat.Rfc3279DerSequence);
        }
    }
}
#endif
