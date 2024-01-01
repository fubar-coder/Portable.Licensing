#if NET462 || NETSTANDARD2_0
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Security;

namespace Portable.Licensing.Security.Cryptography
{
    class BouncySigner : Signer
    {
        private readonly string signatureAlgorithm = X9ObjectIdentifiers.ECDsaWithSha512.Id;

        public override byte[] Sign(byte[] documentToSign, string privateKey, string passPhrase)
        {
            var privKey = BouncyKeyFactory.FromEncryptedPrivateKeyString(privateKey, passPhrase);

            var signer = SignerUtilities.GetSigner(signatureAlgorithm);
            signer.Init(true, privKey);
            signer.BlockUpdate(documentToSign, 0, documentToSign.Length);
            var signature = signer.GenerateSignature();
            return signature;
        }

        public override bool VerifySignature(byte[] documentToSign, byte[] signature, string publicKey)
        {
            var pubKey = BouncyKeyFactory.FromPublicKeyString(publicKey);

            var signer = SignerUtilities.GetSigner(signatureAlgorithm);
            signer.Init(false, pubKey);
            signer.BlockUpdate(documentToSign, 0, documentToSign.Length);

            return signer.VerifySignature(signature);
        }
    }
}
#endif
