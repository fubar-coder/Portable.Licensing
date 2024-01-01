#if NET6_0_OR_GREATER
using System;
using System.Security.Cryptography;

namespace Portable.Licensing.Security.Cryptography
{
    public class NativeKeyPair : KeyPair
    {
        private readonly AsymmetricAlgorithm algorithm;

        public NativeKeyPair(AsymmetricAlgorithm algorithm)
        {
            this.algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
        }

        /// <summary>
        /// Gets the encrypted and DER encoded private key.
        /// </summary>
        /// <param name="passPhrase">The pass phrase to encrypt the private key.</param>
        /// <returns>The encrypted private key.</returns>
        public override string ToEncryptedPrivateKeyString(string passPhrase)
        {
            var data = this.algorithm.ExportEncryptedPkcs8PrivateKey(passPhrase, new PbeParameters(PbeEncryptionAlgorithm.TripleDes3KeyPkcs12, HashAlgorithmName.SHA1, 10));
            return Convert.ToBase64String(data);
        }

        /// <summary>
        /// Gets the DER encoded public key.
        /// </summary>
        /// <returns>The public key.</returns>
        public override string ToPublicKeyString()
        {
            var data = this.algorithm.ExportSubjectPublicKeyInfo();
            return Convert.ToBase64String(data);
        }
    }
}
#endif
