namespace Portable.Licensing.Security.Cryptography
{
    public abstract class Signer
    {
        public static Signer Create()
        {
#if NET452 || NETSTANDARD2_0
            return new BouncySigner();
#else
            return new NativeSigner();
#endif
        }

        public abstract byte[] Sign(byte[] documentToSign, string privateKey, string passPhrase);

        public abstract bool VerifySignature(byte[] documentToSign, byte[] signature, string publicKey);
    }
}
