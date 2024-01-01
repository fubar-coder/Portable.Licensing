namespace Portable.Licensing.Security.Cryptography
{
    public abstract class KeyGenerator
    {
        public static KeyGenerator Create()
        {
#if NET462 || NETSTANDARD2_0
            return new BouncyKeyGenerator();
#else
            return new NativeKeyGenerator();
#endif
        }

        /// <summary>
        /// Generates a private/public key pair for license signing.
        /// </summary>
        /// <returns>An <see cref="BouncyKeyPair"/> containing the keys.</returns>
        public abstract KeyPair GenerateKeyPair();
    }
}
