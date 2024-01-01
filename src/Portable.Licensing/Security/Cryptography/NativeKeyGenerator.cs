#if NET6_0_OR_GREATER
using System.Security.Cryptography;

namespace Portable.Licensing.Security.Cryptography
{
    public class NativeKeyGenerator : KeyGenerator
    {
        public override KeyPair GenerateKeyPair()
        {
            return new NativeKeyPair(ECDsa.Create());
        }
    }
}
#endif
