// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

// Self-contained file — no SR dependencies, no dependency on Interop.EvpPkey.cs.
// Can be compiled into both System.Security.Cryptography and System.Net.Security.

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

internal static partial class Interop
{
    internal static partial class Crypto
    {
        // X509_get0_privkey: returns borrowed EVP_PKEY* from X509* — no refcount change.
        [LibraryImport("libcrypto.so.3")]
        private static partial nint X509_get0_privkey(nint x509);

        // EVP_PKEY_up_ref: increment refcount — self-contained here to avoid
        // dependency on Interop.EvpPkey.cs which has SR string dependencies
        // not available in System.Net.Security.
        // Named differently to avoid duplicate symbol with CryptoNative_UpRefEvpPkey
        // if Interop.EvpPkey.cs is also compiled into the same assembly.
        [LibraryImport("libcrypto.so.3", EntryPoint = "CryptoNative_UpRefEvpPkey")]
        private static partial int UpRefEvpPkeyX509(SafeEvpPKeyHandle handle);

        /// <summary>
        /// Returns a SafeEvpPKeyHandle for the private key stored in an X509 certificate,
        /// or null if no private key is present.
        /// Uses X509_get0_privkey (borrowed ref) + EVP_PKEY_up_ref (refcount increment).
        /// TPM-safe: never calls EVP_PKEY_dup.
        /// </summary>
        internal static SafeEvpPKeyHandle? X509GetPrivateKey(IntPtr x509Handle)
        {
            if (x509Handle == IntPtr.Zero)
                return null;

            nint pkey = X509_get0_privkey((nint)x509Handle);
            if (pkey == 0)
                return null;

            // Borrowed ref — must up_ref before owning.
            var borrowed = new SafeEvpPKeyHandle((IntPtr)pkey, ownsHandle: false);
            int upRefResult = UpRefEvpPkeyX509(borrowed);
            if (upRefResult != 1)
                return null;

            return new SafeEvpPKeyHandle((IntPtr)pkey, ownsHandle: true);
        }
    }
}
