// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if !TARGET_WINDOWS

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class OpenSsl
    {
        internal static partial class Tpm2KeyChecker
        {
            // ── LibraryImport P/Invoke ────────────────────────────────────────
            // SYSLIB1051: LibraryImport source generator does not support IntPtr.
            // Use 'nint' instead — it is the same underlying type but is
            // recognised by the source generator as a blittable native integer.

            [LibraryImport("libcrypto.so.3")]
            private static partial nint EVP_PKEY_get0_provider(nint pkey);

            [LibraryImport("libcrypto.so.3")]
            private static partial nint OSSL_PROVIDER_get0_name(nint provider);

            // ── Detection ─────────────────────────────────────────────────────

            // Shared detection logic
            private static bool IsHandleTpm2Backed(nint rawPtr)
            {
                nint provider = EVP_PKEY_get0_provider(rawPtr);
                if (provider == 0)
                    return false;

                nint namePtr = OSSL_PROVIDER_get0_name(provider);
                if (namePtr == 0)
                    return false;

                string name = Marshal.PtrToStringAnsi(namePtr) ?? string.Empty;
                return string.Equals(name, "tpm2", StringComparison.Ordinal);
            }

            internal static bool IsTpm2Key(SafeEvpPKeyHandle keyPtr)
            {
                if (keyPtr == null || keyPtr.IsInvalid)
                    return false;

                bool addedRef = false;
                try
                {
                    keyPtr.DangerousAddRef(ref addedRef);
                    return IsHandleTpm2Backed(keyPtr.DangerousGetHandle());
                }
                finally
                {
                    if (addedRef)
                        keyPtr.DangerousRelease();
                }
            }

            // Used by OpenSslX509CertificateReader.GetRSAPrivateKey() to detect
            // TPM-backed keys before constructing RSAOpenSsl (which calls EVP_PKEY_dup).
            internal static bool IsTpm2BackedHandle(SafeEvpPKeyHandle keyHandle)
            {
                if (keyHandle == null || keyHandle.IsInvalid)
                    return false;

                bool addedRef = false;
                try
                {
                    keyHandle.DangerousAddRef(ref addedRef);
                    return IsHandleTpm2Backed(keyHandle.DangerousGetHandle());
                }
                finally
                {
                    if (addedRef)
                        keyHandle.DangerousRelease();
                }
            }

            // ── Verification ──────────────────────────────────────────────────

            internal static void VerifyKeyMatchesCertificate(
                SafeEvpPKeyHandle keyPtr,
                SafeX509Handle certPtr)
            {
                RSAParameters certPubParams;
                RSAParameters tpmPubParams;

                using (var cert = new X509Certificate2(certPtr.DangerousGetHandle()))
                using (RSA? certRsa = cert.GetRSAPublicKey())
                {
                    if (certRsa is null)
                        throw new CryptographicException(
                            "TPM2 mTLS: Certificate does not have an RSA public key.");

                    certPubParams = certRsa.ExportParameters(includePrivateParameters: false);
                }

                // ownsHandle: false — SSL_CTX still owns the key, we just inspect it.
                using (var tempHandle = new SafeEvpPKeyHandle(keyPtr.DangerousGetHandle(), ownsHandle: false))
                using (var tpmRsa = new RSAOpenSsl(tempHandle))
                {
                    // ExportParameters(false) on TPM-backed RSAOpenSsl:
                    // → EVP_PKEY_todata → tpm2 provider → Esys_ReadPublic
                    // → returns modulus + exponent only, no private material
                    tpmPubParams = tpmRsa.ExportParameters(includePrivateParameters: false);
                }

                if (certPubParams.Modulus is null || tpmPubParams.Modulus is null ||
                    !certPubParams.Modulus.AsSpan().SequenceEqual(tpmPubParams.Modulus.AsSpan()))
                {
                    throw new CryptographicException(
                        "TPM2 mTLS: RSA modulus of TPM key does not match certificate.");
                }

                if (certPubParams.Exponent is null || tpmPubParams.Exponent is null ||
                    !certPubParams.Exponent.AsSpan().SequenceEqual(tpmPubParams.Exponent.AsSpan()))
                {
                    throw new CryptographicException(
                        "TPM2 mTLS: RSA public exponent of TPM key does not match certificate.");
                }
            }
        }
    }
}

#endif // !TARGET_WINDOWS
