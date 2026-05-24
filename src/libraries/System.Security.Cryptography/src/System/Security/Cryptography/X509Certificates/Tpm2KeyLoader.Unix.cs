// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if !TARGET_WINDOWS

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace System.Security.Cryptography.X509Certificates
{
    internal static partial class Tpm2KeyLoader
    {
        internal const string Tss2Label = "TSS2 PRIVATE KEY";

        [LibraryImport("libcrypto.so.3")]
        private static partial nint BIO_new_mem_buf(nint buf, int len);

        [LibraryImport("libcrypto.so.3")]
        private static partial void BIO_free(nint bio);

        [LibraryImport("libcrypto.so.3", StringMarshalling = StringMarshalling.Utf8)]
        private static partial nint PEM_read_bio_PrivateKey_ex(
            nint bio, nint x, nint cb, nint u, nint libCtx, string propQuery);

        [LibraryImport("libcrypto.so.3")]
        private static partial void EVP_PKEY_free(nint pkey);

        [LibraryImport("libcrypto.so.3")]
        private static partial nint EVP_PKEY_get0_provider(nint pkey);

        [LibraryImport("libcrypto.so.3")]
        private static partial nint OSSL_PROVIDER_get0_name(nint provider);

        internal static bool ContainsTss2Key(ReadOnlySpan<char> keyPem)
        {
            foreach ((ReadOnlySpan<char> contents, PemFields fields) in PemEnumerator.Utf16(keyPem))
            {
                if (contents[fields.Label].SequenceEqual(Tss2Label))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Loads TSS2 PRIVATE KEY PEM via OpenSSL tpm2 provider and binds it
        /// to the certificate using DuplicateHandles() + SetPrivateKey().
        ///
        /// Why NOT CopyWithPrivateKey(SafeEvpPKeyHandle):
        ///   That overload is PRIVATE on OpenSslX509CertificateReader — inaccessible.
        ///
        /// Why NOT CopyWithPrivateKey(RSA):
        ///   Calls RSAOpenSsl(SafeEvpPKeyHandle) which calls EvpPKeyDuplicate
        ///   -> EVP_PKEY_dup -> tpm2 provider refuses (keymgmt export failure).
        ///
        /// Correct path — both methods are INTERNAL, accessible from same assembly:
        ///   DuplicateHandles(): X509UpRef(_cert) only, no private key dup
        ///                       (cert has no key yet so key branch is skipped)
        ///   SetPrivateKey():    _privateKey = keyHandle  (stores handle, no dup)
        /// </summary>
        internal static X509Certificate2 LoadAndBind(
            X509Certificate2 certificate,
            ReadOnlySpan<char> keyPem)
        {
            int maxBytes = Encoding.UTF8.GetMaxByteCount(keyPem.Length);
            byte[] pemBytes = new byte[maxBytes];
            int actualBytes = Encoding.UTF8.GetBytes(keyPem, pemBytes);

            nint bio = 0;
            nint evpKey = 0;
            GCHandle pin = default;

            try
            {
                pin = GCHandle.Alloc(pemBytes, GCHandleType.Pinned);

                bio = BIO_new_mem_buf(pin.AddrOfPinnedObject(), actualBytes);
                if (bio == 0)
                    throw new CryptographicException(
                        "TPM2: BIO_new_mem_buf failed. Check LD_LIBRARY_PATH.");

                // propquery "provider=tpm2" forces OpenSSL to use tpm2 provider.
                // Matches C client: PEM_read_bio_PrivateKey_ex(..., "tpm2")
                // tpm2 provider: Esys_Load -> EVP_PKEY* backed by TPM handle.
                // Private key bytes NEVER enter process memory.
                evpKey = PEM_read_bio_PrivateKey_ex(bio, 0, 0, 0, 0, "provider=tpm2");

                if (evpKey == 0)
                    throw new CryptographicException(
                        "TPM2: PEM_read_bio_PrivateKey_ex returned null.\n" +
                        "  1. OPENSSL_CONF set with [tpm2_provider] activate=1 ?\n" +
                        "  2. tpm2.so module path correct ?\n" +
                        "  3. LD_LIBRARY_PATH includes tpm2-tss .libs ?\n" +
                        "  4. /dev/tpm0 or /dev/tpmrm0 accessible ?");

                VerifyTpm2Provider(evpKey);

                // SafeEvpPKeyHandle stores the EVP_PKEY* pointer.
                // ReleaseHandle calls EVP_PKEY_free — supported by tpm2 provider.
                // Does NOT call EVP_PKEY_dup — NOT supported (non-exportable key).
                var keyHandle = new SafeEvpPKeyHandle(evpKey, ownsHandle: true);
                evpKey = 0; // keyHandle owns it now

                // Cast Pal to concrete Linux implementation — same assembly.
                OpenSslX509CertificateReader palReader =
                    (OpenSslX509CertificateReader)certificate.Pal;

                // DuplicateHandles() — internal method on OpenSslX509CertificateReader:
                //   SafeX509Handle certHandle = Interop.Crypto.X509UpRef(_cert);
                //   OpenSslX509CertificateReader dup = new(certHandle);
                //   if (_privateKey != null) { ... }  <- skipped, cert has no key yet
                //   return dup;
                // Result: new reader with same X509* cert, _privateKey is null.
                OpenSslX509CertificateReader duplicate = palReader.DuplicateHandles();

                // SetPrivateKey() — internal method on OpenSslX509CertificateReader:
                //   _privateKey = privateKey;   <- one line, stores handle directly
                // No EVP_PKEY_dup, no export, no validation. Fully TPM-safe.
                duplicate.SetPrivateKey(keyHandle);

                // Internal X509Certificate2 constructor accepts ICertificatePal.
                return new X509Certificate2(duplicate);
            }
            finally
            {
                if (evpKey != 0) EVP_PKEY_free(evpKey);
                if (bio != 0) BIO_free(bio);
                if (pin.IsAllocated) pin.Free();
                Array.Clear(pemBytes, 0, actualBytes);
            }
        }

        private static void VerifyTpm2Provider(nint evpKey)
        {
            nint provider = EVP_PKEY_get0_provider(evpKey);
            if (provider == 0)
                throw new CryptographicException(
                    "TPM2: EVP_PKEY has no OSSL_PROVIDER. Ensure OpenSSL 3.x.");

            nint namePtr = OSSL_PROVIDER_get0_name(provider);
            string name = namePtr != 0
                ? Marshal.PtrToStringAnsi(namePtr) ?? string.Empty
                : string.Empty;

            if (!string.Equals(name, "tpm2", StringComparison.Ordinal))
                throw new CryptographicException(
                    $"TPM2: Key loaded by provider '{name}' not 'tpm2'.");
        }
    }
}

#endif // !TARGET_WINDOWS
