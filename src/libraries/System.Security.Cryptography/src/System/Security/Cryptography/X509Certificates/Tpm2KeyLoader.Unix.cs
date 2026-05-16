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

        // ── LibraryImport P/Invoke ────────────────────────────────────────────
        // SYSLIB1051: use 'nint' not 'IntPtr' for pointer-sized native integers
        // in LibraryImport source-generated P/Invokes.

        [LibraryImport("libcrypto.so.3")]
        private static partial nint BIO_new_mem_buf(nint buf, int len);

        [LibraryImport("libcrypto.so.3")]
        private static partial void BIO_free(nint bio);

        // PEM_read_bio_PrivateKey_ex with propquery "provider=tpm2":
        // Forces OpenSSL to use the tpm2 provider — same as the C client.
        // libCtx = 0 (nint zero) uses the default OSSL_LIB_CTX.
        [LibraryImport("libcrypto.so.3", StringMarshalling = StringMarshalling.Utf8)]
        private static partial nint PEM_read_bio_PrivateKey_ex(
            nint bio,
            nint x,
            nint cb,
            nint u,
            nint libCtx,
            string propQuery);

        [LibraryImport("libcrypto.so.3")]
        private static partial void EVP_PKEY_free(nint pkey);

        [LibraryImport("libcrypto.so.3")]
        private static partial nint EVP_PKEY_get0_provider(nint pkey);

        [LibraryImport("libcrypto.so.3")]
        private static partial nint OSSL_PROVIDER_get0_name(nint provider);

        // ── Public API ────────────────────────────────────────────────────────

        /// <summary>
        /// Scans keyPem for "TSS2 PRIVATE KEY" label.
        /// Pure text scan — no OpenSSL call, no TPM access.
        /// Used as early-exit gate in CreateFromPem before the OID switch.
        /// </summary>
        internal static bool ContainsTss2Key(ReadOnlySpan<char> keyPem)
        {
            foreach ((ReadOnlySpan<char> contents, PemFields fields) in new PemEnumerator(keyPem))
            {
                if (contents[fields.Label].SequenceEqual(Tss2Label))
                    return true;
            }
            return false;
        }

        /// <summary>
        /// Loads a "TSS2 PRIVATE KEY" PEM via OpenSSL PEM_read_bio_PrivateKey_ex
        /// with propquery "provider=tpm2". Dispatches to tpm2-openssl provider.
        /// Returns RSAOpenSsl(SafeEvpPKeyHandle) — all crypto ops run in TPM.
        /// Private key bytes NEVER enter process memory.
        /// </summary>
        internal static RSA LoadFromPem(ReadOnlySpan<char> keyPem)
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
                        "TPM2: BIO_new_mem_buf failed. " +
                        "Verify libcrypto.so.3 is accessible via LD_LIBRARY_PATH.");

                // propquery "provider=tpm2" — explicit provider routing.
                // Matches C client: PEM_read_bio_PrivateKey_ex(..., "tpm2")
                evpKey = PEM_read_bio_PrivateKey_ex(bio, 0, 0, 0, 0, "provider=tpm2");

                if (evpKey == 0)
                    throw new CryptographicException(
                        "TPM2: PEM_read_bio_PrivateKey_ex returned null.\n" +
                        "Checklist:\n" +
                        "  1. OPENSSL_CONF set to config with [tpm2_provider] activate=1 ?\n" +
                        "  2. tpm2.so module path correct in config ?\n" +
                        "  3. LD_LIBRARY_PATH includes tpm2-tss .libs ?\n" +
                        "  4. /dev/tpm0 or /dev/tpmrm0 accessible ?\n" +
                        "  5. testkey.priv is a valid TSS2 PRIVATE KEY blob ?");

                VerifyTpm2Provider(evpKey);

                var handle = new SafeEvpPKeyHandle(evpKey, ownsHandle: true);
                evpKey = 0; // handle owns it now

                return new RSAOpenSsl(handle);
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
                    "TPM2: EVP_PKEY has no OSSL_PROVIDER. " +
                    "Ensure OpenSSL 3.x (not 1.x) is in use.");

            nint namePtr = OSSL_PROVIDER_get0_name(provider);
            string name = namePtr != 0
                ? Marshal.PtrToStringAnsi(namePtr) ?? string.Empty
                : string.Empty;

            if (!string.Equals(name, "tpm2", StringComparison.Ordinal))
                throw new CryptographicException(
                    $"TPM2: Key loaded by provider '{name}' not 'tpm2'. " +
                    $"Check OPENSSL_CONF tpm2 provider config.");
        }
    }
}

#endif // !TARGET_WINDOWS
