// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if !TARGET_WINDOWS

using System;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography
{
    public sealed class Tpm2SafeRSAWrapper : RSA
    {
        private SafeEvpPKeyHandle? _keyHandle;

        internal Tpm2SafeRSAWrapper(SafeEvpPKeyHandle keyHandle)
        {
            _keyHandle = keyHandle.DuplicateHandle();
        }

        public SafeEvpPKeyHandle DuplicateKeyHandle()
        {
            ObjectDisposedException.ThrowIf(_keyHandle == null || _keyHandle.IsInvalid, this);
            return _keyHandle.DuplicateHandle();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _keyHandle?.Dispose();
                _keyHandle = null;
            }
            base.Dispose(disposing);
        }

        public override RSAParameters ExportParameters(bool includePrivateParameters)
            => throw new NotSupportedException("TPM2 key export not supported.");
        public override void ImportParameters(RSAParameters parameters)
            => throw new NotSupportedException();
        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
            => throw new NotSupportedException();
        public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
            => throw new NotSupportedException();

        // Called from System.Net.Security without referencing Tpm2SafeRSAWrapper by name.
        // Returns the SafeEvpPKeyHandle if rsa is Tpm2SafeRSAWrapper, null otherwise.
        public static SafeEvpPKeyHandle? TryGetKeyHandle(RSA rsa)
        {
            if (rsa is Tpm2SafeRSAWrapper wrapper)
                return wrapper.DuplicateKeyHandle();
            return null;
        }
    }
}

#endif
