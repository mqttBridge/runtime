// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Security.Cryptography.X509Certificates
{
    public partial class X509Certificate2
    {
        // Returns raw EVP_PKEY* pointer (up_ref'd) for TPM-safe key access.
        // Caller must wrap in SafeEvpPKeyHandle(ptr, ownsHandle:true).
        // Returns IntPtr.Zero if no private key or not OpenSsl PAL.
        public static IntPtr GetPrivateKeyHandlePtr(X509Certificate2 certificate)
        {
#if !TARGET_WINDOWS
            if (certificate.Pal is OpenSslX509CertificateReader reader)
            {
                var handle = reader.PrivateKeyHandle;
                if (handle != null && !handle.IsInvalid)
                {
                    // DuplicateHandle = EVP_PKEY_up_ref — TPM-safe
                    using var dup = handle.DuplicateHandle();
                    // Transfer ownership — caller wraps this pointer
                    bool addedRef = false;
                    dup.DangerousAddRef(ref addedRef);
                    return dup.DangerousGetHandle();
                }
            }
#endif
            return IntPtr.Zero;
        }
    }
}
