using System;

namespace ManagedCertificates.Revocation.Exceptions
{
    public class RevocationException : Exception
    {
        public uint ErrorCode { get; }
        public uint ReasonCode { get; }

        public RevocationException(uint errorCode, uint reasonCode)
        {
            ErrorCode = errorCode;
            ReasonCode = reasonCode;
        }
    }
}
