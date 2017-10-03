namespace Miracl
{
    /// <summary>
    /// Status used to notify the user if the DVS verification succeeds or not
    /// </summary>
    public enum VerificationStatus
    {
        /// <summary>
        /// The signature verification is successful
        /// </summary>
        ValidSignature,
        /// <summary>
        /// Bad PIN or token
        /// </summary>
        BadPin,
        /// <summary>
        /// Identity revoked due to some invalid attempts
        /// </summary>
        UserBlocked,
        /// <summary>
        /// Unexpected server response, no signature received
        /// </summary>
        MissingSignature,
        /// <summary>
        /// The received signature is not valid
        /// </summary>
        InvalidSignature
    }

    /// <summary>
    /// Describes the result of a DVS signature verification
    /// </summary>
    public class VerificationResult
    {
        /// <summary>
        /// Gets the status.
        /// </summary>
        /// <value>
        /// The status.
        /// </value>
        public VerificationStatus Status { get; internal set; }

        /// <summary>
        /// Gets a value indicating whether the signature verification is valid.
        /// </summary>
        /// <value>
        ///   <c>true</c> if signature verification is valid; otherwise, <c>false</c>.
        /// </value>
        public bool IsSignatureValid { get; internal set; }
    }
}
