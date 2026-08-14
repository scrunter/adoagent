namespace AdoAgent.ClusterKey;

public enum ExitCode
{
    Success = 0,
    InvalidArguments = 2,
    InvalidConfiguration = 3,
    MissingFile = 10,
    WrongMachineDpapi = 11,
    FingerprintMismatch = 12,
    NamedContainerKey = 13,
    DpapiNgAuthorizationFailure = 14,
    ActivationFailure = 15,
    AdditionalCredentialStore = 16,
    PathSecurityFailure = 18,
    UnexpectedError = 20,
}
