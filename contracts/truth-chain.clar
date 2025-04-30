;; TrustChain: Decentralized Identity & Credential Verification Protocol

;; Error Constants
(define-constant contract-owner tx-sender)
(define-constant ERR-NOT-AUTHORIZED-OWNER (err u100))
(define-constant ERR-CONTRACT-ALREADY-ACTIVE (err u101))
(define-constant ERR-CONTRACT-NOT-ACTIVE (err u102))
(define-constant ERR-INVALID-FEE-AMOUNT (err u103))
(define-constant ERR-INSUFFICIENT-FUNDS (err u104))
(define-constant ERR-IDENTITY-ALREADY-EXISTS (err u105))
(define-constant ERR-IDENTITY-NOT-FOUND (err u106))
(define-constant ERR-UNAUTHORIZED-ACCESS (err u107))
(define-constant ERR-CREDENTIAL-ALREADY-VERIFIED (err u108))
(define-constant ERR-CREDENTIAL-NOT-FOUND (err u109))
(define-constant ERR-INVALID-TIME (err u110))
(define-constant ERR-ATTESTATION-PERIOD-ENDED (err u111))
(define-constant ERR-ALREADY-ATTESTED (err u112))
(define-constant ERR-IDENTITY-INACTIVE (err u113))
(define-constant ERR-INVALID-DATA (err u114))
(define-constant ERR-ISSUER-NOT-REGISTERED (err u115))
(define-constant ERR-REVOKED-CREDENTIAL (err u116))

;; TrustChain Credential Types
(define-constant credential-types 
    (list 
        "education"
        "professional"
        "government"
        "membership"
        "certification"
    )
)

;; Main Identity Information Storage
(define-map TrustChainIdentityDetails
    { identity-id: uint }
    {
        identity-owner: principal,
        identity-name: (string-ascii 50),
        identity-description: (string-ascii 500),
        identity-public-key: (buff 33),
        identity-metadata-url: (string-ascii 100),
        identity-type: (string-ascii 12),
        credential-count: uint,
        trust-score: uint,
        identity-status: (string-ascii 20),
        verification-status: bool,
        creation-block-height: uint,
        expiration-block-height: uint,
        attestation-count: uint,
        revocation-count: uint
    }
)

;; Issuer Registry
(define-map TrustChainIssuerRecord
    { issuer-address: principal }
    { 
        issuer-name: (string-ascii 50),
        issuer-category: (string-ascii 20),
        registration-date: uint,
        credentials-issued: uint,
        issuer-trust-level: uint
    }
)

;; Trusted Verifier Registry
(define-map TrustChainVerifiers principal bool)

;; Credential Details
(define-map TrustChainCredentialDetails
    { identity-id: uint, credential-id: uint }
    {
        credential-title: (string-ascii 100),
        credential-description: (string-ascii 200),
        issuance-date: uint,
        expiration-date: uint,
        credential-status: bool,
        credential-hash: (buff 32),
        credential-issuer: principal
    }
)

;; Attestation Records
(define-map TrustChainAttestationRegistry
    { identity-id: uint, attester-address: principal }
    {
        attestation-weight: uint,
        attestation-date: uint,
        attestation-comment: (string-ascii 100)
    }
)

;; Revocation Records
(define-map TrustChainRevocationRegistry
    { identity-id: uint, credential-id: uint }
    {
        revocation-reason: (string-ascii 100),
        revocation-date: uint,
        revocation-authority: principal,
        contest-status: bool,
        dispute-evidence: (optional (buff 32))
    }
)

;; Contract State Management
(define-data-var identity-counter uint u0)
(define-data-var active-identities uint u0)
(define-data-var contract-active bool false)
(define-data-var registration-fee uint u100)
(define-data-var attestation-period uint u1440) ;; 10 days in blocks

;; Helper Functions
(define-private (is-valid-string (input (string-ascii 500)))
    (and 
        (>= (len input) u1)
        (<= (len input) u500)
    )
)

(define-private (is-valid-credential-type (credential-type (string-ascii 12)))
    (is-some (index-of credential-types credential-type))
)

(define-private (is-valid-identity-id (identity-id uint))
    (<= identity-id (var-get identity-counter))
)

(define-private (is-valid-credential-id (identity-id uint) (credential-id uint))
    (match (map-get? TrustChainIdentityDetails { identity-id: identity-id })
        id-data (<= credential-id (get credential-count id-data))
        false
    )
)

;; Contract Initialization
(define-public (activate-trustchain-protocol)
    (begin
        (asserts! (is-eq tx-sender contract-owner) ERR-NOT-AUTHORIZED-OWNER)
        (asserts! (not (var-get contract-active)) ERR-CONTRACT-ALREADY-ACTIVE)
        (var-set contract-active true)
        (ok true)
    )
)
