;; TruthBlockn: Decentralized Identity & Credential Verification Protocol

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

;; Update Registration Fee
(define-public (update-registration-fee (new-fee-amount uint))
    (begin
        (asserts! (is-eq tx-sender contract-owner) ERR-NOT-AUTHORIZED-OWNER)
        (asserts! (> new-fee-amount u0) ERR-INVALID-FEE-AMOUNT)
        (var-set registration-fee new-fee-amount)
        (ok true)
    )
)

;; Register New Issuer
(define-public (register-credential-issuer 
    (issuer-name (string-ascii 50))
    (issuer-category (string-ascii 20)))
    (begin
        (asserts! (var-get contract-active) ERR-CONTRACT-NOT-ACTIVE)
        (asserts! (is-valid-string issuer-name) ERR-INVALID-DATA)
        (asserts! (is-valid-string issuer-category) ERR-INVALID-DATA)
        
        ;; Process registration fee
        (try! (stx-transfer? (var-get registration-fee) tx-sender (as-contract tx-sender)))
        
        (map-set TrustChainIssuerRecord
            { issuer-address: tx-sender }
            {
                issuer-name: issuer-name,
                issuer-category: issuer-category,
                registration-date: block-height,
                credentials-issued: u0,
                issuer-trust-level: u1
            }
        )
        (ok true)
    )
)

;; Register New Digital Identity
(define-public (register-digital-identity 
    (identity-name (string-ascii 50))
    (identity-description (string-ascii 500))
    (identity-public-key (buff 33))
    (identity-metadata-url (string-ascii 100))
    (identity-type (string-ascii 12))
    (validity-period uint))
    (let
        (
            (new-identity-id (+ (var-get identity-counter) u1))
            (identity-expiration (+ block-height validity-period))
        )
        (asserts! (var-get contract-active) ERR-CONTRACT-NOT-ACTIVE)
        (asserts! (is-valid-string identity-name) ERR-INVALID-DATA)
        (asserts! (is-valid-string identity-description) ERR-INVALID-DATA)
        (asserts! (is-valid-string identity-metadata-url) ERR-INVALID-DATA)
        (asserts! (is-valid-credential-type identity-type) ERR-INVALID-DATA)
        (asserts! (> validity-period u0) ERR-INVALID-TIME)
        
        ;; Process registration fee
        (try! (stx-transfer? (var-get registration-fee) tx-sender (as-contract tx-sender)))
        
        (map-set TrustChainIdentityDetails
            { identity-id: new-identity-id }
            {
                identity-owner: tx-sender,
                identity-name: identity-name,
                identity-description: identity-description,
                identity-public-key: identity-public-key,
                identity-metadata-url: identity-metadata-url,
                identity-type: identity-type,
                credential-count: u0,
                trust-score: u0,
                identity-status: "active",
                verification-status: false,
                creation-block-height: block-height,
                expiration-block-height: identity-expiration,
                attestation-count: u0,
                revocation-count: u0
            }
        )
        (var-set identity-counter new-identity-id)
        (var-set active-identities (+ (var-get active-identities) u1))
        (ok new-identity-id)
    )
)

;; Issue New Credential
(define-public (issue-identity-credential 
    (identity-id uint)
    (credential-title (string-ascii 100))
    (credential-description (string-ascii 200))
    (credential-hash (buff 32))
    (validity-period uint))
    (let
        (
            (identity-data (unwrap! (map-get? TrustChainIdentityDetails { identity-id: identity-id }) ERR-IDENTITY-NOT-FOUND))
            (issuer-data (unwrap! (map-get? TrustChainIssuerRecord { issuer-address: tx-sender }) ERR-ISSUER-NOT-REGISTERED))
            (current-credential-count (get credential-count identity-data))
            (expiration-height (+ block-height validity-period))
        )
        (asserts! (var-get contract-active) ERR-CONTRACT-NOT-ACTIVE)
        (asserts! (is-valid-identity-id identity-id) ERR-IDENTITY-NOT-FOUND)
        (asserts! (is-valid-string credential-title) ERR-INVALID-DATA)
        (asserts! (is-valid-string credential-description) ERR-INVALID-DATA)
        (asserts! (> validity-period u0) ERR-INVALID-TIME)
        
        (map-set TrustChainCredentialDetails
            { identity-id: identity-id, credential-id: current-credential-count }
            {
                credential-title: credential-title,
                credential-description: credential-description,
                issuance-date: block-height,
                expiration-date: expiration-height,
                credential-status: true,
                credential-hash: credential-hash,
                credential-issuer: tx-sender
            }
        )
        
        ;; Update identity record
        (map-set TrustChainIdentityDetails
            { identity-id: identity-id }
            (merge identity-data {
                credential-count: (+ current-credential-count u1)
            })
        )
        
        ;; Update issuer record
        (map-set TrustChainIssuerRecord
            { issuer-address: tx-sender }
            (merge issuer-data {
                credentials-issued: (+ (get credentials-issued issuer-data) u1)
            })
        )
        
        (ok current-credential-count)
    )
)

;; Revoke Credential
(define-public (revoke-identity-credential 
    (identity-id uint)
    (credential-id uint)
    (revocation-reason (string-ascii 100)))
    (let
        (
            (identity-data (unwrap! (map-get? TrustChainIdentityDetails { identity-id: identity-id }) ERR-IDENTITY-NOT-FOUND))
            (credential-data (unwrap! (map-get? TrustChainCredentialDetails { identity-id: identity-id, credential-id: credential-id }) ERR-CREDENTIAL-NOT-FOUND))
        )
        (asserts! (var-get contract-active) ERR-CONTRACT-NOT-ACTIVE)
        (asserts! (is-valid-identity-id identity-id) ERR-IDENTITY-NOT-FOUND)
        (asserts! (is-valid-credential-id identity-id credential-id) ERR-CREDENTIAL-NOT-FOUND)
        (asserts! (is-eq (get credential-issuer credential-data) tx-sender) ERR-UNAUTHORIZED-ACCESS)
        (asserts! (get credential-status credential-data) ERR-REVOKED-CREDENTIAL)
        (asserts! (is-valid-string revocation-reason) ERR-INVALID-DATA)
        
        ;; Update credential status
        (map-set TrustChainCredentialDetails
            { identity-id: identity-id, credential-id: credential-id }
            (merge credential-data {
                credential-status: false
            })
        )
        
        ;; Record revocation details
        (map-set TrustChainRevocationRegistry
            { identity-id: identity-id, credential-id: credential-id }
            {
                revocation-reason: revocation-reason,
                revocation-date: block-height,
                revocation-authority: tx-sender,
                contest-status: false,
                dispute-evidence: none
            }
        )
        
        ;; Update identity revocation count
        (map-set TrustChainIdentityDetails
            { identity-id: identity-id }
            (merge identity-data {
                revocation-count: (+ (get revocation-count identity-data) u1)
            })
        )
        
        (ok true)
    )
)

;; Provide Identity Attestation
(define-public (attest-to-identity 
    (identity-id uint)
    (attestation-weight uint)
    (attestation-comment (string-ascii 100)))
    (let
        (
            (identity-data (unwrap! (map-get? TrustChainIdentityDetails { identity-id: identity-id }) ERR-IDENTITY-NOT-FOUND))
            (existing-attestation (map-get? TrustChainAttestationRegistry { identity-id: identity-id, attester-address: tx-sender }))
        )
        (asserts! (var-get contract-active) ERR-CONTRACT-NOT-ACTIVE)
        (asserts! (is-valid-identity-id identity-id) ERR-IDENTITY-NOT-FOUND)
        (asserts! (is-eq (get identity-status identity-data) "active") ERR-IDENTITY-INACTIVE)
        (asserts! (is-none existing-attestation) ERR-ALREADY-ATTESTED)
        (asserts! (>= (- (get expiration-block-height identity-data) block-height) (var-get attestation-period)) ERR-ATTESTATION-PERIOD-ENDED)
        (asserts! (> attestation-weight u0) ERR-INVALID-FEE-AMOUNT)
        (asserts! (is-valid-string attestation-comment) ERR-INVALID-DATA)
        
        ;; Process attestation fee
        (try! (stx-transfer? attestation-weight tx-sender (as-contract tx-sender)))
        
        (map-set TrustChainAttestationRegistry
            { identity-id: identity-id, attester-address: tx-sender }
            {
                attestation-weight: attestation-weight,
                attestation-date: block-height,
                attestation-comment: attestation-comment
            }
        )
        
        ;; Update identity trust score and attestation count
        (map-set TrustChainIdentityDetails
            { identity-id: identity-id }
            (merge identity-data {
                trust-score: (+ (get trust-score identity-data) attestation-weight),
                attestation-count: (+ (get attestation-count identity-data) u1)
            })
        )
        
        (ok true)
    )
)

;; Contest Credential Revocation
(define-public (contest-credential-revocation 
    (identity-id uint)
    (credential-id uint)
    (contest-evidence (buff 32)))
    (let
        (
            (identity-data (unwrap! (map-get? TrustChainIdentityDetails { identity-id: identity-id }) ERR-IDENTITY-NOT-FOUND))
            (credential-data (unwrap! (map-get? TrustChainCredentialDetails { identity-id: identity-id, credential-id: credential-id }) ERR-CREDENTIAL-NOT-FOUND))
            (revocation-data (unwrap! (map-get? TrustChainRevocationRegistry { identity-id: identity-id, credential-id: credential-id }) ERR-CREDENTIAL-NOT-FOUND))
        )
        (asserts! (var-get contract-active) ERR-CONTRACT-NOT-ACTIVE)
        (asserts! (is-valid-identity-id identity-id) ERR-IDENTITY-NOT-FOUND)
        (asserts! (is-valid-credential-id identity-id credential-id) ERR-CREDENTIAL-NOT-FOUND)
        (asserts! (is-eq (get identity-owner identity-data) tx-sender) ERR-UNAUTHORIZED-ACCESS)
        (asserts! (not (get credential-status credential-data)) ERR-CREDENTIAL-ALREADY-VERIFIED)
        
        ;; Update revocation contest info
        (map-set TrustChainRevocationRegistry
            { identity-id: identity-id, credential-id: credential-id }
            (merge revocation-data {
                contest-status: true,
                dispute-evidence: (some contest-evidence)
            })
        )
        
        (ok true)
    )
)

;; Read-only Functions

;; Get Identity Information
(define-read-only (get-identity-details (identity-id uint))
    (map-get? TrustChainIdentityDetails { identity-id: identity-id })
)

;; Get Credential Information
(define-read-only (get-credential-details (identity-id uint) (credential-id uint))
    (map-get? TrustChainCredentialDetails { identity-id: identity-id, credential-id: credential-id })
)

;; Get Attestation Details
(define-read-only (get-attestation-details (identity-id uint) (attester-address principal))
    (map-get? TrustChainAttestationRegistry { identity-id: identity-id, attester-address: attester-address })
)

;; Get Revocation Information
(define-read-only (get-revocation-details (identity-id uint) (credential-id uint))
    (map-get? TrustChainRevocationRegistry { identity-id: identity-id, credential-id: credential-id })
)

;; Get Issuer Information
(define-read-only (get-issuer-details (issuer-address principal))
    (map-get? TrustChainIssuerRecord { issuer-address: issuer-address })
)

;; Get Identity Verification Status
(define-read-only (check-identity-verification (identity-id uint))
    (match (map-get? TrustChainIdentityDetails { identity-id: identity-id })
        identity-data (ok {
            verification-status: (get verification-status identity-data),
            trust-score: (get trust-score identity-data),
            attestation-count: (get attestation-count identity-data),
            revocation-count: (get revocation-count identity-data)
        })
        ERR-IDENTITY-NOT-FOUND
    )
)

;; Get Identity Trust Metrics
(define-read-only (get-identity-trust-metrics (identity-id uint))
    (match (map-get? TrustChainIdentityDetails { identity-id: identity-id })
        identity-data (ok {
            trust-level: (/ (get trust-score identity-data) (if (is-eq (get attestation-count identity-data) u0) u1 (get attestation-count identity-data))),
            valid-credentials: (- (get credential-count identity-data) (get revocation-count identity-data)),
            remaining-validity: (- (get expiration-block-height identity-data) block-height),
            credential-issuer-count: (get credential-count identity-data)
        })
        ERR-IDENTITY-NOT-FOUND
    )
)