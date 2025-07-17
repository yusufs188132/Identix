(define-data-var admin principal tx-sender)

(define-map identity-records
    { id: uint }
    {
        owner: principal,
        active: bool,
        created-at: uint,
        updated-at: uint
    }
)

(define-map identity-attributes
    { id: uint, key: (string-ascii 64) }
    { value: (string-ascii 256) }
)

(define-map identity-verifications
    { id: uint, verifier: principal }
    {
        verified: bool,
        timestamp: uint,
        signature: (string-ascii 128)
    }
)

(define-data-var next-id uint u1)

(define-constant PERMISSION-MANAGE-ATTRIBUTES u1)
(define-constant PERMISSION-VERIFY-IDENTITY u2)
(define-constant PERMISSION-TRANSFER-IDENTITY u4)
(define-constant PERMISSION-DEACTIVATE-IDENTITY u8)
(define-constant PERMISSION-DELEGATE u16)
(define-constant PERMISSION-ALL u31)

(define-map identity-delegations
    { id: uint, delegate: principal }
    {
        permissions: uint,
        expires-at: uint,
        delegated-by: principal,
        created-at: uint,
        active: bool
    }
)

(define-map delegation-chains
    { id: uint, delegate: principal, delegated-by: principal }
    { permissions: uint, depth: uint }
)

(define-data-var max-delegation-depth uint u3)

(define-public (create-identity)
    (let
        (
            (new-id (var-get next-id))
        )
        (unwrap! (create-base-identity new-id tx-sender) (err u4))
        (var-set next-id (+ new-id u1))
        (ok new-id)
    )
)

(define-public (add-attribute (id uint) (key (string-ascii 64)) (value (string-ascii 256)))
    (let
        (
            (identity (unwrap! (get-identity-record id) (err u1)))
        )
        (asserts! (is-owner id tx-sender) (err u2))
        (asserts! (get active identity) (err u3))
        (map-set identity-attributes { id: id, key: key } { value: value })
        (ok true)
    )
)

(define-public (verify-identity (id uint) (signature (string-ascii 128)))
    (let
        (
            (identity (unwrap! (get-identity-record id) (err u1)))
        )
        (asserts! (get active identity) (err u3))
        (map-set identity-verifications
            { id: id, verifier: tx-sender }
            {
                verified: true,
                timestamp: stacks-block-height,
                signature: signature
            }
        )
        (ok true)
    )
)

(define-public (deactivate-identity (id uint))
    (let
        (
            (identity (unwrap! (get-identity-record id) (err u1)))
        )
        (asserts! (is-owner id tx-sender) (err u2))
        (map-set identity-records
            { id: id }
            {
                owner: (get owner identity),
                active: false,
                created-at: (get created-at identity),
                updated-at: stacks-block-height
            }
        )
        (ok true)
    )
)

(define-public (transfer-identity (id uint) (new-owner principal))
    (let
        (
            (identity (unwrap! (get-identity-record id) (err u1)))
        )
        (asserts! (is-owner id tx-sender) (err u2))
        (asserts! (get active identity) (err u3))
        (map-set identity-records
            { id: id }
            {
                owner: new-owner,
                active: true,
                created-at: (get created-at identity),
                updated-at: stacks-block-height
            }
        )
        (ok true)
    )
)

(define-read-only (get-identity-record (id uint))
    (map-get? identity-records { id: id })
)

(define-read-only (get-attribute (id uint) (key (string-ascii 64)))
    (map-get? identity-attributes { id: id, key: key })
)

(define-read-only (get-verification (id uint) (verifier principal))
    (map-get? identity-verifications { id: id, verifier: verifier })
)

(define-read-only (is-owner (id uint) (user principal))
    (match (get-identity-record id)
        identity (is-eq (get owner identity) user)
        false
    )
)

(define-private (create-base-identity (id uint) (owner principal))
    (begin
        (map-set identity-records
            { id: id }
            {
                owner: owner,
                active: true,
                created-at: stacks-block-height,
                updated-at: stacks-block-height
            }
        )
        (ok true)
    )
)

(define-public (delegate-permissions (id uint) (delegate principal) (permissions uint) (expires-at uint))
    (let
        (
            (identity (unwrap! (get-identity-record id) (err u1)))
            (current-delegation (get-delegation id tx-sender))
        )
        (asserts! (get active identity) (err u3))
        (asserts! (> expires-at stacks-block-height) (err u7))
        (asserts! (<= permissions PERMISSION-ALL) (err u8))
        (asserts! (not (is-eq delegate tx-sender)) (err u9))
        (asserts! (can-delegate-permissions id tx-sender permissions) (err u10))
        (map-set identity-delegations
            { id: id, delegate: delegate }
            {
                permissions: permissions,
                expires-at: expires-at,
                delegated-by: tx-sender,
                created-at: stacks-block-height,
                active: true
            }
        )
        (unwrap! (update-delegation-chain id delegate tx-sender permissions) (err u11))
        (ok true)
    )
)

(define-public (revoke-delegation (id uint) (delegate principal))
    (let
        (
            (identity (unwrap! (get-identity-record id) (err u1)))
            (delegation (unwrap! (get-delegation id delegate) (err u12)))
        )
        (asserts! (get active identity) (err u3))
        (asserts! 
            (or 
                (is-owner id tx-sender)
                (is-eq (get delegated-by delegation) tx-sender)
            ) 
            (err u2)
        )
        (map-set identity-delegations
            { id: id, delegate: delegate }
            (merge delegation { active: false })
        )
        (unwrap! (remove-from-delegation-chain id delegate) (err u13))
        (ok true)
    )
)

(define-public (add-attribute-delegated (id uint) (key (string-ascii 64)) (value (string-ascii 256)))
    (let
        (
            (identity (unwrap! (get-identity-record id) (err u1)))
        )
        (asserts! (get active identity) (err u3))
        (asserts! (has-permission id tx-sender PERMISSION-MANAGE-ATTRIBUTES) (err u14))
        (map-set identity-attributes { id: id, key: key } { value: value })
        (ok true)
    )
)

(define-public (verify-identity-delegated (id uint) (signature (string-ascii 128)))
    (let
        (
            (identity (unwrap! (get-identity-record id) (err u1)))
        )
        (asserts! (get active identity) (err u3))
        (asserts! (has-permission id tx-sender PERMISSION-VERIFY-IDENTITY) (err u14))
        (map-set identity-verifications
            { id: id, verifier: tx-sender }
            {
                verified: true,
                timestamp: stacks-block-height,
                signature: signature
            }
        )
        (ok true)
    )
)

(define-public (transfer-identity-delegated (id uint) (new-owner principal))
    (let
        (
            (identity (unwrap! (get-identity-record id) (err u1)))
        )
        (asserts! (get active identity) (err u3))
        (asserts! (has-permission id tx-sender PERMISSION-TRANSFER-IDENTITY) (err u14))
        (map-set identity-records
            { id: id }
            {
                owner: new-owner,
                active: true,
                created-at: (get created-at identity),
                updated-at: stacks-block-height
            }
        )
        (unwrap! (clear-all-delegations id) (err u15))
        (ok true)
    )
)

(define-public (deactivate-identity-delegated (id uint))
    (let
        (
            (identity (unwrap! (get-identity-record id) (err u1)))
        )
        (asserts! (get active identity) (err u3))
        (asserts! (has-permission id tx-sender PERMISSION-DEACTIVATE-IDENTITY) (err u14))
        (map-set identity-records
            { id: id }
            {
                owner: (get owner identity),
                active: false,
                created-at: (get created-at identity),
                updated-at: stacks-block-height
            }
        )
        (unwrap! (clear-all-delegations id) (err u15))
        (ok true)
    )
)

(define-read-only (get-delegation (id uint) (delegate principal))
    (map-get? identity-delegations { id: id, delegate: delegate })
)

(define-read-only (get-delegation-chain (id uint) (delegate principal) (delegated-by principal))
    (map-get? delegation-chains { id: id, delegate: delegate, delegated-by: delegated-by })
)

(define-read-only (has-permission (id uint) (user principal) (permission uint))
    (or
        (is-owner id user)
        (has-active-delegation-permission id user permission)
    )
)

(define-read-only (has-active-delegation-permission (id uint) (delegate principal) (permission uint))
    (match (get-delegation id delegate)
        delegation 
        (and
            (get active delegation)
            (> (get expires-at delegation) stacks-block-height)
            (> (bit-and (get permissions delegation) permission) u0)
        )
        false
    )
)

(define-read-only (can-delegate-permissions (id uint) (delegator principal) (permissions uint))
    (or
        (is-owner id delegator)
        (and
            (has-active-delegation-permission id delegator PERMISSION-DELEGATE)
            (has-sufficient-permissions id delegator permissions)
        )
    )
)

(define-read-only (has-sufficient-permissions (id uint) (delegator principal) (requested-permissions uint))
    (match (get-delegation id delegator)
        delegation
        (is-eq (bit-and (get permissions delegation) requested-permissions) requested-permissions)
        false
    )
)

(define-private (update-delegation-chain (id uint) (delegate principal) (delegated-by principal) (permissions uint))
    (let
        (
            (delegator-chain (get-delegation-chain id delegated-by delegated-by))
            (new-depth (+ (default-to u0 (get depth delegator-chain)) u1))
        )
        (asserts! (<= new-depth (var-get max-delegation-depth)) (err u16))
        (map-set delegation-chains
            { id: id, delegate: delegate, delegated-by: delegated-by }
            { permissions: permissions, depth: new-depth }
        )
        (ok true)
    )
)

(define-private (remove-from-delegation-chain (id uint) (delegate principal))
    (begin
        (map-delete delegation-chains { id: id, delegate: delegate, delegated-by: delegate })
        (ok true)
    )
)

(define-private (clear-all-delegations (id uint))
    (begin
        (ok true)
    )
)