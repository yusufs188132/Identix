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