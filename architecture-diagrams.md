# Architecture Diagrams — Scenario Systems

---

## 1. Fintech — Multi-Region Expansion (US + EU)

```
                    ┌─────────────────────────┐
                    │     CloudFront + Edge    │
                    │  (reads JWT, routes by   │
                    │   account-origin region) │
                    └────────┬────────┬────────┘
                             │        │
                    US users │        │ EU users
                             ▼        ▼
               ┌─────────────┐        ┌─────────────┐
               │  us-east-1  │        │  eu-west-1   │
               │             │        │              │
               │  ┌───────┐  │        │  ┌───────┐   │
               │  │  ALB   │  │        │  │  ALB   │   │
               │  └───┬───┘  │        │  └───┬───┘   │
               │      ▼      │        │      ▼       │
               │  ┌───────┐  │        │  ┌───────┐   │
               │  │  EKS   │  │        │  │  EKS   │   │
               │  └───┬───┘  │        │  └───┬───┘   │
               │      ▼      │        │      ▼       │
               │  ┌───────┐  │        │  ┌───────┐   │
               │  │  RDS   │  │        │  │  RDS   │   │
               │  │(primary)│  │        │  │(primary)│   │
               │  └───────┘  │        │  └───────┘   │
               │  ┌───────┐  │        │  ┌───────┐   │
               │  │ Redis  │  │        │  │ Redis  │   │
               │  └───────┘  │        │  └───────┘   │
               └─────────────┘        └──────────────┘

Key: Each region has independent infra. No cross-region DB replication
(data residency). Route by account origin, not physical location.
```

---

## 1a. Fintech — Auth System (Multi-Region with Data Residency)

```
SIGNUP FLOW:
   ┌──────┐  POST /signup           ┌──────────────┐
   │ User │────────────────────────►│ Global Auth  │  determine region:
   └──────┘  (email, pw, country)   │   Gateway     │  - IP geolocation
                                    │ (small, sta-  │  - declared country
                                    │  teless svc)  │  - explicit choice
                                    └──────┬───────┘
                                           │ forward to chosen region
                            US ◄───────────┴───────────► EU
                            ▼                           ▼
                  ┌─────────────────┐         ┌─────────────────┐
                  │   us-east-1     │         │   eu-west-1     │
                  │ ┌─────────────┐ │         │ ┌─────────────┐ │
                  │ │  Auth API   │ │         │ │  Auth API   │ │
                  │ └──────┬──────┘ │         │ └──────┬──────┘ │
                  │        ▼        │         │        ▼        │
                  │ ┌─────────────┐ │         │ ┌─────────────┐ │
                  │ │    RDS      │ │         │ │    RDS      │ │
                  │ │  (users +   │ │         │ │  (users +   │ │
                  │ │  pw hashes) │ │         │ │  pw hashes) │ │
                  │ └─────────────┘ │         │ └─────────────┘ │
                  └────────┬────────┘         └────────┬────────┘
                           │  write (email → region)   │
                           └─────────────┬─────────────┘
                                         ▼
                          ┌─────────────────────────────┐
                          │  Global User Index          │
                          │  (DynamoDB Global Table)    │
                          │  email → region             │
                          │  user_id → region           │
                          └─────────────────────────────┘
                                         │
                                         ▼
                          ┌─────────────────────────────┐
                          │  JWT returned to user       │
                          │  { sub, region, exp, iss }  │
                          │  signed via KMS             │
                          └─────────────────────────────┘

LOGIN FLOW:
   ┌──────┐  POST /login    ┌──────────────┐   lookup email
   │ User │────────────────►│ Global Auth  │──►Global User Index
   └──────┘  (email, pw)    │   Gateway    │   → region = "eu"
                            └──────┬───────┘
                                   │ forward
                                   ▼
                            ┌──────────────┐
                            │  eu-west-1   │
                            │  Auth API    │
                            │   • verify   │
                            │     pw hash  │
                            │   • issue    │
                            │     JWT      │
                            └──────┬───────┘
                                   │
                                   ▼
                            ┌──────────────┐
                            │ JWT returned │
                            │ { sub: 123,  │
                            │   region:    │
                            │   "eu", ... }│
                            └──────────────┘

EVERY SUBSEQUENT API REQUEST:
   User ──► CloudFront ──► CloudFront Function decodes JWT
                           → reads `region` claim
                           → routes to correct regional ALB
   Regional API verifies JWT signature via KMS public key.

Key: Only the email → region INDEX is replicated globally (DynamoDB
Global Tables) — PII and password hashes stay regional for GDPR
compliance. Global Auth Gateway is small/stateless (no user data),
so it can run anywhere. JWTs are signed via KMS; each regional API
verifies signatures locally with the public key. CloudFront Functions
at the edge use the JWT's region claim to route every subsequent
request to the user's home region (see Diagram #1).
```

---

## 2. E-Commerce — Scaling for Black Friday

```
              ┌──────────┐
              │ Route 53  │
              └─────┬────┘
                    ▼
              ┌──────────┐
              │   ALB     │
              └─────┬────┘
                    ▼
         ┌──────────────────┐
         │   EKS / EC2      │
         │  (HPA on CPU +   │
         │   memory, pre-   │
         │   scaled before  │
         │   Black Friday)  │
         └────────┬─────────┘
                  │
        ┌─────────┼──────────┐
        ▼         ▼          ▼
   ┌────────┐ ┌───────┐ ┌────────┐
   │ Redis  │ │  RDS   │ │   S3   │
   │(cache) │ │(primary│ │(static │
   │        │ │+ read  │ │ assets)│
   │        │ │replicas)│ │        │
   └────────┘ └───────┘ └────┬───┘
                              ▼
                         ┌─────────┐
                         │CloudFront│
                         └─────────┘

Key: Reserved instances for baseline, spot for burst.
Canary deployments via ArgoCD/ArgoRollouts.
Scheduled scaling down during 1am-7am.
```

---

## 3. Healthcare — Telehealth Video + Medical Files

```
Video Flow:
   ┌────────┐         ┌─────┐        ┌───────────┐
   │Patient │◄─WebRTC─►│TURN/│◄──────►│  Doctor   │
   │Browser │         │STUN │        │  Browser  │
   └────────┘         └─────┘        └───────────┘
                         │
                    (recording)
                         ▼
                    ┌──────────┐    Lifecycle rules
                    │    S3    │───────────────────►  Glacier
                    └──────────┘

Medical File Serving:
   ┌────────┐     1. Request file     ┌──────────┐
   │ Client │ ──────────────────────► │ API Server│
   └────┬───┘                         └─────┬────┘
        │                                   │ 2. Generate
        │                                   │    signed URL
        │     3. Fetch file                 ▼
        │◄──────────────────────── ┌──────────────┐
        │  (byte-range requests    │  CloudFront   │
        │   for large files)       │  (signed URL) │
                                   └──────┬───────┘
                                          │ origin
                                          ▼
                                     ┌─────────┐
                                     │   S3    │
                                     │(private)│
                                     └─────────┘

Key: WebRTC for video (not WebSocket). Signed URLs for file access.
Byte-range requests for large medical images. Envelope encryption
for sensitive DB fields (only app IAM role can decrypt via KMS).
```

---

## 4. Ride-Sharing — Geospatial + Payments + Telemetry

```
   ┌──────────┐  location updates   ┌──────────┐
   │  Driver  │ ──────────────────► │ API / EKS │
   │   App    │  every 3 sec        └─────┬────┘
   └──────────┘                           │
                                ┌─────────┼──────────┐
                                ▼         ▼          ▼
                          ┌────────┐ ┌────────┐ ┌─────────┐
                          │ Redis  │ │ Kafka  │ │PostgreSQL│
                          │(current│ │(event  │ │(business │
                          │location│ │stream) │ │ data:    │
                          │GEORADIUS│ │        │ │ rides,   │
                          └────────┘ └───┬────┘ │ payments)│
                                         │      └─────────┘
                              ┌──────────┼──────────┐
                              ▼          ▼          ▼
                        ┌──────────┐┌────────┐┌──────────┐
                        │ Alerting ││Firehose││  Redis   │
                        │ Service  ││  → S3  ││(real-time│
                        └──────────┘└────────┘│  state)  │
                                       │      └──────────┘
                                       ▼
                                  ┌─────────┐
                                  │  Athena  │
                                  │(analytics│
                                  └─────────┘

Payment Retries:
   ┌────────┐     ┌─────┐     ┌─────────┐     ┌────────┐
   │ Ride   │────►│ SQS │────►│ Payment │────►│ Stripe │
   │Complete│     │     │     │ Service  │     │        │
   └────────┘     └──┬──┘     │(idempotency   └────────┘
                     │        │  key per ride)│
                     │        └──────────────┘
                     ▼ (after max retries)
                  ┌─────┐
                  │ DLQ │
                  └─────┘

Key: Ephemeral data (location) → Redis. Business data → PostgreSQL.
Analytics → S3/Athena. Geospatial matching via Redis GEORADIUS.
Payment retries via SQS with idempotency keys.
```

---

## 5. SaaS Project Management — Multi-Tenancy + Notifications

```
   ┌────────────┐
   │   Clients  │
   └──────┬─────┘
          ▼
   ┌────────────────────────────────────┐
   │  API Gateway (managed)             │
   │  • JWT / Lambda authorizer         │
   │  • injects tenant_id into context  │
   │  • usage plans → per-tenant limits │
   └──────────────────┬─────────────────┘
                      │  X-Tenant-Id: acme
                      ▼
   ┌───────────────────────────────┐      ┌──────────────────────┐
   │  EKS — Project API pods       │      │  Notification Queue  │
   │  ┌─────────────────────────┐  │─────►│  (SQS)               │
   │  │Tenant Routing MIDDLEWARE│  │      └───────────┬──────────┘
   │  │(in-process, not a hop)  │  │                  ▼
   │  │                         │  │      ┌──────────────────────┐
   │  │1. read tenant_id header │  │      │  Notification Svc    │
   │  │2. catalog lookup → shard│  │      │  (batching/digest    │
   │  │   (cached, TTL 60s)     │  │      │   for bulk ops)      │
   │  │3. pick conn pool        │  │      └──────────────────────┘
   │  │4. SET RLS tenant context│  │
   │  └─────┬─────────────┬─────┘  │      ┌──────────────────────┐
   │        │             │        │      │  Tenant Catalog      │
   │        │             │        │◄─────┤  (DynamoDB)          │
   └────────┼─────────────┼────────┘ step │  tenant_id → shard   │
            │             │        2 read └──────────────────────┘
            ▼             ▼
        ┌────────┐  ┌───────────┐
        │Shared  │  │ Dedicated │
        │  RDS   │  │   RDS     │
        │(most   │  │(enterprise│
        │tenants)│  │customers) │
        └────────┘  └───────────┘
         RLS on       one DB per
         tenant_id    enterprise tenant

Thumbnail Generation:
   ┌──────────┐   S3 event   ┌────────┐   store    ┌───────────┐
   │  Upload  │ ───────────► │ Lambda │ ─────────► │ S3 / CDN  │
   │  to S3   │              │(generate│            │(thumbnails)│
   └──────────┘              │ thumb)  │            └───────────┘
                             └────────┘
                        (at upload time, not request time)

Key: Tiered multi-tenancy. Tenant routing is MIDDLEWARE inside the EKS
API pods, not a separate service — a network hop there would add latency
for no benefit. API Gateway only authenticates and stamps tenant_id;
choosing a connection pool and enforcing row-level security is
application-level. Notifications batched into digests. Thumbnails
pre-computed at upload time via S3 event → Lambda.

Watch for: connection pool explosion (N pods × M databases — cap pools
or front with PgBouncer), migrations must run against every dedicated
DB, and moving a tenant from shared → dedicated is a data migration
plus a catalog flip.
```

---

## 6. Online Banking — Fraud Detection + Audit

```
Transaction Flow (Two-Phase: sync pending + async ML approval):

PHASE 1 — Fast Path (synchronous, <50ms):
   ┌────────┐  submit  ┌──────────┐  fast rule    ┌──────────┐
   │  User  │─────────►│   API     │──check ──────►│PostgreSQL│
   └────────┘          │  Server   │  (~10ms)      │ (status: │
       ▲               └─────┬─────┘  signature,   │ PENDING) │
       │  "PENDING"          │        velocity,    └──────────┘
       │◄────────────────────┘        blocklist
                               │
                               │ publish "txn.submitted"
                               ▼
                         ┌──────────┐
                         │  Queue   │
                         │  (SQS)   │
                         └─────┬────┘
                               │
PHASE 2 — Async ML (~800ms):   │
                               ▼
                         ┌──────────┐
                         │  Fraud   │  ML model
                         │ Service  │  scores risk
                         └─────┬────┘
                               │
                 approved      │      declined
                     ┌─────────┴─────────┐
                     ▼                   ▼
               ┌──────────┐        ┌──────────┐
               │ Payment  │ move   │  Update  │
               │ Service  │ money  │  status: │
               └─────┬────┘        │ DECLINED │
                     │             └─────┬────┘
                     │                   │
                     └──────────┬────────┘
                                ▼
                         ┌──────────┐
                         │PostgreSQL│  status:
                         │          │   COMPLETED
                         └─────┬────┘   or DECLINED
                               │
                               ▼
                         ┌──────────┐
                         │  Notify  │  WS / push / email
                         │ Service  │
                         └─────┬────┘
                               │
                               ▼
                          ┌─────────┐
                          │  User   │ sees final status
                          └─────────┘

Audit System:
   ┌──────────┐    ┌───────────┐    ┌──────────────┐
   │  Every   │───►│ Kafka/SQS │───►│ Audit Writer │
   │  action  │    │  (async)  │    │              │
   └──────────┘    └───────────┘    └──────┬───────┘
                                           │
                                    ┌──────┴───────┐
                                    ▼              ▼
                              ┌──────────┐   ┌─────────┐
                              │   S3     │   │Redshift/ │
                              │(Object   │   │ Athena   │
                              │ Lock for │   │(queries) │
                              │immutable)│   └─────────┘
                              └──────────┘

Zero-Downtime Migration (Expand & Contract):
   1. Create new table
   2. Dual-write to old + new
   3. Batch-copy old data to new table
   4. Verify data matches
   5. Switch reads to new table
   6. Stop writing to old table
   7. Drop old table weeks later

Key: Two-phase pattern — fast rule check (sync, ~10ms) accepts the
transaction as PENDING; slow ML inference (~800ms) runs async via
the queue and finalizes status (COMPLETED or DECLINED). User is
notified of the final status via WebSocket / push / email. Queue
buffers bursts and absorbs ML latency. Audit writes are async —
never on the hot path. S3 Object Lock for immutability.
```

---

## 7. Logistics — Telemetry Pipeline

```
   ┌──────────┐
   │  Trucks  │  telemetry every 3s
   │  (GPS,   │  MQTT over cellular
   │  temp,   │
   │  fuel)   │
   └────┬─────┘
        │
        ▼
   ┌────────────────────┐
   │  NLB / AWS IoT     │  ◄── load balancing belongs HERE
   │  Core (MQTT)       │
   └────┬───────────────┘
        │
        ▼
   ┌────────────────────┐
   │  Ingest Tier       │  stateless, autoscaled
   │  (Kafka producer)  │  • device auth
   │                    │  • schema validation
   │                    │  • per-truck rate limit
   └────┬───────────────┘
        │  only this tier holds broker connections
        │  produce key = truck_id → per-truck ordering
        ▼
   ┌──────────┐   NO load balancer in front: clients fetch
   │  Kafka   │   metadata, then connect DIRECTLY to each
   │ (ingest) │   partition leader. An LB would cause
   └────┬─────┘   NOT_LEADER_OR_FOLLOWER errors.
        │
        ├──────────────┬──────────────┐
        ▼              ▼              ▼
   ┌──────────┐  ┌──────────┐   ┌──────────┐
   │  Redis   │  │ Alerting │   │ Firehose │
   │(current  │  │ Service  │   │  → S3    │
   │ state per│  │(anomaly  │   │(archive) │
   │ truck)   │  │detection)│   └─────┬────┘
   └────┬─────┘  └──────────┘         │
        │                             ▼
        ▼                       ┌──────────┐
   ┌──────────┐                 │  Athena/ │
   │Dashboard │                 │ Redshift │
   │(SSE to   │                 │(analytics│
   │ browser) │                 └──────────┘
   └──────────┘

Key: One Kafka stream, three independent consumers.
Redis for real-time state. Firehose → S3 for archive.
Alerting consumes directly from Kafka, no DB queries.

Why an ingest tier instead of trucks producing to Kafka directly:
brokers would be internet-exposed, tens of thousands of device TCP
connections would exhaust broker limits, credentials would live in
firmware you can't rotate, and MQTT handles flaky cellular links far
better than the Kafka protocol. The gateway is stateless, so it scales
horizontally and is cheap to load balance.

Kafka itself is never behind a load balancer — each partition has one
leader and writes must reach that exact broker. A LB is only valid for
the bootstrap/metadata call. (MSK multi-VPC uses an NLB with a distinct
port per broker, which is port routing, not balancing.)
```

---

## 8. Food Delivery — Pricing + Order Status

```
Order Flow:
   ┌────────┐    ┌──────┐    ┌──────────┐
   │  User  │───►│ Order│───►│ Pricing  │ (third-party)
   │        │    │  Svc │    │ Service  │
   └────────┘    └──┬───┘    └──────────┘
                    │          ▲
                    │          │ circuit breaker
                    │          │ (if down, return
                    │          │  last cached price)
                    │
                    ▼
              ┌──────────┐
              │PostgreSQL│
              └──────────┘

Menu/Pricing Updates (Write-Through):
   ┌────────────┐     write     ┌──────────┐
   │ Restaurant │ ────────────► │PostgreSQL│
   │ Admin      │               └─────┬────┘
   └────────────┘                     │ simultaneously
                                      ▼
                                ┌──────────┐
                                │  Redis   │
                                │ (always  │
                                │  fresh)  │
                                └──────────┘
                                Users always read from Redis

Order Status (SNS → SQS FIFO):
   ┌──────────┐    ┌─────┐    ┌──────────┐    ┌──────────┐
   │  Status  │───►│ SNS │───►│SQS FIFO  │───►│ Consumer │
   │  Change  │    │     │    │(ordered  │    │(validates│
   │          │    │     │    │ per order)│    │ state    │
   └──────────┘    └─────┘    └──────────┘    │ machine) │
                                              └──────────┘

Key: Circuit breaker + cached fallback on hot path (user waiting).
Write-through caching for menus/prices. SQS FIFO for ordered
status transitions. TTL as safety net on all cached data.
```

---

## 9. Social Media — Feeds + Hashtags

```
Login (once per session — low volume, NOT on the hot path):
   ┌────────┐  1. POST /login  ┌──────────────┐  2. Sign  ┌──────────┐
   │ Client │─────────────────►│   Auth Svc   │──────────►│   KMS    │
   │        │◄─────────────────│              │◄──────────│ private  │
   └────────┘  4. JWT          └──────┬───────┘  3. sig   │key never │
   stores JWT,                        │                   │  leaves  │
   sends it on                        │ exposes           └──────────┘
   every request                      ▼
                          ┌──────────────────────┐
                          │ /.well-known/        │
                          │   jwks.json          │  PUBLIC keys only
                          │  (public keys)       │  (safe to expose)
                          └──────────────────────┘
                                      ▲
                                      │ GET once at startup,
                                      │ then periodic refresh
                                      │ (Envoy PULLS — nothing
                                      │  is pushed to it)
                                      │
                          ┌───────────┴──────────┐
                          │  Istio ingress GW    │  ◄── keys CACHED
                          │  (Envoy)             │      HERE, in
                          └──────────────────────┘      Envoy memory

Front Door (every subsequent request):
   ┌────────┐   ┌────────────┐   ┌──────┐   ┌──────────────────┐
   │ Client │──►│ CloudFront │──►│ ALB  │──►│ Istio ingress    │
   └────────┘   │ TLS term,  │   │(cheap│   │ gateway (Envoy)  │
    sends JWT   │ static/img │   │ per  │   │ • verify JWT sig │
                └────────────┘   │ req) │   │   w/ cached JWKS │
                                 └──────┘   │ • strip client   │
                                            │   identity hdrs  │
                                            │ • inject         │
                                            │   x-user-id      │
                                            │ • rate limit     │
                                            └────────┬─────────┘
                                                     │ mTLS
                                                     ▼
                                            ┌──────────────────┐
                                            │   Feed Svc       │
                                            │   (EKS pods)     │
                                            │  trusts x-user-id│
                                            └──────────────────┘

   No API Gateway here: at feed read volume, ~$1/M requests would cost
   more than the service itself, and it adds tens of ms. Auth and rate
   limiting live in the service mesh / BFF instead.

   Auth svc ISSUES the token; the mesh only VERIFIES it (public key, no
   secret, no per-request call to auth svc). Two separate key systems:
   JWT keys = "which user" (KMS + JWKS); mTLS certs = "which workload"
   (istiod CA, auto-rotated). Feed Svc trusts x-user-id only because
   mTLS proves the request came from the ingress gateway.

   Trap: Istio RequestAuthentication alone does NOT require a token —
   it validates one if present, but no token = anonymous pass-through.
   Pair it with an AuthorizationPolicy requiring requestPrincipals.

Feed Delivery (Hybrid Fan-Out):

Regular user posts (< 100K followers):
   ┌──────┐  post  ┌──────┐  fan-out   ┌──────────┐
   │ User │──────►│ Feed │──on write──►│ Redis    │
   │      │       │  Svc │            │(each     │
   └──────┘       └──────┘            │follower's│
                                      │ feed)    │
                                      └──────────┘

Celebrity posts (> 100K followers):
   ┌──────────┐  post  ┌──────┐  store  ┌──────────┐
   │Celebrity │──────►│ Feed │───────►│PostgreSQL│
   │          │       │  Svc │        └──────────┘
   └──────────┘       └──────┘

   Follower opens app → app fetches their pre-computed feed
   from Redis + fetches celebrity posts from DB at read time

Hashtag Write Bottleneck:
   Problem: millions of writes to one hashtag mapping table
            → index lock contention

   Fix: Table partitioning
   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
   │ Partition 1 │  │ Partition 2 │  │ Partition 3 │
   │ (own index) │  │ (own index) │  │ (own index) │
   └─────────────┘  └─────────────┘  └─────────────┘
   Writes spread across partitions → less lock contention

Key: Hybrid fan-out based on follower count threshold.
Table partitioning for write-heavy tables with index contention.

Front door choice: ALB, not API Gateway. The discriminator is volume,
not service count — ALB also does path-based routing to many services.
ALB is ~$16-20/mo idle + negligible per request and ~1-3ms; API Gateway
is $0 idle but ~$1/M requests and tens of ms. High steady traffic → ALB.
Low/spiky traffic, or you want managed authz + usage plans → API Gateway
(see #5). ALB also handles WebSocket/SSE natively for live feed pushes.
```

---

## 10. Video Streaming — CDN + Uploads + Search + Recommendations

```
Video Upload + Transcode:
   ┌────────┐  1. request URL   ┌──────┐
   │  User  │ ────────────────► │ API  │
   │Browser │ ◄──────────────── │Server│
   └───┬────┘  2. pre-signed URL└──────┘
       │
       │  3. multipart upload DIRECT to S3 (bypasses API server)
       ▼
   ┌──────────┐  4. S3 event   ┌──────────────┐
   │    S3    │───────────────►│ MediaConvert │
   │ (source  │                │  transcode:  │
   │  upload) │                │  1 file → N  │
   └──────────┘                │  renditions  │
                               └──────┬───────┘
                                      │ 5. write segments + manifest
                                      ▼
                         ┌──────────────────────────┐
                         │  S3 (packaged output)    │
                         │   master.m3u8            │
                         │   1080p/seg0001.m4s ...  │
                         │    720p/seg0001.m4s ...  │
                         │    480p/seg0001.m4s ...  │
                         └────────────┬─────────────┘
                                      │
                                      └──► CloudFront origin (below)

   Without transcoding there is nothing to stream: the raw upload has
   one bitrate, so the player has nothing to switch between.

Video Playback (client-driven ABR — server makes NO decisions):
   ┌──────────┐        ┌────────────┐        ┌───────────┐
   │  Player  │◄──────►│ CloudFront │◄──────►│    S3     │
   │  (Asia)  │        │ edge: Tokyo│ on miss│(us-east-1)│
   └──────────┘        └────────────┘  only  └───────────┘

   a. GET /master.m3u8       → manifest lists renditions
                               (1080p / 720p / 480p) + segment URLs
   b. GET /720p/seg0001.m4s  → player picks rendition from measured
                               throughput + buffer level
   c. throughput drops:
      GET /480p/seg0002.m4s  → switches at the SEGMENT BOUNDARY,
                               mid-playback, invisible to the user

   Segments are static files (2-10s each) → highly cacheable. Popular
   content is served entirely from the edge; origin sees almost
   nothing. No session state anywhere — just ordinary HTTP GETs.

   NOT byte-range: byte-range is for seeking within one progressive
   MP4. HLS/DASH fetch discrete per-rendition segment files instead.

Search (CQRS):
   Write path:
   ┌──────┐    ┌──────────┐   async sync   ┌───────────────┐
   │ API  │───►│PostgreSQL│──────────────►│ Elasticsearch │
   └──────┘    │(source of│               │ (search reads)│
               │  truth)  │               └───────────────┘
               └──────────┘

Recommendations:
   ┌──────────┐  off-peak job  ┌──────────┐  pre-computed  ┌───────┐
   │ Redshift │ ◄─────────────│ Rec Job  │──────────────►│ Redis │
   │(analytics│               │(scheduled)│               │(serve │
   │  data)   │               └──────────┘               │to user)│
   └──────────┘                                          └───────┘
   User opens app → pull recommendations from Redis (sub-ms)

Key: Pre-signed URL + multipart upload for large files (bytes never
touch the API server). S3 event → MediaConvert produces N renditions
as short segments + a manifest. Playback is client-driven ABR over
CloudFront: the player reads the manifest, then picks each segment's
quality from measured throughput, switching at segment boundaries.
Server holds no session and makes no quality decision. Elasticsearch
for search. Pre-compute recommendations off-peak, serve from Redis.
```

---

## 11. Real-Time Messaging — WebSocket + Presence + Chat

```
Message Flow:
   ┌────────┐              ┌────────────┐              ┌────────┐
   │ User A │◄──WebSocket──►│  Server 1  │              │ User B │
   └────────┘              └─────┬──────┘              └────────┘
                                 │                          ▲
                          1. write msg                      │
                          to PostgreSQL              5. push msg
                                 │                     via WebSocket
                          2. publish to                     │
                          Redis Pub/Sub              ┌──────┴─────┐
                                 │                   │  Server 3  │
                                 ▼                   └──────┬─────┘
                          ┌──────────┐                      │
                          │  Redis   │──3. deliver to───────┘
                          │ Pub/Sub  │   all subscribed
                          └──────────┘   servers

Presence (Online/Offline):
   ┌────────┐  heartbeat   ┌──────────┐  SET with TTL  ┌──────────┐
   │  User  │ ───────────► │  Server  │ ─────────────► │  Redis   │
   └────────┘  every 30s   └──────────┘                │          │
                                                       │presence: │
                                                       │user123   │
                                                       │TTL: 60s  │
                                                       └──────────┘
   Key exists = online. Key expired = offline. No cleanup needed.

Message History:
   Cursor-based pagination (not offset)
   SELECT * FROM messages
   WHERE channel_id = ? AND message_id < ?
   ORDER BY message_id DESC LIMIT 50
   → Constant performance at any depth

Large Channel Fan-Out (50K members):
   1 message → Redis Pub/Sub → all servers
   Each server pushes to its local connections in parallel
   100 servers × 500 users each = fast delivery

Key: WebSocket servers are stateful proxies. Redis Pub/Sub for
server-to-server relay. Presence via Redis key TTL. Cursor-based
pagination for message history. Scale servers for large fan-out.
```

---

## 12. Concert Ticket Sales — Flash Sale + Inventory + Saga

```
Traffic Control — Virtual Waiting Room:
                    ┌──────────────┐
                    │  500K Users  │
                    └──────┬───────┘
                           │ every request carries
                           │ admission_token cookie (or none)
                           ▼
              ┌────────────────────────────────────┐
              │ CloudFront Function (viewer-req)   │
              │ verify SIGNED admission_token      │
              └───┬─────────────────────────┬──────┘
               NO │                         │ YES
                  ▼                         ▼
        ┌──────────────────┐                ┌──────────────┐
        │  Waiting Room    │                │ API Gateway  │─ token
        │  static page     │                └───────┬──────┘  bucket
        │  (S3 + CF)       │                        ▼         per-user
        └──────────────────┘                ┌──────────────┐  / per-IP
                                            │ EKS (pre-    │
                                            │  scaled)     │
                                            └───────┬──────┘
                                                    │
                                     ┌──────────────┴───┐
                                     ▼                  ▼
                                  ┌───────┐        ┌─────────┐
                                  │ Redis │        │   RDS   │
                                  │(browse│        │(source  │
                                  │ cache)│        │of truth)│
                                  └───────┘        │+ RDS    │
                                                   │ Proxy   │
                                                   └─────────┘

   The static page cannot release anyone. Three pieces do the work:

   1. ARRIVE   One call to Queue Svc → Redis INCR queue:next
               → "you are #412,000", stored in a cookie.
               This is the ONLY backend call made while waiting.

   2. WAIT     Admission Controller advances now_serving from REAL
               capacity (checkout throughput, healthy pods, DB
               headroom): +5,000 every 30s. It publishes
               now_serving.json to S3 + CloudFront, TTL 5-10s.
               → 500K browsers poll THE CDN for that one file and
                 compare locally. Origin serves it once per TTL,
                 not 500K times. THIS is the "zero backend load".

   3. ADMIT    When my_number <= now_serving, the page calls Queue
               Svc ONCE and gets a SIGNED, short-TTL, single-use
               admission_token cookie. The CloudFront Function now
               verifies it and lets the request through.

   WHO RETURNS WHAT:
     Queue Svc      → your NUMBER (on arrival), later your TOKEN
     CloudFront/S3  → now_serving.json (the cursor)
     Client         → compares the two ITSELF. Nobody tells you it is
                      your turn.
   Why not have Queue Svc return now_serving? 500K clients polling
   every 3s = ~165K req/s. As a cached static file it is ~0.

   ┌──────────────┐  INCR   ┌─────────┐  SET   ┌──────────────────┐
   │ Queue Svc    │────────►│  Redis  │◄───────│    Admission     │
   │ (small,      │◄────────│ queue:* │        │    Controller    │
   │  Lambda)     │  #412K  └─────────┘        │  control loop,   │
   └──────────────┘                            │  runs every 30s  │
     returns your NUMBER,                      └───┬──────────▲───┘
     then your TOKEN                    publishes  │          │
                                                   ▼          │ reads
                              ┌──────────────────────┐  ┌─────┴──────────┐
                              │  now_serving.json    │  │  CloudWatch    │
                              │  S3 + CloudFront     │  │ • checkout tps │
                              │  (polled by clients) │  │ • healthy pods │
                              └──────────────────────┘  │ • RDS conns    │
                                                        │ • error rate   │
                                                        └───────▲────────┘
                                                                │ emitted by
                                                            EKS + RDS
                                                          (the real capacity
                                                           being protected)

   The controller is just a knob-turner: read capacity → decide how
   many more to admit → SET now_serving → publish the file. If the
   backend starts struggling, it slows the rate. That feedback loop
   is the entire point of the waiting room.

   Without a signed token verified at the EDGE, anyone skips the queue
   by navigating straight to the checkout URL — the room is theater.
   Token needs a TTL (admitted at 10am ≠ valid at 2pm), and you must
   admit MORE than nominal capacity because many admitted users
   abandon; otherwise the funnel starves.

   What the CF Function does NOT do:
   - It does not serve the page. It 302s (or rewrites the URI) to
     /waiting-room; CloudFront serves that HTML+JS from S3. Function
     code limit is 10KB — you cannot inline an app in it.
   - It does not queue anything. No request is ever held; there is no
     buffer of pending requests. "Queue" = a counter + a cursor.
     Handing out 500K integers scales; holding 500K open requests
     does not.
   - It does not read Redis. CloudFront Functions have NO network
     access (no HTTP, no sockets). It only checks "is this token
     validly signed and unexpired?" — pure local computation.
   - It does not decide capacity. The Admission Controller does that
     out of band; a token in hand IS the decision.

   Edge crypto constraint: the CF Functions crypto module is HMAC only
   (md5/sha1/sha256) — no RSA/EC. So admission_token must be HS256,
   with the shared secret in CloudFront KeyValueStore (the one store a
   function CAN read, since it is replicated to the edge rather than
   fetched over the network). Need RS256? Use Lambda@Edge — but it
   cannot read KeyValueStore.
   Contrast #1a: there the function only DECODES an unverified claim
   for routing, and the regional API verifies for real. Here the edge
   check is the only gate, so it must actually verify.

Seat Purchase (Atomic Conditional Update):
   ┌──────┐  select seat  ┌──────┐  UPDATE ... WHERE status='available'
   │ User │ ─────────────►│ API  │──────────────────────────────────────►┌─────┐
   └──────┘               └──────┘  1 row affected = success            │ RDS │
                                    0 rows affected = seat taken        └─────┘

Temporary Hold:
   User selects seat
     → UPDATE status='held', held_until=NOW()+5min
     → User has 5 min to complete payment
     → Background job releases expired holds

Purchase Saga (with compensation):
   ┌────────────┐    ┌────────────┐    ┌────────────┐    ┌────────────┐
   │ 1. Reserve │───►│ 2. Charge  │───►│ 3. Confirm │───►│ 4. Send    │
   │    Seat    │    │   Stripe   │    │   Ticket   │    │   Email    │
   │            │    │(idempotency│    │            │    │            │
   └─────┬──────┘    │   key)     │    └─────┬──────┘    └────────────┘
         │           └─────┬──────┘          │
    undo:│            undo:│            undo:│
    release           refund           revoke
    seat              payment          ticket

   Order status tracked at each step:
   seat_reserved → payment_charged → ticket_confirmed → email_sent
   Support can look up any order and see exactly where it is/failed.

   If step 3 fails → compensate backwards:
   refund Stripe → release seat → status = 'failed_refunded'

Real-Time Analytics (during sale):
   ┌──────────┐    ┌───────┐    ┌──────────┐    ┌───────┐
   │ Purchase │───►│ Kafka │───►│ Consumer │───►│ Redis │
   │  Events  │    │       │    │(increment│    │(INCR  │
   └──────────┘    └───┬───┘    │counters) │    │tickets│
                       │        └──────────┘    │:sold) │
                       ▼                        └───┬───┘
                  ┌──────────┐                      │
                  │ Firehose │                      ▼
                  │  → S3 →  │               ┌──────────┐
                  │ Redshift │               │Dashboard │
                  │(post-sale│               │(real-time│
                  │analytics)│               └──────────┘
                  └──────────┘

Key: Virtual waiting room controls inflow — the static page is only
UI; a queue service + Redis counter + admission controller do the
releasing, and a signed token checked at the CloudFront edge is what
makes it enforceable. Rate limiting stops bots.
Atomic conditional update prevents double-selling. Temporary holds
prevent wasted checkout effort. Saga pattern with compensation for
reliable multi-step purchase. Kafka → Redis for real-time counters.
Strategy pattern for different event type inventory logic.
```

---

## 13. Monitoring & Alerting Platform — Metrics + Alerts + Dashboards

```
Metric Ingestion:
   ┌──────────┐    ┌──────────┐    ┌──────────────┐
   │ 2,000+   │───►│  Metric  │───►│  Time-Series │
   │ Services │    │   API    │    │   Database   │
   │(50K pts/ │    │          │    │ (InfluxDB/   │
   │  sec)    │    └──────────┘    │  Timestream) │
   └──────────┘                    └──────┬───────┘
                                          │
                                   Downsampling:
                                   24h: per-second
                                   30d: 1-min avg
                                   1yr: 1-hr avg

Alert Evaluation (partitioned):
   ┌──────────────┐
   │  Rule Store  │ (thousands of alert rules)
   │  (PostgreSQL)│
   └──────┬───────┘
          │ partitioned evenly by hash
   ┌──────┼──────────┬──────────┐
   ▼      ▼          ▼          ▼
┌──────┐┌──────┐ ┌──────┐ ┌──────┐
│Eval 1││Eval 2│ │Eval 3│ │Eval 4│  each handles
│1500  ││1500  │ │1500  │ │1500  │  a subset of
│rules ││rules │ │rules │ │rules │  rules
└──┬───┘└──┬───┘ └──┬───┘ └──┬───┘
   │       │        │        │
   │  query TSDB per rule every 60s
   │  "p99 latency > 500ms for 5 min?"
   ▼
   If one evaluator dies → rules rebalanced
   to remaining evaluators (consumer group pattern)

Escalation (delayed queue):
   ┌───────────┐
   │ Alert     │  1. create incident row, status='firing'
   │ fires     │  2. notify on-call
   └─────┬─────┘  3. enqueue escalation check, delay 5 min
         │
         ├──────────────────────────┐
         ▼                          ▼
   ┌───────────┐            ┌────────────────┐
   │  On-call  │            │ Delayed Queue  │
   │  engineer │            │ SQS DelaySecs  │
   └─────┬─────┘            │ (or Step Fns / │
         │ clicks ACK       │  EB Scheduler) │
         │ in Slack/        └───────┬────────┘
         │ PagerDuty                │ fires at T+5min
         ▼                          ▼
   ┌───────────┐            ┌────────────────┐
   │ Alert API │            │  Escalation    │
   │ sets:     │            │  Worker        │
   │ status=   │            │  reads incident│
   │ 'acked'   │            │  status        │
   │ acked_by  │            └───────┬────────┘
   │ acked_at  │                    │
   └─────┬─────┘                    │
         │ write                    │ read
         ▼                          ▼
   ┌──────────────────────────────────────┐
   │  Incident State (Redis / PostgreSQL) │  ◄── THE source of
   │  incident_id, rule_id, status,       │      truth both sides
   │  acked_by, acked_at, escalation_lvl  │      talk to
   └──────────────────────────────────────┘
                    │
         ┌──────────┴──────────┐
         ▼                     ▼
   status='acked'        status='firing'
   or 'resolved'         (still unacked)
   → drop, do nothing    → notify team lead
                         → escalation_lvl++
                         → enqueue next check (10 min)

   The two paths never talk to each other — they only share the
   incident row. That is what makes the ack race safe.

   Gotchas:
   - SQS DelaySeconds maxes at 15 MIN. Longer/multi-step escalation
     ladders need Step Functions `wait` or EventBridge Scheduler.
   - Ack can land AFTER the worker already escalated. Make escalation
     idempotent and compare-and-set on escalation_lvl so a late ack
     stops the NEXT rung rather than corrupting state.
   - 'resolved' must short-circuit the ladder too, not just 'acked'.

Multi-Channel Delivery (fan-out):
   ┌───────┐    ┌─────────┐    ┌───────┐
   │ Alert │───►│   SNS   │───►│ Slack │
   │ Event │    │(fan-out)│    ├───────┤
   └───────┘    └─────────┘    │ Email │
                               ├───────┤
                               │  SMS  │
                               ├───────┤
                               │Pager- │
                               │ Duty  │
                               └───────┘

Deduplication (incident state):
   Rule fires → check Redis: open incident exists?
     No  → create incident, notify
     Yes → increment counter, skip notification
   Rule resolves → notify "resolved after 23 min"

Dashboard Performance:
   ┌────────────┐  every 30s   ┌───────┐  always warm  ┌───────┐
   │ Background │─────────────►│ Redis │◄──────────────│ Dash- │
   │ Pre-compute│  query TSDB  │(cached│  pure Redis   │ board │
   │ Job        │  + write     │results│  reads only   │ Users │
   └────────────┘  to Redis    └───────┘               └───────┘

Key: TSDB for metrics (not PostgreSQL/MongoDB). Downsampling for
storage. Partition evaluators evenly (not by severity). Delayed
queues for escalation — the ack path and the escalation path never
call each other; they only share the incident row, which is both the
dedup key and the ack record. Pre-compute dashboard results into
Redis so users never hit the TSDB.
```

---

## 14. Cloud File Storage & Sync — Deduplication + Sync + Conflicts

```
File Upload (pre-signed + multipart):
   ┌────────┐  1. request URL  ┌──────┐  2. pre-signed URL
   │ Client │ ───────────────► │ API  │ ◄────────────────
   └───┬────┘                  └──────┘
       │  3. multipart upload
       ▼
   ┌──────────┐
   │    S3    │
   └──────────┘

Deduplication (content-addressable storage):
   ┌────────┐  upload file  ┌──────┐  hash = SHA-256(content)
   │ Client │ ────────────► │ API  │──────────────────────────┐
   └────────┘               └──────┘                          │
                                                    ┌─────────▼─────────┐
                                                    │ Hash exists in S3?│
                                                    └──┬──────────┬─────┘
                                                  Yes  │          │  No
                                                       ▼          ▼
                                              Skip upload    Upload to S3
                                              just add       (key = hash)
                                              metadata row   + add metadata

   PostgreSQL metadata:
   ┌─────────┬──────────────┬──────────────┐
   │ user_id │   filename   │ content_hash │
   │ user1   │ slides.pdf   │ abc123...    │ ──┐
   │ user2   │ deck.pdf     │ abc123...    │ ──┼── same S3 object
   │ user3   │ pres.pdf     │ abc123...    │ ──┘
   └─────────┴──────────────┴──────────────┘

   Delete: remove metadata row only.
   Cleanup job: delete S3 objects with zero references.

Real-Time Sync (push, not poll):
   ┌────────┐  file changed   ┌──────────┐  upload   ┌─────┐
   │ User A │─(OS file event)─►│ Client A │─────────►│  S3 │
   │ Laptop │                  └────┬─────┘          └─────┘
   └────────┘                       │
                          metadata update
                                    ▼
                              ┌──────────┐  WebSocket push:
                              │  Server  │  "file X updated"
                              └────┬─────┘
                                   │ Redis Pub/Sub
                          ┌────────┼────────┐
                          ▼        ▼        ▼
                     ┌────────┐┌────────┐┌────────┐
                     │User A  ││User B  ││User A  │
                     │Tablet  ││Laptop  ││Phone   │
                     └────────┘└────────┘└────────┘
                     (download updated file from S3)

   Offline device reconnects → one-time sync check:
   "what changed since my last_seen timestamp?"

Conflict Resolution:
   User A (offline): edits budget.docx (based on version 3)
   User B (offline): edits budget.docx (based on version 3)

   User B syncs first → version 4 on server
   User A syncs → tries to update version 3, but server has v4
     → Conflict detected!
     → Keep both: budget.docx (v4) + budget (conflicted copy).docx
     → Users manually resolve

Key: Pre-signed URL + multipart for uploads. Content hashing for
deduplication. WebSocket + Redis Pub/Sub for real-time sync (don't
poll). OS file events for local change detection. Version numbers
for conflict detection. Timestamp sync for offline reconnection.
```

---

## 15. CI/CD Pipeline Platform — Workers + Logs + Secrets + Artifacts

```
Architecture (control plane + workers):
   ┌────────┐  webhook    ┌──────────────┐   job    ┌───────┐
   │ GitHub │────────────►│ Control Plane│────────►│  SQS  │
   └────────┘             │(schedule jobs,│         │(job   │
                          │ track status) │         │queue) │
                          └──────┬───────┘         └───┬───┘
                                 │                     │
                          always on, lightweight       │ pull jobs
                                                       │
                                    ┌──────────────────┼──────────────┐
                                    ▼                  ▼              ▼
                              ┌──────────┐      ┌──────────┐   ┌──────────┐
                              │ Worker 1 │      │ Worker 2 │   │ Worker 3 │
                              │(spot     │      │(spot     │   │(spot     │
                              │instance) │      │instance) │   │instance) │
                              └──────────┘      └──────────┘   └──────────┘
                              Auto-scale on queue depth.
                              Spot instances = cheap.
                              Crash? Job re-queued automatically.

Real-Time Log Streaming:
   ┌──────────┐  log line  ┌───────────┐  subscribe  ┌──────────┐  WebSocket  ┌─────────┐
   │  Worker  │───────────►│Redis Pub/ │────────────►│  Server  │────────────►│Engineer │
   │          │  publish   │   Sub     │             │          │   push      │ Browser │
   └──────────┘            └───────────┘             └──────────┘             └─────────┘

   After build completes → full log written to S3/CloudWatch
   for permanent storage and search.

Secrets Management:
   ┌──────────┐  resolve at runtime  ┌──────────────┐
   │  Worker  │─────────────────────►│   Secrets    │
   │          │  "prod-db-password"  │   Manager /  │
   │ pipeline │◄─────────────────────│    Vault     │
   │  config  │  actual value        └──────────────┘
   │references│
   │name only │  Rotate in one place → all pipelines
   └──────────┘  pick it up. IAM controls access.

Artifacts:
   ┌──────────┐  push image   ┌──────────┐
   │  Worker  │──────────────►│   ECR    │
   └──────────┘  (via VPC     │(Docker   │
                  endpoint,   │ images)  │
                  no public   └──────────┘
                  internet)
                              ┌──────────┐
   Non-Docker artifacts ────►│    S3    │
   (binaries, test reports)  │(lifecycle│
                              │ policies)│
                              └──────────┘

Build Speed Optimizations:
   - Pre-baked base images with common dependencies
   - Dockerfile layer ordering (dependencies before source)
   - Shared dependency cache in S3 (node_modules, .m2)
   - Pre-scale workers before peak hours (morning, after lunch)

Key: Separate control plane from workers. Workers are ephemeral
spot instances, auto-scale on queue depth. WebSocket + Redis Pub/Sub
for real-time log streaming. Secrets Manager for centralized secret
management. ECR + VPC endpoint for fast, private image storage.
```

---

## 16. Multi-Tenant SaaS Analytics — Ingestion + Tenancy + Funnels

```
Event Ingestion (client-side batching):
   ┌────────────┐  batch of 20 events   ┌──────┐
   │ JS Snippet │──(every 5s or on ────►│ API  │
   │ (browser)  │   page unload via     │      │
   └────────────┘   sendBeacon)         └──┬───┘
                                           │
                                    check Redis:
                                    tenant over quota?
                                    Yes → 429 reject
                                    No → INCR counter
                                           │
                                           ▼
                                      ┌─────────┐
                                      │  Kafka  │
                                      └────┬────┘
                                           │
                          ┌────────────────┼─────────────────┐
                          ▼                ▼                  ▼
                    ┌──────────┐    ┌──────────┐       ┌──────────┐
                    │ Consumer │    │ Consumer │       │ Firehose │
                    │→ Redis   │    │→ Postgres│       │ → S3     │
                    │(real-time│    │(recent   │       │(archive) │
                    │counters) │    │queries)  │       └─────┬────┘
                    └──────────┘    └──────────┘             │
                                                             ▼
                                                       ┌──────────┐
                                                       │ Redshift │
                                                       │(complex  │
                                                       │analytics)│
                                                       └──────────┘

Three-Tier Analytics:
   Hot:  Kafka → Redis        (real-time counters, seconds)
   Warm: Kafka → PostgreSQL   (recent queries, minutes)
   Cold: Kafka → S3 → Redshift (historical reports, batch)

Tiered Multi-Tenancy:
   ┌───────────────┐         ┌───────────────┐
   │  Shared DB    │         │  Dedicated DB │
   │  (199 small   │         │  (1 large     │
   │   tenants)    │         │   tenant)     │
   └───────────────┘         └───────────────┘
   Tenant routing layer maps tenant_id → correct DB

Per-Tenant Rate Limiting (daily quota):
   Redis key: tenant:123:2026-03-26
   INCR on every request, TTL 24h (auto-resets daily)
   Check against plan limit before ingesting

Dashboard (pre-computed funnels):
   ┌────────────┐  scheduled   ┌──────────┐  results  ┌───────┐
   │ Background │─────────────►│ Redshift │─────────►│ Redis │
   │ Cron Job   │  complex     │(funnel   │          │(serve │
   │(every 5min)│  query       │ query)   │          │to UI) │
   └────────────┘              └──────────┘          └───────┘

   Kafka consumers for simple real-time counters.
   Background jobs for complex historical computations.

Key: Client-side batching to reduce request volume. Kafka as
ingestion buffer. Three-tier pipeline (hot/warm/cold). Tiered
tenancy for noisy neighbor. Redis daily counters for quota.
Pre-compute complex queries, serve from Redis.
```

---

## 18. Healthcare Patient Portal — HIPAA + Real-Time + Audit

```
Database Layer (read/write splitting):
   ┌──────────┐  writes    ┌──────────┐  async repl  ┌──────────┐
   │  Doctor  │────────────►│  Primary │─────────────►│ Replicas │
   │  Admin   │             │   RDS    │              │ (reads)  │
   └──────────┘             └──────────┘              └──────────┘
                                 ▲                         ▲
                    clinical reads│                        │ low-stakes
                    + stale-replica                        │ browsing
                      fallback    │                        │ (history,
                                 │                         │  billing)
                            ┌────┴─────────────────────────┘
                            │        Patient Portal
                            └──────────────────────┘

   NOT read-after-write. RAW = read YOUR OWN write (same session,
   pinned to primary for a few seconds). Here the WRITER is the doctor
   and the READER is the patient — different session, different user.
   The patient's session has no idea a write happened.

   The actual problem: the WebSocket push ("results ready") is FASTER
   than replication. Patient clicks through and sees stale data.

   Three fixes, pick per read:
   1. Route clinical reads to PRIMARY. Blunt; usually correct for
      healthcare. Replicas serve only billing/history browsing.
   2. Version token (fits this design — the push already exists):
        push includes record_version/LSN
        → client sends it back as "min version I expect"
        → API compares to replica's applied LSN
        → behind? read primary. caught up? read replica.
      Monotonic reads without sending everything to primary.
   3. Replica lag check / Aurora aurora_replica_read_consistency:
      retry against primary when the replica is behind.

   Encryption at rest (KMS), envelope encryption for PHI fields.
   IAM least privilege + IdP federation (no IAM users).

Real-Time Updates (WebSocket):
   ┌────────┐  update record  ┌──────────┐  publish  ┌───────┐
   │ Doctor │────────────────►│  Server  │──────────►│ Redis │
   └────────┘                 └──────────┘           │Pub/Sub│
                                                     └───┬───┘
                                                         │
                                              subscribe  │
                                                         ▼
                                                   ┌──────────┐  WebSocket  ┌─────────┐
                                                   │  Server  │────────────►│ Patient │
                                                   └──────────┘   push      │ Browser │
                                                                            └─────────┘

Audit Logging (async, tamper-proof):
   ┌──────────┐  audit event  ┌───────┐  consumer  ┌──────────────┐
   │ App      │──────────────►│  SQS  │───────────►│     S3       │
   │ Server   │  (async)      │       │            │ (Object Lock │
   └──────────┘               └───────┘            │  + KMS enc)  │
                                                   └──────┬───────┘
   Who accessed what patient,                             │
   when, from where.                                      ▼
                                                   ┌──────────┐
                                                   │  Athena  │
                                                   │(compliance│
                                                   │ queries) │
                                                   └──────────┘

Notification System (multi-channel + scheduled):
   ┌──────────┐  hourly cron:                    ┌───────────┐
   │PostgreSQL│  "appointments in next 24h"      │   Kafka   │
   │          │─────────────────────────────────►│           │
   └──────────┘                                  └─────┬─────┘
                                                       │
                                          ┌────────────┼────────────┐
                                          ▼            ▼            ▼
                                    ┌──────────┐┌──────────┐┌──────────┐
                                    │  Email   ││   SMS    ││   Push   │
                                    │ Consumer ││ Consumer ││ Consumer │
                                    └──────────┘└──────────┘└──────────┘

   Or EventBridge Scheduler for precise time-based delivery.

Key: Read/write splitting. Cross-actor freshness (doctor writes,
patient reads) is NOT read-after-write — use a version token from the
WebSocket push, or send clinical reads to the primary. Envelope
encryption for PHI. IAM + IdP federation. WebSocket + Redis Pub/Sub
for real-time updates. S3 Object Lock for tamper-proof audit logs.
Cron + DB query for scheduled reminders, Kafka fan-out per channel.
```

---

## 19. URL Shortener at Scale — Generation + Analytics + Expiration + Multi-Tenant

```
URL Creation:
   ┌────────┐  long URL   ┌──────┐  get next ID  ┌────────────┐
   │  User  │────────────►│ API  │───────────────►│Coordinator │
   │        │             │Server│  (INCRBY 10K)  │(Redis/     │
   └────────┘             └──┬───┘                │DynamoDB)   │
                             │                    └────────────┘
                     ID → base62 encode
                     → short code (abc123)
                             │
                     ┌───────┴────────┐
                     ▼                ▼
               ┌──────────┐    ┌──────────┐
               │PostgreSQL│    │  Redis   │
               │(primary  │    │ (cache,  │
               │ region)  │    │  local)  │
               └────┬─────┘    └──────────┘
                    │ ASYNC replication (seconds)
        ┌───────────┼────────────┐
        ▼           ▼            ▼
   ┌─────────┐ ┌─────────┐ ┌──────────┐
   │ us-east │ │ eu-west │ │ ap-south │  read replicas, or
   │ replica │ │ replica │ │ replica  │  DynamoDB Global
   └─────────┘ └─────────┘ └──────────┘  Tables

   Redirects are read-heavy and GLOBAL — every region must resolve any
   code. Writes go to one place; reads are served locally. This is why
   the store is replicated but the coordinator is not: only ID handout
   needs to be strongly consistent, and it happens once per creation.

   Race: a link shared instantly (Slack/SMS) can be clicked in another
   region BEFORE replication lands → 404 on a valid link.
   Fix: on miss, fall back to the ORIGIN region before returning 404.
   Never negative-cache a miss (or cache it ~1s at most), or you pin
   the 404 in place long after replication catches up.

Redirect Flow:
   ┌────────┐
   │  User  │  GET sho.rt/abc123
   └───┬────┘
       │ 1
       ▼
   ┌────────┐
   │  NLB   │  L4 only — looks nothing up
   └───┬────┘
       │ 2  forward
       ▼
   ┌──────────┐   3. GET code    ┌─────────┐
   │   API    │─────────────────►│  Redis  │
   │  Server  │◄─────────────────│ (cache) │
   └────┬─────┘   hit: long URL  └─────────┘
        │
        │ 4  MISS only
        ▼
   ┌──────────┐
   │PostgreSQL│  → backfill Redis, then respond
   └──────────┘

   5. API returns HTTP 302 + Location: <long URL>  ──► User
   6. API async-emits click event ──► Kafka (never blocks the redirect)

   Note: LBs don't query Redis directly — the API server is the worker that
   does the cache lookup, DB fallback, and writes the redirect response.
   Use 302 (not 301) to avoid browser caching the redirect, which would
   skip your server on subsequent clicks and break click analytics.

Analytics:
   ┌──────────┐  click event  ┌───────┐
   │   API    │──────────────►│ Kafka │
   │  Server  │  (async)      └───┬───┘
   └──────────┘                   │
                    ┌─────────────┼──────────────┐
                    ▼             ▼              ▼
              ┌──────────┐ ┌──────────┐   ┌──────────┐
              │ Consumer │ │ Consumer │   │ Firehose │
              │→ Redis   │ │→ TSDB    │   │ → S3     │
              │(real-time│ │(historical│  │(archive) │
              │counters) │ │ by hour) │   └──────────┘
              └──────────┘ └──────────┘

   Background job queries TSDB → writes to Redis (cache always warm)
   Dashboard reads from Redis.

URL Expiration:
   - Every record has expires_at column
   - On redirect: check expires_at → expired = "link expired" page
   - Daily cleanup job: DELETE WHERE expires_at < NOW()
   - Lazy expiration (check on read) + background cleanup (free storage)

Custom Domains (multi-tenant):
   Nike: go.nike.com CNAME → shorturl.com
   ┌────────┐  go.nike.com/sale  ┌─────┐  Host header  ┌──────┐
   │  User  │───────────────────►│ ALB │──────────────►│ API  │
   └────────┘                    └─────┘               │Server│
                                                       └──┬───┘
                                              read Host header
                                              lookup domain → tenant_id
                                              scope all data by tenant_id

   Auth: Cognito for simple users. SSO/OIDC for enterprise
   (redirect to customer's IdP, map to tenant_id on return).
   Branding assets (logos, custom pages) in S3 by tenant.

Key: Auto-increment ID + base62 for collision-free short codes.
Write once to the primary region, replicate async to every region so
redirects resolve locally; on a miss, fall back to the origin region
before 404 (a freshly created link can be clicked before replication
lands). LB forwards to API server; API server checks Redis cache for fast
redirects, falls back to PostgreSQL on miss. HTTP 302 (not 301) so
browsers don't cache the redirect and skip your analytics. Kafka
async for analytics. TSDB for click time-series. Lazy expiration +
cleanup job. Tenant_id on all data for multi-tenant isolation.
CNAME for custom domains, Host header for tenant lookup.
```

---

## 20. Webhook Delivery System — Reliability + Retries + Security + Monitoring

```
Event Delivery (async, partitioned by customer):
   ┌──────────┐  event    ┌───────┐  partitioned by   ┌──────────┐
   │  Event   │──────────►│ Kafka │  customer_id       │ Workers  │
   │ Producer │           │       │───────────────────►│ (pool of │
   └──────────┘           └───────┘                    │  50-100) │
                                                       └─────┬────┘
                     Per-customer partitions:                 │
                     Nike events → Nike partition             │
                     Spotify events → Spotify partition       │
                     One bad endpoint only affects             │
                     its own partition                        │
                                                              ▼
                                                   ┌──────────────────┐
                                                   │  HTTP POST to    │
                                                   │  customer URL    │
                                                   │  (5s timeout)    │
                                                   │  + HMAC signature│
                                                   └────────┬─────────┘
                                                            │
                                                   success? │
                                                   ┌────────┴────────┐
                                                   ▼                 ▼
                                                 Yes               No
                                              log success     retry with
                                              to TSDB         exponential
                                                              backoff

Retry Strategy (exponential backoff):
   Attempt 1: immediate
   Attempt 2: 1 min later
   Attempt 3: 5 min later
   Attempt 4: 30 min later
   Attempt 5: 2 hours later
   ...up to 3 days
   All retries failed → DLQ → notify customer + support team

   Event log (DB) stores all events for 30 days.
   Customer can replay missed events via API/dashboard.

Webhook Signature (HMAC-SHA256):
   ┌──────────┐                          ┌──────────────┐
   │  Your    │  HMAC-SHA256(payload,    │   Customer   │
   │  Server  │  shared_secret)          │   Server     │
   │          │──────────────────────────►│              │
   │  Header: │  X-Webhook-Signature:    │  Verify:     │
   │  sha256= │  sha256=abc123...        │  hash payload│
   │  abc123  │                          │  with same   │
   └──────────┘                          │  secret      │
                                         └──────────────┘
   Each customer gets a unique shared secret on registration.

Observability:
   ┌──────────┐  delivery metrics  ┌──────┐
   │ Workers  │───────────────────►│ TSDB │
   │          │  (status, latency, │      │
   └──────────┘   response code)   └──┬───┘
                                      │
                          ┌───────────┼───────────┐
                          ▼           ▼           ▼
                    ┌──────────┐┌──────────┐┌──────────┐
                    │ Customer ││ Health   ││ Support  │
                    │Dashboard ││ Monitor  ││Dashboard │
                    │(my URL's ││(failure  ││(all      │
                    │ delivery ││ rate >50%││customers)│
                    │ history) ││→ alert)  ││          │
                    └──────────┘└──────────┘└──────────┘

Key: Partition by customer for blast radius reduction. Exponential
backoff for retries. HMAC-SHA256 shared secret for webhook
signatures. TSDB for delivery metrics. Event log for replay.
DLQ + customer notification for permanent failures.
```

---

## 21. Online Gaming Platform — Matchmaking + Leaderboard + Game State

```
Matchmaking (partitioned by skill):
   ┌────────┐  find match  ┌─────────────┐
   │ Player │─────────────►│ Matchmaking │
   └────────┘              │   Service   │
                           └──────┬──────┘
                                  │ route by skill level
                    ┌─────────────┼─────────────┐
                    ▼             ▼              ▼
              ┌──────────┐ ┌──────────┐   ┌──────────┐
              │ Bronze   │ │  Gold    │   │ Diamond  │
              │  Queue   │ │  Queue   │   │  Queue   │
              └──────────┘ └──────────┘   └──────────┘

   10 players found → assign to game server → match starts.
   Thin bracket? Widen skill range over time
   (±100 → ±200 → ±300 as wait increases).
   No Kafka: single consumer type, no fan-out needed.

Leaderboard (Redis sorted sets):
   ┌──────────┐  match ends   ┌───────┐  ZADD         ┌──────────┐
   │  Game    │──────────────►│ Redis │  leaderboard   │PostgreSQL│
   │  Server  │  dual-write   │sorted │  4500          │(long-term│
   └──────────┘               │ set   │  "player123"   │  store)  │
                              └───┬───┘                └──────────┘
                                  │
                     ZREVRANGE 0 99 → top 100 (instant)
                     ZREVRANK "player123" → rank #48,231

Game State (Redis snapshots):
   ┌──────────┐  player actions   ┌──────────┐
   │ 10       │◄──UDP/WebSocket──►│  Game    │
   │ Players  │  30 updates/sec   │  Server  │
   └──────────┘  per player       │(state in │
                                  │ memory)  │
                                  └─────┬────┘
                                        │ snapshot every 5-10s
                                        ▼
                                  ┌──────────┐
                                  │  Redis   │
                                  │(multi-AZ │
                                  │ cluster) │
                                  └──────────┘

   Server crash → detect via heartbeat → new server
   → load last snapshot from Redis → players reconnect.
   Lost game state = annoying, not catastrophic.

Post-Match Processing:
   ┌──────────┐  match result  ┌───────┐
   │  Game    │───────────────►│ Kafka │
   │  Server  │                └───┬───┘
   └──────────┘                    │
        │                ┌─────────┼──────────┐
        │                ▼         ▼          ▼
        │          ┌──────────┐┌────────┐┌──────────┐
        │          │Achievmnt ││ Stats  ││Analytics │
        │          │ Service  ││Service ││ Service  │
        │          └──────────┘└────────┘└──────────┘
        │
        │ Hot path (player waiting):
        └──► Redis (XP + leaderboard) + PostgreSQL
             Show results immediately.
             Everything else → Kafka → async.

Key: Partition matchmaking by skill, widen over time. Redis sorted
sets for real-time leaderboard. Redis snapshots for game state
recovery. Dual-write to Redis + PostgreSQL on match completion.
Hot path for XP, Kafka fan-out for background processing.
```

---

## 22. Smart Home Security Cameras — Video + Notifications + Live Stream

```
Video Ingestion (pre-signed URL):
   ┌────────┐  motion!   ┌──────┐  pre-signed URL  ┌─────┐
   │ Camera │───────────►│ API  │──────────────────►│  S3 │
   │        │            │Server│                   │     │
   └────────┘            └──────┘                   └──┬──┘
       │                                               │
       │  direct upload                          S3 event
       │  (multipart)                                  │
       └──────────────────────────────────────────►    ▼
                                                  ┌─────────┐
                                                  │  Kafka  │
                                                  └────┬────┘
                                          ┌────────────┼────────────┐
                                          ▼            ▼            ▼
                                    ┌──────────┐┌──────────┐┌──────────┐
                                    │Notificat-││Thumbnail ││ Timeline │
                                    │ion Svc   ││Generator ││ Writer   │
                                    └──────────┘└──────────┘└──────────┘

Push Notification:
   ┌──────────┐  lookup users  ┌───────┐  camera→users  ┌─────┐  push
   │Notificat-│───────────────►│ Redis │  mapping       │ SNS │──────►📱
   │ion Svc   │  (cache-aside) │       │               │(APNs│
   └──────────┘                └───────┘               │/FCM)│
                                                       └─────┘

Live Streaming (WebRTC + STUN/TURN):
   ┌────────┐              ┌────────────┐              ┌────────┐
   │ Camera │◄──WebRTC────►│ TURN Server│◄───WebRTC───►│  Phone │
   │(behind │  (via TURN   │(relay when │              │(cell-  │
   │  NAT)  │   fallback)  │ direct P2P │              │ ular)  │
   └────────┘              │ fails)     │              └────────┘
                           └────────────┘
   Auth via API Gateway before stream is established.
   STUN first (direct P2P). TURN fallback (relayed).
   Geo-distributed TURN servers for low latency.

Video Storage (lifecycle policies):
   ┌──────────────────────────────────────────────┐
   │                    S3                         │
   │  0-7 days:   S3 Standard (frequent access)   │
   │  7-30 days:  S3 Infrequent Access (cheaper)  │
   │  30d-1yr:    Glacier Instant (premium only)   │
   │  After TTL:  Deleted (lifecycle rule)         │
   │              Free=30 days, Premium=1 year     │
   │  + Intelligent Tiering for variable access    │
   └──────────────────────────────────────────────┘

Timeline (cursor-based pagination):
   ┌──────────┐  today's events  ┌───────┐  pre-loaded   ┌──────────┐
   │PostgreSQL│─────────────────►│ Redis │◄─────────────│  App     │
   │(all      │                  │(cache)│              │ (phone)  │
   │ events)  │                  └───────┘              └──────────┘
   │          │
   │  Cursor: WHERE camera_id = ? AND event_time < ?   │
   │  ORDER BY event_time DESC LIMIT 20                │
   │  Constant speed at any depth.                      │
   └──────────────────────────────────────────────────┘

   No EMR needed — camera provides timestamps.
   EMR/ML only for advanced features (person detection,
   package detection, license plate recognition).

Key: Pre-signed URL + multipart for video upload. Kafka fan-out
for notifications, thumbnails, timeline. SNS for mobile push.
WebRTC + STUN/TURN for live streaming. S3 lifecycle policies
for cost. Redis cache for timeline, cursor-based pagination.
```

---

## 17. Global E-Commerce Marketplace — Multi-Region + Search + Checkout

```
Multi-Region (GDPR data residency):
   EU customers' PERSONAL data stays in eu-west-1, US in us-east-1.
   Only NON-personal data (product catalog) replicates cross-region.

                        ┌──────────────┐
                        │    Users     │
                        └──────┬───────┘
                               ▼
                     ┌───────────────────┐
                     │    Route 53       │  DNS only — sees the
                     │  geolocation      │  RESOLVER IP. No JWT,
                     │  (anonymous only) │  no cookie, no account.
                     └─────────┬─────────┘
                               │ alias → CloudFront
                               ▼
                  ┌────────────────────────────┐
                  │  AWS WAF (on CloudFront)   │  L7. Blocks at the
                  │  • rate-based rules        │  EDGE, before traffic
                  │    (per IP / header / JA3, │  enters your network.
                  │     5-min rolling window)  │
                  │  • Bot Control (allow      │  NOTE: WAF does NOT
                  │    Googlebot, block        │  authenticate. It only
                  │    price scrapers)         │  inspects and blocks.
                  │  • ATP on /login           │
                  │    (credential stuffing)   │
                  │  • managed SQLi / XSS      │
                  │  • CAPTCHA / JS challenge  │
                  │  • geo blocking, IP rep    │
                  └─────────────┬──────────────┘
                                ▼
                  ┌────────────────────────────┐
                  │  CloudFront + CF Function  │
                  │  verify JWT, then route    │
                  │  by PATH:                  │
                  │                            │
                  │  /products, /search, /cat  │
                  │    → NEAREST region        │
                  │      (catalog is           │
                  │       replicated, no PII)  │
                  │                            │
                  │  /account, /orders,        │
                  │  /checkout, /purchase      │
                  │    → read JWT region claim │
                  │      → ORIGIN region       │
                  └───────┬────────────┬───────┘
                          │            │
              ┌───────────┘            └───────────┐
              ▼                                    ▼
   ┌─────────────────────┐             ┌─────────────────────┐
   │     us-east-1       │             │     eu-west-1       │
   │  ┌───────────────┐  │             │  ┌───────────────┐  │
   │  │      ALB      │  │             │  │      ALB      │  │
   │  │ • path → tgt  │  │             │  │ • path → tgt  │  │
   │  │   group       │  │             │  │   group       │  │
   │  │ • TLS to EKS  │  │             │  │ • TLS to EKS  │  │
   │  │ • OIDC/Cognito│  │             │  │ • OIDC/Cognito│  │
   │  │   if you want │  │             │  │   if you want │  │
   │  │   auth HERE   │  │             │  │   auth HERE   │  │
   │  └───────┬───────┘  │             │  └───────┬───────┘  │
   │  ┌───────▼───┐ ┌────┴───┐  async  │  ┌───────▼───┐ ┌────┴───┐
   │  │    EKS    │ │  RDS   │◄─repl──►│  │    EKS    │ │  RDS   │
   │  │           │ │(US data│(products│  │           │ │(EU data│
   │  └───────────┘ │  +PII) │  ONLY)  │  └───────────┘ │  +PII) │
   │                └────────┘         │                └────────┘
   └─────────────────────┘             └─────────────────────┘

   DDoS: Shield Standard is free and automatic on CloudFront/ALB/
   Route 53 — not drawn, nothing to enable. Shield Advanced is the
   paid tier (L7 protections, DDoS response team, cost protection).

   ALB, not API Gateway: marketplace read volume makes per-request
   pricing brutal (see #9). The features API Gateway would have given
   you are already covered — WAF for rate limiting and bots, the CF
   Function for JWT verification.

   LOCK THE ORIGIN. All of the above is worthless if the ALB is
   publicly reachable — attackers just resolve its DNS name and hit it
   directly, skipping Shield's edge capacity, WAF, and the CF Function.
   Fix with any of:
     - ALB security group allows ONLY the AWS-managed prefix list
       com.amazonaws.global.cloudfront.origin-facing
     - CloudFront injects a secret header; ALB rule drops requests
       without it
     - CloudFront VPC origins (ALB stays private, no public IP)

   WAF caveat: rate-based rules evaluate over a 5-MINUTE rolling
   window. Good for stopping abuse, too coarse for "100 req/sec per
   customer" precision. That precision is what API Gateway usage
   plans buy you (see #5).

   WHY NOT Route 53 for account-origin: DNS resolution happens before
   any HTTP request exists. Route 53 never sees the token, so it cannot
   know a traveling EU customer belongs in eu-west-1 — it would send
   them to us-east-1 on geography. Account-origin routing REQUIRES
   edge logic that can read the request. See #1a.

   Route 53 handles: geolocation for anonymous traffic, health-check
   failover, latency-based routing. That is the limit of DNS.

   ROUTE BY OPERATION, NOT BY USER. The catalog is replicated
   everywhere, so browsing has no residency constraint — sending a
   traveling EU user's product searches back to Frankfurt adds a
   trans-Atlantic round trip for nothing. Only requests that TOUCH
   PII need the origin region:

     GET /products/123, GET /search   → nearest region
     GET /account/orders              → origin region (JWT claim)
     POST /checkout, POST /purchase   → origin region (JWT claim)

   Most requests in a browsing session never trigger account routing
   at all; it kicks in on the handful touching the user's own data.

   Cart edge case: arguably PII, but if it lives in the origin region
   every add-to-cart is a cross-Atlantic hop. Keep it client-side (or
   in a local edge store) and commit it to the origin region only at
   checkout.

   CloudFront (global) for static assets / product images
   Browse: read from local replica (fast, eventually consistent)
   Commit: read from origin region DB (accurate, strongly consistent)

Search (CQRS):
   ┌──────────┐  async sync  ┌───────────────┐
   │PostgreSQL│─────────────►│ Elasticsearch │
   │(source   │              │(fuzzy search, │
   │of truth) │              │ relevance,    │
   └──────────┘              │ autocomplete) │
                             └───────────────┘

Checkout (Saga + Async):
   ┌──────────┐  ┌───────┐  ┌─────────┐  ┌───────┐  ┌───────┐
   │Validate  │─►│Charge │─►│Decrement│─►│Create │─►│ Send  │
   │Inventory │  │Stripe │  │ Stock   │  │Order  │  │ Email │
   │          │  │(idemp-│  │         │  │Record │  │(async,│
   └────┬─────┘  │otency │  └────┬────┘  └───┬───┘  │off hot│
  undo: │        │ key)  │  undo:│       undo:│      │ path) │
  (none)│        └──┬────┘  restore     cancel│      └───────┘
        │      undo:│       stock       order
        │      refund│
        │            │
   Order status tracked at each step in DB.
   DLQ for permanent failures.

Hot Product Reads (Black Friday):
   ┌────────────┐   pre-warm    ┌───────┐   read    ┌───────┐
   │ Top 1,000  │──────────────►│ Redis │◄──────────│ Buyer │
   │ products   │  before sale  │(cache)│           │Browser│
   └────────────┘               └───────┘           └───────┘

Inventory Write (atomic conditional):
   UPDATE products SET stock = stock - 1
   WHERE product_id = 'ABC' AND stock > 0;
   → 1 row affected = success (got it)
   → 0 rows affected = sold out
   No locking, no retries, no contention queue.

Key: Multi-region with GDPR. Route by OPERATION, not by user: catalog
reads go to the nearest region (replicated, no PII), and only PII
paths (/account, /checkout) follow the JWT region claim to the origin
region. That routing happens at the CloudFront edge, NOT Route 53,
which only sees the resolver IP and can do geolocation for anonymous
traffic. Only the product catalog replicates cross-region; PII stays put.
Elasticsearch
for search (CQRS). Saga + async for checkout. Idempotency on payments.
Redis cache + pre-warm for hot products. Atomic conditional update
for inventory — simplest solution when logic fits in one WHERE clause.
```

---

## 23. Real-Time Collaborative Document Editor (Google Docs)

```
Real-Time Collaboration (OT + WebSockets):
   ┌────────┐  WebSocket   ┌─────┐  consistent   ┌─────────────┐
   │ Client │─────────────►│ ALB │  hash on      │Collab Server│
   │(browser)│             │     │  doc_id       │ (instance A)│
   └────────┘              └─────┘───────────────►└──────┬──────┘
                                                         │
   Keystroke → operation (insert/delete + position        │
   + revision number) → WebSocket → Collab Server         │
                                                         │
   ┌─────────────────────────────────────────────────────┘
   │
   ▼ OT Engine (every operation, not just conflicts)
   1. Receive op based on revision N
   2. Transform against all ops since revision N
   3. Apply to server state (Redis)
   4. Broadcast transformed op to all other clients
   5. Flush to PostgreSQL async (operation log)

Document Storage & Auto-Save:
   ┌─────────────┐  ops (hot)   ┌───────┐  flush async   ┌──────────┐
   │Collab Server│─────────────►│ Redis │───────────────►│PostgreSQL│
   └─────────────┘              │(active│                │(operation│
                                │ doc)  │                │  log +   │
                                └───────┘                │snapshots)│
                                                         └──────────┘
   Auto-save = operations continuously flushed to PostgreSQL.
   No full-document writes on every save.

   ┌──────────────────────────────────────────────┐
   │     Event Sourcing with Snapshots            │
   │                                              │
   │  Op 1, Op 2, ... Op 100 → [SNAPSHOT] →      │
   │  Op 101, Op 102, ... Op 200 → [SNAPSHOT] →  │
   │                                              │
   │  Version from 3 days ago:                    │
   │  1. Load nearest snapshot before target time │
   │  2. Replay ops between snapshot and target   │
   │  Result: exact document state at that moment │
   └──────────────────────────────────────────────┘

   Images: S3 (upload once, reference by URL)
   Document text: Redis + PostgreSQL (NOT S3 — too
   frequent changes, S3 replaces whole object every write)

Presence & Cursors (ephemeral):
   ┌────────┐  cursor pos   ┌─────────────┐  Pub/Sub  ┌─────────────┐
   │Client A│──────────────►│Collab Server│──────────►│   Redis     │
   └────────┘  (WebSocket)  │  (instance) │           │  Pub/Sub    │
                            └─────────────┘           └──────┬──────┘
                                                             │
                                              ┌──────────────┼───────────┐
                                              ▼              ▼           ▼
                                        ┌──────────┐ ┌──────────┐ ┌────────┐
                                        │ Server B │ │ Server C │ │  ...   │
                                        │→Client B │ │→Client C │ │        │
                                        └──────────┘ └──────────┘ └────────┘

   Redis only — no PostgreSQL persistence needed.
   Heartbeat + TTL (30s) for ungraceful disconnects.
   WebSocket close event for graceful departures.

Offline Reconnection:
   Client queues ops locally while offline.
   On reconnect: sends all queued ops with last known
   revision number → server transforms against all ops
   that happened during the gap → same OT process,
   just a larger batch. No special offline merge needed.

Access Control:
   ┌────────┐  auth   ┌─────────┐  relay  ┌─────────────┐
   │ Client │────────►│   API   │────────►│   Collab    │
   └────────┘         │ Gateway │         │   Server    │
                      └─────────┘         └──────┬──────┘
                                                 │ check perms
                                                 │ on EVERY op
                                                 ▼
   ┌──────────────┐  sync write   ┌───────┐
   │ Permissions  │──────────────►│ Redis │ (+ PostgreSQL)
   │   Service    │               │(perms)│
   └──────┬───────┘               └───────┘
          │ Pub/Sub notification
          ▼
   Collab Server → WebSocket push → Client UI
   switches to read-only immediately.

   Permission changes are synchronous (low volume,
   must take effect immediately). No queue needed.
   User retries on failure — not a DLQ use case.

Key: OT for conflict-free concurrent editing. Redis hot
path + PostgreSQL durable store. Event sourcing with
snapshots for version history. Ephemeral presence in
Redis with Pub/Sub + TTL. Same OT process handles
offline reconnection. Sync permission enforcement on
every operation, real-time revocation via WebSocket.
```

---

## 24. Web Crawler (Googlebot-style)

```
Core Crawl Loop:
   ┌───────────┐  pull URL   ┌────────┐  HTTP GET   ┌──────────┐
   │   Queue   │────────────►│ Worker │────────────►│ Website  │
   │(per-domain│             │(100s of│             └──────────┘
   │ hashing)  │◄────────────│workers)│
   └───────────┘  new URLs   └───┬────┘
                                 │
                   ┌─────────────┼─────────────┐
                   ▼             ▼             ▼
             ┌──────────┐ ┌──────────┐ ┌──────────┐
             │  Parse   │ │  Store   │ │  Store   │
             │  HTML    │ │  HTML in │ │ metadata │
             │ extract  │ │   S3     │ │   in     │
             │  links   │ │ (gzip)   │ │Cassandra │
             └──────────┘ └──────────┘ └──────────┘

URL Discovery & Dedup:
   ┌──────────┐  normalize   ┌───────────┐  seen?   ┌────────────┐
   │ Extracted│─────────────►│ URL       │─────────►│   Bloom    │
   │  Links   │ (lowercase,  │Normalizer │          │   Filter   │
   └──────────┘  strip trail │           │          │ (1-2GB for │
                 slash, rm   └───────────┘          │ 1B URLs)   │
                 tracking                           └─────┬──────┘
                 params)                                  │
                                              ┌───────────┴──────────┐
                                              ▼                      ▼
                                        "not seen"              "probably
                                        → add to queue           seen"
                                        + Bloom filter           → skip

Content Dedup (after crawling):
   ┌──────────┐  SHA-256   ┌───────────┐  hash exists   ┌───────────┐
   │   HTML   │───────────►│  Content  │───────────────►│ Cassandra │
   │ content  │            │   Hash    │  in Cassandra? │           │
   └──────────┘            └───────────┘                └─────┬─────┘
                                                    yes ──┘       └── no
                                                 skip S3         store in S3
                                                 upload          + save hash

Politeness & Rate Limiting:
   ┌────────┐  first visit  ┌─────────────┐  cache rules  ┌───────┐
   │ Worker │──────────────►│ robots.txt  │──────────────►│ Redis │
   └────────┘               │ (per domain)│               │       │
                            └─────────────┘               └───────┘

   Before each request:
   ┌────────┐  check domain  ┌───────┐
   │ Worker │───────────────►│ Redis │
   └────────┘                └───┬───┘
                                 │
                    now - last_request >= crawl_delay?
                    ├── yes → fetch page, update timestamp
                    └── no  → skip, pull URL from different domain

Queue Structure (hashed by domain):
   hash("cnn.com") % 100 → Queue 12
   hash("bbc.com") % 100 → Queue 47
   hash("smallblog.com") % 100 → Queue 37

   Multiple domains per queue, all URLs for same
   domain always in same queue. Workers pull from
   whichever queue has a domain ready to crawl.

Freshness & Adaptive Re-crawl:
   ┌───────────┐  scan for    ┌───────────┐  URLs due   ┌───────────┐
   │ Scheduler │  due URLs    │ Cassandra │────────────►│   Queue   │
   │  (cron)   │─────────────►│           │             └───────────┘
   └───────────┘              └───────────┘

   Cassandra metadata per URL:
   ┌──────────────────────────────────────────┐
   │ url: "cnn.com"                           │
   │ last_crawl_time: 2026-03-26T10:00:00     │
   │ content_hash: "def456"                   │
   │ change_count: 4                          │
   │ crawl_count: 6                           │
   │ recrawl_interval: 1800 (seconds)         │
   └──────────────────────────────────────────┘

   After each crawl: compare new hash to stored hash.
   Changed → increment change_count, shorten interval.
   Unchanged → lengthen interval.
   change_rate = change_count / crawl_count drives interval.

Fault Tolerance:
   You are fetching from servers you do NOT control. Every line below
   is a failure you WILL hit within hours of running. Unifying theme:
   NO SINGLE SITE MAY CONSUME UNBOUNDED RESOURCES. Each entry is a
   bound.

   ┌────────────────────────────────────────────────┐
   │ Timeouts/500s → DLQ, retry with exp backoff    │
   │ DNS failure × 5 → flag dead in Cassandra       │
   │ Redirect loops → cap at 5 redirects, then fail │
   │ Spider traps → cap pages per domain (10K)       │
   │              → cap URL depth (5-6 segments)     │
   │ Malformed HTML → best-effort parse, log error   │
   └────────────────────────────────────────────────┘

   Timeouts/500s   Site temporarily down or slow. TRANSIENT, so retry
                   with backoff; after N attempts drop to DLQ rather
                   than blocking the worker on it.

   DNS failure     Domain does not resolve at all — dead site, expired
                   domain. PERMANENT, so flag it and stop retrying
                   forever, or you accumulate millions of URLs that
                   can never succeed.

   Redirect loops  A → B → A forever. Cap the chain at 5 hops.

   Spider traps    The important one. Sites that generate INFINITE
                   unique URLs:
                     - calendar with "next month" links, forever
                     - faceted search: every filter combination
                     - session IDs in the URL → every visit looks new
                   Each generated page yields more links, so the queue
                   grows without bound and ONE site eats the entire
                   crawl budget. The page-count and depth caps are the
                   only defense.

   Malformed HTML  A large fraction of the real web is invalid. The
                   parser must degrade gracefully — an uncaught
                   exception here kills the worker.

Storage:
   ┌──────────────────────────────────────────────┐
   │  S3 (HTML content, gzip compressed)          │
   │  ~10TB for 1B pages (vs 50TB raw)            │
   │  Recent crawls → S3 Standard                 │
   │  Old versions → S3 Glacier or delete          │
   │                                              │
   │  Cassandra (metadata)                        │
   │  URL, hash, timestamps, crawl stats,         │
   │  recrawl interval, S3 key reference          │
   └──────────────────────────────────────────────┘

Key: Bloom filter for URL dedup (1-2GB vs 100GB+).
URL normalization before Bloom check. Content hash
for cross-URL dedup. robots.txt + per-domain rate
limiting. Adaptive recrawl from change history.
Per-domain queue hashing. DLQ for failures. Compress
+ lifecycle policies for storage cost.
```

---

## 25. Zero-Downtime Database Migration (Single → Sharded PostgreSQL)

```
ORDER OF OPERATIONS (the whole migration, start to finish):

  1. Deploy shards (empty)
  2. Code change: DUAL-WRITE, old DB primary  ......... phase 1
  3. BACKFILL history from a read replica
  4. SHADOW READS — query both, serve old, log mismatches
  5. CANARY READS — 5% → 25% → 50% → 100% to shards
  6. Flip WRITE primary to shards ..................... phase 2
  7. SOAK for weeks (old DB still written = free rollback)
  8. Retire old DB .................................... phase 3

  Two things people get backwards:

  WRITES FLIP, READS RAMP.
    Writes are a binary feature-flag flip, not a percentage. In BOTH
    phase 1 and phase 2 both stores receive every write — "primary"
    only means whose failure fails the user's request. There is no
    5%-of-writes state.
    Reads ramp gradually because a wrong read is visible, harmless,
    and instantly reversible.

  DUAL-WRITE DOES NOT BACKFILL ITSELF.
    Dual-write captures only NEW writes. Every pre-existing row is
    still only in the old DB. Until step 3 completes, the shards are
    incomplete and reads cannot move.

  Why writes flip LAST: while the old DB is still being written,
  rollback is just flipping the flag back. The moment you stop
  writing to it, it starts drifting and rollback stops being free.

Migration Phases (feature flag controlled):

  Phase 1: old_primary
  ┌─────┐  write  ┌──────────┐  success  ┌──────────┐
  │ App │────────►│  Old DB  │──────────►│  Done    │
  │     │         │(primary) │           └──────────┘
  │     │────────►│  Shards  │──fail──►┌──────┐
  │     │  write  │(secondary)│        │ DLQ  │ (retry async)
  └─────┘         └──────────┘         └──────┘

  Phase 2: new_primary (flip feature flag, no redeploy)
  ┌─────┐  write  ┌──────────┐  success  ┌──────────┐
  │ App │────────►│  Shards  │──────────►│  Done    │
  │     │         │(primary) │           └──────────┘
  │     │────────►│  Old DB  │
  │     │  write  │(secondary)│
  └─────┘         └──────────┘

  Phase 3: new_only (after weeks of validation)
  ┌─────┐  write  ┌──────────┐
  │ App │────────►│  Shards  │  Old DB retired
  └─────┘         │  (only)  │
                  └──────────┘

Backfill (old data → shards):
  ┌──────────────┐  batch by ID range  ┌──────────┐
  │ Read Replica │────────────────────►│  Shards  │
  │ (not primary)│  throttled, track   └──────────┘
  └──────────────┘  progress in state
                    table for resume

  COPY, not update — you are inserting rows the shards don't have.
  Read from a REPLICA so the backfill doesn't compete with live
  traffic on the primary.

  The race: backfill runs CONCURRENTLY with dual-writes. A customer
  updates a row while your batch is copying that same range, and a
  blind insert overwrites the newer value with stale data.
  Use one of:
    INSERT ... ON CONFLICT DO NOTHING
      → live writes always win (a row already there IS newer)
    INSERT ... ON CONFLICT DO UPDATE
      WHERE excluded.updated_at > target.updated_at
      → only overwrite if genuinely newer

  Never a blind INSERT/UPDATE. That bug silently corrupts a subset
  of rows and only surfaces later as shadow-read mismatches.

Read Cutover (canary at internal LB):
  ┌─────┐      ┌──────────────┐
  │ App │─────►│ Internal LB  │
  └─────┘      └──────┬───────┘
                      │ canary %
               ┌──────┴──────┐
               ▼             ▼
         ┌──────────┐ ┌──────────┐
         │  Old DB  │ │  Shards  │
         │  (95%)   │ │  (5%)    │
         └──────────┘ └──────────┘
         Ramp: 5% → 25% → 50% → 100%
         Rollback: flip LB back instantly

Verification (shadow reads):
  ┌─────┐  read   ┌──────────┐  compare  ┌──────────┐
  │ App │────────►│  Old DB  │◄────────►│  Shards  │
  └─────┘         └──────────┘  results  └──────────┘
  Return old DB result to user.
  Log mismatches. 0% mismatch = safe to cutover.

Shard Routing (application layer):
  ┌─────┐  hash(customer_id) % 8  ┌───────────┐
  │ App │────────────────────────►│ Shard Map  │
  └─────┘                         │ (config)   │
                                  └─────┬──────┘
                    ┌──────┬──────┬─────┴┬──────┐
                    ▼      ▼      ▼      ▼      ▼
                  Shard  Shard  Shard  ...    Shard
                    0      1      2             7

Per-Shard Architecture:
  ┌─────┐      ┌───────────┐      ┌──────────┐
  │ App │─────►│ PgBouncer │─────►│ Primary  │ (writes)
  └─────┘      │ (proxy)   │─────►│ Replica A│ (reads)
               │           │─────►│ Replica B│ (reads)
               └───────────┘      └──────────┘
  Proxy handles: connection pooling, read/write
  splitting, failover transparency.
  One connection string per shard to the proxy.

Cross-Shard Queries (scatter-gather):
  ┌─────┐  parallel query  ┌────────────────────┐
  │ App │─────────────────►│ All 8 shards       │
  └──┬──┘                  │ each returns partial│
     │                     │ result              │
     │◄────────────────────┘                     │
     │ aggregate results                         │
     ▼                                           │
  For heavy analytics: push to Redshift/BigQuery
  instead of scatter-gather.

Failover (per shard):
  ┌──────────┐  dies   ┌──────────────────┐
  │ Primary  │────────►│ RDS Multi-AZ     │
  └──────────┘         │ auto-promotes    │
                       │ replica to       │
                       │ primary, flips   │
                       │ DNS endpoint     │
                       └──────────────────┘
  Self-managed: Patroni + etcd for leader election
  Routing doesn't change — failover is within the shard.

Schema Changes (canary across shards):
  Deploy migration to shard 1 → validate → roll to rest.
  Schema must be backward compatible during rollout
  (add columns as nullable first).

Monitoring (per shard + unified):
  ┌─────────────────────────────────────────────┐
  │  Per shard: 4 golden signals (latency,      │
  │  saturation, error rate, traffic)           │
  │  + replication lag + connection pool usage   │
  │  Unified Grafana dashboard across all shards│
  └─────────────────────────────────────────────┘

Key: Feature flag for instant phase switching (no redeploy).
Dual-write with DLQ for failed shard writes. Backfill from
read replica. Canary read cutover at LB. Shadow reads for
verification. PgBouncer for connection pooling + read/write
splitting. Scatter-gather for cross-shard queries. Stay in
dual-write (phase 2) for weeks before retiring old DB.
```

---

## 26. Multi-Region Active-Active Global Financial App

```
User Routing (Route 53 geolocation):
   ┌──────────────┐
   │   Route 53   │
   │  geolocation │
   └──────┬───────┘
          │
   ┌──────┴──────────────────────────────┐
   ▼              ▼                      ▼
┌─────────┐  ┌──────────┐  ┌──────────────────┐
│us-east-1│  │eu-west-1 │  │ap-southeast-1    │
│(N.Amer) │  │(Europe)  │  │(Asia-Pacific)    │
└─────────┘  └──────────┘  └──────────────────┘

Per-Region Stack (identical in each region):
   ┌───────────────────────────────────────┐
   │  Route 53 → ALB (NOT API Gateway)    │
   │  → App Servers (EKS)                 │
   │  → PostgreSQL (Aurora) + Redis cache  │
   │  → Prometheus (local monitoring)      │
   └───────────────────────────────────────┘

   ALB: steady high volume makes API Gateway's ~$1/M per-request
   pricing lose badly, and it adds tens of ms. Rate limiting via WAF,
   JWT verification in the mesh/app. See #9, #17.

   Prometheus is LOCAL to each region on purpose: monitoring must
   survive the region being isolated (a global stack that dies with
   the region is useless exactly when needed), and you avoid shipping
   raw high-cardinality metrics cross-region. Federated into one view
   below (Thanos/Grafana).

Data Layer (account-origin routing):
   User in US, data in EU:
   ┌──────────┐  request  ┌──────────┐  cross-region  ┌──────────┐
   │us-east-1 │─────────►│ App      │───────────────►│eu-west-1 │
   │ (nearest)│          │ Server   │  DB call        │ DB       │
   └──────────┘          └──────────┘                 └──────────┘

   How the app knows the origin: the JWT's `region` claim, set at
   login. App reads it and picks that region's DB connection. No
   token yet (i.e. login itself)? Fall back to a globally replicated
   email → region index (DynamoDB Global Tables). Same source of
   truth as #1a — only the CONSUMER of the claim differs.

   TWO ROUTING STRATEGIES — know both, they trade off differently:

   A) Route the REQUEST to the origin region        (#17, #1a)
      CloudFront Function reads the JWT region claim and selects the
      regional origin. One routing decision, then EVERY query is
      local.
      Cost: edge logic to build and operate.
      Best when: a request makes MANY DB queries (chatty workloads).

   B) Route to NEAREST region, cross-region DB call  (THIS diagram)
      Route 53 geolocation only. The local app server reaches across
      to the origin DB for user data.
      Cost: ~80-150ms per cross-region query, and it MULTIPLIES with
      query count.
      Best when: few queries per request and latency is tolerable —
      which is why it is acceptable here for payments.

   Static/non-user data → served from local region (Redis/CDN)
   User payment data → always reads/writes to origin DB
   Cross-region write latency acceptable for payments

Data Residency (GDPR compliance):
   ┌─────────────────────────────────────────────┐
   │  EU data stays within EU                    │
   │  eu-west-1 (Ireland) = primary              │
   │  eu-central-1 (Frankfurt) = standby replica │
   │  NO replicas outside EU                     │
   │                                             │
   │  Same pattern per geographic area:          │
   │  US: us-east-1 primary, us-west-2 standby  │
   │  APAC: ap-southeast-1 primary,             │
   │        ap-northeast-1 standby              │
   └─────────────────────────────────────────────┘

Failover (Route 53 + Aurora Global Database):
   ┌──────────┐  health check  ┌──────────┐
   │ Route 53 │───────────────►│eu-west-1 │ ← UNHEALTHY
   └────┬─────┘                └──────────┘
        │ reroute EU users
        ▼
   ┌──────────────┐  promote replica  ┌──────────────┐
   │ eu-central-1 │◄────────────────│ CloudWatch   │
   │ (Frankfurt)  │  Lambda triggers │ alarm (5min) │
   │ new primary  │  Aurora promote  └──────────────┘
   └──────────────┘

   Cross-region failover is manual/scripted (not automatic)
   to avoid false positives from transient network blips.
   Multi-AZ failover (within region) IS automatic (60-120s).

Staggered Regional Deployment:
   ┌────────────────┐
   │  Deploy to     │ smallest traffic region first
   │ ap-southeast-1 │
   └───────┬────────┘
           │ monitor 15-30 min
           ▼
   ┌────────────────┐
   │  Deploy to     │
   │  us-east-1     │
   └───────┬────────┘
           │ monitor 15-30 min
           ▼
   ┌────────────────┐
   │  Deploy to     │
   │  eu-west-1     │
   └────────────────┘

   Bad deploy breaks one region → rollback that region.
   Other two unaffected. Never risk all three at once.
   "Always limit the blast radius."
   Schema migrations: backward compatible (both old and
   new code must work during staggered rollout).

Observability (unified + per-region):
   ┌──────────────┐
   │ us-east-1    │─── Prometheus ──►
   │ eu-west-1    │─── Prometheus ──► Thanos/Mimir ──► Grafana
   │ap-southeast-1│─── Prometheus ──►  (central)     (unified)
   └──────────────┘

   Dashboards:
   - Global: all regions health at a glance
   - Per-region: deep dive into one region
   - Comparison: same metric across regions side by side
   
   OpenTelemetry: trace ID follows requests across regions.
   US user → us-east-1 app → eu-west-1 DB → response.
   Full trace shows exactly where latency is.

   Alerts: per-region AND global with different escalation.
   One region spike = regional issue.
   All regions spike = bad deploy or upstream dependency.

Key: Route 53 geolocation for routing. Account-origin
routing for data residency. Standby replica in same
geographic area for failover. Staggered regional deploys.
Thanos/Mimir for unified monitoring. Cross-region write
latency acceptable for payments. Always limit blast radius.
```

---

## 27. Real-Time Ride-Sharing Platform (Uber/Lyft)

```
Location Ingestion & Spatial Queries:
   ┌────────┐
   │ Driver │  GPS every 3s
   │  App   │  persistent WebSocket / gRPC stream
   └───┬────┘
       │
       ▼
   ┌────────┐
   │  NLB   │
   └───┬────┘
       │
       ▼
   ┌──────────────────┐
   │  Location Ingest │  • authenticate driver
   │  Service         │  • validate payload
   │  (stateless,     │  • DROP redundant pings (parked driver
   │   autoscaled)    │    sending identical coords every 3s
   │                  │    never needs to reach Kafka)
   │                  │  • produce key = driver_id → per-driver
   │                  │    ordering
   └───┬──────────────┘
       │
       ▼
   ┌───────┐  660K/sec  ┌──────────┐
   │ Kafka │───────────►│ Consumer │
   └───────┘            └─────┬────┘
                              │ GEOADD
                              ▼
                        ┌───────────┐
                        │   Redis   │
                        │   GEO     │
                        │(GEOADD,   │
                        │ GEOSEARCH)│
                        └─────┬─────┘
                              │ async
                              ▼
                        ┌───────────┐
                        │PostgreSQL │
                        │(historical│
                        │  data)    │
                        └───────────┘

   Rider query: "find drivers within 2km"
   GEOSEARCH drivers FROMLONLAT -73.9850 40.7490 BYRADIUS 2 km
   Sub-millisecond response, millions of entries.

   WHY PHONES ARE NOT KAFKA CLIENTS (same as #7):
   - brokers would have to be internet-exposed
   - 100Ks of concurrent driver connections blow past broker limits
   - Kafka credentials would ship inside an app you cannot rotate
   - the Kafka protocol handles cellular drops / IP changes badly;
     a persistent WebSocket or gRPC stream reconnects cleanly
   - APP STORE RELEASE CYCLES: if the phone speaks Kafka directly,
     any pipeline change needs a client release that takes weeks and
     never reaches 100% of users. A server-side ingest tier
     redeploys in minutes.

   Kafka itself is never behind a load balancer — each partition has
   one leader and writes must reach that exact broker. The NLB fronts
   the INGEST TIER, not the brokers.

Matching & Dispatch (atomic claim):
   ┌───────┐  request  ┌──────────┐  GEOSEARCH  ┌───────┐
   │ Rider │──────────►│ Matching │────────────►│ Redis │
   └───────┘           │ Service  │   nearby    │  GEO  │
                       └─────┬────┘   drivers   └───────┘
                             │
                             │ score drivers (distance, rating, ETA, type)
                             ▼
                       ┌──────────────────────────────┐
                       │ Lua script (atomic):         │
                       │  IF driver:123:status =      │
                       │     'available'              │
                       │  THEN SET to 'assigned'      │
                       │       RETURN success         │
                       │  ELSE RETURN fail, try next  │
                       └──────────────────────────────┘
   
   No cart/browse phase — instant matching.
   Atomic update prevents two riders claiming same driver.

Real-Time Trip Tracking:
   ┌────────┐  GPS, WS/gRPC   ┌──────────────────┐
   │ Driver │────────────────►│ Location Ingest  │  SAME ingest tier
   │  App   │   (via NLB)     │    Service       │  as above, reused
   └────────┘                 └────────┬─────────┘
                                       │
                                       ▼
                                  ┌───────┐
                                  │ Kafka │
                                  └───┬───┘
                                      │ consumer
                                      ▼
                              ┌──────────────┐
                              │    Redis     │
                              │  GEO +       │
                              │  Pub/Sub     │
                              └──────┬───────┘
                                     │ PUBLISH trip:abc
                                     ▼
                            ┌────────────────────┐
                            │   Trip Tracking    │  SUBSCRIBES to
                            │      Server        │  trip:abc
                            └─────────┬──────────┘
                                      │ WebSocket PUSH
                                      │ (server → client)
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                 ▼
              ┌──────────┐      ┌──────────┐    ┌──────────────┐
              │  Rider   │      │  Driver  │    │    Family    │
              └──────────┘      └──────────┘    │ (shared link)│
                                                └──────────────┘

   Each trip has its own Pub/Sub channel.
   WebSocket pushes updates to all connected viewers.
   No polling — same pattern as doc editor and cameras.

   Direction matters: the Trip Tracking Server SUBSCRIBES to Redis and
   PUSHES down the WebSocket. Viewers never pull and never talk to
   Redis or Kafka.

   Why Pub/Sub and not another Kafka consumer per viewer: viewers are
   ephemeral and there can be thousands of short-lived channels. Redis
   Pub/Sub is fire-and-forget with no offset tracking, which is right
   here — a viewer who misses a position update just gets the next one
   1-3s later.

Surge Pricing (geographic zones with H3):
   ┌─────────────────────────────────────────────┐
   │  App code: h3.latLngToCell(lat, lng, 9)    │
   │  → returns zone ID: "89283082837ffff"       │
   │                                             │
   │  Supply: zone:89283082837ffff:drivers = 20  │
   │  Demand: zone:89283082837ffff:requests = 100│
   │  (TTL 5 min, auto-expires old demand)       │
   └─────────────────────────────────────────────┘

   ┌──────────┐  zone     ┌───────────┐  read     ┌───────┐
   │ Pricing  │──────────►│ Read      │──────────►│ Redis │
   │ Service  │  lookup   │ counters  │           └───────┘
   └────┬─────┘           └───────────┘
        │
        │ surge_multiplier = f(demand/supply)
        │ ratio 5 → 2.5x
        │
        ▼
   fare = (base + distance×per_mile + time×per_min) × surge
   
   Return to rider: "$25 (2.5x surge)"
   Surge multiplier locked at trip start.

Payment Flow (independent, idempotent, with DLQ):
   ┌──────────┐  trip    ┌───────┐
   │ Trip     │  ends    │ Kafka │
   │ Service  │─────────►│       │
   └──────────┘          └───┬───┘
                             │ fan-out
                     ┌───────┴────────┐
                     ▼                ▼
              ┌────────────┐   ┌─────────────┐
              │  Charging  │   │ Driver      │
              │  Service   │   │ Payout Svc  │
              └─────┬──────┘   └──────┬──────┘
                    │ idempotent       │ accumulates
                    │ Idempotency-Key  │ toward weekly
                    │ = trip_id        │ payout
                    ▼                  ▼
              ┌────────────┐    ┌────────────┐
              │   Stripe   │    │  Driver    │
              └─────┬──────┘    │  Balance   │
                    │ fails     └────────────┘
                    ▼
              ┌────────────┐
              │    DLQ     │ manual review
              └────────────┘

   Independent flows — driver gets paid even if rider
   charge fails (platform absorbs loss). Not a saga.
   Saga only needed when steps must all succeed or
   all roll back (ecommerce checkout, bookings).

Key: Redis GEO for spatial indexing. Atomic Lua scripts
for driver claiming. WebSocket + Pub/Sub for live trip
tracking. H3 for geographic zone-based surge pricing.
Independent payment flows with idempotency keys and DLQ.
Partition all geographic data into zones — never operate
on the whole map.
```

---

## 28. Notification Platform — Email + SMS + Push + In-App

```
   ┌──────────────────────────────────────────────┐
   │              REGION: us-east-1               │
   │   (mirror in eu-west-1, EU data pinned)      │
   └──────────────────────────────────────────────┘

CALLING SERVICES
   Orders ──┐
   Auth ────┤
   Marketing┼──►  POST /notifications
   Social ──┘
            │
            ▼
   ┌────────────────────────┐
   │  WAF + regional ALB    │
   └───────────┬────────────┘
               ▼
   ┌──────────────────────────────────┐    ┌────────────────────┐
   │  Notification API (EKS)          │    │  Status check API  │
   │  • JWT authN/Z                   │    │  GET /notif/:id    │
   │  • schema validation             │    └────────────────────┘
   │  • idempotency: Redis SETNX      │
   │  • persist to Postgres           │
   │  • pref check (cached)           │
   │  • publish to Kafka              │
   │  • return 202 + notif_id         │
   └───────────────┬──────────────────┘
                   ▼
   ┌────────────────────────────────┐
   │            Kafka               │
   │  topics:                       │
   │   - notif.transactional        │
   │   - notif.marketing            │
   │   - campaign.fanout            │
   │   - delivery.status            │
   │   - dlq                        │
   └───┬────────────────────┬───────┘
       │ campaign.fanout    │ notif.transactional / notif.marketing
       ▼                    ▼
 ┌──────────────┐      ┌────────────────────────┐
 │ Fan-out      │      │  Channel workers       │
 │ worker       │      │  • render template     │
 │ • expand 10M │─────►│  • re-check prefs      │
 │   per-user   │ via  │  • rate-limit check    │
 │   messages   │ Kafka│    (Redis bucket)      │
 └──────────────┘      │  • call provider       │
                       │  • DLQ on fail         │
                       └──────────┬─────────────┘
                                  │
          ┌───────────┬───────────┼───────────┐
          ▼           ▼           ▼           ▼
    ┌──────────┐┌──────────┐┌──────────┐┌──────────┐
    │  Email   ││   SMS    ││   Push   ││  In-app  │
    │ SendGrid ││  Twilio  ││ FCM/APNs ││ DynamoDB │
    └────┬─────┘└────┬─────┘└────┬─────┘└────┬─────┘
         │           │           │           │
         └───────────┴─────┬─────┴───────────┘
                           │ delivery + bounce webhooks
                           ▼
                  ┌──────────────────┐
                  │  Status updater  │
                  │   → Postgres     │
                  └──────────────────┘

   In-app delivery to a LIVE client (no push provider involved):
      DynamoDB write → Redis Pub/Sub → WS gateway → mobile/web client

   ┌──────────────────────────────────────────────────────────────┐
   │                        DATA STORES                           │
   │  Postgres  — notifications, templates (versioned), prefs     │
   │  Redis     — idempotency keys (24h TTL), rate-limit counters │
   │              (per-priority budget), pref cache, inbox cache  │
   │  DynamoDB  — in-app inbox (user_id PK, notif_id SK, read)    │
   │  S3        — audit archive (>90d)                            │
   └──────────────────────────────────────────────────────────────┘

Provider rate limit partition (per provider):
   SendGrid total: 1000/sec
     ├─ rate_limit:sendgrid:transactional → 200/sec reserved
     └─ rate_limit:sendgrid:marketing      → 800/sec
   (Marketing blasts cannot starve password resets.)

Multi-region + residency:
   - JWT origin_region claim routes cross-region for roaming users.
   - EU user data pinned to eu-west-1; never replicated to us-east-1.
   - HA for EU = multi-AZ within eu-west-1 (+ optional eu-central-1).
   - Failover ≠ cross-region for EU. Region outage = degraded EU service.

Idempotency:
   - Caller supplies Idempotency-Key header.
   - API does Redis SETNX key → {notif_id, status} EX 86400.
   - Duplicate requests get the original notif_id back, no second send.

Templates:
   - Stored in Postgres, cached in Redis with TTL.
   - Snapshot template_version onto notification at enqueue time
     (in-flight sends render the version they were enqueued with;
     campaign edits don't change in-flight messages underneath you).

Preferences (defense-in-depth):
   - Schema: (user_id, category, channel, opted_in)
   - Categories: marketing, transactional, security, social, digest
   - Transactional + security categories not opt-out-able (legal).
   - Check happens in worker right before provider call,
     even though API also pre-checks. Single point of enforcement.

Two paths in one platform:
   Transactional: API → SETNX → persist → notif.transactional → worker
                  → render + pref check + rate check → provider.   <5s SLO.
   Marketing:     API → persist campaign → campaign.fanout → fan-out worker
                  → expands to per-user messages → notif.marketing
                  → workers drain at 800/sec.   <30 min for 10M.

Key: Separate Kafka topics + worker pools per priority. Separate
Redis rate-limit buckets per priority on the SAME provider account
(or use separate provider accounts). Idempotency via SETNX. Templates
versioned at enqueue. Preferences enforced server-side, not by callers.
Multi-region with EU residency = no cross-region failover for EU;
multi-AZ inside EU is the HA strategy. Async with 202 + notif_id;
fire-and-forget for callers, optional status polling.
```

---

## Reference — Istio Service Mesh (Envoy Gateway vs Envoy Sidecar)

Not tied to any scenario above. Same Envoy binary, two deployments.

```
CONTROL PLANE — writes config, enforces nothing
   ┌───────────────────────────────┐
   │         CONTROL PLANE         │
   │  ┌───────────────────────────┐│
   │  │         istiod            ││
   │  │ • watches k8s CRDs        ││
   │  │ • issues mTLS certs (CA)  ││
   │  │ • compiles policy →       ││
   │  │   Envoy config            ││
   │  └─────────────┬─────────────┘│
   └────────────────┼──────────────┘
                    │
                    │  xDS push (config + certs)
        ┌───────────┼───────────┬───────────┐
        ▼           ▼           ▼           ▼
     gateway    sidecar A   sidecar B   sidecar C
        │           │           │           │
        └───────────┴───────────┴───────────┘
                    (all data plane)


DATA PLANE — every request crosses TWO proxies

   internet
      │
      ▼
  ┌────────┐
  │  ALB   │   k8s Service type=LoadBalancer
  └───┬────┘   targets the gateway pods
      │
      ▼
 ┌─────────────────────────┐
 │POD: istio-ingressgateway│  ← Envoy alone in its own pod.
 │  ┌───────────────────┐  │    NO app container.
 │  │      Envoy        │  │    Sees only north-south traffic.
 │  └───────────────────┘  │    Enforces: JWT verify, rate
 └───────────┬─────────────┘    limit, strip+inject headers.
             │ mTLS
             ▼
 ┌─────────────────────────┐
 │POD: feed-svc            │  ← Envoy injected INTO the app pod.
 │  ┌────────┐  ┌─────────┐│    Shares pod network namespace;
 │  │ Envoy  │─►│   App   ││    iptables redirects all traffic
 │  │sidecar │  │container││    through it. Sees everything
 │  └────────┘  └─────────┘│    arriving at THIS service.
 └───────────┬─────────────┘    Enforces: who may call me.
             │ mTLS
             ▼
 ┌─────────────────────────┐
 │POD: user-svc            │
 │  ┌────────┐  ┌─────────┐│  ← east-west hop: gateway is not
 │  │ Envoy  │─►│   App   ││    involved at all. Only the
 │  │sidecar │  │container││    sidecars enforce here.
 │  └────────┘  └─────────┘│
 └─────────────────────────┘


WHO ENFORCES WHAT — the selector picks the proxy

   AuthorizationPolicy               enforced at        governs
   ───────────────────               ───────────        ───────
   selector: istio=ingressgateway →  gateway Envoy   →  north-south
   selector: app=feed-svc         →  feed sidecar    →  east-west
   no selector, in istio-system   →  ALL proxies     →  mesh-wide
                                                        default (deny-all)

Enforcement is always at the DESTINATION proxy, evaluated locally in
Envoy (microseconds). No per-request call to any central authz server.

Two independent key systems:
   JWT keys   = "which USER"     — private in KMS, public via JWKS,
                                   Envoy pulls + caches the public keys
   mTLS certs = "which WORKLOAD" — issued by istiod CA, auto-rotated,
                                   identity = SPIFFE service account

Both must be on for policy to mean anything:
   PeerAuthentication STRICT   → reject plaintext; every caller has a
                                 verified identity to match rules against
   AuthorizationPolicy         → allowlist per service, default deny
   RequestAuthentication       → validates a JWT IF PRESENT; alone it
                                 does NOT require one (anonymous passes
                                 through). Pair with an AuthorizationPolicy
                                 requiring requestPrincipals.

Distinct from k8s NetworkPolicy:
   NetworkPolicy       L3/L4, enforced by CNI (Calico/Cilium), pod
                       selectors + IPs + ports
   AuthorizationPolicy L7, enforced by Envoy, workload identity + HTTP
                       method/path + JWT claims
   Run both — NetworkPolicy is the floor that holds if a sidecar is
   bypassed.

Ambient mode (newer): sidecars replaced by a per-node ztunnel for mTLS
plus optional waypoint proxies for L7 policy. Gateways are unchanged.
```

---

## Reference — Observability Stack (Prometheus + OTel + Grafana)

Not tied to any scenario above.

```
THREE SIGNALS — three different stores. Do NOT mix them up.
   METRICS   numeric time series   → Prometheus / Mimir / AMP
   TRACES    request spans         → Tempo / Jaeger / X-Ray
   LOGS      text events           → Loki / OpenSearch / CloudWatch
   Prometheus stores METRICS ONLY. It cannot hold traces or logs.


TWO COLLECTION MODELS — both are usually present

   PULL — Prometheus                 PUSH — OpenTelemetry
   ┌────────────┐                    ┌────────────┐
   │    Pod     │                    │    Pod     │
   │  /metrics  │                    │  OTel SDK  │
   └─────▲──────┘                    └─────┬──────┘
         │ scrape every 15-30s             │ OTLP (gRPC/HTTP)
         │ targets found via k8s           │ exported every 60s
         │ service discovery               │
   ┌─────┴──────┐                    ┌─────▼──────────┐
   │ Prometheus │                    │ OTel Collector │
   └────────────┘                    └────────────────┘

   Pull knows what SHOULD exist, so a missing target = DOWN.
   Push cannot distinguish "silent/crashed" from "healthy but idle".
   Pull is also immune to load: scrape rate is fixed no matter how
   much traffic the app is taking.


FULL PIPELINE (one region)

 ┌─────────────────────────────────────────────────┐
 │ NODE                                            │
 │   ┌──────────┐   ┌──────────┐                   │
 │   │  Pod A   │   │  Pod B   │                   │
 │   │ OTel SDK │   │ OTel SDK │                   │
 │   │ /metrics │   │ /metrics │                   │
 │   └────┬─────┘   └────┬─────┘                   │
 │        │ OTLP         │ OTLP                    │
 │        │ to localhost │ (no network hop)        │
 │        └──────┬───────┘                         │
 │               ▼                                 │
 │      ┌──────────────────┐                       │
 │      │  OTel Collector  │  AGENT (DaemonSet)    │
 │      │  • batch         │  ONE PER NODE, not    │
 │      │  • add resource  │  one per pod          │
 │      │    labels (region│                       │
 │      │    cluster, pod) │                       │
 │      └────────┬─────────┘                       │
 └───────────────┼─────────────────────────────────┘
                 │ OTLP
                 ▼
   ┌───────────────────────────────────┐
   │           OTel Collector          │  GATEWAY (Deployment)
   │   • tail sampling                 │  • scaled separately
   │   • fan-out by signal             │  • ONLY tier holding
   │   • holds all backend credentials │    backend credentials
   └────▲─────────────┬─────────────┬──┘
        │             │             │
metrics │      traces │        logs │
SCRAPED │       OTLP  │       OTLP  │
 (pull) │      (push) ▼      (push) ▼
   ┌────┬─────┐  ┌────┬─────┐  ┌────┬─────┐
   │Prometheus│  │  Tempo   │  │   Loki   │
   │ or Mimir │  │ (Jaeger, │  │ (OpenS., │
   │  / AMP   │  │  X-Ray)  │  │   CW)    │
   └────┬─────┘  └────┬─────┘  └────┬─────┘
        │             │             │
        └─────────────┼─────────────┘
                      ▼
               ┌─────────────┐
               │   Grafana   │  queries all three, correlates by
               │             │  trace_id + timestamp: click a slow
               │             │  span → jump to that service's
               └──────┬──────┘  metrics and logs at that moment
                      │
                      ▼
               ┌─────────────┐
               │Alertmanager │  routing, grouping, dedup, silences
               │             │  → PagerDuty / Slack / email
               └─────────────┘
               (alert RULES are evaluated by Prometheus itself,
                Alertmanager only handles what to do with a firing
                alert — see #13 for the escalation ladder)

   NOTE THE ARROW DIRECTIONS. Traces and logs are PUSHED out of the
   Collector over OTLP. Metrics are not: Prometheus cannot receive a
   push. The Collector runs a `prometheus` exporter that serves its
   own /metrics endpoint, and Prometheus SCRAPES it like any other
   target — which is why that one arrow points back up.


WHY TWO COLLECTOR TIERS
   Agent   keeps the hot path node-local and cheap; no cross-node
           dependency, app just writes to localhost.
   Gateway one place to change routing/sampling/credentials without
           touching every node. REQUIRED for tail-based sampling —
           deciding to keep a trace AFTER seeing it was slow or
           errored only works if all spans for that trace land on
           the same collector.

WHY OTEL AT ALL
   One SDK and one pipeline for all three signals. Swapping a backend
   becomes a Collector config change instead of re-instrumenting every
   service. Auto-instrumentation agents hook common HTTP/DB libraries
   with no code changes.

GETTING METRICS INTO PROMETHEUS — three options
   1. Collector EXPOSES /metrics, Prometheus scrapes it (drawn above).
      Keeps the pull model and its "missing target = down" property.
   2. Collector PUSHES via the prometheusremotewrite exporter. The
      receiver is normally Mimir / Thanos Receive / AMP — vanilla
      Prometheus only accepts this with
      --web.enable-remote-write-receiver, which is off by default.
      This is the usual choice at scale, where the metrics store is
      not a single Prometheus anyway.
   3. Skip the Collector for metrics entirely. Instrument with the
      OTel SDK but let Prometheus scrape pods' /metrics directly,
      routing only traces and logs through the Collector. Common,
      because metrics have a mature pull ecosystem and traces do not.

   The Collector can also SCRAPE targets itself via its prometheus
   receiver and forward them onward — useful for pulling in exporters
   you do not control.

PER-REGION, NOT GLOBAL (see #26)
   Run the stack local to each region: monitoring must survive the
   region being isolated — a global stack that dies with the region
   is useless exactly when you need it. Federate upward (Thanos /
   Mimir / AMP) for the unified cross-region view. Also avoids
   shipping raw high-cardinality metrics across regions.

PUSHGATEWAY — the exception
   Short-lived batch jobs finish before any scrape could catch them,
   so they PUSH to a Pushgateway that Prometheus then scrapes. Use
   sparingly; it breaks the "missing target = down" property.
```

### Multi-Cluster / Multi-Region

Three levels. The collection tiers are identical in every cluster —
what changes going up is that the STORES become shared.

```
LEVEL 1 — CLUSTER   collection only. Nothing is shared at this level.

 ┌──────────────────────────────────────────────────────┐
 │ CLUSTER prod-a — repeat this block per cluster       │
 │                                                      │
 │   node 1            node 2            node 3         │
 │  ┌────────┐        ┌────────┐        ┌────────┐      │
 │  │  pods  │        │  pods  │        │  pods  │      │
 │  │ +agent │        │ +agent │        │ +agent │      │
 │  └───┬────┘        └───┬────┘        └───┬────┘      │
 │      └─────────────────┼─────────────────┘           │
 │                        ▼ OTLP to localhost           │
 │             ┌──────────────────────┐                 │
 │             │   OTel Collector     │                 │
 │             │   GATEWAY (cluster)  │                 │
 │             │   egress point       │                 │
 │             └──▲───────────────┬───┘                 │
 │                │               │                     │
 │        scrape  │               │ OTLP traces + logs  │
 │                │               │ (NO tail sampling — │
 │     ┌──────────┬──────────┐    │  sees only this     │
 │     │   Prometheus        │    │  cluster's spans)   │
 │     │   local, 24h        │    │                     │
 │     │   ext_labels:       │    │                     │
 │     │    cluster, region  │    │                     │
 │     └──────────┬──────────┘    │                     │
 │                │               │                     │
 └────────────────┼───────────────┼─────────────────────┘
                  │               │
                  │ remote_write  │ OTLP
                  ▼               ▼


LEVEL 2 — REGION   one observability cluster per region.
                   Repeat this whole block in every region.

     remote_write            OTLP traces + logs
     from every cluster      from every cluster
          │                            │
          ▼                            ▼
   ┌─────────────┐        ┌──────────────────────────┐
   │    Mimir    │        │     OTel Collector       │
   │  (metrics)  │        │  CENTRAL SAMPLING TIER   │
   │  long-term  │        │  • first tier to see a   │
   │    → S3     │        │    COMPLETE trace        │
   └──────┬──────┘        │  • tail sampling HERE    │
          │               │  • trace-ID-aware LB     │
          │               └──────┬────────────┬──────┘
          │                      │ traces     │ logs
          │                      ▼            ▼
          │                 ┌────┬────┐  ┌────┬────┐
          │                 │  Tempo  │  │  Loki   │
          │                 │  → S3   │  │  → S3   │
          │                 └────┬────┘  └────┬────┘
          │                      │            │
          └─────────────┬────────┴────────────┘
                        ▼
                ┌───────┬───────┐
                │ Grafana (rgn) │  still works when the
                └───────┬───────┘  global tier is down
                        ▼
                ┌───────────────┐
                │ Alertmanager  │  regional paging (see #13)
                └───────────────┘


LEVEL 3 — GLOBAL   READ PATH ONLY. Nothing ingests here.

    us-east-1           eu-west-1         ap-south-1
  ┌────────────┐     ┌────────────┐     ┌────────────┐
  │  regional  │     │  regional  │     │  regional  │
  │   stack    │     │   stack    │     │   stack    │
  └──────┬─────┘     └──────┬─────┘     └──────┬─────┘
         └──────────────────┼──────────────────┘
                            ▼  query fan-out (reads)
                ┌───────────────────────┐
                │  Thanos Query /       │
                │  Mimir global query   │
                └───────────┬───────────┘
                            ▼
                ┌───────────────────────┐
                │    GLOBAL GRAFANA     │
                └───────────────────────┘


WHERE EACH COMPONENT LIVES — and why

   OTel Collector   EVERY LEVEL. It is transport, not a store.
                    agent per node → gateway per cluster →
                    sampling tier per region.

   Prometheus       PER CLUSTER. Pull needs network reachability to
                    every pod. Scraping cluster B from cluster A
                    means routable pod IPs across clusters, cross-AZ
                    egress bills, and monitoring that dies exactly
                    when the network partitions.

   Tempo            PER REGION, SHARED BY ALL CLUSTERS IN IT. A
                    request crossing clusters via the east-west
                    gateway makes ONE trace with spans in both. Split
                    the backend and you get two useless halves.

   Loki             PER REGION. Not forced like traces, but you do
                    not want to guess which cluster to search mid-
                    incident.

   Grafana          Per region AND one global. The regional one is
                    what you use during an outage.

TAIL SAMPLING MOVES UP A LEVEL
   A cluster gateway cannot decide whether to keep a trace: it never
   sees the spans that happened in the other cluster. So cluster
   gateways do batching and enrichment ONLY and forward everything;
   the regional collector runs the sampling processor. Put a
   `loadbalancing` exporter keyed on trace ID in front of it so all
   spans of a trace reach the same replica.

SCRAPE POD IPs, NOT THE SERVICE VIP
   The gateway is a multi-replica Deployment and each replica only
   exposes the metrics that flowed through IT. Scraping through the
   Service load balancer returns a random subset each time. Use
   service discovery on the pods.

LABEL EVERYTHING OR SERIES COLLIDE
   Set cluster / region / env as Prometheus external_labels AND as
   OTel resource attributes at the agent tier. Without them
   http_requests_total{pod="api-7f9"} from two clusters merges into
   nonsense. Budget for it: the cluster label multiplies series count.

THE GLOBAL TIER MUST NOT BE ON THE INGEST PATH
   It only fans queries out to regional stores. If regions shipped
   raw samples to a global store, you would pay cross-region egress
   on every sample and lose all monitoring whenever the global tier
   or a single inter-region link went down.
```

---

## Reference — Auth Service (JWT Issuance vs Verification)

Not tied to any scenario above. The single idea: **ISSUANCE and
VERIFICATION are different jobs, done by different components, at
wildly different rates.**

```
ISSUANCE — once per session. Low volume. NOT on the hot path.

   ┌────────┐  1. POST /login   ┌───────────────┐  2. Sign  ┌──────────┐
   │ Client │──────────────────►│ Auth Service  │──────────►│   KMS    │
   │        │◄──────────────────│               │◄──────────│ private  │
   └────────┘  4. JWT +         └───────┬───────┘  3. sig   │key never │
               refresh token            │                   │  leaves  │
                                        │ exposes           └──────────┘
                                        ▼
                           ┌──────────────────────────┐
                           │ /.well-known/            │
                           │   jwks.json              │  PUBLIC keys
                           │  (public keys + kid)     │  only — safe
                           └──────────────────────────┘  to expose
                                        ▲
                                        │ GET at startup, then periodic
                                        │ refresh. The VERIFIER PULLS.
                                        │ Nothing is pushed to it.
                                 (enforcement point, below)

   Auth Service owns: password check, MFA, OAuth/OIDC flows, refresh
   tokens, revocation list, the user database. All the stateful parts.


VERIFICATION — every request. High volume. Pick exactly ONE point.

   ┌────────┐
   │ Client │  Authorization: Bearer eyJ...   (or HttpOnly cookie)
   └───┬────┘
       ▼
   ╔═══════════════════════════════════════════════════╗
   ║  ENFORCEMENT POINT — choose ONE:                  ║
   ║    • CDN edge function   CloudFront Fn / L@E      ║
   ║    • Managed API gateway AWS APIGW / Kong / Apigee║
   ║    • LB native OIDC      ALB + Cognito            ║
   ║    • Envoy               mesh gateway or sidecar  ║
   ║    • Reverse proxy       nginx / oauth2-proxy     ║
   ║    • BFF                 your own edge service    ║
   ║    • In-service library  N copies, they DRIFT     ║
   ║                                                   ║
   ║  What it does, per request:                       ║
   ║   1. read token from header or cookie             ║
   ║   2. verify signature with the CACHED public key  ║
   ║      → ZERO calls to the Auth Service             ║
   ║   3. check exp / iss / aud                        ║
   ║   4. STRIP any client-supplied identity headers   ║
   ║   5. INJECT trusted x-user-id, x-roles            ║
   ╚═════════════════════┬═════════════════════════════╝
                         │ mTLS (proves WHICH workload
                         │        forwarded this)
                         ▼
              ┌─────────────────────┐
              │  Backend services   │  They trust x-user-id ONLY
              │  (read x-user-id,   │  because they are unreachable
              │   skip verifying)   │  except through the enforcement
              └─────────────────────┘  point. Lock that down or the
                                       whole scheme is theater.


WHY THE AUTH SERVICE DOES NOT VERIFY
   That would be a network call on EVERY request — turning your auth
   service into a latency tax and a single point of failure for the
   entire system. Asymmetric signing exists precisely so verification
   needs no contact with the issuer.

STRIPPING MATTERS AS MUCH AS INJECTING
   If the enforcement point does not DELETE a client-supplied
   x-user-id before adding its own, an attacker just sets the header
   themselves and impersonates anyone — because downstream trusts it
   blindly.

DO NOT STACK ENFORCEMENT POINTS
   Three layers all verifying independently is how configs drift: one
   gets updated for a new issuer, the others do not, and behavior now
   depends on which path a request took.

TWO INDEPENDENT KEY SYSTEMS (they answer different questions)
                   JWT keys                mTLS certs
   answers         which USER              which WORKLOAD
   issued by       your auth service       istiod / internal CA
   distributed     JWKS, verifier pulls    pushed to proxies (xDS)
   identity        sub: user_123           spiffe://.../sa/feed-svc
   rotation        you rotate + republish  automatic (~24h)
   A single request carries BOTH: the client cert proves the calling
   pod, the Authorization header proves the end user.

TOKEN TYPES — pick per use case
   JWT (signed, self-contained)
     + verify locally, no lookup, no shared state, scales flat
     + carries claims (roles, tenant, region) to every service
     + built-in expiry: a leaked token dies on its own
     - revocation is HARD; valid until exp. Keep TTL short.
     - readable by anyone (base64, NOT encrypted) — no secrets in it
     → user auth

   Opaque token (random string + introspection endpoint)
     + instantly revocable
     - requires a lookup per request (cache it)
     → when revocation matters more than scale

   API key (long-lived opaque secret)
     + dead simple, instantly revocable
     - stateful lookup, no expiry, no claims
     → machine-to-machine, public APIs (Stripe/GitHub style)

   mTLS client cert
     + no bearer secret to steal; identity is cryptographic
     - PKI to operate
     → service-to-service inside the mesh

   Split by identity type: USERS get JWTs, WORKLOADS get certs.
   Neither displaced the other.

AUTHENTICATION vs AUTHORIZATION — different layers
   "is this token valid?"            → Envoy JWT filter / gateway
   "can service A call service B?"   → mesh AuthorizationPolicy
   "can user X do Y to resource Z?"  → ext_authz → OPA, a Zanzibar-
                                       style service (SpiceDB /
                                       OpenFGA), or your app
   That last row needs your domain model. It does NOT belong in mesh
   config — this is the boundary people get wrong.

REVOCATION — the JWT weak spot, three options
   - Short TTL (5-15 min) + refresh tokens. Revoke the refresh token;
     the access token dies on its own shortly after. Most common.
   - Denylist of revoked jti in Redis, checked at the enforcement
     point. Reintroduces a lookup, but only one, and it is local.
   - Switch to opaque tokens when instant revocation is a hard
     requirement (finance, healthcare).

STORAGE ON THE CLIENT
   HttpOnly + Secure + SameSite cookie, so JavaScript cannot read it
   and XSS cannot exfiltrate it. localStorage is convenient and is
   how tokens get stolen. Cookies are also sent automatically on
   top-level navigation, which is required when the check happens at
   a CDN edge before any of your code runs (see #12).
```

