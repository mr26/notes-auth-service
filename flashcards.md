# Systems Design Flashcards

---

## 1. Networking & Communication

**What does DNS do and why does TTL matter for migrations?**

DNS translates domain names to IP addresses. TTL controls how long DNS results are cached — set TTL low before a migration so clients pick up the new IP quickly, then increase it after.

---

**Name the 5 Route 53 routing policies and when to use each.**

Simple (one IP), Weighted (canary/traffic splitting), Latency-based (nearest region), Failover (primary/secondary), Geolocation (compliance/regulatory routing).

---

**Unicast vs Anycast — what's the difference?**

Unicast: one IP, one destination. Anycast: one IP, many destinations, request goes to the nearest one. Anycast is how Global Accelerator and CDNs work.

---

**ALB vs NLB — when to use each?**

ALB (Layer 7): HTTP routing, path/host-based routing, web apps, REST APIs. NLB (Layer 4): TCP/UDP, gRPC, gaming, IoT. ALB inspects HTTP content, NLB doesn't.

---

**What is GraphQL and when would you use it over REST?**

Client specifies exactly which fields it wants — no over-fetching (getting 20 fields when you need 3) or under-fetching (needing 3 REST calls to build one screen). Single endpoint, one round trip for nested data. Use when multiple frontends (web, mobile, tablet) need different data shapes from the same API. Don't default to it — REST is simpler and right for most systems. Only use GraphQL when you can explain why (e.g., "three frontends each need different subsets of the same data").

---

**REST vs GraphQL vs gRPC — when to use each?**

REST: public/external APIs, simple CRUD — the default choice. GraphQL: multiple frontends needing different data shapes, mobile apps with bandwidth constraints. gRPC: internal service-to-service when you need performance — binary over HTTP/2, strongly typed, supports streaming.

---

**WebSocket vs SSE vs WebRTC — when to use each?**

WebSocket: bidirectional real-time messages (chat, collaboration). SSE: server-to-client only (dashboards, live feeds). WebRTC: real-time audio/video (video calls). WebRTC has built-in adaptive bitrate.

---

**What are pre-signed URLs and when do you use them?**

Temporary URLs with a cryptographic signature that grant scoped access to private resources. The URL is the credential — it expires. Use for private file access without making resources public (healthcare, finance).

---

**S3 pre-signed URL vs CloudFront signed URL?**

Same security model. S3 pre-signed serves from S3 directly (simple, single region). CloudFront signed serves from the nearest edge (cached, faster for large/frequent files).

---

**What are S3 byte-range requests?**

Fetch specific portions of a file instead of the whole thing. Use for large files where you can start processing partial data — medical image previews, video seeking, resuming downloads.

---

**What is S3 multipart upload and when do you use it?**

Splits a large file into chunks and uploads them independently. If a chunk fails (connection drop, timeout), only that chunk is re-uploaded — not the whole file. Combine with pre-signed URLs so the client uploads directly to S3 in chunks without going through your API server. Use for any upload over ~100MB — video uploads, large file attachments, dataset imports.

---

**Offset vs cursor pagination — when to use each?**

Offset: skip N rows, give me 10. Simple but degrades at deep pages. Use for small data, admin UIs. Cursor: give me 10 after this marker. Constant performance at any depth. Use for feeds, timelines, large datasets.

---

**When do you need an API Gateway vs just a Load Balancer?**

Multiple services behind one domain → API Gateway (routing, auth, rate limiting centralized). One service with multiple endpoints → Load Balancer only.

---

**What is a service mesh and when do you need one?**

Infrastructure layer (sidecar proxies) managing service-to-service communication — mTLS, retries, timeouts, observability, access control. Need one when 15+ microservices and managing networking per-service is unsustainable.

---

**What is mTLS?**

Mutual TLS — both client and server verify each other's identity. Zero-trust networking for microservices. The mesh CA issues and rotates certificates automatically.

---

## 2. Data Storage

**What does ACID stand for?**

Atomicity (all or nothing), Consistency (valid state to valid state), Isolation (concurrent transactions don't interfere), Durability (committed data survives crashes).

---

**SQL vs NoSQL — quick decision?**

SQL: relationships, transactions, complex queries, fixed schema. NoSQL: flexible schema, massive scale, simple access patterns (key-based lookups), high write throughput.

---

**Name 4 types of NoSQL databases and when to use each.**

Document (MongoDB, DynamoDB): flexible schema, profiles, catalogs. Key-value (Redis): caching, sessions, leaderboards. Wide-column (Cassandra): time-series, IoT, massive writes. Graph (Neo4j): social networks, fraud detection.

---

**What is Elasticsearch and when do you use it?**

A search engine built for full-text search. Uses inverted indexes — like a book's index, maps every word to the documents containing it. Instant lookup regardless of dataset size. Handles fuzzy matching (typos), relevance ranking, tokenization, and autocomplete — things SQL can't do well. General principle: whenever your system needs user-facing search (search bars, filtering, autocomplete), use Elasticsearch. Don't use PostgreSQL `LIKE '%term%'` — it can't use indexes, doesn't rank results, and gets slower as data grows. Write to PostgreSQL (source of truth), async sync to Elasticsearch (search reads). That's CQRS.

---

**Redis sorted sets — when to use?**

Whenever you hear "ranking," "top N," or "real-time sorted data." Always sorted, O(log n) updates, O(k) to get top K. Don't use a database with ORDER BY.

---

**What is Redis Pub/Sub and when do you use it?**

Redis has a built-in publish/subscribe system. A client publishes a message to a channel, all subscribers receive it instantly. Use for real-time message relay between servers — e.g., WebSocket servers in a chat app. User A on Server 1 sends a message, Server 1 publishes to Redis Pub/Sub, Server 3 is subscribed and pushes it to User B. Fire-and-forget — no persistence, no replay. If a subscriber is down, it misses the message. For durable streaming with replay, use Kafka instead.

---

**Redis geospatial indexing — when to use?**

Whenever you hear "find nearby X" — drivers, restaurants, stores, friends. GEORADIUS returns all members within X km. Sub-millisecond. Never brute-force distance calculation in application code.

---

**Three replication modes — when to use each?**

Single primary (default, consistency matters), Multi-primary (fast writes in multiple regions, must handle conflicts), Leaderless (massive scale, eventual consistency acceptable).

---

**Sync vs async replication — when to use each?**

Sync: critical data you can't lose AND replica is nearby (same region). Async: everything else — cross-region replicas, high write throughput, tolerant of small loss window. Standard: one sync replica nearby + async replicas for read scaling.

---

**Three consistency patterns?**

Eventual (replicas converge eventually, OK for feeds/catalogs), Read-after-write (user sees their own write immediately), Strong (every read returns latest write, for payments/inventory).

---

**What is consistent hashing?**

Map servers and keys onto a ring. Adding a server only moves keys between the new server and its neighbor. Minimizes data movement during resharding vs hash % N which redistributes everything.

---

**When to shard?**

Last resort. Order: optimize queries → indexes → vertical scale → read replicas → caching → THEN shard. Shard when writes exceed single primary capacity or data exceeds single machine.

---

**Name 4 cache strategies.**

Cache-aside (check cache, miss → query DB, populate cache). Write-through (write to cache AND DB simultaneously). Write-behind (write to cache, async flush to DB). Read-through (cache queries DB on miss, not the app).

---

**What is write-through caching and when to use it?**

Write to cache AND database simultaneously on every update. Cache is always fresh. Use when stale cache causes real problems (menu prices, inventory). The write goes "through" both layers.

---

**TTL as safety net — what's the principle?**

Always set TTL even with write-through or invalidation. If any cache update mechanism fails, stale data self-destructs after TTL expires. Last line of defense against serving stale data forever.

---

**What is cache stampede?**

A popular cache key expires and thousands of requests all miss cache at the same time, all hitting the DB simultaneously. Fix: locking — first request acquires a lock, queries DB, populates cache. Others wait for the lock then read from cache.

---

**What is cache penetration?**

Repeated requests for data that doesn't exist in the DB. Every request misses cache AND misses DB. Fix: cache the "not found" result with a short TTL, or use a Bloom filter.

---

**What is a Bloom filter?**

A space-efficient data structure that answers "is this item in the set?" with either "definitely no" or "probably yes." Check it before hitting the DB — if the Bloom filter says the key doesn't exist, skip the DB entirely. Small false positive rate, but zero false negatives. Use to block cache penetration from non-existent keys.

---

**What is cache avalanche?**

Many cache keys expire at the same time, causing a massive spike in DB traffic. Fix: add random jitter to TTL values so expirations are spread out.

---

**What is the hot key problem?**

One cache key gets disproportionate traffic (celebrity profile, viral post). Single cache node becomes a bottleneck. Fix: replicate hot keys across multiple cache nodes, or use local in-memory cache.

---

**Name the 4 cache problems and their fixes.**

Stampede (lock so only one request hits DB). Penetration (cache "not found" with short TTL). Avalanche (jitter on TTLs). Hot key (replicate across nodes or local in-memory cache).

---

**Indexes — what's the trade-off?**

Speed up reads, slow down writes. Every insert/update must update every index. Too many indexes = slow writes. Only index columns you query on (WHERE, JOIN, ORDER BY).

---

**Database scaling order (priority)?**

1. Indexes (free), 2. Caching (high impact), 3. Read replicas, 4. Vertical scale, 5. Connection pooling (RDS Proxy), 6. Shard (last resort).

---

**What is a database proxy (PgBouncer / ProxySQL / RDS Proxy) and when do you use one?**

A lightweight process that sits between your app and database, speaking the database's wire protocol — your app thinks it's talking directly to PostgreSQL. It does three things: (1) Connection pooling — 1,000 app connections map to ~50 actual DB connections, preventing connection exhaustion (PostgreSQL struggles past a few hundred). Critical for serverless/Lambda workloads. (2) Read/write splitting — parses queries and routes SELECTs to replicas, writes to primary. Your app uses one connection string per shard instead of managing separate read/write strings. (3) Failover handling — detects primary failure and reroutes to the newly promoted replica. Self-managed: run PgBouncer/ProxySQL as a sidecar container or standalone deployment in Kubernetes. Managed: AWS RDS Proxy does the same thing without you running the pod. Use when: you have many app instances connecting to a database (connection exhaustion risk), you want automatic read/write splitting, or you need transparent failover.

---

**CAP theorem — what's the real choice?**

P is mandatory (networks fail). Real choice: CP (consistency over availability during partition — payments, inventory) or AP (availability over consistency — feeds, catalogs, analytics).

---

**Browse vs Commit pattern?**

When a user is just browsing (viewing products, scrolling feeds), serve from cache/replicas — fast but possibly slightly stale. When a user takes action (places order, transfers money), check the primary DB for real-time accuracy. To decide which phase data belongs to, ask: "if this is 30 seconds stale, does anything bad happen?" No → cache it. Yes → read from primary at the moment of action.

---

## 3. Scaling

**Horizontal vs vertical scaling — quick decision by tier?**

Web/API: horizontal (stateless, easy). DB reads: read replicas + caching. DB writes: vertical first, then shard. Cache: bigger instance, then cluster mode.

---

**Stateless vs stateful — the rule?**

Make application tier stateless. Push all state to dedicated stateful services (databases, caches, queues). Stateless services scale trivially.

---

**Token bucket rate limiting — what is it, how does it work, and what is it used for?**

Bucket holds N tokens, refills at rate R/sec. Each request consumes one token. Empty = rejected (429). Allows short bursts while enforcing average rate. Used to protect services from abuse, brute-force attacks, and overload. Applied at the API gateway for external traffic, service mesh for internal traffic. AWS API Gateway, NGINX, and Istio use it under the hood.

---

## 4. Reliability & Availability

**What is N+1 AZ redundancy?**

N = number of AZs you need to run your app, +1 = one extra for redundancy. Each AZ must handle full production load on its own. If you need 4 pods at peak, run 4 per AZ, not 2 and 2. HPA can't save you from sudden AZ loss (30-60s reaction time). Most apps need 1 AZ, so 2 total is the common case. If one AZ can't fit your full workload, N=2 and you'd run 3 AZs.

---

**Three Kubernetes health probes?**

Liveness (is it alive? restart if not), Readiness (can it take traffic? remove from service if not), Startup (has it finished starting? protect slow starters).

---

**Circuit breaker — three states?**

Closed (normal, counting failures), Open (tripped, all requests fail fast with fallback), Half-open (testing, one request allowed through to check recovery).

---

**Timeout, Retry, Circuit Breaker, Idempotency — what does each handle?**

Timeout: single request hanging. Retries: momentary blips. Circuit breaker: sustained outages. Idempotency: makes retries safe (same request processed twice produces the same result).

---

**Hot path vs background — when to retry vs fall back?**

Hot path = user is staring at a loading spinner (e.g., placing an order). If a downstream call fails, don't retry — immediately fall back to a cached or default value. User doesn't notice. Background = no user waiting (e.g., payment job from SQS). Retries with exponential backoff are fine because nobody is blocked. Rule: loading spinner → fall back. Background job → retry.

---

**Four deployment strategies — when to use each?**

Rolling (routine, compatible changes). Canary (default for high-risk — route 5% to new version, monitor, increase gradually. Use when old and new versions can coexist). Blue-green (clean cutover — all traffic switches at once. Use when old and new versions CANNOT coexist, e.g., regulatory/pricing changes that must apply to all users simultaneously. Instant rollback by switching back). A/B testing (product experimentation, business metrics — not a safety strategy).

---

**Expand and contract pattern?**

When changing something that other things depend on (DB schema, API format, event schema), never swap old for new in one step — that breaks rollback. Instead: 1. Expand — add the new thing alongside the old. Both work. (e.g., add new DB column, old code ignores it). 2. Migrate — move consumers to the new thing one by one. (e.g., deploy new code that uses the new column). 3. Contract — remove the old thing once nothing uses it. (e.g., drop old column weeks later). At every step, rollback is safe because the old thing still exists until the very end.

---

**Expand and contract — give an example of why you can't deploy code and schema changes at the same time.**

You need to add a tax_rate column. If you deploy the new schema AND new code together and the code has a bug, you rollback the code — but now the old code is running against a schema it doesn't understand (it doesn't know tax_rate exists). Instead: 1. Add tax_rate column first — old code still runs fine, ignores the new column. 2. Deploy new code that uses tax_rate — if it breaks, rollback to old code, which still works because it just ignores the extra column. Each change is independent and rollback-safe.

---

**Zero-downtime data migration steps?**

1. Create new table. 2. Dual-write to old + new. 3. Copy old data to new table in batches. 4. Verify data matches. 5. Switch reads to new table (rollback = switch back). 6. Stop writing to old table. 7. Drop old table weeks later.

---

**Shadow traffic / dark launching — what is it and when would you use it?**

Send a copy of real production requests to a new service in the background. Compare its responses to the old service's responses, but only return the old service's response to the user — they're never affected. Use when replacing a critical service (e.g., extracting a microservice from a monolith) and you need high confidence the new service behaves identically before routing any real users to it.

---

## 5. Security

**Authentication vs Authorization?**

AuthN: who are you? (password, MFA, biometric). AuthZ: what can you do? (permissions, roles). AuthN always comes first.

---

**Session-based vs token-based auth?**

Session: server stores state, hard to scale. Token (JWT): stateless, server validates signature, any server can verify. Token-based is the modern standard.

---

**Refresh token pattern?**

Short-lived access token (15 min) + long-lived refresh token (7 days). Access token for API calls (stateless). Refresh token to get new access tokens (revocable server-side). Short exposure + instant revocation.

---

**HS256 (symmetric) vs RS256 (asymmetric) for JWTs?**

Two ways to sign JWTs. HS256 (symmetric): one secret key signs AND verifies. Every service that checks tokens needs the same secret — more copies = more leak risk. Fine for a monolith. RS256 (asymmetric): auth server signs with a private key, all other services verify with the public key. Public key can't forge tokens, only verify them. Better for microservices — only the auth server has the secret, everyone else just has the public key.

---

**Envelope encryption — what is it and how does it work?**

Ask KMS for a data key. KMS returns a plaintext key + an encrypted copy of the same key. Use the plaintext key to encrypt your records locally. Store the encrypted key + encrypted records in the DB. Delete the plaintext key from memory. To decrypt: send the encrypted key back to KMS, KMS decrypts it with its master key, use the returned plaintext key to decrypt the records.

---

**Envelope encryption — why, where, and when would you use it?**

Why: KMS has rate limits (~5,000-10,000 req/sec). Without envelope encryption, you'd call KMS per record and bottleneck. With it, you call KMS once and encrypt thousands locally. Also prevents DBAs from reading sensitive data — the app's IAM role can call KMS, the DBA's cannot. Where/when: encrypting sensitive DB fields at the application layer (healthcare, fintech), encrypting files before storing in S3, any bulk encryption where data should be unreadable even to database administrators.

---

**What is OAuth 2.0?**

An authorization framework that lets third-party apps access user resources without getting the user's password. The app redirects the user to the identity provider (Google, Okta), the user logs in there, the IdP gives the app an access token scoped to specific permissions (e.g., read photos only). The app then uses that token to call APIs on the user's behalf — the API verifies the token and serves the data. The app never sees the user's password. OAuth answers: "is this app allowed to access this user's stuff?" It does NOT tell the app who the user is.

---

**What is OIDC (OpenID Connect)?**

An identity layer built on top of OAuth 2.0. OAuth alone gives the app an access token to call APIs — but the app doesn't know who the user is. It can access your photos but can't display "Welcome back, John" or tie data to your account. OIDC adds an ID token (a JWT) containing the user's identity — name, email, user ID. Now the app can create accounts, personalize the experience, and associate data with a specific person. OAuth = "let me in to grab the photos." OIDC = "and here's who I am." Use OAuth alone for machine-to-machine (no human identity needed). Use OAuth + OIDC when a human is involved and you need to know who they are.

---

**Secret management — the rule?**

Never hardcode. Use secret stores (Secrets Manager, Vault). External Secrets Operator syncs to K8s. Rotate automatically. Least privilege per service.

---

## 6. Observability

**Three pillars of observability?**

Metrics (what's happening — dashboards, alerting). Traces (where is it slow — follow a request across services). Logs (why it broke — specific error details).

---

**Four golden signals?**

Latency (how long requests take, use percentiles not averages), Traffic (requests/sec), Errors (failure rate), Saturation (how full — CPU, memory, connections).

---

**What do p50, p95, p99 mean?**

p50 = 50% of requests are faster than this value (the median, typical user experience). p95 = 95% are faster, only 5% are slower. p99 = 99% are faster, 1% are slower. Compare them to find outliers — if p50 is 50ms but p99 is 10s, a subset of users is having a terrible experience. The bigger the gap between p50 and p99, the more inconsistent your system is. Most teams monitor p50, p95, p99, and max.

---

**Why percentiles over averages for latency?**

Averages hide outliers. If 99 requests take 50ms but 1 takes 10 seconds, the average is 150ms — looks fine on a dashboard. But 1 in 100 users is waiting 10 seconds. At scale, 1% is a lot — 10 million daily users means 100,000 people having a terrible experience. Percentiles expose this: p50 (median) shows the typical experience, p95 shows what most users see, p99 shows the worst-case. Use p99 to catch problems that averages would hide.

---

**Alerting best practice?**

Alert on symptoms, not causes ("error rate > 5%" not "CPU > 80%"). Every alert must be actionable. Avoid alert fatigue.

---

**Troubleshooting triage order?**

1. Metrics (what's wrong), 2. Traces (where in the chain), 3. Logs (why), 4. Infrastructure state (is the platform the cause).

---

## 7. Message Queues & Async Processing

**What do queues actually do?**

Decouple services, enable async processing, and buffer traffic spikes. Buffering means the queue absorbs bursts — if a spike sends 10x normal traffic, requests pile up in the queue instead of overwhelming your service. Your service keeps processing at its own pace. Queues do NOT make consumers faster — they prevent them from being crushed. To actually increase throughput, scale the consumers.

---

**SQS visibility timeout — how does it work?**

Consumer picks up message → message invisible for timeout period. Success → consumer deletes it. Failure → timeout expires → message reappears → SQS redelivers. After max receive count → moves to DLQ.

---

**Standard SQS vs SQS FIFO?**

Standard: best-effort ordering, unlimited throughput. FIFO: strict ordering within message group, exactly-once, 3,000 msg/sec with batching. Use FIFO for state transitions that must be processed in order.

---

**Queue vs Pub/Sub?**

Queue (SQS): one consumer per message, deleted after processing. Pub/Sub (SNS, Kafka): every subscriber gets a copy. Use queue for task processing, pub/sub for event broadcasting.

---

**Kafka vs SQS — when to use which?**

SQS: one producer, one consumer, process-and-delete. Kafka: high volume, multiple independent consumers need the same stream, event replay needed. Kafka is a persistent event log, not a queue.

---

**What is Kafka?**

An event streaming platform. Events are appended to a persistent log and stay for a configurable retention period. Multiple consumers read the same log independently at their own pace. Messages aren't "consumed" — they're read.

---

**S3 + Athena vs Redshift?**

S3 + Athena: serverless, cheap storage, pay per query, best for massive volume with infrequent queries. Redshift: always-on cluster, faster for complex recurring queries, best for BI dashboards needing sub-second response.

---

**What is Kinesis Firehose?**

A managed delivery truck for streaming data. Kafka gives you the stream, but you still need to get that data somewhere (S3, Redshift). Without Firehose, you'd write a custom Kafka consumer to batch events, convert to Parquet, and write to S3 — then deploy and monitor it. Firehose does all of that automatically. Zero code, zero infrastructure. Kafka = the stream. Firehose = the delivery truck that lands stream data into storage for archival/analytics.

---

**Event sourcing — what is it and why use it?**

Instead of storing current state (balance = $800), store every event that happened (opened account, deposited $1000, withdrew $200). Current state is calculated by replaying events. Why: full audit trail (know exactly how you got to $800), time travel (reconstruct state at any past timestamp), bug recovery (fix logic and replay events to rebuild correct state). Trade-off: more complex, more storage, need snapshots to avoid replaying from the beginning every read. Use for banking, finance, healthcare — anywhere "how did we get here" matters as much as "where are we now."

---

**Event Sourcing Snapshots — how do you avoid replaying millions of events?**

Periodically save a full snapshot of the current state (e.g., every 100 operations or every hour). To reconstruct state at any point in time: (1) load the nearest snapshot before the target timestamp, (2) replay only the operations between that snapshot and the target time. Example: a collaborative document has 50,000 operations over a month. Snapshots every 100 ops. User requests the version from 3 days ago — load the nearest snapshot (a full copy of the document), replay ~40 operations on top of it. Without snapshots you'd replay all 50,000 from the beginning. Each snapshot is standalone — you only need one snapshot plus the small operation gap. Same concept as EBS snapshots, Redis RDB saves, or video game save points. Use anywhere you have an event/operation log: collaborative editors, financial ledgers, audit systems.

---

**Saga pattern — what is it?**

Chain of local transactions across services with compensating undos. If step 3 fails, undo step 2, undo step 1. Use for multi-service workflows (checkout, booking).

---

**CQRS (Command Query Responsibility Segregation) — what is it?**

Separate read and write databases. Write to PostgreSQL (optimized for writes), read from Elasticsearch or a denormalized read store (optimized for reads). Use when read/write patterns are fundamentally different.

---

## 8. Content Delivery & Storage

**What is a CDN and when to use one?**

Geographically distributed cache servers serving content from nearest location. Use for static assets (images, CSS, JS), geographically distributed users, reducing origin load, DDoS protection.

---

**What is AWS Global Accelerator?**

Gives you two static anycast IPs (two for redundancy). Point your DNS at them. When a user hits one, traffic enters the AWS private backbone at the nearest edge location and gets routed over AWS's private network to your ALB/NLB — instead of traversing the public internet with unpredictable hops. Benefits: lower and more consistent latency, instant failover if a region goes down (BGP reroutes automatically, no DNS TTL wait). Costs extra — it's a performance tool, not a cost tool.

---

**Global Accelerator vs CloudFront?**

CloudFront: CDN, caches content, runs edge functions. For HTTP, caching, edge logic. Global Accelerator: network router, no caching, no code. For any TCP/UDP, consistent latency, instant failover.

---

**CloudFront Functions vs Lambda@Edge?**

CloudFront Functions: sub-ms, lightweight JS, can't make network calls. For URL rewrites, header manipulation, simple routing. Lambda@Edge: full runtime, CAN make network calls. For DB lookups, auth at edge, complex logic.

---

**Redis vs CloudFront for caching — what goes where?**

Redis: data (query results, sessions, JSON, counters — small, structured). CloudFront: files (images, PDFs, videos, CSS/JS — static assets). Redis is memory. CloudFront is edge disk.

---

**Account-origin routing — what is it and when do you need it?**

Problem: EU regulations require EU user data stays in the EU. A US user traveling to Europe would get routed to the EU cluster by geolocation routing — but their data lives in the US. Wrong region. Solution: route based on where the user's account belongs, not where they physically are. The user's JWT contains a claim like `region: us-east-1`. A CloudFront edge function reads that claim and routes to the correct region's ALB. Use when data residency/compliance requires requests to go where the data lives, not where the user is.

---

## 9. Estimation

**Key latency numbers to know?**

Memory read: 100ns. SSD read: 100μs. Network round trip (same DC): 0.5ms. HDD seek: 10ms. Cross-country round trip: 30-40ms. Cross-ocean: 70-80ms.

---

## 10. Kubernetes

**Deployment vs StatefulSet vs DaemonSet?**

Deployment: stateless workloads (APIs, web apps). StatefulSet: stateful workloads with stable identity and persistent storage (databases, Kafka). DaemonSet: one pod per node (log collectors, monitoring agents).

---

**ClusterIP vs NodePort vs LoadBalancer service?**

ClusterIP: internal only (default). NodePort: static port on every node (rarely used). LoadBalancer: provisions cloud LB for external traffic.

---

**When to use Ingress?**

When multiple services need external HTTP access through one LB. The Ingress resource defines routing rules (path/host → service). The Ingress controller (NGINX, AWS ALB) reads those rules, provisions a cloud LB, and routes traffic. Flow: User → Cloud LB → Ingress Controller → ClusterIP Service → Pods. Centralizes TLS termination, path-based routing (/api → API service, /web → frontend), and host-based routing — all through one LB instead of one per service. One service → just use LoadBalancer service. Internal only → ClusterIP.

---

**HPA vs VPA vs Cluster Autoscaler?**

HPA: scales pod count based on metrics. VPA: adjusts pod resource requests/limits (requires restart). Cluster Autoscaler: adds/removes nodes when pods can't be scheduled.

---

**HPA defaults to CPU only — why does this matter?**

Pods can get OOM-killed (Out Of Memory killed — Kubernetes kills the pod for exceeding its memory limit) while HPA does nothing because CPU is fine. HPA only watches CPU by default, so it thinks everything is healthy. Add memory as an HPA metric when memory usage correlates with traffic — more pods spread the load and each pod uses less memory. Don't scale on memory for leaks (adding pods just gives you more leaking pods — masks the bug instead of fixing it).

---

**Resource requests vs limits?**

Requests: guaranteed minimum, scheduler uses for placement. Limits: hard ceiling, OOM-killed if exceeded (memory), throttled (CPU). Set both. Over-requesting wastes capacity. Under-limiting causes noisy neighbors.

---

**What is a Pod Disruption Budget (PDB)?**

"At least 3 of 5 pods must be running at all times." During a node drain, Kubernetes kills one pod, waits for its replacement to be healthy on another node, then kills the next — never dropping below the PDB minimum at any point. Without a PDB, Kubernetes evicts all pods on the node at once, causing a gap in availability until replacements spin up. Why it matters: routine operations like node upgrades, maintenance, or spot instance reclaims can take your app down without a PDB. With one, your app stays up throughout — users never notice.

---

**NetworkPolicies — what are they?**

Firewall rules at the pod level. By default all pods can talk to all pods. NetworkPolicies restrict that. "Only frontend namespace can talk to api namespace on port 8080."

---

**IRSA — what is it?**

IAM Roles for Service Accounts. Each K8s pod gets its own AWS IAM role via its ServiceAccount. Pod A accesses S3, Pod B accesses DynamoDB. No shared credentials.

---

**How does IRSA work under the hood?**

EKS acts as an OIDC identity provider and mounts a JWT token inside each pod identifying its ServiceAccount. The pod presents this token to AWS STS to assume its mapped IAM role. STS verifies the token against the EKS OIDC provider, and if the trust policy matches, returns temporary AWS credentials. The pod uses those to call AWS services. No hardcoded credentials — just a token, a trust policy, and temporary creds that auto-refresh.

---

**What is a Kubernetes CRD (Custom Resource Definition)?**

A way to extend Kubernetes with your own resource types beyond the built-in ones (Pods, Services, Deployments). You define a new resource type — like `PostgresCluster` or `Certificate` — and Kubernetes treats it like a native object. You can `kubectl get`, `kubectl apply`, and manage it like any other resource. CRDs define the "what" — the desired state you declare in YAML. An Operator watches for CRDs and handles the "how" — the actual logic to make it happen.

---

**Kubernetes Operators — what are they?**

Controllers that watch CRDs and automate complex operations. CRD is the "what" (I want a 3-replica PostgreSQL). Operator is the "how" (provisions, configures replication, handles failover). Encodes operational knowledge into software.

---

**ECS vs EKS — when to use which?**

ECS/Fargate: simpler, cheaper, less operational overhead. Good for small teams, few services. EKS: more powerful, fine-grained control, service mesh, multi-cloud. Good for many services, multiple teams.

---

## 11. Cloud Architecture

**Terraform — key concepts?**

Declarative IaC, state file tracks reality, remote state (S3 + DynamoDB lock) for teams, modules for reuse, drift detection via terraform plan.

---

**VPC architecture — standard pattern?**

Internet → IGW → Public subnet (ALB) → Private subnet (app servers/EKS) → Private subnet (RDS/ElastiCache) → NAT Gateway (outbound only). Only LB is public.

---

**Security Groups vs NACLs?**

Security Groups: per-resource, stateful (response auto-allowed). NACLs: per-subnet, stateless (must allow both directions). SGs are primary firewall, NACLs are backup safety net.

---

**VPC Peering vs Transit Gateway?**

Peering: 1-to-1 direct connection, doesn't scale (N VPCs = N(N-1)/2 connections). Transit Gateway: hub-and-spoke, scales cleanly (one connection per VPC).

---

**PrivateLink / VPC Endpoints — what for?**

Access AWS services (S3, ECR, Secrets Manager) privately without going through public internet or NAT Gateway. Reduces cost and improves security. Gateway endpoints (S3, DynamoDB) are free — always use them. Interface endpoints (everything else) cost ~$7-8/month per endpoint per AZ. Don't blindly add them for every service — do the math. If NAT Gateway traffic for a service is only a few GB/month, the endpoint costs more than the NAT traffic. Add interface endpoints for high-traffic services where NAT costs exceed endpoint cost (ECR, STS, CloudWatch Logs).

---

**IAM principle?**

Least privilege. IRSA for K8s pods, IAM roles for EC2/Lambda, no hardcoded credentials anywhere. SSO through central IdP for humans — no IAM users, no long-lived keys, temporary role sessions.

---

**Reserved Instances vs Spot vs On-Demand?**

Reserved/Savings Plans: 30-60% discount, 1-3 year commit, for steady-state (production DBs, base load). Spot: up to 90% off, can be reclaimed, for interruptible work (batch, CI/CD). On-demand: full price, for unpredictable/dev workloads.

---

**Multi-account strategy — why?**

Blast radius isolation, billing separation, security boundaries. Structure: management, security, logging, shared services, prod, staging, dev. SCPs enforce guardrails.

---

**Explain the four DR strategies.**

1. Backup & Restore — Take periodic backups (snapshots, DB dumps) and store them in another region. On disaster, spin up new infrastructure and restore from backup. Cheapest but slowest — hours to recover, you lose all data since the last backup.
2. Pilot Light — Core infrastructure (database replicas) runs in the DR region at all times, but app servers are off. On disaster, spin up the app servers and point traffic to the DR region. Data is already there, but compute takes 10-30 minutes to boot.
3. Warm Standby — A scaled-down but fully running copy of your system in the DR region. On disaster, scale it up to full capacity and route traffic. Faster than pilot light because everything is already running, just smaller.
4. Active-Active — Both regions run at full capacity and serve live traffic all the time. On disaster, the healthy region absorbs all traffic. Near-zero downtime but double the cost.

---

**Four DR strategies — cheapest to most expensive?**

Backup & Restore (hours RPO/RTO, $). Pilot Light (minutes RPO, 10-30 min RTO, $$). Warm Standby (seconds RPO, minutes RTO, $$$). Active-Active (near zero RPO/RTO, $$$$).

---

**RPO vs RTO?**

RPO (Recovery Point Objective): how much data can you afford to lose. If you back up every 24 hours and disaster hits, you lose up to 24 hours of data. RPO = 24 hours. If you replicate in real-time, RPO = near zero. RTO (Recovery Time Objective): how fast must you be back online after a disaster. If it takes 4 hours to restore from backup and spin up servers, RTO = 4 hours. If you have active-active, RTO = near zero. Lower RPO/RTO = more expensive infrastructure (real-time replication, always-on standby). These two numbers drive every DR decision — the business tells you what they can tolerate, and that determines which DR strategy you use.

---

**AWS Well-Architected Framework — five pillars?**

Operational Excellence (automate, IaC, CI/CD). Security (least privilege, encryption, audit). Reliability (multi-AZ, auto-scaling, health checks). Performance Efficiency (right-size, cache, CDN). Cost Optimization (reserved, spot, lifecycle policies).

---

**What are the conflict resolution strategies and when do you use each?**

Last-write-wins (LWW): simplest, timestamp decides the winner, silent data loss. Use when losing a write is acceptable (caches, session data). Version vectors: track version history across nodes, detect conflicts and let the app merge. More accurate but complex. Use in multi-primary replication. Application-level / conflict detection: present both versions to the user and let them decide (Dropbox's "conflicted copy"). Most correct, requires UI work. Use when user data matters and silent loss is unacceptable (file storage, documents). Optimistic locking (version column): reject the second write and let the app retry. Use for database-level race conditions (inventory, booking).

---

**When do you use push (WebSocket) vs polling?**

Push when data changes frequently and users need it immediately (chat, file sync, live dashboards, presence) — especially if most poll responses would be "nothing changed." Polling when changes are infrequent and a small delay is fine (software updates, background email sync), or when clients are short-lived and can't hold persistent connections (serverless, CLI tools). Rule of thumb: if 90% of poll responses would be "nothing changed," you should be pushing instead.

---

**How do you generate unique short codes (URL shortener)?**

Use an auto-incrementing ID and encode it in base62 (a-z, A-Z, 0-9 = 62 characters). Sequential IDs guarantee uniqueness, base62 makes them short. 7 characters = 3.5 trillion possible codes. For multiple servers, pre-allocate ID ranges (server 1 gets 1-10,000, server 2 gets 10,001-20,000) — no coordination per request. Alternative: hash the URL and truncate, but must check for collisions. Sequential ID + base62 is simpler and collision-free.

---

## Storage Patterns

**What is content-addressable storage / deduplication and when do you use it?**

Instead of storing a file per user, hash the file content and use the hash as the storage key. If two users upload the same file, the hash is identical — store it once, point both users' metadata to it. 50MB file uploaded by 5,000 users = 50MB stored, not 250GB. Only delete the actual file when no users reference it anymore. Use for enterprise file storage where many users have the same files.

---

**How does SSO integration work for enterprise customers accessing your app?**

User hits your app → app redirects to the customer's corporate IdP (Okta, Azure AD) → user authenticates with their corporate credentials → IdP sends a SAML assertion or OIDC token back to your app's callback URL → your app reads the token, maps the IdP to a tenant_id, creates a session → user sees only their company's data. You register each enterprise customer's IdP in your system and map it to their tenant_id. Same protocols as AWS IAM federation (SAML/OIDC), but your app is the service provider instead of AWS.

---

**What is HMAC and how is it used for webhook signature verification?**

HMAC (Hash-based Message Authentication Code) uses a shared secret to sign and verify payloads. When sending a webhook: hash the payload with the shared secret (HMAC-SHA256), include the hash in a header (`X-Webhook-Signature`). The receiver hashes the payload with the same secret — if signatures match, it's genuine. Each customer gets a unique shared secret on registration. Simpler than asymmetric keys but less secure — anyone with the secret can forge signatures. Asymmetric (sign with private key, verify with public key) is more secure but more complex. HMAC is the industry standard for webhooks (Stripe, GitHub, Shopify).

---

## Security

**What is defense in depth and how does it apply to AWS network architecture?**

Layering multiple security controls so no single point of failure compromises the system. In AWS: (1) WAF in front of CloudFront/ALB — blocks application attacks (SQL injection, XSS, bots). (2) Public/private subnet isolation — ALB in public subnet (internet-facing), app servers and databases in private subnet (no public IP, unreachable from the internet). (3) Security groups — control which ports and sources can talk to each instance. Even if one layer is bypassed, the others still protect you. In interviews: "WAF at the edge, ALB in public subnet, everything else in private subnets, security groups restricting access per service."

---

**How does IAM + IdP federation work?**

User tries to access AWS → redirected to company IdP (Okta, Azure AD) → authenticates there (SSO, MFA) → IdP sends a SAML/OIDC token with the user's groups → AWS maps groups to IAM roles (e.g., "devops" group → DevOpsRole) → user gets temporary credentials via STS. No permanent AWS credentials, no IAM users. Employee leaves → revoke in IdP → AWS access gone. Use for any company AWS account — never create individual IAM users with long-lived keys.

---

## AWS Services

**What is AWS WAF and where does it go?**

Web Application Firewall. Sits in front of CloudFront or ALB and filters malicious traffic — SQL injection, cross-site scripting, bot traffic, DDoS. Inspects HTTP requests and blocks bad ones before they reach your servers. Mention it in interviews when discussing security: "WAF at the edge to block attacks, rate limiting at the API Gateway for per-user throttling."

---

**What is AWS EMR and when do you use it?**

Managed cluster for processing massive datasets using Spark, Hadoop, or Presto. Spin up a cluster, run your job, tear it down. Use when data processing is too complex for SQL — multi-step transformations, ML training, custom Spark jobs on terabytes of data. Data lives in S3, EMR reads it, processes it, writes results back. Heavy-duty batch processing. For simple SQL queries on S3 data, use Athena instead.

---

**What is AWS Athena and when do you use it?**

Serverless SQL query engine that runs queries directly on data in S3. No servers, no database setup. Point at S3, write SQL, get results. Pay per query (per TB scanned). Use for ad-hoc analytics, log analysis, and reporting on data already in S3. Not real-time — queries take seconds to minutes. For complex multi-step processing or custom code, use EMR instead.

---

**What is read/write splitting and what's the catch?**

Route writes to the primary DB, route reads to read replicas. Most apps are 90%+ reads, so this offloads the majority of traffic from the primary. Scale reads by adding more replicas. The catch: replication lag — replicas are eventually consistent (milliseconds to seconds behind). Fix with read-after-write consistency: after a user writes, route their subsequent reads to the primary for a short window so they see their own changes. Everyone else reads from replicas. Simplest DB scaling move before you need caching or CQRS.

---

**What is the difference between a data lake and a data warehouse?**

Data lake (S3): stores raw, unprocessed data in any format (JSON, CSV, logs, images). Cheap, no schema needed, dump everything in. Query with Athena or process with EMR when needed. Data warehouse (Redshift, BigQuery): stores structured, processed data in defined schemas. Optimized for fast analytical SQL queries. They work together: raw data lands in S3 (lake) → gets transformed → loaded into Redshift (warehouse) for analysts. Lake = cheap archive of everything. Warehouse = organized, query-ready analytics.

---

## Data Stores

**What is a time-series database and when do you use it?**

A database purpose-built for timestamped data points (e.g., "at 10:05:03, CPU was 72%"). Optimized for high-volume writes (50K+ data points/sec), time-range queries ("show me CPU for the last hour"), and built-in aggregation (avg, percentiles over time windows). Key feature: **downsampling** — automatically reduces granularity as data ages (per-second → 1-min averages → 1-hour averages), solving the storage problem without dumping to S3. Also has built-in retention policies to auto-delete old data. Use whenever you hear "metrics," "monitoring," "telemetry," or "IoT." Examples: Prometheus, InfluxDB, TimescaleDB, Amazon Timestream.

---

**What is downsampling and why is it important for metrics?**

Automatically reducing the granularity of time-series data as it ages. Last 24 hours: keep every data point (per-second). Last 30 days: aggregate to 1-minute averages. Last year: 1-hour averages. Nobody needs per-second precision from 6 months ago. Dramatically reduces storage while still allowing historical queries. Built into time-series databases — no separate archival system needed.

---

## Concurrency & Inventory

**Why doesn't ACID prevent double-selling by default?**

PostgreSQL's default isolation is Read Committed — each transaction sees a snapshot of committed data at the time it reads. If two transactions both read a seat as "available" before either writes, both proceed to mark it "sold." The second overwrites the first because it made a decision based on data that changed after it read it. Fix: atomic conditional update (`UPDATE ... WHERE status = 'available'` — 0 rows affected means someone else got it), pessimistic locking (SELECT FOR UPDATE — lock the row on read), or optimistic locking (version column — reject if version changed since your read).

---

**What is an atomic conditional update and when do you use it?**

Combine the check and write into one SQL statement: `UPDATE seats SET status = 'sold' WHERE seat_id = 'A5' AND status = 'available'`. If someone else already changed the status, the WHERE clause doesn't match and 0 rows are affected. Your app checks the affected row count — 0 means the item was taken. No separate read, no lock, no race condition. Use for simple inventory/booking systems (ticket sales, hotel rooms, shopping carts).

---

**Pessimistic vs optimistic locking — when to use each?**

Can you do it in one statement? → Atomic conditional update (`UPDATE ... WHERE status = 'available'`). No read, no lock. Default for inventory/booking. Conflicts rare? → Optimistic locking. Read the row, note its version, do your logic, write with `WHERE version = 3`. If someone changed it, retry. Good when conflicts are unlikely (e.g., two people editing different settings on the same account). Conflicts frequent? → Pessimistic locking (`SELECT FOR UPDATE`). Lock the row upfront, nobody else can touch it until you're done. No retries needed. Good when many transactions hit the same row constantly (e.g., bank account balance during peak hours).

---

**Simple rule: atomic vs optimistic vs pessimistic?**

One statement? → Atomic conditional update. Conflicts rare? → Optimistic (no lock, retry if unlucky). Conflicts frequent? → Pessimistic (lock upfront, no retries needed).

---

**What is a virtual waiting room and when do you use it?**

Instead of letting 500K users slam your backend in a flash sale, put them in a static waiting room page (served from CloudFront — handles millions with zero backend load). A queue controller releases users in controlled batches (e.g., 5,000 at a time) based on backend capacity. Users get a token to access the real app. When they finish or their session expires, the slot opens for the next person. Use whenever you have a predictable traffic spike — ticket sales, product launches, registration openings. Don't try to scale big enough for everyone simultaneously — control the inflow.

---

**What is a temporary reservation (hold with TTL) and why use it?**

When a user selects an item (seat, hotel room), immediately mark it as "held" with a timeout (e.g., 5 minutes) using an atomic conditional update. Other users see it as unavailable. If the user completes payment, status moves to "sold." If they don't, a background job releases expired holds. Without this, a user spends 3 minutes entering payment info, only to discover someone else bought the item while they were typing. Use in any booking system where users select-then-pay.

---

**What is the saga pattern and when do you use it?**

In microservices, you can't wrap a multi-service operation in one DB transaction. A saga breaks it into a chain of steps, each with a compensating action (undo). Reserve seat → charge Stripe → confirm ticket → send email. If step 3 fails: refund Stripe (undo step 2), release seat (undo step 1). Either the whole chain completes or everything gets undone. Use for any multi-service workflow where consistency matters — checkout flows, booking systems, order processing.

---

**What is the strategy/plugin pattern for varying business logic?**

When a workflow is the same but one step varies by type, don't hardcode if/else logic everywhere — isolate the varying step behind a common interface. Example: a ticket platform's purchase flow (reserve → pay → confirm → notify) is identical for all events, but "reserve" differs per type. Concerts decrement a counter, theater locks a specific seat, conferences check capacity. Each type has its own service behind a shared "reserve" interface. Adding a new event type = one new service, nothing else changes.

---

## Patterns from Scenarios

**How do you design a social media feed (Twitter/Instagram) — fan-out on write vs read?**

When a user posts, how do their followers see it? Fan-out on write: the moment a user posts, push that post into every follower's pre-computed feed in Redis. When a follower opens the app, the feed is already there — instant. Works great for regular users with 500 followers (500 writes). Terrible for celebrities with 5M followers (5 million writes per post). Fan-out on read: don't pre-compute anything. When a follower opens the app, go fetch posts from everyone they follow at that moment. No write overhead, but slow reads. Hybrid (what Twitter actually does): regular users fan-out on write (pre-compute). Celebrities (>100K followers) fan-out on read (fetch at read time). Best of both — fast feeds without millions of writes per celebrity post.

---

**When and why would you use notification batching / digest?**

When a bulk action triggers hundreds of notifications (e.g., manager reassigns 500 tasks). Without batching, users get 500 emails and downstream APIs get hammered. Fix: hold notifications in an aggregation window (5-10s), detect related events, collapse into one digest: "500 tasks were reassigned to you." One notification instead of 500.

---

**How do you handle data isolation in a multi-tenant SaaS app?**

Problem: an enterprise customer demands their data is fully isolated from other customers — for security, compliance, or performance. You can't give every customer a dedicated database (too expensive). Solution: tiered approach. Most customers share a database (cheap, row-level isolation via tenant_id). Enterprise customers paying for isolation get a dedicated database. A tenant routing layer in the API maps tenant_id → correct database connection. Same app code, different data paths based on the customer's tier.

---

**When should you pre-compute instead of computing on demand?**

Problem: a project management app generates file thumbnails when users open their task board at 9am. Thousands of users hit the page simultaneously, each triggering thumbnail generation — the system buckles at peak traffic. Fix: move expensive computation from the read path (when users request it) to the write path (when files are uploaded). Generate thumbnails at upload time (S3 event → Lambda), store them, and serve pre-built thumbnails when users open the page. Uploads are spread throughout the day (low traffic). Page views spike at 9am (peak traffic). Do the heavy work when traffic is low, serve cached results when traffic is high.

---

**Why should you separate ephemeral data from persistent data?**

Data that gets overwritten every few seconds (current location, live status) doesn't belong in a relational DB — it overwhelms it with throwaway writes. Use the right store for each type: ephemeral data (current state, only need latest value) → Redis. Persistent business data (written once, queried forever) → PostgreSQL. Historical analytics (trends, reporting) → S3/Athena/Redshift.

---


**How do you handle high-volume events that multiple services need (telemetry, IoT, analytics)?**

Send all events to Kafka as a single stream. Multiple independent consumers read from the same stream for different purposes: one writes current state to Redis (real-time dashboards), one runs anomaly detection (alerting), one sends data via Firehose to S3 (long-term archive/analytics). Each consumer reads at its own pace without affecting the others. This is the core Kafka pattern — one stream in, many consumers out, each doing something different with the same data.

---


**What is table partitioning and when would you use it?**

When a single table gets millions of writes and has an index, all writes compete for the same index lock — slowing everything down. Fix: split the table into partitions within the same DB. Each partition has its own index, so writes spread across multiple locks instead of one. Different from sharding (which splits across multiple DBs). Partitioning stays within the same DB — same queries, same app code, just less contention. Use when a high-write table is bottlenecked on index lock contention, not overall DB load.

---

**How do you scale a rule/job evaluation system?**

Partition rules evenly across multiple evaluator instances (by service name, team, or rule ID hash — not by severity, which creates uneven load). Each evaluator handles a subset independently. If one crashes, use consumer-group-style rebalancing — remaining evaluators pick up the orphaned rules. Same pattern as Kafka consumer groups.

---

**What is a delayed queue and when do you use it?**

A regular queue (like SQS) with a delay on the message — "deliver this to a consumer, but not until X minutes from now." The message sits invisible in the queue until the delay expires, then becomes available for processing. SQS supports up to 15 minutes delay per message. For longer delays, use EventBridge scheduled rules or Step Functions with a Wait state. Use anytime you need "if X doesn't happen within Y minutes, do Z" — alert escalation, payment timeout, reservation expiry, retry after cooldown.

---

**How do you implement time-based escalation?**

Use a delayed queue/scheduled job. When an alert fires: notify the on-call, then schedule a delayed message for 5 minutes. When it fires, check if the alert was acknowledged (status field in DB). If not, escalate to the next person and schedule another delayed job. Use anytime you need "if X doesn't happen within Y minutes, do Z."

---

**How do you deduplicate alerts during an ongoing incident?**

Track incident state: firing → acknowledged → resolved. First breach creates an incident and notifies. Subsequent firings check Redis for an open incident — if one exists, increment the occurrence counter silently (no new notification). Only notify on state changes: new incident (firing) and resolution (resolved). Prevents hundreds of duplicate pages for the same outage.

---

**How do you make dashboards fast under heavy concurrent load?**

Cache query results in Redis with short TTL (30-60s). Even better: a background pre-computation job runs every 30-60 seconds, queries the TSDB for all active dashboard panels, and writes results to Redis. Cache is always warm — no user ever queries the TSDB directly. Every dashboard load is a pure Redis read. Same principle as pre-computing recommendations.

---

**S3 vs EBS vs EFS — what's the mutability difference?**

S3 (object storage) — immutable blobs. Every write replaces the entire object. Cannot update specific bytes or blocks. Supports byte-range reads (download a portion) but not byte-range writes. Cheapest, scales infinitely. Best for write-once-read-many: images, videos, backups, logs. EBS (block storage) — mutable blocks. Can read/write individual blocks without touching the rest. Snapshots are incremental (only changed blocks). Attached to a single EC2 instance. Best for databases, OS disks — anything that needs in-place updates. EFS (file storage) — mutable files over NFS. Can open a file, seek to a position, overwrite specific bytes. Shared across multiple instances. Best for shared filesystems where multiple servers need read/write access to the same files. Key rule: if your data changes frequently (document text, database rows, config files), use EBS or EFS. If your data is written once and read many times (images, uploaded videos, backups, chunks in a dedup system), use S3.

---

**Operational Transformation (OT) — how do collaborative editors handle concurrent edits?**

Every edit is an operation: insert('x', position=5) or delete(position=3). When two users edit concurrently, their operations are based on stale positions (neither knows about the other's edit yet). The server transforms each incoming operation against all concurrent operations before applying and broadcasting. Example: doc is "HELLO", User A inserts at position 1, User B deletes position 0. Server transforms A's position to account for B's delete. Both edits preserved, all clients converge on the same state. Key properties: convergence (all clients reach same state), intent preservation (each edit does what the user meant), fully automatic (no manual merge). Each operation includes a revision number so the server knows what to transform against. Alternative: CRDTs (used by Figma) — each character gets a unique ID, operations never conflict by design, works without a central server but uses more memory. For interviews: know OT exists and what it does. You won't implement it, but you need to explain how concurrent edits don't overwrite each other.

---

**When does a DLQ make sense vs just returning an error to the user?**

DLQ makes sense for async fire-and-forget operations where no user is waiting — webhook delivery, notification sends, event processing. If it fails, nobody sees the failure, so you need infrastructure to retry. Returning an error makes sense for synchronous user-facing operations — permission changes, form submissions, API requests. The user is waiting for a response, sees the error, and can retry themselves. Rule: match retry strategy to interaction pattern. Sync user action = return error. Async background work = DLQ.

---

**AWS IoT Greengrass — what is it and why use it?**

Runs a lightweight AWS runtime directly on IoT devices so they can execute Lambda functions, ML models, and messaging locally — without needing a constant internet connection. Problem it solves: IoT devices (cameras, sensors, factory machines) can't always reach the cloud. Without Greengrass, no connectivity = no processing. With Greengrass, devices process data at the edge (low latency, works offline) and sync results back to AWS when connectivity returns. Example: a factory with 500 sensors — Greengrass runs on a local gateway, filters noise and detects anomalies locally, only sends meaningful events to the cloud. Saves bandwidth, sub-millisecond response. In a smart home camera system, Greengrass could run person detection on the device itself, only uploading clips when a person is detected instead of streaming everything. Think of it as: AWS Lambda running on the physical device instead of in the cloud.

---

**AWS IoT Core — what is it and how does it relate to Greengrass?**

The managed cloud-side hub that connects IoT devices to AWS. Devices connect using MQTT (lightweight pub/sub protocol designed for low-power devices with unreliable networks). Each device authenticates with an X.509 certificate (more secure than passwords for millions of unattended devices). IoT Core provides: a device registry (tracks all devices, metadata, status), an MQTT broker (devices publish messages, cloud services subscribe), and a rules engine (routes device messages to AWS services — "temperature > 100 → trigger Lambda," "motion detected → write to Kinesis," "all data → S3"). Relationship to Greengrass: IoT Core = cloud side (receives data, routes, manages devices). Greengrass = device side (processes data locally). They work together — Greengrass filters/processes locally, sends results to IoT Core, which routes them to the rest of AWS. Think of it as: API Gateway but for IoT devices instead of web clients.

---

**Amazon EventBridge — what is it and how is it different from SQS, SNS, and Kafka?**

A serverless event bus that routes events to targets based on content-based rules. Producer publishes an event, EventBridge inspects the event fields and routes it to the right consumers — "if order amount > $500 AND region = US-East, send to fraud Lambda." Events are NOT stored — fire-and-route, no retention, no replay. Fully serverless, zero infrastructure. How it compares: SQS = point-to-point, one consumer picks up a message. SNS = fan-out, all subscribers get a copy. EventBridge = smart routing, rules decide who gets what based on content. Kafka = high-throughput distributed log with retention and replay, millions/sec, you manage infrastructure. EventBridge = low-volume AWS-to-AWS glue, thousands/sec, serverless. Use EventBridge for: connecting AWS services ("user signs up in Cognito → trigger welcome email Lambda + create default settings Lambda"), low-volume event routing where you need content-based filtering. Use Kafka for: high-volume streaming, event sourcing, when you need retention and replay.

---

**When do you use an internal load balancer vs other routing mechanisms?**

Internal LBs (ALB/NLB) sit in front of stateless, interchangeable servers — app servers, microservices, API servers. Any instance can handle any request, so the LB distributes based on health, throughput, or routing rules. Do NOT use a generic LB in front of databases — databases are stateful and not interchangeable (primary handles writes, replicas handle reads). Database routing uses: separate connection strings for primary vs replicas (RDS gives you two endpoints), database-aware proxies like PgBouncer or ProxySQL that understand read vs write queries, and app-level shard routing (hash customer ID → look up shard connection string from config). Failover is handled by RDS Multi-AZ (managed) or Patroni/pg_auto_failover (self-managed), not by a load balancer — failover requires promoting a replica to read-write, which is a database operation, not a routing decision.

---

**What are the different API authentication methods and when do you use each?**

(1) Username/password — user sends credentials, server checks against hashed password in DB, returns a session cookie or token. Traditional web app login. (2) OAuth 2.0 / OIDC — delegate authentication to an IDP (Okta, Google). User logs in at the IDP, IDP returns a JWT. Your app validates the JWT locally using the IDP's public key — no callback to IDP needed. OIDC = authentication (who is this user?), OAuth = authorization (what can this app access on their behalf?). Used for SSO, "Sign in with Google," third-party API access. (3) SAML — older enterprise SSO protocol. Same concept as OIDC but uses XML assertions instead of JWTs. Common in corporate environments with Active Directory. Being replaced by OIDC in new apps. (4) API keys — static key in request header (X-API-Key). Simple, no user context. Used for service-to-service calls and public APIs with rate limiting. If leaked, anyone can use it until rotated. (5) mTLS (certificate-based) — both client and server present certificates. No passwords or tokens. The certificate IS the identity. Used for service-to-service communication and IoT devices. (6) HMAC signature — client signs the request body with a shared secret, server verifies. Proves sender identity AND that the request wasn't tampered with. Used for webhook verification and AWS API calls (Signature V4). (7) IAM roles (cloud-native) — no credentials in the app. Infrastructure (EC2, Lambda, pods via IRSA) gets temporary credentials automatically from AWS. Used for service-to-AWS calls. JWT is not a protocol — it's a token format used by both OIDC and OAuth 2.0.

---

**GraphQL vs REST — when do you use each?**

REST: server defines fixed endpoints, each returns a fixed shape of data. Simple, well-understood, easily cached at CDN/proxy level (URL-based). Best for straightforward CRUD APIs. GraphQL: one endpoint, client specifies exactly which fields to return. Best when: (1) multiple clients with different data needs — mobile needs 3 fields, web dashboard needs 20, admin needs 50. REST would require separate endpoints or return everything wastefully. (2) Deeply nested/related data — "user → orders → items → reviews" in one request instead of multiple REST roundtrips. (3) Overfetching/underfetching — REST returns fixed shapes, GraphQL returns exactly what's requested. REST wins on: simplicity, caching (every GraphQL request body is different so CDN caching is harder), and easier maintenance (no risk of clients writing expensive nested queries that kill your DB). Interview default: reach for REST unless the question involves multiple clients, complex nested data, or bandwidth-sensitive mobile apps — then mention GraphQL and explain why.

---

**gRPC — what is it and when do you use it over REST?**

A high-performance RPC framework for service-to-service communication. Uses Protocol Buffers (binary serialization — compact, fast to parse, ~3x smaller than JSON) over HTTP/2 (multiplexed streams over a single connection — multiple requests/responses simultaneously). You define APIs in a .proto file with strict types, and client/server code is auto-generated for any language. Supports bidirectional streaming natively. Use for: internal microservice-to-microservice calls where performance matters, high-throughput inter-service communication, streaming between services, polyglot environments (proto generates clients for all languages). Do NOT use for: user-facing APIs (browsers don't natively support gRPC), third-party integrations (REST is universally understood), debugging (binary protobuf isn't human-readable like JSON). Common interview pattern: REST/GraphQL for the outside world (browser → API Gateway), gRPC for internal communication (API Gateway → microservices).

---

**API authentication decision tree — which method for which scenario?**

End user logging into web/mobile app → OIDC/OAuth with external IDP (Okta, Google). Third-party developer calling your public API → API keys (hashed in DB, looked up on every request, permissions/rate limits tied to the key). Internal service → internal service → mTLS (certificates, zero-trust) or API keys for simpler setups. Your service → AWS resource (S3, DynamoDB) → IAM roles / IRSA (no credentials in the app). External system → your webhook endpoint → HMAC signature (verify sender identity + payload integrity). Enterprise employee via corporate SSO → OIDC (preferred) or SAML (if legacy IDP like Active Directory only supports it). API keys work like passwords: store hashed version in DB/Redis with associated permissions and rate limit tier, hash the incoming key on each request and look it up. Default interview answer for user-facing auth: "OIDC with an external IDP, validate JWTs at the API Gateway." Default for service-to-AWS: "IAM roles, no stored credentials."

---

**Thanos / Grafana Mimir — how do you get unified monitoring across multiple regions?**

Each region runs its own Prometheus instance (monitoring shouldn't depend on cross-region connectivity). Problem: Grafana can only query one Prometheus at a time — no unified view. Thanos or Grafana Mimir sits on top of all regional Prometheus instances and provides a single query layer. Grafana queries Thanos/Mimir, which fans out to all regional Prometheus instances and aggregates results. One dashboard, all regions. Setup: Region 1 Prometheus → Thanos/Mimir ← Region 2 Prometheus, Region 3 Prometheus → Grafana queries Thanos/Mimir. Use this to build: global dashboard (all regions health at a glance), per-region dashboards (deep dive), comparison dashboards (same metric side by side across regions — if latency spikes in one region but not others, it's regional; if it spikes everywhere, it's a code or upstream issue). Alerts should be per-region AND global with different escalation paths.
