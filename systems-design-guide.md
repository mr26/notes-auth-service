# Systems Design Interview Guide

## How to Approach Every Systems Design Question

Every question follows the same framework:

1. **Requirements** (2-3 min) — Clarify functional + non-functional requirements
2. **Estimation** (2-3 min) — Back-of-envelope math: users, QPS, storage, bandwidth
3. **High-Level Design** (5 min) — Draw the boxes: clients → LB → services → DB
4. **Deep Dive** (15-20 min) — Go deep on the hardest parts
5. **Trade-offs & Bottlenecks** (5 min) — What breaks first? What are the alternatives?

---

## 1. Networking & Communication

### DNS (Domain Name System)

DNS translates domain names to IP addresses. When a user types `api.example.com`, a DNS resolver looks up the corresponding IP address and routes the request there.

**How DNS resolution works:**

1. Browser checks its local cache
2. OS checks its cache
3. Request goes to a recursive resolver (usually your ISP)
4. Resolver queries root nameservers → TLD nameservers (.com) → authoritative nameserver
5. Authoritative nameserver returns the IP
6. Result is cached at every level based on TTL (Time to Live)

**DNS record types:**

- **A record** — Maps domain to an IPv4 address
- **AAAA record** — Maps domain to an IPv6 address
- **CNAME** — Maps domain to another domain (alias)
- **MX** — Mail server routing
- **NS** — Delegates a subdomain to another nameserver

**Routing policies (AWS Route 53):**

- **Simple** — One domain → one IP
- **Weighted** — Split traffic: 90% to us-east-1, 10% to us-west-2 (useful for canary deployments)
- **Latency-based** — Route users to the closest region
- **Failover** — Primary region dies → automatically route to secondary
- **Geolocation** — Route based on user's country/region

**Interview relevance:** DNS is the first hop in every request. TTL matters — if you're migrating to a new server, a high TTL means users will still hit the old IP for hours. Set TTL low before a migration, then increase it after.

---

### IP Addressing Models


| Model         | How it works                                                                                                                                         | Example                                                                                                                                    |
| ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| **Unicast**   | One IP → one destination. A request always reaches the same server.                                                                                  | Standard EC2 instance with a public IP. You hit that IP, you reach that machine.                                                           |
| **Anycast**   | One IP → many locations, but each request reaches only the **nearest** one. The network (BGP) routes to the closest destination advertising that IP. | AWS Global Accelerator gives you a single IP that routes to the nearest edge location. CloudFront and most CDNs use anycast.               |
| **Multicast** | One packet → delivered to **all members** of a group simultaneously. The network replicates the packet to every subscriber.                          | Stock market data feeds (exchange sends price updates once, all trading systems receive it). Live video streaming. Cluster node discovery. |
| **Broadcast** | One packet → delivered to **every device** on the network, whether they want it or not.                                                              | ARP requests on a local network ("who has IP 10.0.0.5?"). Rarely relevant at the cloud/internet level.                                     |


**Why this matters for cloud roles:**

- **Anycast** is how Global Accelerator and CDNs work — understanding it explains why Global Accelerator provides instant failover (BGP reroutes to the next nearest edge if one goes down) and why you get a single static IP that works globally.
- **Multicast** is rarely used in cloud — AWS doesn't support it in VPCs (only via Transit Gateway). But it comes up in discussions about real-time data distribution and cluster coordination.
- **Broadcast** doesn't exist at the internet level. Only relevant within local network segments.

---

### Load Balancers

A load balancer distributes incoming traffic across multiple backend servers to prevent any single server from being overwhelmed.

**Layer 4 (Transport) — NLB:**

- Routes based on IP address and TCP/UDP port
- Doesn't inspect HTTP content
- Extremely fast, millions of requests/sec
- Use for: TCP traffic, gRPC, gaming, IoT

**Layer 7 (Application) — ALB:**

- Routes based on HTTP content: URL path, headers, cookies, query strings
- Can do path-based routing: `/api/`* → backend, `/static/*` → CDN
- Can do host-based routing: `api.example.com` → API servers, `admin.example.com` → admin panel
- Supports WebSocket and HTTP/2
- Use for: Web applications, REST APIs, microservices

**Load balancing algorithms:**

- **Round Robin** — Rotate through servers sequentially
- **Least Connections** — Send to the server with fewest active connections
- **Weighted** — Send more traffic to stronger servers
- **IP Hash** — Hash the client IP to always route to the same server (sticky)
- **Random** — Pick a random server (surprisingly effective at scale)

**Key concepts:**

- **Health checks** — LB periodically pings backend servers; unhealthy ones get removed from rotation
- **Connection draining** — When removing a server, let in-flight requests finish before cutting traffic
- **Sticky sessions** — Route the same user to the same backend (needed if backend has local session state — but avoid this by being stateless)
- **SSL termination** — LB handles HTTPS decryption so backends don't have to
- **Internal vs External** — Internal LB is only accessible within your private network; external is internet-facing

**Interview tip:** Always put a load balancer between any two tiers. Clients → LB → Web servers → LB → App servers → LB → Database read replicas.

---

### API Types

**REST (Representational State Transfer):**

- Request-response model, stateless
- Human-readable (JSON payloads)
- Verbs: GET, POST, PUT, DELETE, PATCH
- Status codes: 2xx (success), 3xx (redirect), 4xx (client error), 5xx (server error)
- Resources identified by URLs: `/users/123`, `/orders/456/items`
- Each endpoint returns a fixed structure — the server decides what fields come back
- **Pro:** Simple, well-understood, huge ecosystem, works everywhere (browsers, mobile, third parties)
- **Con:** Over-fetching (endpoint returns 20 fields when you need 3) and under-fetching (need data from 3 endpoints to build one screen, requiring 3 round trips)
- Good for: External/public APIs, CRUD operations, browser-facing services. The default choice for most APIs.

**GraphQL:**

- Client specifies exactly which fields it wants in the query — no over-fetching or under-fetching
- Single endpoint (`/graphql`), client sends a query describing the shape of the data it needs
- Example: instead of calling `/users/123` then `/users/123/orders` then `/users/123/addresses`, the client sends one query that asks for the user's name, their last 5 orders, and their primary address — one round trip, exact data needed
- **Pro:** Flexible — frontend teams can change what data they fetch without backend changes. Great for mobile where bandwidth matters (only fetch what you need)
- **Con:** More complex to set up (schema definition, resolvers). Caching is harder (single endpoint, POST requests). Risk of expensive queries if not rate-limited (a client can ask for deeply nested data that hammers the DB)
- **N+1 problem:** A naive GraphQL resolver fetches one user, then loops through their orders one by one (N queries). Solved with DataLoader — batches multiple individual requests into one query.
- Good for: Apps with complex, nested data and multiple frontend clients (web, mobile, tablet) that each need different data shapes from the same API. GitHub, Shopify, and Facebook use GraphQL.

**When to use what:**


| Use Case                                         | API Type                                               |
| ------------------------------------------------ | ------------------------------------------------------ |
| Public/external API                              | REST (simple, well-understood, easy for third parties) |
| Internal service-to-service (performance)        | gRPC (binary, fast, typed contracts)                   |
| Multiple frontends needing different data shapes | GraphQL (flexible queries, no over/under-fetching)     |
| Simple CRUD app                                  | REST (don't overcomplicate it)                         |
| Mobile app with bandwidth constraints            | GraphQL (fetch only what you need)                     |


**Interview tip:** Don't default to GraphQL because it sounds modern. REST is the right answer for most systems. Only reach for GraphQL when you can articulate why — "we have three frontends that each need different subsets of the same data, and REST would require either bloated responses or dozens of endpoints."

---

### Protocols

**HTTP/HTTPS (REST):**

- Request-response model, stateless
- Human-readable (JSON payloads)
- Verbs: GET, POST, PUT, DELETE, PATCH
- Status codes: 2xx (success), 3xx (redirect), 4xx (client error), 5xx (server error)
- Good for: External APIs, CRUD operations, browser-facing services

**gRPC:**

- Binary protocol built on HTTP/2
- Uses Protocol Buffers (protobuf) for serialization — 3-10x smaller than JSON
- Supports 4 patterns: unary, server streaming, client streaming, bidirectional streaming
- Requires a `.proto` schema definition shared between client and server — both sides generate code from the same `.proto` file, so contracts are strongly typed and enforced at compile time
- Good for: Internal service-to-service communication, low-latency requirements, streaming
- NOT good for: External/public APIs (browsers don't natively support gRPC), simple CRUD apps (overhead of `.proto` files not worth it)

**gRPC example — a stock price service:**

1. Define the contract (`.proto` file):

```protobuf
service StockService {
  rpc GetPrice (PriceRequest) returns (PriceResponse);          // unary
  rpc StreamPrices (PriceRequest) returns (stream PriceResponse); // server streaming
}
message PriceRequest { string symbol = 1; }
message PriceResponse { string symbol = 1; double price = 2; int64 timestamp = 3; }
```

1. Server implements the function, client calls it like a local function:

```
response = client.GetPrice(PriceRequest(symbol="AAPL"))  # looks local, actually a network call
```

**When to use:** REST for external/public APIs. gRPC for internal service-to-service when you need performance or streaming. Example architecture:

```
Browser ←— WebSocket/SSE —→ UI Server ←— gRPC streaming —→ Stock Service ←— Market Feed
```

Each protocol where it's strongest.

**WebSocket:**

- Persistent, full-duplex TCP connection
- Client and server can push messages at any time without a new HTTP request
- Starts as HTTP, then "upgrades" to WebSocket
- Good for: Chat, live notifications, real-time collaboration, stock tickers, gaming

**Server-Sent Events (SSE):**

- Server pushes data to client over a single HTTP connection
- One-directional: server → client only
- Simpler than WebSocket, auto-reconnects
- Good for: Live feeds, dashboards, event streams where client doesn't need to send data

**Long polling:**

- Client sends HTTP request, server holds it open until there's new data (or timeout)
- Simpler to implement than WebSocket, works through all firewalls/proxies
- More overhead than WebSocket (new HTTP request each time)
- Good for: Simple real-time needs when WebSocket isn't available

**WebRTC (Web Real-Time Communication):**

- Peer-to-peer protocol designed specifically for real-time audio and video
- Browsers connect directly to each other (or through a media relay server) to stream audio/video with minimal latency
- Has built-in adaptive bitrate — automatically adjusts video resolution and frame rate based on network conditions
- Uses STUN servers (help peers discover each other's public IP) and TURN servers (relay media when direct connection isn't possible, e.g., behind strict firewalls)
- For large-scale video (thousands of sessions), you use a **media server** (Janus, mediasoup) or a **managed service** (Amazon Chime SDK, Twilio, Agora) that handles the WebRTC complexity
- **Key distinction from WebSocket:** WebSocket is for messages (chat, notifications, live updates). WebRTC is for media streams (audio, video, screen sharing). A video call app typically uses both — WebRTC for the actual audio/video and WebSocket for signaling (call setup, chat messages, participant events).

**When to use what:**


| Use Case                           | Protocol     |
| ---------------------------------- | ------------ |
| CRUD API                           | REST         |
| Service-to-service (performance)   | gRPC         |
| Bidirectional real-time (messages) | WebSocket    |
| Real-time audio/video              | WebRTC       |
| Server push only                   | SSE          |
| Simple real-time, legacy support   | Long Polling |


---

### Signed URLs

A signed URL is a URL that contains a cryptographic signature proving it was generated by someone with the right credentials. The server verifies the signature before serving the content — invalid or expired signature means access denied.

**General principle:** Use signed URLs whenever you need to grant temporary, scoped access to a private resource without giving the requester permanent credentials or making the resource public.

**S3 Pre-signed URLs:**

- Your backend generates a URL with embedded AWS credentials and an expiration time
- Anyone with the URL can download (or upload) the specific object until it expires
- The request goes directly to S3 — your application servers are not in the data path
- Use for: giving users temporary access to private S3 objects (file downloads, direct uploads)

**CloudFront Signed URLs:**

- Same concept but the file is served from the nearest CloudFront edge location instead of directly from S3
- Signature is generated using a CloudFront key pair (different from S3 pre-signing)
- First request pulls the file from S3 to the edge and caches it. Subsequent requests from nearby users are served from the cache — same security, much faster delivery.
- Use for: large files, frequently accessed files, or geographically distributed users where edge caching matters


|                     | S3 Pre-signed URL                                   | CloudFront Signed URL                           |
| ------------------- | --------------------------------------------------- | ----------------------------------------------- |
| Who serves the file | S3 directly                                         | CloudFront edge (cached)                        |
| Speed               | Depends on user's distance from S3 region           | Fast — served from nearest edge                 |
| When to use         | Small files, infrequent access, single-region users | Large files, frequent access, distributed users |
| Caching             | No caching                                          | Edge caching with configurable TTL              |


**S3 Byte-Range Requests:**

- Fetch specific portions of a file instead of downloading the entire object
- Request: `GET /file.dcm` with header `Range: bytes=0-1048575` (first 1MB only)
- Use for: large files where the consumer can start processing partial data — medical image viewers that render a preview before the full file loads, video players that seek to a specific timestamp, resuming interrupted downloads
- Same principle as how YouTube lets you skip to any point in a video without downloading everything before it

**S3 Multipart Upload:**

- Splits a large file into chunks and uploads them independently to S3
- If a chunk fails (connection drops, timeout), only that chunk is re-uploaded — not the whole file
- For a 2GB video on a flaky mobile connection, this is the difference between "upload failed, start over" and "resumes where it left off"
- Combine with pre-signed URLs: your API server generates a pre-signed URL for each part, the client uploads directly to S3 in chunks. Your API server never touches the file data.
- Use for: any upload over ~100MB — video uploads, large file attachments, dataset imports

**Interview relevance:** In any system that serves private files (healthcare, finance, SaaS), signed URLs are the standard pattern. They let you keep storage private, grant temporary access, audit who requested what, and keep files off your application servers. Combine with CloudFront for performance, byte-range requests for large file downloads, multipart upload for large file uploads.

---

### Content-Addressable Storage & Deduplication

When many users store the same file (onboarding PDF, company logo, slide deck template), storing a separate copy for each user wastes massive storage. A 50MB file uploaded by 5,000 users = 250GB for one file.

**How content-addressable storage works:**

1. When a file is uploaded, compute a hash of the content (SHA-256). The hash becomes the S3 key.
2. Before writing to S3, check: does an object with this hash already exist?
3. Yes → skip the upload, just point the user's metadata to the existing object
4. No → upload it, store it with the hash as the key

The metadata table (PostgreSQL) maps users to content hashes:

```
user_id | filename           | folder    | content_hash (→ S3 key)
user1   | onboarding.pdf     | /docs     | abc123...
user2   | new_hire_guide.pdf | /my-files | abc123...  (same file, stored once)
```

Multiple users, different filenames, one S3 object. 50MB stored once instead of 250GB.

**Reference counting for safe deletion:** You can't delete the S3 object when one user deletes their file — others still reference it. Only delete the user's metadata row. The actual S3 object is deleted only when zero users reference it. Use a reference counter or a periodic cleanup job that finds orphaned content hashes with no remaining metadata references.

**Key insight:** Whenever you hear "file storage at scale" or "many users with the same files" in an interview, deduplication via content hashing is the standard answer. This is how Dropbox, Google Drive, and most cloud storage systems work under the hood.

---

### API Pagination

When an API returns a large dataset (thousands of results), you paginate — return a chunk at a time instead of everything at once.

**Offset-based pagination:**

- Client sends: `GET /posts?offset=20&limit=10` (skip 20, give me 10)
- Simple to implement — translates directly to `SELECT ... LIMIT 10 OFFSET 20`
- **Problem:** As offset grows, the DB still scans and discards all skipped rows. `OFFSET 100000` means the DB reads 100,000 rows and throws them away. Gets slower the deeper you paginate.
- **Problem:** If new data is inserted between page requests, results shift — user might see duplicates or miss items.
- **Use for:** Small datasets, admin dashboards, anything where users rarely go past page 5. Simple and good enough for most CRUD apps.

**Cursor-based pagination:**

- Client sends: `GET /posts?cursor=abc123&limit=10` (give me 10 posts after this cursor)
- The cursor is an opaque token encoding the last item's position (usually the last item's ID or timestamp)
- Server queries: `SELECT ... WHERE id > cursor_value LIMIT 10` — no rows skipped, consistently fast regardless of how deep you are
- **Pro:** Stable results — inserts don't cause duplicates or missed items
- **Pro:** Constant performance — page 1 and page 10,000 are equally fast
- **Con:** Can't jump to "page 50" — you can only go forward (or backward) from where you are
- **Use for:** Infinite scroll feeds, timelines, any dataset that's large, frequently updated, or needs consistent performance. This is what Twitter, Facebook, and most modern APIs use.


| Factor                        | Offset                   | Cursor                           |
| ----------------------------- | ------------------------ | -------------------------------- |
| Jump to page N                | Yes                      | No                               |
| Performance at deep pages     | Degrades                 | Constant                         |
| Handles inserts between pages | Poorly (duplicates/gaps) | Cleanly                          |
| Implementation complexity     | Simple                   | Moderate                         |
| Best for                      | Small data, admin UIs    | Feeds, timelines, large datasets |


---

### API Gateway

A single entry point that sits in front of all your backend services and handles cross-cutting concerns.

**What it does:**

- **Routing** — `/users/`* → User Service, `/orders/*` → Order Service
- **Authentication** — Validate JWT/API keys before requests hit services
- **Rate limiting** — 1000 req/min per API key
- **Throttling** — Reject excess traffic with HTTP 429
- **Request/response transformation** — Add headers, rewrite paths, convert XML to JSON
- **Caching** — Cache GET responses to reduce backend load
- **Logging & monitoring** — Centralized request logging
- **Circuit breaking** — Stop forwarding to a failing service

**Why it matters:** Without a gateway, every service needs to implement auth, rate limiting, and logging independently. A gateway centralizes this.

**When to use an API Gateway vs just a Load Balancer:**

- **One service, multiple endpoints** (e.g. `/purchase` and `/return` in the same codebase) → **Load balancer only.** The app handles its own routing internally.
- **Multiple services behind one domain** (e.g. `/purchase` → Purchase Service, `/return` → Returns Service, separate codebases on different servers) → **API gateway** to route between them + centralize auth, rate limiting, and logging. Each service still has its own load balancer behind the gateway.

The gateway exists because of **multiple services**, not multiple endpoints.

**API Gateway vs Reverse Proxy vs Load Balancer:**

- **Load Balancer** — Distributes traffic across instances of the SAME service
- **Reverse Proxy** (Nginx) — Forwards requests to backend servers, can do caching/SSL
- **API Gateway** — All of the above + auth, rate limiting, request transformation, API-specific logic

**Examples:** AWS API Gateway, Kong, Envoy, Istio Ingress Gateway, Traefik

---

### Service Mesh & mTLS

**Service Mesh:** A dedicated infrastructure layer for managing service-to-service communication. Implemented as sidecar proxies (Envoy) attached to every pod.

**What it handles:**

- **mTLS** — Automatic encryption and mutual authentication between services
- **Traffic management** — Retries, timeouts, circuit breaking, traffic splitting
- **Observability** — Automatic metrics, traces, and logs for all traffic
- **Access control** — Service A can talk to Service B but not Service C

**mTLS (Mutual TLS):**

- Normal TLS: client verifies server identity
- Mutual TLS: BOTH sides verify each other's identity
- The mesh's CA (Certificate Authority) issues certificates to every sidecar
- Certificates are automatically rotated

**Why mTLS in microservices:** Zero-trust networking. Don't trust any traffic just because it's "internal." If an attacker compromises one pod, they can't impersonate another service because they don't have a valid certificate.

**Examples:** Istio, Linkerd, Consul Connect

**When to use a service mesh:**

- Many microservices (15+) and you need consistent networking policies across all of them
- You need mTLS between all services (zero-trust networking)
- You want automatic observability (metrics, traces) for all service-to-service traffic without instrumenting each service
- You need traffic management (canary routing, traffic splitting) at the network level
- Multiple teams own different services and you can't rely on each team implementing networking correctly

**When you don't need one:**

- A few services — the overhead isn't worth it
- Running a monolith
- Small team that can manage networking concerns in application code
- You don't want the operational complexity of running Istio/Linkerd

**The general principle:** A service mesh makes sense when managing mTLS, retries, timeouts, and observability individually in each service becomes unsustainable — you push it to the infrastructure layer so it's consistent and automatic.

---

## 2. Data Storage

### SQL (Relational Databases)

Data stored in tables with rows and columns. Strict schema. Relationships via foreign keys. Transactions with ACID guarantees.

**ACID:**

- **Atomicity** — Transaction either fully completes or fully rolls back (no partial writes)
- **Consistency** — Database moves from one valid state to another (constraints are enforced)
- **Isolation** — Concurrent transactions don't interfere with each other
- **Durability** — Once committed, data survives crashes (written to disk)

**Important: ACID doesn't prevent race conditions by default.** PostgreSQL's default isolation level is Read Committed. Two transactions can both read a row, see the same value, and both write — the second overwrites the first. This is the read-then-write race condition. To prevent it:

- **Atomic conditional update** — combine the check and write into one statement: `UPDATE seats SET status = 'sold' WHERE seat_id = 'A5' AND status = 'available'`. If the WHERE clause doesn't match (someone else already changed it), 0 rows are affected. Check the affected row count in your app. No lock needed, no separate read.
- **Pessimistic locking (SELECT FOR UPDATE)** — lock the row when you read it: `SELECT * FROM seats WHERE seat_id = 'A5' FOR UPDATE`. The second transaction blocks until the first commits. Use when you need complex logic between the read and write.
- **Optimistic locking (version column)** — add a `version` column. Read the version, do your logic, then `UPDATE ... WHERE version = 3`. If someone else changed it, version won't match. No lock held during your logic — good for low-contention scenarios.

Use atomic conditional updates for simple inventory/booking systems. Pessimistic locking for complex multi-step logic on the same row. Optimistic locking when contention is rare and you want to avoid holding locks.

**When to use SQL:**

- Data has clear relationships (users → orders → products)
- You need transactions (transfer $100 from account A to B — both or neither)
- You need complex queries (JOINs, aggregations, GROUP BY)
- Schema is well-defined and doesn't change often

**Examples:** PostgreSQL, MySQL, Aurora, SQL Server

---

### NoSQL Databases

**Document stores (MongoDB, DynamoDB):**

- Store JSON-like documents
- Flexible schema — each document can have different fields
- Good for: Content management, user profiles, catalogs
- Bad for: Complex relationships, multi-document transactions

**Key-Value stores (Redis, DynamoDB, Memcached):**

- Simple: key → value
- Extremely fast (sub-millisecond for in-memory)
- Good for: Caching, session storage, leaderboards, rate limiting
- Bad for: Complex queries, relationships

**Redis specifically** is more than a simple key-value store. It has specialized data structures:

- **Sorted sets** — Every entry has a score, Redis keeps them sorted automatically. Perfect for leaderboards, rankings, "top N" queries. Update a score = O(log n), get top 100 = O(k). Always sorted, no query-time sorting needed.
- **Lists** — Message queues, activity feeds
- **Sets** — Unique items, intersections (mutual friends)
- **HyperLogLog** — Count unique items (unique visitors) with minimal memory

**Key insight:** Whenever you hear "ranking," "top N," or "real-time sorted data" in an interview — think Redis sorted sets, not a database with ORDER BY.

**Pub/Sub** — Redis has a built-in publish/subscribe system. Any client can publish a message to a channel, and all clients subscribed to that channel receive it instantly. Use for: real-time messaging between servers (e.g., WebSocket servers relaying chat messages — User A on Server 1 sends a message, Server 1 publishes to Redis, Server 3 is subscribed and pushes it to User B). Fire-and-forget — if a subscriber is down, it misses the message. No persistence, no replay. That's fine for real-time use cases (if the server was down, the user wasn't connected anyway). For durable event streaming where you need replay and persistence, use Kafka instead.

**Key insight:** When you need real-time message relay between servers (chat, live collaboration, notifications), think Redis Pub/Sub. When you need durable event streaming with replay, think Kafka.

**Geospatial indexing** — Redis has built-in geo commands that let you store locations and query by radius efficiently. `GEOADD` stores a coordinate, `GEORADIUS` returns all members within X km of a point. Under the hood it uses a sorted set with geohash encoding — the radius query doesn't scan every entry, it uses the index to find only nearby ones. For 60,000 entries, a radius query returns in sub-millisecond. PostgreSQL has the same capability via the **PostGIS** extension, and DynamoDB can do it with geohash-based keys. **Key insight:** Whenever you hear "find nearby X" in an interview (drivers, restaurants, stores, friends), the answer is a geospatial index — not brute-force distance calculation in application code.

**Wide-column stores (Cassandra, HBase):**

- Rows with dynamic columns, organized by partition key
- Designed for massive write throughput and horizontal scaling
- Good for: Time-series data, IoT, event logging, messaging
- Bad for: Ad-hoc queries, transactions

**Graph databases (Neo4j, Amazon Neptune):**

- Nodes and edges (relationships are first-class citizens)
- Good for: Social networks, recommendation engines, fraud detection
- Bad for: Simple CRUD, bulk data processing

**When to use NoSQL:**

- Schema changes frequently
- Massive scale with simple access patterns (get by ID)
- High write throughput needed
- Denormalization is acceptable

---

### Time-Series Databases (InfluxDB, TimescaleDB, Prometheus, Amazon Timestream)

Purpose-built for timestamped data points — metrics, telemetry, IoT sensor data, monitoring. Every data point is a timestamp + value (e.g., "at 10:05:03, CPU was 72%"). The primary query pattern is always by time range: "show me CPU for the last hour."

**Why not PostgreSQL or MongoDB?**

- Metric ingestion can be 50,000+ data points per second. Relational DBs aren't designed for this sustained write volume on time-ordered data.
- Time-range queries ("average latency over the last 6 hours, grouped by minute") require aggregation across millions of rows — slow in a general-purpose DB, fast in a TSDB because the storage engine is organized by time.

**What makes them different:**

- **Columnar, time-ordered storage** — data is compressed in time-ordered blocks, making writes fast and time-range scans efficient
- **Built-in downsampling** — automatically reduce granularity as data ages. Last 24 hours: per-second. Last 30 days: 1-minute averages. Last year: 1-hour averages. Same data, fraction of the storage. Nobody needs per-second granularity from 6 months ago
- **Built-in retention policies** — automatically delete data older than X days/months
- **Native aggregation functions** — avg, max, min, percentiles over time windows are first-class operations

**Key insight:** Whenever you hear "metrics," "monitoring," "telemetry," or "time-series" in an interview, the answer is a time-series database — not PostgreSQL, not MongoDB, not Elasticsearch. Use downsampling for the storage problem instead of dumping raw data to S3.

**Examples:** Prometheus (pull-based, popular in Kubernetes), InfluxDB (push-based, general purpose), TimescaleDB (PostgreSQL extension — familiar SQL interface), Amazon Timestream (serverless, managed).

---

### Elasticsearch (Search Engine)

Elasticsearch is a search engine built specifically for full-text search. Regular databases answer "give me the row where `id = 123`" — they know exactly where to look. Search asks "give me everything that *contains* the word 'cooking' in the title, description, or tags, ranked by relevance." A regular database has to scan every row. At 200 million rows, that's brutal.

**How it works — inverted indexes:**

- Like the index at the back of a textbook. Instead of reading every page to find "cooking," you go to the index: "cooking → documents #12, #45, #892." Instant lookup regardless of dataset size.
- Elasticsearch builds this index for every word across every field automatically.

**What it does that SQL can't do well:**

- **Fuzzy matching** — "cookin" still finds "cooking"
- **Relevance scoring** — results ranked by how well they match, not just match or no match
- **Tokenization** — "New York pizza recipe" matches documents containing those words in any order
- **Autocomplete** — prefix-based suggestions as the user types

**The CQRS pattern with Elasticsearch:**

```
Write path: App → PostgreSQL (source of truth)
            → async sync (queue or CDC) → Elasticsearch

Read path:  Search queries → Elasticsearch (fast, ranked results)
            Normal CRUD → PostgreSQL
```

PostgreSQL stores your data. Elasticsearch makes it searchable. They serve different purposes.

**General principle:** Whenever your system needs user-facing search (search bars, filtering, autocomplete, "find similar"), use Elasticsearch. Don't make PostgreSQL do it — `LIKE '%term%'` can't use indexes, doesn't rank results, and gets slower as data grows. Elasticsearch scales horizontally and stays fast regardless of dataset size.

**Examples:** YouTube (video search), Netflix (content discovery), GitHub (code search), Amazon (product search), any app with a search bar.

---

### SQL vs NoSQL Decision Framework


| Factor            | SQL                                | NoSQL                       |
| ----------------- | ---------------------------------- | --------------------------- |
| Schema            | Fixed, well-defined                | Flexible, evolving          |
| Relationships     | Complex (JOINs)                    | Simple or denormalized      |
| Transactions      | Multi-row ACID                     | Usually single-document     |
| Scale             | Vertical first, then read replicas | Horizontal from the start   |
| Query flexibility | Ad-hoc queries, aggregations       | Primarily key-based lookups |
| Consistency       | Strong by default                  | Eventual (tunable)          |


---

### Replication

Copying data across multiple database instances. There are three replication modes — know when to use each.

**Mode 1: Single Primary (Master-Replica / Primary-Secondary)**

- **One node** accepts all writes. Replicas receive copies and handle reads.
- If primary dies, one replica is promoted to become the new primary (failover).
- Simple — no conflict resolution needed because there's only one source of truth for writes.
- Trade-off: all writes go to one place, so write throughput has a ceiling, and writes from distant regions have higher latency.
- **Use for:** Anything where consistency matters — inventory, payments, user accounts. This should be your default choice.

**Mode 2: Multi-Primary (Multi-Master)**

- **Multiple nodes** accept writes simultaneously.
- Needed when you want low-latency writes in multiple regions (e.g., users in US and EU both writing frequently).
- **The hard part is conflict resolution** — if a user updates their email on the US master and EU master simultaneously, which one wins?
- Trade-off: you get fast writes everywhere but must deal with conflicting writes.
- **Use for:** When you truly need low-latency writes in every region AND the data can tolerate conflict resolution. Product catalogs, user preferences — yes. Inventory counts, financial balances — no.

**Mode 3: Leaderless (Peer-to-Peer / No Primary)**

- **Any node** can accept both reads and writes. No special "primary" node.
- Uses quorum — write to W nodes, read from R nodes. As long as W + R > N (total nodes), you get consistency.
- No failover needed — there's no single leader to lose.
- Trade-off: more complex consistency model, harder to reason about.
- **Examples:** Cassandra, DynamoDB.
- **Use for:** Massive scale, high availability, when eventual consistency is acceptable.

**Quick decision guide:**


| Need                                      | Mode                                     |
| ----------------------------------------- | ---------------------------------------- |
| Consistency matters (payments, inventory) | Single primary                           |
| Fast writes in multiple regions           | Multi-primary (with conflict resolution) |
| Massive scale, high availability          | Leaderless                               |
| Not sure / default choice                 | Single primary                           |


---

**Synchronous vs Asynchronous replication** (applies to any mode with replicas):

**Synchronous replication:**

- Primary waits for at least one replica to confirm write before responding to client
- Guarantees consistency — that replica always has latest data
- Slower writes (waiting for network round trip to replica)
- Typically one synchronous replica (for safety) + remaining replicas async (for performance)

**Asynchronous replication:**

- Primary responds to client immediately, then sends write to replica in the background
- Faster writes
- Risk: replica might be slightly behind (replication lag)
- If primary crashes before replicating, that data is lost

**When to use sync:** Two conditions must BOTH be true:

1. **The data is critical enough that you can't lose even the most recent write.** If the primary crashes 1 second after a write, that write must already exist on another node. Active rides, financial transactions, inventory decrements, payment records.
2. **The replica is close enough that the round trip doesn't kill latency.** Same region / same AZ = 1-2ms round trip, barely noticeable. Cross-region = 100-200ms per write — unacceptable.

If either condition is false, use async.

**When to use async:** Everything else.

- Data that can tolerate a small window of potential loss (profiles, feeds, analytics, read receipts)
- Replicas that are far away (cross-region read replicas — can't beat the speed of light)
- High write throughput where you can't afford to wait (messaging, logging, activity feeds)

**The standard production pattern:**

- **Within a region:** One sync replica (safety net — guaranteed latest data for failover) + additional async replicas (read scaling — slightly behind but fast). The sync replicas also double as read replicas.
- **Across regions:** Always async. The physics of distance makes sync impractical.


| Question                                  | Answer                                         |
| ----------------------------------------- | ---------------------------------------------- |
| Is this write-critical data I can't lose? | Yes → sync to at least one nearby replica      |
| Is the replica in the same region?        | No → async (distance makes sync too expensive) |
| Is write throughput a priority?           | Yes → async (sync slows every write)           |
| Is this profile/feed/analytics data?      | Yes → async (small loss window is acceptable)  |


---

**Consistency patterns — know these three:**

**Eventual consistency** (weakest) — If no new writes happen, all replicas eventually converge to the same value. No promise about when. This is the default for most async-replicated systems (DynamoDB, Cassandra). Use for browse-phase data where staleness is acceptable — feeds, catalogs, analytics, "last seen" timestamps.

**Read-after-write consistency** — After a user writes, they can immediately read their own write. Everyone else might still see stale data until replication catches up, but the user who wrote always sees their own change. Implement by routing a user's reads to the node they just wrote to. Use for any user-facing write — posting a tweet, sending a message, updating a profile.

**Strong consistency** (strongest) — Every read returns the most recent write, period. Most expensive in latency and availability because it requires synchronous replication or reading from the primary. Use for commit-phase data where being wrong has real consequences — payments, inventory at checkout, account balances.

---

**Conflict resolution strategies** (for multi-primary):

- **Last-write-wins (LWW)** — Timestamp each write, latest one wins. Simple but can silently lose data. Used by DynamoDB, Cassandra.
- **Version vectors** — Track the version history of each record across nodes. Detect conflicts and let the application decide how to merge. More accurate than LWW but more complex.
- **Application-level resolution** — Present both conflicting versions to the user and let them choose (like Google Docs showing merge conflicts). Most correct but requires UI/UX work.

**Interview tip:** Don't jump to multi-master. The simpler approach is single primary + read replicas in each region (fast local reads, writes go to the primary with higher latency). Only go multi-master when you truly need low-latency writes in every region, and always mention the conflict resolution trade-off.

**Interview tip:** Read replicas are your first scaling lever for read-heavy workloads. If 90% of traffic is reads, adding 3 read replicas gives you ~4x read capacity without changing anything else.

---

### Sharding (Horizontal Partitioning)

Splitting your database across multiple instances, each holding a subset of data.

**Shard key selection** — The most important decision:

- **Hash-based:** `shard = hash(user_id) % num_shards` — Even distribution, but range queries are expensive because the hash scatters sequential data randomly across shards (user 1000 on Shard 3, user 1001 on Shard 1, user 1002 on Shard 5). A query like "get users 1000-2000" has to hit every shard and merge results.
- **Range-based:** Users 1-1M on shard 1, 1M-2M on shard 2 — Easy range queries, but risk of hotspots
- **Directory-based:** A lookup table maps each entity to its shard — Flexible but the directory is a single point of failure

**Problems with sharding:**

- **Cross-shard queries** — "Find all orders across all users" requires querying every shard and merging results
- **Cross-shard joins** — If two related tables live on different shards, you can't JOIN them. You either denormalize (store all needed data in one table so you never need to join) or do application-level joins (query each shard separately and combine results in your code)
- **Resharding** — Adding a new shard means redistributing data. Consistent hashing minimizes this
- **Hotspots** — A celebrity's shard gets hammered. Solution: further split hot shards or add caching

**Consistent hashing:**

- Instead of `hash % N` (which redistributes everything when N changes), map both servers and keys onto a ring
- When adding a server, only keys between the new server and its neighbor get moved
- Minimizes data movement during resharding

**Different access patterns need different data models.** Your shard key is optimized for one access pattern. Any query that doesn't use that shard key hits every shard (expensive). If you have two fundamentally different ways you query data, maintain a secondary store optimized for the second pattern. Example: primary store sharded by `user_id` for user-scoped queries, secondary store indexed by timestamp for time-range queries across all users. Same data, different organization, different questions.

**When to shard — general principle:** Shard when you have massive writes that a single primary can't handle, or when your data is too large to fit on one machine. Read replicas solve read load. Caching solves repeated reads. Multi-master solves multi-region writes. But none of those split the dataset — sharding is the only option that divides data across machines, scaling both write throughput and storage.

**Interview tip:** Don't shard prematurely. The order is: optimize queries → add indexes → vertical scaling → read replicas → caching → THEN shard if you still need to. Always show you've considered simpler options first.

---

### Caching

Store frequently accessed data in memory for fast retrieval.

**Cache strategies:**

**Cache-aside (Lazy loading):**

1. App checks cache
2. Cache miss → query DB
3. Write result to cache
4. Return to client

- Pro: Only caches what's actually requested
- Con: First request is always slow (cache miss)

**Write-through:**

1. App writes to cache AND DB simultaneously
2. Reads always hit cache (always fresh)

- Pro: Cache is always consistent with DB
- Con: Write latency increases, caches data that may never be read

**Write-behind (Write-back):**

1. App writes to cache only
2. Cache asynchronously writes to DB later

- Pro: Fastest writes
- Con: Data loss risk if cache crashes before DB write

**Read-through:**

1. App asks cache for data
2. On miss, CACHE queries DB (not the app)
3. Cache stores result and returns to app

- Pro: App logic is simpler
- Con: Cache needs DB access

**Cache eviction policies:**

- **LRU (Least Recently Used)** — Evict the item that hasn't been accessed longest (most common)
- **LFU (Least Frequently Used)** — Evict the item accessed least often
- **TTL (Time to Live)** — Items expire after N seconds regardless of access

**TTL as a safety net:** Always set a TTL on cached data, even when using write-through or explicit invalidation. If any cache update mechanism fails — write-through didn't fire, invalidation was missed, a bug in your code — the stale entry self-destructs after the TTL expires. TTL is your last line of defense against serving stale data indefinitely.

**Cache problems:**

**Cache stampede / Thundering herd:**

- Popular cache key expires
- 1000 concurrent requests all miss cache at the same time
- All 1000 hit the DB simultaneously
- Fix: Use locking — first request acquires a lock (in Redis), goes to the DB, gets the data, writes it to the cache, releases the lock. All other requests for the same key wait for the lock to release, then read from the cache. One DB query instead of thousands.

**Cache penetration:**

- Repeated requests for data that doesn't exist in DB
- Every request misses cache AND misses DB
- Fix: Cache the "not found" result with a short TTL, or use a Bloom filter

**Cache avalanche:**

- Many cache keys expire at the same time
- Massive spike in DB traffic
- Fix: Add random jitter to TTL values so expirations are spread out

**Hot key problem:**

- One cache key gets disproportionate traffic (celebrity profile, viral post)
- Single cache node becomes bottleneck
- Fix: Replicate hot keys across multiple cache nodes, or use local in-memory cache

---

### Indexing

Indexes speed up database reads at the cost of slower writes. Three things to know:

1. **Indexes speed up reads, slow down writes.** Every INSERT/UPDATE/DELETE also updates every index on that table. If writes are slow and the table has 15 indexes, that's likely why.
2. **Composite indexes — order matters.** An index on `(user_id, created_at)` helps queries filtering by `user_id` or `user_id + created_at`, but NOT `created_at` alone. In systems design, this matters when discussing database schema and access patterns.
3. **Not everything should be indexed.** Indexes cost storage and write performance. Only index columns you actually query on (WHERE, JOIN, ORDER BY clauses).

---

### Database Scaling Principles — The Decision Framework

When a database can't keep up, the fix depends on what's bottlenecked. Follow this order — each step is cheaper and simpler than the next. Only move down the list when the previous step isn't enough.

**Scaling reads (in order of priority):**


| Step                               | What it does                                                                                                               | When to use                                                                                                       |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| 1. Add indexes                     | Makes queries faster — a full table scan taking 200ms becomes a 2ms index lookup. Same hardware handles 100x more queries. | Always do first. Check slow query logs, add indexes on columns used in WHERE, JOIN, ORDER BY.                     |
| 2. Add caching (Redis/ElastiCache) | Hot data served from memory in sub-millisecond. Eliminates 70-80% of DB reads for most workloads.                          | Frequently-read data that tolerates slight staleness — product pages, session data, user profiles.                |
| 3. Add read replicas               | Copies of the database that handle read traffic. Primary handles writes only.                                              | Reads that can't be cached — complex queries, low-frequency data, freshness-sensitive reads, analytics/reporting. |
| 4. Shard the database              | Split data across multiple databases. Each shard holds a subset of data.                                                   | Only when data is too large for one machine or read replicas aren't enough. Last resort for reads.                |


**How caching and read replicas work together:**

```
Read request comes in
  → Check cache (Redis) → hit → return immediately (sub-ms)
  → Cache miss → query read replica (not the primary)
  → Store result in cache for next time
  → Return to user
```

Cache handles hot data. Read replicas handle the long tail. Primary handles only writes. Each layer protects the one behind it.

**Scaling writes (in order of priority):**


| Step                            | What it does                                                                                                        | When to use                                                                                                             |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| 1. Optimize queries and indexes | Reduce write amplification — fewer/better indexes means faster writes (every index must be updated on every write). | Table has 10+ indexes and writes are slow. Drop unused indexes.                                                         |
| 2. Vertical scaling             | Bigger instance — more CPU, memory, IOPS.                                                                           | Quick fix when you're close to the ceiling but haven't optimized yet.                                                   |
| 3. Write-behind caching         | Queue writes in Redis/memory and batch-flush to DB. Reduces per-write overhead.                                     | High-volume writes where slight delay to DB is acceptable (analytics events, activity logs).                            |
| 4. Shard the database           | Split data across multiple primaries. Each shard handles writes for its subset.                                     | When a single primary truly can't keep up with write volume. The hard option — introduces cross-shard query complexity. |


**Scaling connections:**


| Problem                                                                   | Solution                                                                                                                                                            |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Too many application connections overwhelming the database                | **RDS Proxy** (works with RDS and Aurora). Pools and multiplexes connections — 500 app connections become 50 actual DB connections. Prevents connection exhaustion. |
| Serverless workloads (Lambda) opening hundreds of short-lived connections | **RDS Proxy** — especially important here because each Lambda invocation opens a new connection. Without pooling, you hit the DB connection limit fast.             |


**The interview answer — prioritize in this order:**

1. Optimize queries and add indexes (free, immediate impact)
2. Add caching for hot reads (high impact, low effort)
3. Add read replicas for remaining reads
4. Vertical scale the primary if writes are bottlenecked
5. Implement connection pooling (RDS Proxy) if connections are the limit
6. Shard only when everything above isn't enough

**Key insight:** Most scaling problems are read problems, and most read problems are solved by caching before you ever need replicas or sharding. In an interview, always show you've considered the simpler options before reaching for the complex ones.

---

### CAP Theorem

In a distributed system experiencing a network partition, you must choose between Consistency and Availability.

**C — Consistency:** Every read returns the most recent write or an error
**A — Availability:** Every request gets a non-error response (but data might be stale)
**P — Partition Tolerance:** System continues working despite network failures between nodes

**You always need P** (networks fail in distributed systems). So the real choice is:

**CP (Consistency + Partition Tolerance):**

- During a partition, system returns errors rather than stale data
- Examples: MySQL, PostgreSQL, MongoDB (default), HBase, Redis (cluster mode)
- Use for: Financial transactions, inventory systems, anything where stale data causes real problems

**AP (Availability + Partition Tolerance):**

- During a partition, system returns whatever data it has (might be stale)
- Examples: Cassandra, DynamoDB (eventually consistent), CouchDB, DNS
- Use for: Social media feeds, product catalogs, analytics — where slightly stale data is acceptable

**PACELC extension:**

- If **Partition** → choose A or C
- **Else** (normal operation) → choose **Latency** or **Consistency**
- Example: DynamoDB is PA/EL — during partition picks availability, during normal operation picks low latency (eventually consistent reads are faster)

**Interview tip:** CAP only applies DURING a network partition. During normal operation, you can have all three. Don't say "MongoDB is CP so it's not available" — it's highly available during normal operation.

**Key principle — different components, different trade-offs:** Don't blanket your entire system with one CAP choice. Break it into parts and ask "what happens if this specific component serves stale data?" Read-heavy browsing (product catalogs, feeds, search results) can tolerate staleness → AP. Write/commit operations (checkout, payments, transfers) cannot → CP. Example: Amazon product pages are served from eventually consistent caches (fast, available), but "Place Order" hits the consistent source for real-time inventory and pricing.

---

### Browse vs Commit — The Most Reusable Pattern in Systems Design

Almost every user-facing system has two phases: the user **looks** at data, then **acts** on it. These two phases have fundamentally different consistency requirements.

**Browse phase** — user is viewing data. Speed and availability matter. Slight staleness is acceptable because nothing consequential is happening. Serve from caches, read replicas, CDN — the fast, eventually consistent layer.

**Commit phase** — user takes an action based on what they saw (buy, book, transfer, reserve). Now accuracy matters because real consequences happen — money moves, inventory decrements, seats get locked. Read from the **primary database directly** — the strongly consistent source of truth.

**The principle: serve stale data on browse, check the source of truth on commit.**

**How to apply it:** For any piece of data in your system, ask: "What happens if this is 30 seconds stale?" If the answer is "nothing bad" — cache it, serve it fast. If the answer is "real consequences" — read from the consistent source at the moment of action.

**Examples of this pattern everywhere:**


| System          | Browse (fast, stale OK)                   | Commit (must be accurate)                         |
| --------------- | ----------------------------------------- | ------------------------------------------------- |
| E-commerce      | Product page shows "In Stock" from cache  | Checkout checks real inventory from primary DB    |
| Flight booking  | Search shows available seats from cache   | Booking confirms real-time seat availability      |
| Banking         | Dashboard shows balance from read replica | Transfer checks real balance from primary         |
| Concert tickets | Listing shows "available" from cache      | Purchase reserves the specific seat in real-time  |
| Ride-sharing    | App shows nearby drivers (approximate)    | Ride request checks real-time driver availability |


**Handling the gap — the reservation pattern:** Since there's always a delay between browse and commit, users can see "In Stock" and get "Sold out" at checkout. To shrink this gap, temporarily reserve the resource when the user signals intent (add to cart, start checkout). Hold it for N minutes — if they don't complete, release it. This is how concert tickets, hotel bookings, and limited-edition drops work.

**In an interview:** When designing any system where users view data then act on it, explicitly call out this split. "Browsing reads from the AP layer for speed. The commit path reads from the CP source for accuracy. If there's a conflict, we handle it gracefully with a clear error and optionally use reservations to reduce the window."

---

## 3. Scaling

### Horizontal vs Vertical Scaling

**Vertical (Scale Up):**

- Bigger machine: more CPU, more RAM, faster disk
- Simple — no code changes
- Has a ceiling (you can't get a 10,000-core server)
- Single point of failure
- Example: Upgrading RDS from db.t3.medium to db.r5.2xlarge

**Horizontal (Scale Out):**

- More machines running the same thing
- No ceiling — add as many as you need
- Requires stateless design (or distributed state management)
- Adds complexity: load balancing, data consistency
- Example: HPA adding more pods, adding read replicas

**Scaling strategy by tier:**


| Tier            | First Move                   | Then                         |
| --------------- | ---------------------------- | ---------------------------- |
| Web/API servers | Horizontal (stateless, easy) | More instances behind LB     |
| Database reads  | Read replicas                | Caching layer                |
| Database writes | Vertical scaling             | Sharding                     |
| Cache           | Bigger instance              | Cluster mode (Redis Cluster) |


---

### Stateless vs Stateful Services

**Stateless:**

- No data stored between requests
- Every request contains everything needed (JWT in header, etc.)
- Can be horizontally scaled trivially — kill/add instances freely
- Examples: REST APIs, Lambda functions

**Stateful:**

- Maintains data between requests (sessions, connections, in-memory state)
- Cannot be freely scaled — need to handle state transfer/replication
- Examples: Databases, WebSocket servers, in-memory caches

**Rule:** Make your application tier stateless. Push all state to dedicated stateful services (databases, caches, message queues).

---

### Rate Limiting

Controlling how many requests a client can make in a given time window. Protects services from abuse, brute-force attacks, and overload.

**What you need to know for interviews:** Mention rate limiting as a protection mechanism at the API gateway / load balancer level. For distributed systems (multiple instances), use Redis-backed rate limiting. You don't need to implement algorithms from scratch — tools like NGINX, Istio, and AWS API Gateway have it built in.

**Token Bucket (know this one):** Bucket holds N tokens, refills at rate R per second. Each request consumes one token. Empty bucket = request rejected (HTTP 429). Allows short bursts (bucket can be full) while enforcing an average rate (refill speed). This is what AWS API Gateway, NGINX, and Istio use under the hood.

**Sliding Window (just know it exists):** Track the number of requests in a rolling time window (e.g., last 60 seconds). If the count exceeds the limit, reject. More precise than token bucket — no burst allowance — but more complex to implement. Used when you need strict "no more than X requests per minute" without allowing bursts.

**Where rate limiting is applied:** API gateway for external traffic, service mesh for internal service-to-service traffic, Redis for distributed rate limiting across multiple instances of a service. You configure these tools — you don't implement the algorithms.

---

### Virtual Waiting Room (Queue-Based Flow Control)

For systems with predictable traffic spikes (flash sales, ticket drops, product launches), don't try to scale big enough to handle everyone simultaneously — control the inflow.

**How it works:**

1. Users hit a static waiting room page (served from CloudFront/S3 — handles millions with zero backend load)
2. The page polls a lightweight queue service: "is it my turn yet?"
3. A queue controller releases users in controlled batches (e.g., 5,000 at a time) based on backend capacity
4. When a user gets a token, they're allowed through to the actual application. The API validates the token on every request
5. When a user completes checkout or their session expires (e.g., 5-minute timeout), that slot opens for the next user

**Why not just scale up?** Even with pre-scaling, HPA, and cluster autoscaler, reactive scaling takes 30-60+ seconds. A flash sale thundering herd hits in the first 5 seconds. The waiting room ensures your backend only ever sees a manageable, predictable load regardless of how many users are waiting.

**Use for:** Any system where you know when a traffic spike will happen — ticket sales, product launches, registration openings, limited-time offers.

---

### Temporary Reservation (Hold with TTL)

In booking/inventory systems where users select an item and then spend time completing checkout, use a temporary hold to prevent conflicts and wasted user effort.

**How it works:**

```sql
UPDATE seats SET status = 'held', held_by = 'user1', held_until = NOW() + INTERVAL '5 minutes'
WHERE seat_id = 'A5' AND status = 'available';
```

The item is immediately shown as unavailable to other users. If the user completes payment within the timeout, the status moves to "sold." If they don't, a background cleanup job sets expired holds back to "available."

**Why not just check at checkout?** Without a hold, a user spends 3 minutes entering payment info, submits, and discovers someone else bought the item while they were typing. That's terrible UX. A temporary hold guarantees the item is theirs for a window of time.

**Use for:** Ticket booking, hotel reservations, shopping carts with limited inventory, seat selection on airlines.

---

### Strategy / Plugin Pattern for Varying Business Logic

When a workflow is the same but one step varies by type, isolate the varying part behind a common interface instead of hardcoding if/else logic everywhere.

**Example:** A ticket platform sells concerts (general admission — decrement a counter), theater (assigned seats — lock a specific row), and conferences (capacity only — check count vs max). The purchase flow (reserve → pay → confirm → notify) is the same for all. Only the "reserve" step differs. Each event type has its own inventory service implementation behind a common "reserve" interface. Adding a new event type means writing one new service — not touching the purchase flow.

**The principle:** Separate what changes from what stays the same. The same pattern applies to notification channels (email, SMS, push behind a "send" interface), payment providers (Stripe, PayPal behind a "charge" interface), etc.

---

## 4. Reliability & Availability

### Availability Numbers

You don't need to memorize the table — know the intuition:

- **Three nines (99.9%)** = ~8-9 hours downtime/year. This is the baseline most systems target.
- **Four nines (99.99%)** = ~52 minutes/year. Required for payments, critical infrastructure.
- **Each additional nine is 10x harder and 10x more expensive.**

The real interview skill is **matching availability to the use case:**

- Payment system → four nines, can't afford more than an hour/year of downtime
- Social media feed → three nines is fine, slightly stale data is acceptable
- Internal analytics dashboard → two nines is plenty

**What you DO need to know — series vs parallel:**

**Series = a chain. Every link must hold.** A request flowing through `User → LB → API Server → Database` passes through all three. If any one is down, the request fails. Multiply the availabilities:

```
99.9% × 99.9% × 99.9% = 99.7%
```

It gets worse with every component you add to the request path. Five services at 99.9% each = 99.5% = 43+ hours downtime/year.

**Parallel = backups. Only one needs to work.** Two API servers behind a load balancer — the request only fails if BOTH are down at the same time. Multiply the failure rates:

```
0.1% × 0.1% = 0.0001% chance both are down
→ 99.9999% availability
```

Every service you chain in the request path makes availability worse. Every redundant copy you run in parallel makes it better. That's the core argument for load balancers and multiple replicas at every layer — you're converting series risk into parallel redundancy.

---

### Redundancy & Fault Tolerance

**Single point of failure (SPOF):** Any component whose failure takes down the entire system.

**Eliminate SPOFs by:**

- Running multiple instances behind a load balancer
- Multi-AZ deployments (survive an entire data center failure)
- Multi-region deployments (survive an entire AWS region failure)
- Database replication with automatic failover
- Multiple load balancers (DNS-level failover)

**N+1 AZ redundancy:** Each AZ should be able to handle full production load on its own. If you need 4 pods minimum at peak, run 4 per AZ — not 2 and 2. HPA handles gradual load increases but can't save you from a sudden AZ loss (scaling takes 30-60+ seconds).

**topologySpreadConstraints:** Tells Kubernetes to spread pods evenly across zones (or nodes). Without this, the scheduler may pack pods unevenly — e.g., 6 in AZ-a and 2 in AZ-b — because one AZ had more available resources. That breaks your AZ failure math. With the constraint, you specify a `maxSkew` (e.g., 1) meaning the difference in pod count between any two zones can't exceed 1. If the constraint can't be met, `DoNotSchedule` blocks the pod, `ScheduleAnyway` allows it but tries its best. This replaces the older pod anti-affinity approach, which is less flexible.

**Multi-region — active-passive vs active-active:**

- **Active-passive:** Standby region only takes traffic on failover. Simpler, but idle infrastructure costs money and failover isn't instant (DNS TTL, cold caches).
- **Active-active:** Both regions serve traffic all the time via latency-based routing. No wasted capacity, lower latency for global users, but the database layer is hard — you need cross-region replication and must deal with conflict resolution if both regions accept writes.

---

### Health Checks

**Liveness probe:** "Is the process alive?" If it fails, the container is restarted.

- Example: HTTP GET /healthz returns 200

**Readiness probe:** "Is the service ready to handle traffic?" If it fails, the pod is removed from the Service's endpoints (no traffic routed to it).

- Example: Check database connectivity, check that cache is warm

**Startup probe:** "Has the service finished starting?" Protects slow-starting containers from being killed by liveness probes.

---

### Circuit Breaker Pattern

Prevents cascading failures when a downstream service is failing.

**States:**

1. **Closed** (normal) — Requests flow through. Failures are counted.
2. **Open** (tripped) — After N failures, circuit opens. All requests immediately fail with a fallback response. No requests sent downstream.
3. **Half-open** (testing) — After a timeout, allow ONE request through. If it succeeds, close the circuit. If it fails, reopen.

**Why it matters:** Without a circuit breaker, if Service B is down, Service A keeps sending requests, consuming threads/connections, eventually Service A goes down too (cascading failure).

---

### Retries, Timeouts, and Idempotency

**Timeouts:** Always set timeouts on outbound calls. Without them, a hung downstream service will exhaust your connection pool and take you down.

- Connect timeout: How long to wait for a TCP connection (short: 1-5s)
- Read timeout: How long to wait for a response (longer: 5-30s)

**Retries:** Automatically retry failed requests.

- **Exponential backoff:** Wait 1s, 2s, 4s, 8s between retries (don't hammer a struggling service)
- **Jitter:** Add randomness to backoff to prevent retry storms (all clients retrying at the exact same time)
- **Max retries:** Cap at 3-5 retries

**Idempotency:** An operation that produces the same result regardless of how many times it's executed. Critical for safe retries.

- GET is naturally idempotent
- DELETE is naturally idempotent (deleting something twice = same result)
- POST is NOT idempotent (submitting a payment twice = charged twice)
- Make POST idempotent with an **idempotency key** — client sends a unique ID, server deduplicates

---

### How Timeouts, Retries, Circuit Breakers, and Idempotency Work Together

**The general principle: assume every network call will fail, and design for it.**

In any distributed system, services call other services. Every call can fail — the downstream can be slow, overloaded, crashed, or unreachable. These four patterns are your escalation ladder for handling those failures:

```
Service A calls Service B:
  → TIMEOUT — don't wait forever (5s). If no response, give up on this attempt.
  → RETRY — maybe it was a blip. Try again with exponential backoff + jitter (1s, 2s, 4s). Cap at 3 attempts.
  → IDEMPOTENCY KEY — included with the request so retries are safe (no double-charges, no duplicate records).
  → CIRCUIT BREAKER — if failures keep happening across many requests, stop trying entirely. Fail fast, return a fallback. Periodically test if the service has recovered.
```

Each pattern handles a different failure duration:

- **Timeout** protects a single request from hanging forever
- **Retries** handle momentary blips (one request failed, next one might work)
- **Circuit breaker** handles sustained outages (stop wasting resources on something that's clearly down)
- **Idempotency** makes retries safe (the same request processed twice produces the same result)

**Hot path vs background — when to retry and when to fall back:**

- **On the hot path (user is waiting):** One attempt with a short timeout. If it fails, immediately return a fallback (cached value, default, graceful degradation). Never make the user wait for retry logic. Example: user places an order, pricing service call fails → immediately return the last cached delivery fee. User doesn't notice.
- **Off the hot path (background process):** Retries with exponential backoff are fine. Queue consumers, batch jobs, async service calls — the user isn't waiting, so you can afford to retry 3-5 times with increasing delays. Example: payment processing from SQS — retry with backoff, user sees "processing" but isn't blocked.

The general rule: **if a human is staring at a loading spinner, don't retry — fall back. If it's a background process, retry.**

**Interview tip:** Whenever you draw two services communicating, mention these. "Service A calls Service B with a 5-second timeout, retries with exponential backoff up to 3 times, includes an idempotency key for safe retries, and has a circuit breaker that trips after 5 consecutive failures." That one sentence shows you understand distributed failure modes and it's free points every time.

---

### Deployment Strategies

**Rolling update:**

- Replace instances one by one with the new version
- **Pro:** Zero downtime, no extra infrastructure cost, simple to set up
- **Con:** Slow rollback (have to reverse the rolling update one by one). During the rollout, both old and new versions serve traffic simultaneously — if they're incompatible (different API contracts, DB schema changes), things break.
- **Use for:** Routine deployments where old and new versions are compatible. The default choice for most teams.

**Blue-Green:**

- Run two identical environments (blue = current, green = new). Switch all traffic from blue to green instantly.
- **Pro:** Instant rollback — just switch traffic back to blue. Clean cutover — no mixed versions serving traffic.
- **Con:** Double the infrastructure cost during deployment. Database migrations are tricky — both environments share the DB, so schema changes must be backward-compatible.
- **Use for:** Critical services where instant rollback is non-negotiable. When you can't afford mixed-version traffic (breaking API changes).

**Canary:**

- Route a small percentage of traffic (5%) to the new version. Monitor for errors. Gradually increase (5% → 25% → 50% → 100%).
- **Pro:** Limits blast radius — if the new version is broken, only 5% of users are affected. Real production traffic validates the deployment before full rollout.
- **Con:** More complex to set up (traffic splitting, monitoring, automated promotion). Slower to fully deploy. Two versions run simultaneously (same compatibility concern as rolling).
- **Use for:** High-risk changes where you want real production validation before committing. Large-scale systems where even a brief full outage is unacceptable.

**A/B Testing:**

- Similar to canary but driven by business metrics, not just errors. Route specific user segments to different versions.
- **Pro:** Measure real business impact (conversion, engagement, revenue) before committing to a change.
- **Con:** Requires analytics infrastructure. Not a deployment safety strategy — it's a product experimentation tool.
- **Use for:** Feature changes where the question is "is this better for users?" not "does this work?"


| Strategy    | Rollback Speed | Extra Cost | Blast Radius           | Best For                            |
| ----------- | -------------- | ---------- | ---------------------- | ----------------------------------- |
| Rolling     | Slow           | None       | Gradual exposure       | Routine, compatible changes         |
| Blue-Green  | Instant        | 2x infra   | All-or-nothing         | Critical services, breaking changes |
| Canary      | Fast           | Small      | Controlled (5% → 100%) | High-risk changes, large systems    |
| A/B Testing | Fast           | Small      | Controlled segments    | Product experimentation             |


**Key decision — canary vs blue-green:**

- Can two versions coexist? Yes → **canary.** Safer, smaller blast radius. Catches production-only bugs (load issues, race conditions, data edge cases) on 5% of traffic before all users see them. Default choice for most deployments.
- Can two versions coexist? No → **blue-green.** Clean cutover, instant rollback. Required when the change must apply uniformly to all users at the same time (regulatory changes, tax rates, pricing rules, compliance updates).

### Shadow Traffic / Dark Launching

Used when migrating to a new service (e.g., extracting a microservice from a monolith). Before routing real user traffic to the new service, send a **copy** of every request to it in the background. Compare the new service's response to the old service's response — but only return the old service's response to the user. The user is never affected.

- If responses match for a sustained period → the new service is behaving correctly, safe to start routing real traffic via canary
- If responses differ → you have a bug in the new service, fix it before any real user ever hits it
- **Use for:** Monolith-to-microservice migrations, replacing a critical service, any time you need high confidence that a new service behaves identically to the old one before going live

---

### Database Migrations — Expand and Contract Pattern

When a code deployment also requires a schema change (adding/removing columns, changing types), you can't deploy both at the same time. If the new code and new schema go out together and you need to roll back the code, the old code is now running against a schema it doesn't understand. Things break.

**The expand and contract pattern (two-phase migration):**

**Phase 1 — Expand (schema first):**

- Deploy the schema change BEFORE the code change
- Add the new column with a default value, or create the new table
- The old code keeps running fine — it just ignores the new column
- Verify the migration worked, no issues

**Phase 2 — Deploy new code:**

- Now deploy the new application version (blue-green, canary, whatever fits)
- New code uses the new column
- If you need to roll back the code, the old code still works — it just ignores the column it doesn't use

**Phase 3 — Contract (cleanup, later):**

- Once the new version is stable and you're confident you won't roll back
- Remove old columns, drop defaults, clean up anything no longer needed

**Why this matters:** Schema changes and code changes deployed in the same step create a coupling that makes rollback dangerous. Decoupling them means you can roll back one without breaking the other. Every major tech company uses this pattern for zero-downtime migrations.

**Example:**

- Old code: `SELECT id, amount FROM orders` (no tax_rate column)
- Phase 1: `ALTER TABLE orders ADD COLUMN tax_rate DECIMAL DEFAULT 0.08` — old code still works, ignores the new column
- Phase 2: Deploy new code: `SELECT id, amount, tax_rate FROM orders` — uses the new column
- Rollback safe: if new code breaks, old code still works with the extra column sitting there unused
- Phase 3: weeks later, drop the default once everything is confirmed stable

**Backfilling existing data — batch processing:**

When a migration requires transforming existing data (e.g., parsing 50 million address strings into separate columns), you can't run one giant UPDATE — it locks the table, blocks production writes, and may time out or crash.

- **Process in small batches** — e.g., 1,000 rows at a time. Parse, write, commit, move to the next batch. Each lock is short so normal operations continue between batches.
- **Throttle between batches** — add a small delay (e.g., 100ms) so the database isn't running backfill and production traffic at full speed simultaneously.
- **Track progress with a cursor** — store the last processed ID. If the backfill crashes halfway through 50 million rows, resume from where you left off instead of starting over.
- **Code must handle both states** — during the backfill, some rows have old format, some have new. Your code checks for the new columns first, falls back to the old column if not yet migrated. Once backfill is complete, remove the fallback logic (contract phase).

**Never ALTER COLUMN type on a large table in production.** In many databases (especially MySQL), changing a column type rewrites every row in the table. On 200 million rows, that means the table is locked for minutes or hours — blocking all reads and writes. Instead, add a new column alongside the old one, backfill in batches, switch the code to use the new column, then drop the old one later. Adding a column is nearly instant (just metadata), altering a column type is a full table rewrite.

**Dual-write during transitions.** While both old and new columns exist and code is being migrated, write to BOTH columns on every new record. That way old code reading the old column and new code reading the new column both have correct data. Once migration is complete and all code uses the new column, stop writing to the old one.

**When existing data violates a new constraint:** If the schema change adds a constraint (unique index, NOT NULL, foreign key), clean up data BEFORE applying the schema change. Otherwise the migration fails — the database refuses to create a constraint that existing data violates.

---

### Expand and Contract — The Universal Migration Principle

This isn't just a database pattern. It applies any time a producer changes something that consumers depend on — database schemas, API response formats, event/message schemas, config file formats. The principle is always the same:

**Never break the contract between a producer and consumer in a single step.**

1. **Expand** — support old AND new simultaneously. Both formats work.
2. **Migrate** — move consumers to the new format one by one. Each migration is independent, testable, and rollback-safe.
3. **Contract** — remove the old format once nobody uses it.


| What's changing      | Expand                          | Migrate                              | Contract                   |
| -------------------- | ------------------------------- | ------------------------------------ | -------------------------- |
| Database column      | Add new column alongside old    | Update code to use new column        | Drop old column            |
| API response format  | Return both old and new fields  | Update clients to read new fields    | Remove old fields          |
| Event/message schema | Publish both old and new format | Update consumers to parse new format | Stop publishing old format |


At no point is anything broken. Each step is independently deployable and rollback-safe. If anything goes wrong at any stage, you roll back that one step and everything still works because the old format is still there.

---

### Database Migration Strategy — Native Replication vs Dual-Write

When migrating a live database, the approach depends on whether the old and new databases are compatible:

**Same engine or compatible (MySQL → Aurora, PostgreSQL → Aurora RDS):**

- Use **native replication.** Create a read replica of the old database on the new engine. Replication syncs data automatically in the background — no code changes, no dual-write logic.
- Once the replica is fully caught up: stop writes to old DB → wait for final sync → promote the replica to primary → point your app at the new DB. This is the only downtime window (minutes).
- Always use this path when available — it's simpler, safer, and requires no application changes.

**Different engines or incompatible (MySQL → DynamoDB, Oracle → PostgreSQL, AWS → GCP):**

- No native replication path exists. Fall back to:
  - **Dual-write** — change your application code to write to both old and new databases simultaneously during the transition. More engineering effort, risk of inconsistency if one write fails.
  - **CDC tool (e.g., AWS DMS)** — a dedicated service that reads the old database's change log and streams changes to the new database automatically. Less application code changes than dual-write.
- Batch-migrate existing data, use dual-write or CDC to capture in-flight changes, then cut over.


| Migration type                      | Approach                     | Code changes | Downtime                |
| ----------------------------------- | ---------------------------- | ------------ | ----------------------- |
| Same engine (MySQL → Aurora)        | Native replication + promote | None         | Minutes                 |
| Different engine (MySQL → DynamoDB) | Dual-write or CDC (AWS DMS)  | Yes          | Minutes (with planning) |


---

### Testing

Know the types, what they catch, and when to mention them in an interview.

**Unit tests:**

- Test a single function or method in isolation
- Fast, cheap, run on every commit
- Mock all dependencies (DB, APIs, etc.)
- Catch: logic bugs in individual functions
- Example: "does my tax calculation function return 8.5% correctly?"

**Integration tests:**

- Test how multiple components work together
- Slower, may need real databases or containers
- Catch: mismatched interfaces, broken API contracts, DB query issues
- Example: "does my API endpoint correctly write to the database and return the right response?"

**End-to-end (E2E) tests:**

- Test the full user flow from frontend to backend to database
- Slowest, most brittle, hardest to maintain
- Catch: full workflow failures that unit/integration tests miss
- Example: "can a user log in, add an item to cart, and complete checkout?"

**Load / Performance tests:**

- Simulate production-level traffic and measure latency, throughput, error rates
- Catch: performance regressions, resource bottlenecks, services that fall over at scale
- Example: "can the API handle 10,000 RPS with p99 latency under 500ms?"
- Tools: k6, Locust, JMeter

**Chaos / Resilience tests:**

- Intentionally break things in production or staging — kill pods, inject latency, drop network connections
- Catch: missing circuit breakers, bad failover behavior, cascading failures
- Example: "what happens if the payment service goes down? Does checkout fail gracefully?"
- Tools: Chaos Monkey, Litmus, Gremlin

**Smoke tests:**

- Quick sanity checks run immediately after a deployment
- Verify core functionality works — "can users log in? can the API respond?"
- If smoke tests fail, trigger an automated rollback
- Catch: completely broken deploys before users notice

**The testing pyramid (how much of each):**

```
        /  E2E  \          ← Few (slow, expensive, brittle)
       / Integration \      ← Moderate
      /    Unit Tests   \   ← Many (fast, cheap, reliable)
```

**Interview relevance:** You won't be asked to write tests in a systems design interview. But when discussing reliability, mention: "We'd have integration tests in CI, load tests before major releases, smoke tests post-deploy that trigger automated rollback, and chaos tests quarterly to validate our circuit breakers and failover."

---

## 5. Security

### Authentication vs Authorization

**Authentication (AuthN):** Verifying WHO you are.

- Something you know (password)
- Something you have (phone, security key)
- Something you are (fingerprint, face)

**Authorization (AuthZ):** Verifying WHAT you can do.

- Can this user access this resource?
- Can this service call that service?

Authentication always comes before authorization.

---

### Token-Based Authentication

**Session-based (traditional):**

1. User logs in → server creates a session, stores it server-side
2. Server sends session ID in a cookie
3. Every request includes the cookie
4. Server looks up session by ID

- Problem: Session state on server → hard to scale horizontally (need sticky sessions or shared session store)

**Token-based (modern):**

1. User logs in → server creates a JWT, sends it to client
2. Client stores JWT and sends it in Authorization header
3. Server validates JWT by checking signature (no server-side state needed)

- Pro: Stateless — any server can validate the token
- Con: Can't invalidate a token before expiry (see refresh token pattern below)

**The refresh token pattern (standard token strategy):**

- **Access token:** Short-lived (5-15 minutes). Sent with every API request. If stolen, attacker has a 15-minute window max.
- **Refresh token:** Long-lived (days/weeks). Used ONLY to request a new access token when the current one expires. Stored securely (HTTP-only cookie, never in localStorage). Never sent to regular API endpoints. Can be revoked server-side instantly because refresh tokens ARE checked against a database.

**Flow:**

1. User logs in → gets an access token (15 min) + refresh token (7 days)
2. User makes API calls with the access token — stateless, no DB lookup
3. Access token expires → client silently sends the refresh token to get a new access token — user never notices
4. Refresh token is compromised → revoke it server-side immediately, user has to re-login

This gives you short exposure windows (15 min) with long session duration (7 days) and instant revocation capability on the refresh token. Best of both worlds.

**Why not a token blacklist instead?** A blacklist works — check every incoming access token against a "revoked" list. But it breaks the stateless benefit of JWTs. Every API request now requires a database/Redis lookup to check the blacklist. At that point you've essentially recreated session-based auth with extra steps. Short access tokens + revocable refresh tokens avoid needing a blacklist entirely.

**JWT (JSON Web Token):**

- Three parts: `header.payload.signature`
- Header: algorithm (RS256, HS256)
- Payload: claims (sub, exp, iat, custom data)
- Signature: a cryptographic hash of the header + payload, produced using a secret key

**How signature verification works:**

1. At login: server takes the header + payload, runs them through a signing algorithm with a **secret key only the server knows**, producing the signature. The full token (`header.payload.signature`) is sent to the client.
2. On every request: server receives the token, takes the header + payload, reruns the same algorithm with the same secret key, and compares its result to the signature on the token.
3. Match → token is legitimate, nobody tampered with it. No match → someone modified the payload (changed user ID, extended expiration, etc.). Rejected.

The client can read the payload (it's just base64 encoded, not encrypted) but can't forge a valid signature without the secret key. Change one character in the payload and the signature won't match.

**Two signing approaches:**

- **HS256 (symmetric):** Same secret key signs and verifies. Simple. Signing server and verifying server must share the same secret.
- **RS256 (asymmetric):** Private key signs, public key verifies. Auth server signs with its private key. Any other service can verify with the public key without ever having the private key. Better for microservices — no need to share secrets across services.

**OAuth 2.0:**

- Authorization framework — lets third-party apps access user resources without passwords
- Flow: User → App → IDP login page → authorization code → App exchanges code for token
- Access token: Used to call APIs
- Refresh token: Used to get a new access token when it expires

**OIDC (OpenID Connect):**

- Identity layer built on OAuth 2.0
- Adds an **ID token** (a JWT) containing the user's identity — name, email, user ID
- OAuth tells the app "you can access this user's stuff." OIDC tells the app "this is who the user is." The ID token lets the app tie every action, record, and piece of data back to a specific person.
- OAuth can exist without OIDC — machine-to-machine and delegated API access never need to identify a person.
- "OIDC cannot exist without OAuth" is only true of the **login flow**. OIDC has two separable halves: the redirect flow (defined as additions to OAuth's `/authorize` and `/token`, so it genuinely needs OAuth) and **token + key discovery** (`.well-known/openid-configuration`, JWKS, ID token claims), which needs no OAuth at all. EKS IRSA uses only the second half — there is no OAuth anywhere in it.
- Why OIDC was built on OAuth at all: deployment economics, not logic. By 2014 every large provider already ran OAuth `/authorize` and `/token` at scale, so identity cost one new scope value and one extra field instead of new endpoints everywhere. Same reason `client_credentials` lives in the OAuth spec despite having no user, no delegation, and no consent.

**Revoking access — the token expiry gap:**
Removing a user from the IDP prevents new logins but doesn't invalidate tokens they already have. A user with a valid 1-hour token can still access the app for up to an hour after being deprovisioned. Close this gap with:

- **Short token TTL (5-15 minutes)** — limits the window where a revoked user still has a valid token
- **SCIM (System for Cross-domain Identity Management)** — a protocol where the IDP automatically notifies your app when a user is deactivated. Your app revokes their sessions and tokens in real-time. This is how enterprise SaaS platforms handle immediate deprovisioning.

**SSO (Single Sign-On):**

- You log in once to a central **Identity Provider (IdP)** — like Okta, Azure AD, or Google Workspace — and get access to multiple applications without logging in again.
- How it works: App A redirects you to the IdP → you authenticate → IdP gives you a token and redirects back → you're in. When you go to App B, it redirects to the same IdP → IdP sees your existing session → issues a token for App B without a login prompt.
- The IdP maintains the session. Each app trusts the IdP. Once the IdP knows who you are, every app that trusts it lets you in.

**Why App B doesn't prompt you again — the IdP session cookie (how Okta actually works):**

The magic isn't shared state between the apps; the apps never talk to each other. It's a **session cookie on the IdP's own domain**, and the browser is what carries it.

```
1. Visit App A (jira.company.com) → not logged in → redirect to okta.com
2. Authenticate at Okta (password + MFA)
   → Okta sets a session cookie for okta.com  ← the SSO session lives here
   → Okta issues an assertion/token for App A → redirect back
   → App A creates its OWN local session cookie for jira.company.com
3. Later, visit App B (github.company.com) → not logged in → redirect to okta.com
   → the browser automatically attaches the okta.com cookie to that request
   → Okta reads it: "this is Mehdi, authenticated 20 min ago, MFA satisfied"
   → issues a NEW assertion/token scoped to App B → redirect back. No prompt.
```

Key points that follow from this:

- **Two layers of session.** The IdP session (at `okta.com`) decides whether you get prompted. Each app's session (at its own domain) decides whether you stay logged into *that* app. They expire independently — an 8-hour Okta session with 1-hour app sessions means silent re-auth all day, no password.
- **Every app gets its own token.** Nothing is shared or reused — the IdP mints a fresh, audience-scoped assertion per app. App A's token is useless at App B.
- **MFA happens once**, at the IdP, and every app inherits it. This is the real security argument for SSO: you enforce MFA and password policy in one place instead of N places.
- **Step-up auth** — a sensitive app can demand a fresh or stronger authentication (SAML `ForceAuthn`, OIDC `prompt=login` / `max_age`), forcing a re-prompt even with a valid IdP session.
- **The browser is required.** SSO is built on redirects and cookies, so it only works for human/browser flows. Service-to-service uses client credentials, mTLS, or IRSA instead (see the decision tree below).
- **Logout is the hard part.** Killing your App A session doesn't kill the Okta session (you'd be silently logged back in), and killing the Okta session doesn't kill sessions already established at each app. **Single Logout (SLO)** — the IdP notifying every app to terminate — is notoriously unreliable in practice. This is the same gap as token expiry above: real deprovisioning needs short app sessions plus SCIM.

**SAML 2.0 vs OIDC:**

- **SAML 2.0** — older, XML-based, common in enterprise. The IdP sends a signed XML assertion to the app.
- **OIDC** — modern, JSON/JWT-based, built on OAuth 2.0. The IdP issues a JWT ID token. Most new apps use this.
- Interview default: "Delegate to a central IdP via OIDC or SAML. Never roll your own auth for internal tools."

**Machine-to-machine authentication patterns:**

**Client credentials grant (OAuth):** The application has a client ID and client secret. It exchanges them directly for an access token. No human involved, no browser redirect. Use for: backend services calling APIs, CI/CD pipelines, monitoring tools.

**JWT assertion with asymmetric keys (how GitHub Apps work):**

1. App creates a JWT locally and signs it with a **private key** that only it has
2. App sends the JWT to the API (e.g., GitHub)
3. API verifies the JWT signature using the corresponding **public key**
4. If valid, API issues a scoped access token back to the app

- More secure than client credentials — the private key never travels over the network. Only the signed JWT does.
- Use for: high-security machine-to-machine authentication, GitHub Apps, GCP service accounts

**When to use OAuth without OIDC:**

- No human user whose identity matters — machine-to-machine communication (Service A calling Service B), CI/CD pipelines accessing cloud resources, monitoring tools pulling metrics
- The app only needs permission to perform actions, not to personalize or store data per user

**When to use OAuth + OIDC:**

- A human user is involved and the app needs to know who they are — "Sign in with Google," creating user accounts, personalizing the experience, storing data tied to a specific user
- Any time the app needs to say "Welcome back, John" or associate records with a user

---

### The Five Auth Modes

Pick by who is calling. Each mode answers a different question.

**1. Service → service, same infra — mTLS.** Certs from an internal CA or mesh (Istio/SPIFFE), short-lived and auto-rotated. No secrets to store or leak, and identity is bound to the connection rather than to a copyable bearer string. Gives you authentication only — whether ServiceA may call `DELETE /accounts` is a separate policy decision.

**2. Service → service, same cloud — cloud IAM.** IRSA / Pod Identity on EKS, SigV4 request signing. No secrets at all. Catch: AWS is the verifier, so this works natively only when AWS is in the path (API Gateway with IAM auth, ALB, Lambda, or AWS services directly). For your own HTTP server, validate the caller's SigV4 yourself by forwarding it to STS `GetCallerIdentity`.

**3. Service → service, across trust boundaries — OAuth `client_credentials`.** Register the caller with an IdP → `client_id` + `client_secret` → POST to the IdP's token endpoint → JWT access token → callee validates against the IdP's JWKS. The callee holds no secret for the caller, so onboarding a new caller needs no change on the callee. **Must check `aud`** — otherwise a token legitimately minted for ServiceC replays against ServiceB and the signature still verifies.

**4. App → third party on a user's behalf — OAuth authorization code.** The original use case. Redirect → `code` → backend exchanges it (with `client_secret`) for an access token + refresh token. Both stay server-side; the browser gets only the app's own session cookie, which is also the key used to look up that user's stored access token. No ID token needed — the app never learns who the user is.

**5. User → your service — OIDC via a managed IdP.** Redirect to the IdP, user authenticates *there* (app never sees credentials), `code` comes back, backend exchanges it for an `id_token`, verify signature via JWKS plus `iss`/`aud`/`exp`/`nonce`, read `sub`, then mint **your own** session cookie. Don't build the IdP: password reset, MFA, lockout, and breach detection are a lot of surface area to own.

**What each mode actually answers:**

| Mode | Question answered |
| --- | --- |
| mTLS / cloud IAM | which *workload* is calling |
| `client_credentials` | which *app* is calling |
| Authorization code (no OIDC) | what may this app do *on a user's behalf* |
| OIDC | which *person* is this |

**The constant across all five:** verification is a local public-key signature check against a cached JWKS or CA cert. Never call the issuer per request — that turns it into a single point of failure and a latency tax on all traffic. The cost of local verification is that you cannot revoke a live token, which is why access tokens are short-lived (5–15 min) and the *refresh* token is the revocable part.

**Propagating user identity through a call chain:** mTLS and IAM only ever identify the immediate caller, and that identity dies at the first proxy that terminates TLS. If a service three hops down needs to know which end user triggered the request, that must ride in a forwarded JWT. Most mature systems run both: mTLS for the channel, a token for the user.

---

### Encryption

**At rest:** Data stored on disk is encrypted.

- Database encryption (RDS encryption, S3 server-side encryption)
- Disk encryption (EBS encryption)
- Application-level encryption (encrypt sensitive fields before storing)

**In transit:** Data moving between systems is encrypted.

- TLS/HTTPS between client and server
- mTLS between services
- VPN for cross-network communication

**Symmetric vs Asymmetric encryption — know when to use each:**

- **Symmetric:** One key encrypts AND decrypts. Fast. Use for encrypting data — database fields, files, disk encryption. All bulk data encryption uses symmetric keys.
- **Asymmetric (public/private keys):** Public key encrypts, private key decrypts (or private signs, public verifies). 100-1000x slower than symmetric. Use for authentication (JWTs, mTLS), signing, and key exchange — NOT for bulk data encryption.

**Application-level encryption — when the threat is insiders:**
Standard database encryption (RDS encryption) encrypts the disk, but the database engine decrypts transparently for anyone who can query it. A DBA runs `SELECT * FROM patients` and sees plain text. Disk encryption only protects against physical disk theft, not authorized users.

To prevent DBAs from reading sensitive data, encrypt at the application layer:

- App encrypts sensitive fields (diagnosis, SSN, etc.) BEFORE writing to the database
- Database stores ciphertext — DBA sees gibberish
- Only the application can decrypt because only the application has access to the encryption key

**Key management:** Never store encryption keys alongside encrypted data.

- AWS KMS (Key Management Service) — AWS manages the keys
- HSM (Hardware Security Module) — Dedicated hardware for key storage

**Envelope encryption (how KMS works in practice):**

1. App asks KMS: "give me a data key"
2. KMS generates a symmetric data key and returns two copies — one plain text, one encrypted with the master key
3. App uses the plain text data key to encrypt the patient record (fast, symmetric)
4. App stores the encrypted record AND the encrypted data key in the database
5. App discards the plain text data key from memory
6. To decrypt: app sends the encrypted data key to KMS, KMS decrypts it using the master key, app uses the plain text data key to decrypt the record

The master key never leaves KMS. The plain text data key only exists in memory briefly. The DBA sees encrypted records and an encrypted data key — both useless without KMS access.

**Why envelope encryption instead of encrypting directly with KMS?** KMS has API rate limits (~5,000-10,000 req/s) and every call is a network round trip. If you're encrypting millions of records, you'd bottleneck on KMS. With envelope encryption, you call KMS once to get a data key, then encrypt thousands of records locally — fast, no network calls. KMS only gets involved when generating or decrypting data keys.

**When to use envelope encryption:**

- Encrypting database fields at the application layer (healthcare, fintech — data DBAs shouldn't see)
- Encrypting files before storing in S3 (SSE-KMS uses envelope encryption under the hood)
- Any bulk data encryption where you need centralized key management but can't afford a KMS call per record

**When you don't need it:**

- Storage-level encryption (RDS encryption, EBS encryption) — AWS handles this transparently
- Signing tokens (JWTs) — that's asymmetric signing, not data encryption
- Low-volume encryption where calling KMS directly per operation is fine

---

### Secret Management

Never hardcode credentials, API keys, or passwords in code or config files.

**Solutions:**

- **Environment variables** — Simple but visible in process listings and logs
- **Secret stores** — AWS Secrets Manager, HashiCorp Vault, Kubernetes Secrets
- **External Secrets Operator** — Syncs cloud secrets (AWS Secrets Manager) into Kubernetes Secrets automatically

**Best practices:**

- Rotate secrets regularly (automate this)
- Least privilege — each service only gets the secrets it needs
- Audit access to secrets
- Never log secrets

---

### AWS WAF (Web Application Firewall)

Sits in front of **CloudFront or the ALB** and filters malicious HTTP traffic before it reaches your servers — SQL injection, XSS, bad bots, and volumetric attacks (with AWS Shield for DDoS). Rule-based (managed rule groups + custom rules), can rate-limit by IP.

**Interview line:** "WAF at the edge to block application-layer attacks, rate limiting at the API Gateway for per-user throttling." WAF handles *attack patterns*; rate limiting handles *volume per client*.

---

### Defense in Depth

Layer multiple independent controls so no single failure exposes the system:

1. **WAF** at the edge (CloudFront/ALB) — blocks SQLi, XSS, bots.
2. **Subnet isolation** — only the ALB is public; app servers and databases sit in private subnets with no public IP.
3. **Security groups** — per-resource firewalls restricting which ports/sources can talk to each instance.
4. **NetworkPolicies** — pod-level firewalls inside the cluster (restrict blast radius if one pod is compromised).
5. **IAM least privilege + encryption** at rest/in transit underneath it all.

Even if one layer is bypassed, the others still hold. Interview phrasing: "WAF at the edge, ALB in public subnet, everything else private, security groups per service, least-privilege IAM."

---

### IAM + IdP Federation (human access to AWS)

Never create IAM users with long-lived keys for people. Instead:

1. User tries to access AWS → redirected to the company IdP (IAM Identity Center / Okta / Azure AD).
2. Authenticates there (SSO + MFA) → IdP returns a SAML/OIDC assertion with the user's groups.
3. AWS maps groups → IAM roles (`devops` group → `DevOpsRole`).
4. User gets **temporary credentials via STS** (auto-expiring).

No permanent credentials, no IAM users. Offboard = revoke in the IdP → AWS access gone everywhere. (Workloads use the same idea: EC2 instance roles, Lambda execution roles, **IRSA** for pods.)

---

### API Authentication — Decision Tree

- **End user (web/mobile)** → OIDC/OAuth via external IdP; validate JWT at the API Gateway.
- **Third-party developer / public API** → API keys (hashed in DB, rate-limited per key).
- **Service → service (internal)** → mTLS (zero-trust) or API keys for simpler setups.
- **Service → AWS resource** → IAM roles; on EKS, IRSA or Pod Identity (no stored credentials).
- **External system → your webhook** → HMAC signature (shared secret; verifies sender + payload integrity).
- **Enterprise employee SSO** → OIDC (SAML if the IdP is legacy AD-only).

Note: JWT is a token *format*, not a protocol — used by both OIDC and OAuth.

---

## 6. Observability

### Three Pillars of Observability

**Metrics:**

- Aggregated numerical data over time
- Examples: Request rate, error rate, CPU usage, memory usage
- Tools: Prometheus, CloudWatch, Datadog
- Use for: Dashboards, alerting, trend analysis
- Question they answer: "What is happening?"

**Traces:**

- Follow a single request as it flows through multiple services
- Shows latency at each hop, which service is slow
- Tools: Jaeger, Tempo, Zipkin, X-Ray
- Use for: Debugging slow requests, understanding service dependencies
- Question they answer: "Where is it slow and why?"

**Logs:**

- Timestamped text records of events
- Examples: Error messages, audit trails, debug output
- Tools: ELK Stack (Elasticsearch, Logstash, Kibana), Loki, CloudWatch Logs
- Use for: Debugging specific errors, audit compliance
- Question they answer: "What went wrong?"

---

### Golden Signals (Google SRE)

The four metrics you should always monitor:

1. **Latency** — How long requests take, measured in percentiles:
  - **p50 (median)** — 50% of requests are faster than this. The typical user experience.
  - **p95** — 95% of requests are faster. Only 5% are slower. The experience for most users.
  - **p99** — 99% of requests are faster. Only 1% are slower. The worst-case experience.
  - Example: p50 = 50ms, p95 = 200ms, p99 = 2s means most users are fine but 1 in 100 waits 2 seconds.
  - **Why percentiles, not averages:** 99 requests at 50ms + 1 request at 10s = 150ms average. Looks fine. But one user waited 10 seconds. Averages hide tail latency — percentiles expose it.
2. **Traffic** — How many requests per second (request rate)
3. **Errors** — What percentage of requests fail (error rate)
4. **Saturation** — How "full" your system is across all resource dimensions — CPU, memory, disk, network bandwidth, connection pools, thread pools. Any resource that has a limit. A system can have low error rates and normal latency but be at 95% CPU — one traffic spike and it falls over. Latency and errors tell you things are broken now. Saturation tells you things are about to break.

If you can only build four dashboards, build these four.

---

### Alerting Best Practices

- Alert on **symptoms**, not causes ("error rate > 5%" not "CPU > 80%")
- Every alert should be **actionable** — if you can't do anything about it, don't alert
- Use severity levels: critical (page someone), warning (investigate next business day)
- Avoid alert fatigue — too many alerts = people ignore them all

### Troubleshooting Triage Order

When something is wrong in production, follow this order:

1. **Metrics (golden signals)** — *what's* wrong? Is it latency, errors, traffic spike, or saturation? Narrows from "something is slow" to "Service A's p99 latency spiked and error rate is up."
2. **Traces** — *where* in the request chain is it slow? Is it Service A itself, or waiting on Service B, or a database call? Traces pinpoint the bottleneck.
3. **Logs** — *why* is it slow? The specific error message, the slow query, the timeout, the OOM event. Logs give you the root cause.
4. **Kubernetes / infrastructure state** — is the infrastructure the cause? Pod restarts, CPU throttling, node events, HPA status. Catches problems that don't show up in application logs.

Metrics tell you *what*, traces tell you *where*, logs tell you *why*, infrastructure state tells you *if the platform is the cause*.

---

## 7. Message Queues & Async Processing

### Why Queues?

Decouple producers from consumers. Instead of Service A calling Service B directly (synchronous), Service A puts a message on a queue and Service B processes it later (asynchronous).

**Benefits:**

- **Decoupling** — Services don't need to know about each other
- **Buffering** — Handle traffic spikes by absorbing messages in the queue. If your service handles 1,000 req/sec and a spike sends 10,000 req/sec, the queue absorbs the burst. Your service keeps processing at its own pace — requests just wait in line instead of overwhelming the service. The queue doesn't make your service faster, it prevents it from being crushed.
- **Reliability** — If consumer is down, messages wait in the queue
- **Scalability** — Add more consumers to process faster

**Dead letter queue (DLQ):** Messages on a normal queue that fail processing get retried. After N failed attempts (usually 3-5), instead of retrying forever or silently dropping, the message moves to a separate dead letter queue.

```
Normal Queue → consumer tries → fails
            → retry 1 → fails
            → retry 2 → fails
            → retry 3 → fails
            → moved to DLQ → alert fires → human investigates
```

The DLQ keeps your normal queue clean and flowing while preserving failed messages (poison messages) so nothing is lost. Critical for financial operations (failed refunds, failed payments) where you can never silently lose a message.

**SQS visibility timeout — how retries actually work in SQS:**
When a consumer picks up a message from SQS, the message isn't deleted — it becomes *invisible* to other consumers for a configured duration (the visibility timeout, e.g., 60 seconds). During this window, the consumer processes the message:

- **Success:** Consumer explicitly deletes the message from the queue. It's gone permanently.
- **Failure (crash, timeout, error):** Consumer never deletes the message. After the visibility timeout expires, SQS makes the message visible again and another consumer (or the same one) picks it up for another attempt.

SQS tracks how many times a message has been received. Once it exceeds the **max receive count** (e.g., 3), SQS automatically moves it to the DLQ. You don't build retry logic in your application — SQS handles redelivery natively.

```
Message arrives in SQS
  → Consumer picks it up (message becomes invisible for 60s)
  → Processing fails, consumer crashes
  → 60s passes, message reappears in queue (attempt 2 of 3)
  → Consumer picks it up again, fails again
  → 60s passes, message reappears (attempt 3 of 3)
  → Consumer picks it up, fails again
  → Max receive count exceeded → SQS moves message to DLQ
```

**Key design decisions:**

- **Visibility timeout** should be longer than your maximum processing time. If processing takes 45 seconds and timeout is 30 seconds, SQS will re-deliver the message while the first consumer is still processing — causing duplicate processing.
- **Max receive count** balances between giving transient failures a chance to recover and not retrying permanent failures endlessly. 3-5 is typical.
- **DLQ consumers should classify failures** — transient failures (timeouts, service outages) can be retried on a longer schedule. Permanent failures (invalid data, card declined) need human intervention or user notification.

**Idempotency with retries:** Since SQS can redeliver the same message multiple times, your consumer must be idempotent — processing the same message twice should produce the same result. For payments, this means generating a unique idempotency key per transaction (e.g., `payment_{ride_id}`) and passing it to the payment provider. The provider returns the original result on duplicate calls instead of processing a new charge.

**Interview relevance:** Any system that processes payments, orders, or critical events through a queue needs this pattern: visibility timeout for automatic retries, max receive count as a circuit breaker, DLQ for failed messages, and idempotency keys to prevent duplicate processing. This comes up in nearly every e-commerce or fintech system design.

---

### Queue vs Pub/Sub

**Message Queue (Point-to-point):**

- One message is consumed by ONE consumer
- Message is deleted after processing
- Examples: SQS, RabbitMQ
- Use for: Task processing, job queues, work distribution

**Pub/Sub (Fan-out):**

- One message is delivered to ALL subscribers
- Each subscriber gets its own copy
- Examples: SNS, Kafka topics, Google Pub/Sub
- Use for: Event notifications, broadcasting (user signed up → send email AND update analytics AND notify admin)

**Standard SQS vs SQS FIFO:**


|            | Standard SQS                                                                                              | SQS FIFO                                                                                                |
| ---------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Ordering   | Best-effort, not guaranteed                                                                               | Strict ordering within a message group                                                                  |
| Delivery   | At-least-once (duplicates possible)                                                                       | Exactly-once processing                                                                                 |
| Throughput | Virtually unlimited                                                                                       | 3,000 msg/sec with batching, 300 without                                                                |
| Use for    | High-throughput workloads where order doesn't matter (email sends, image processing, general task queues) | Workloads where order matters (order status updates, financial transactions, state machine transitions) |


**How FIFO ordering works:** You assign a **message group ID** to each message (e.g., the order ID). FIFO guarantees all messages in the same group are delivered one at a time, in order. The next message is not released until the previous one is acknowledged. Different message groups are processed in parallel — Order #123 and Order #456 don't block each other.

**When to use FIFO:** Any time events represent state transitions that must be applied in sequence — order status changes, account balance updates, workflow steps. If processing Event B before Event A would corrupt your data or confuse your users, use FIFO.

**Defense in depth:** Even with FIFO, implement state machine validation in the consumer — only allow forward state transitions. If ordering somehow breaks (bug, migration, replay), the consumer rejects invalid transitions. Two layers: ordering at the queue, validation at the consumer.

---

### Kafka vs SQS — Queues vs Event Streaming

**SQS** is a message queue — a message is delivered to one consumer, and once processed and deleted, it's gone. Good for task distribution where each message needs to be processed once.

**Kafka** is an event streaming platform — messages are written to a log and stay there for a configurable retention period (hours, days, forever). Multiple consumers can read the same stream independently at their own pace. Consumers don't "consume" messages — they read from a position in the log and track their own offset.


|                   | SQS                                                   | Kafka                                                                         |
| ----------------- | ----------------------------------------------------- | ----------------------------------------------------------------------------- |
| Message lifecycle | Deleted after processing                              | Stays in log for retention period                                             |
| Consumers         | One consumer per message                              | Multiple independent consumers read the same stream                           |
| Ordering          | Best-effort (FIFO available)                          | Guaranteed within a partition                                                 |
| Throughput        | High (virtually unlimited for standard)               | Very high (millions of events/sec)                                            |
| Use for           | Task queues, job processing, one consumer per message | Event streaming, multiple consumers need the same data, high-volume ingestion |


**When to use Kafka over SQS:** When multiple services need to independently process the same stream of events. Example: truck telemetry → Consumer 1 updates Redis (real-time tracking), Consumer 2 checks for anomalies (alerting), Consumer 3 archives to S3 (historical analytics). One stream, three independent consumers. With SQS, you'd need SNS fan-out to three separate queues. With Kafka, all three consumers just read the same topic.

**Quick decision rule:**

- One producer, one consumer, process-and-delete → **SQS** (simpler, cheaper)
- High volume, multiple independent consumers, need event replay → **Kafka / Kinesis**
- Need to ask: "Are thousands+ events/sec flowing in? Do multiple services need the same events? Might I need to replay events later?" If yes to any → Kafka/Kinesis.

---

### Data Analytics Pipeline — Kinesis Firehose, S3, Athena, Redshift

For high-volume data that needs to be stored and queried analytically (telemetry, logs, audit events, clickstream data), the standard AWS pattern is a streaming pipeline.

**Kinesis Data Firehose:** A managed delivery service that takes streaming data and automatically batches, compresses, converts to efficient formats (Parquet), and delivers to S3, Redshift, or Elasticsearch. Zero code — configure it and it runs. Use it to get streaming data into S3 without writing a custom consumer.

**S3 + Athena (serverless analytics):**

- Store raw data in S3 as compressed Parquet files, partitioned by date/hour
- Athena queries S3 directly using standard SQL — no database to manage
- Pay per query, not per hour. No always-on infrastructure.
- Best for: massive volume, infrequent or variable query patterns, compliance reports run weekly/monthly

**Redshift (managed data warehouse):**

- Always-on cluster with dedicated compute and storage
- Faster for complex recurring queries and dashboards that need sub-second responses
- Pay per hour whether you query or not
- Best for: frequent complex queries, BI dashboards, multiple analysts running queries constantly


|              | S3 + Athena                        | Redshift                                    |
| ------------ | ---------------------------------- | ------------------------------------------- |
| Storage cost | Very cheap ($0.023/GB/month)       | More expensive (compute + storage)          |
| Query speed  | Seconds to minutes                 | Sub-second to seconds for optimized queries |
| Management   | Serverless, nothing to manage      | Cluster to manage, resize, tune             |
| Best for     | Massive volume, infrequent queries | Frequent complex queries, fast dashboards   |
| Pay model    | Per query                          | Per hour (always-on)                        |


**The decision:** If compliance runs a report once a week against billions of rows → S3 + Athena. If fleet managers need a live dashboard refreshing every 10 seconds → Redshift (or pre-aggregate into Redis/PostgreSQL).

**Common pipeline pattern:**

```
High-volume events → Kafka → Kinesis Firehose → S3 (Parquet, partitioned by date)
                                                  → Athena for ad-hoc queries
                                                  → Redshift for dashboards (optional)
```

**Interview relevance:** Any scenario with high-volume event data (IoT telemetry, audit logs, clickstream, transaction history) should use this pipeline pattern. PostgreSQL is not designed for billions of append-only events — use the right tool for the job.

---

### Event-Driven Architecture

Services communicate through events rather than direct HTTP calls. Three patterns to know:

---

**Event Sourcing — "store what happened, not what is"**

Normally you store current state: "Account balance = $500." If someone asks "how did we get to $500?" — no idea.

With event sourcing, you store every event that happened:

```
1. Deposit  $1,000
2. Withdraw $200
3. Withdraw $300
→ Current balance = $500 (derived by replaying events)
```

You never store the balance directly — it's always calculated from the event history.

**Why it matters:**

- Full audit trail — you can prove exactly how you got to the current state
- Time travel — "what was the balance on March 1st?" Replay events up to that date
- Never lose information — updating state overwrites history, appending events preserves everything

**Use for:** Financial systems, banking, accounting, healthcare — anywhere you need to prove how the current state was reached. Regulatory and compliance-heavy domains.

**For your roles:** You probably won't design event sourcing systems, but know what it is and when it's used. It comes up when interviewers ask about audit trails or financial record-keeping.

**Snapshots — making event sourcing practical at scale**

The problem with pure event sourcing: replaying millions of events to reconstruct current state (or any past state) is slow and expensive. A collaborative document edited for months could have hundreds of thousands of operations.

The solution: periodically save a **snapshot** — a full copy of the current state at a specific point in time.

How it works:

1. Operations are continuously appended to the log (this never changes)
2. Every N operations (e.g., 100) or every T time interval (e.g., 1 hour), save a full snapshot of the state
3. To reconstruct state at any timestamp:
  - Find the nearest snapshot **before** the target time
  - Load that snapshot (complete, standalone — doesn't depend on other snapshots)
  - Replay only the operations between that snapshot and the target time

Example: Document has 50,000 operations over a month. Snapshots every 100 ops = 500 snapshots. User wants the version from Tuesday at 3 PM. Find the nearest snapshot before that time, load it, replay ~30 operations. Done in milliseconds instead of replaying 50,000 operations.

Trade-off: snapshots use more storage (each is a full state copy), but dramatically reduce reconstruction time. Balance frequency: too often = wasted storage, too rarely = slow reconstruction. Tune based on operation volume and access patterns.

Same pattern appears in: Redis RDB persistence, EBS snapshots, database point-in-time recovery, video game save points.

---

**CQRS (Command Query Responsibility Segregation) — "reads and writes go to different places"**

Normally your app reads and writes to the same database. But sometimes reads and writes have fundamentally different needs:

- Writes need strong consistency, normalization, ACID transactions
- Reads need speed, denormalized data, complex queries across many tables

CQRS splits them apart:

- **Write database** — optimized for writes (normalized, transactional, strongly consistent)
- **Read database** — optimized for reads (denormalized, cached, eventually consistent)
- When a write happens, an event is published. The read database consumes that event and updates itself.

**Concrete example:** An e-commerce order system. Writing an order needs ACID (payment + inventory in one transaction). But the admin dashboard needs "show me all orders by region, grouped by status, with revenue totals" — an expensive query that would slow down the transactional database. CQRS puts the dashboard reads on a separate denormalized database optimized for those queries.

**Use for:** Systems where read and write patterns are very different — read-heavy with complex queries, or when you need to scale reads and writes independently.

---

**Saga Pattern — "distributed transactions without a distributed transaction"**

In a monolith, you can wrap everything in one database transaction: charge the card, decrement inventory, create the order — all or nothing. If anything fails, the whole thing rolls back automatically.

In microservices, you can't do that. Payment Service has its own database. Inventory Service has its own database. There's no single transaction that spans both.

The saga breaks it into a chain of steps, each with an undo:

```
1. Order Service → create order (pending)         | undo: cancel order
2. Payment Service → charge card                   | undo: refund payment
3. Inventory Service → decrement stock             | undo: restore stock
4. Notification Service → send confirmation email  | undo: (nothing to undo)
```

If step 3 fails (out of stock), **compensating transactions** run backwards:

- Refund the payment (undo step 2)
- Cancel the order (undo step 1)

Each service handles its own step, publishes an event for the next service, and defines how to undo its step if something downstream fails. Either the whole chain completes successfully or everything gets undone. Without the undo logic, a failure at step 3 means the user was charged but never got the product — inconsistent state.

**Use for:** Any multi-service workflow where consistency matters — checkout flows, booking systems, order processing. This comes up in almost every "design an e-commerce checkout" interview question.

---

**How these three connect:** All are patterns for event-driven systems, but they solve different problems. Event sourcing = how you store data. CQRS = how you separate reads from writes. Sagas = how you coordinate multi-service transactions. They can be used independently or together.

---

## 8. Content Delivery & Storage

### CDN (Content Delivery Network)

Geographically distributed cache servers that serve content from the nearest location to the user.

**How it works:**

1. User requests `image.jpg` from CDN
2. CDN edge server checks if it has the file cached
3. Cache hit → serve immediately (fast, from nearby server)
4. Cache miss → fetch from origin server, cache it, serve to user

**What to put on CDN:** Static assets (images, CSS, JS, videos), API responses that don't change often

**When to use a CDN:**

- Your users are geographically distributed and latency matters
- You serve static content that many users request (product images, JS/CSS bundles, marketing pages)
- You want to reduce load on your origin servers — the CDN handles the majority of reads
- You need DDoS protection — CDNs absorb traffic at the edge before it reaches your infrastructure

**When you don't need a CDN:**

- All your users are in one region and latency is already fine
- All your content is dynamic/personalized (CDN can't cache it)
- Internal tools or admin dashboards with low traffic

**Examples:** CloudFront, Cloudflare, Akamai, Fastly

---

### AWS Global Accelerator

Global Accelerator provides two static anycast IP addresses that act as a global entry point to your application. Instead of users connecting to your regional ALB over the public internet (unpredictable routing, variable latency), traffic enters the AWS private backbone at the nearest edge location and is routed internally to your backend.

**Why use it — the core benefits:**

- **Lower latency.** Traffic travels over AWS's optimized private backbone instead of the public internet. AWS's internal network has shorter, more direct paths than the unpredictable series of hops that public internet routing takes.
- **More consistent latency.** Public internet routing can vary wildly between requests — one request takes 50ms, the next takes 200ms because it got routed through different networks. Global Accelerator eliminates that variance because the path is always through AWS's backbone.
- **Instant failover.** With DNS-based failover (Route 53), when a region goes down, clients keep hitting the dead endpoint until the DNS TTL expires and they re-resolve to the healthy region — that can be 60+ seconds. Global Accelerator failover is instant because routing happens at the network level, not DNS. AWS detects the unhealthy endpoint and reroutes traffic within seconds, with no client-side caching to wait out.

**How it works:**

1. You get two static IPs (e.g., `75.2.60.5`, `99.83.190.102`). These IPs are anycast — advertised from all AWS edge locations simultaneously.
2. When a user sends a request, it's picked up by the nearest edge location (same 100+ locations used by CloudFront).
3. From the edge, traffic travels over AWS's private global backbone directly to your endpoint (ALB, NLB, EC2, or Elastic IP) in any region.
4. The public internet is involved only for the last mile between the user and the nearest edge location.

**Global Accelerator vs Route 53:**

- **Route 53** is DNS-based routing — it tells the client which IP to connect to, but after DNS resolution the client connects over the public internet. If the path is congested or inefficient, latency suffers.
- **Global Accelerator** is network-level routing — the client always connects to the same static IPs, traffic enters the AWS backbone immediately, and AWS routes internally. More consistent latency, and failover is instant (no DNS TTL to wait for).

**Global Accelerator vs CloudFront:**

- **CloudFront** is a CDN — it caches content at the edge and can run edge functions. It's designed for HTTP/HTTPS and is ideal when you want caching, edge compute, or request manipulation.
- **Global Accelerator** is a network router — it doesn't cache anything or run code. It's designed for any TCP/UDP traffic (not just HTTP) where you want consistent low latency and fast failover. Use it for gaming, IoT, VoIP, or API traffic where caching doesn't help.

**When to use which:**


| Use Case                                                                           | Tool                        |
| ---------------------------------------------------------------------------------- | --------------------------- |
| Static assets, cacheable API responses                                             | CloudFront                  |
| Need to run logic on requests at the edge                                          | CloudFront + edge functions |
| Non-HTTP traffic (TCP/UDP), gaming, VoIP                                           | Global Accelerator          |
| API traffic where you want consistent latency but don't need caching or edge logic | Global Accelerator          |
| Multi-region failover with instant (non-DNS) switching                             | Global Accelerator          |


**Interview relevance:** "How do you reduce latency for globally distributed users?" If the workload is HTTP and benefits from caching or edge logic → CloudFront. If the workload is non-HTTP or you need consistent network performance without caching → Global Accelerator. If you need both, you can use them together.

---

### CloudFront Functions & Lambda@Edge

CloudFront can run your code at the edge — at the same 100+ global edge locations that serve cached content. This lets you inspect, modify, or reroute requests before they ever reach your backend. There are two options with very different capabilities.

**CloudFront Functions:**

- Run on every request at the edge with sub-millisecond execution.
- Written in JavaScript. Very lightweight — designed for simple, high-volume transformations.
- Can inspect and modify HTTP headers, URLs, query strings, and cookies.
- **Cannot** make network calls (no database lookups, no API calls, no fetching external data).
- Use for: URL rewrites, header manipulation, simple routing decisions based on data already in the request (e.g., reading a cookie or JWT claim to decide which origin to forward to), A/B testing via cookie-based routing, redirects.

**Lambda@Edge:**

- Runs at regional edge caches (fewer locations than CloudFront Functions, but still globally distributed).
- Written in Node.js or Python. Full Lambda runtime — can do anything a normal Lambda can do.
- **Can** make network calls — query DynamoDB, call an API, look up a user's home region in a database.
- Higher latency than CloudFront Functions (single-digit milliseconds vs sub-millisecond) and more expensive.
- Use for: complex routing logic that requires a database lookup, authentication/authorization at the edge, generating responses at the edge without hitting the backend, modifying response bodies.

**When to use which:**


| Need                                                                   | Tool                |
| ---------------------------------------------------------------------- | ------------------- |
| Rewrite URLs, manipulate headers, simple routing based on request data | CloudFront Function |
| Look up user data in a database to make routing decisions              | Lambda@Edge         |
| A/B testing based on a cookie value                                    | CloudFront Function |
| Validate an auth token and enrich the request with user metadata       | Lambda@Edge         |
| Redirect HTTP to HTTPS                                                 | CloudFront Function |
| Generate a custom error page with dynamic content                      | Lambda@Edge         |


**Practical example — account-origin routing for multi-region:**
A US user traveling in Europe hits your CloudFront distribution. A CloudFront Function reads the `home_region` claim from their JWT (no network call needed — the data is in the request). It sets the origin to the us-east-1 ALB. The request is forwarded to the correct region without ever touching the EU cluster. If you needed to look up the home region from a database instead of a JWT, you'd use Lambda@Edge.

**Interview relevance:** Edge functions let you make routing, security, and personalization decisions before requests reach your infrastructure. They're how you implement account-origin routing for data residency, geo-based A/B testing, bot filtering, and auth validation at the edge — reducing load and latency on your backend.

---

### How Data Propagates Globally — General Principle

Different data propagates through different layers at different speeds. Not everything needs the same consistency or delivery mechanism.

**Text/structured data (tweets, posts, records):** Written to primary DB in the origin region → async replicated to other regions within seconds. Fast, small payloads. Eventual consistency is fine — a user in another region seeing it 2-3 seconds later is imperceptible.

**Media (images, videos):** Stored in blob storage (S3) in the origin region. CDN uses **pull-based caching** — the first user in a region to request the media triggers a CDN cache miss, CDN fetches from S3, caches it at the local edge. Every subsequent request from that region is served from the edge. For viral content, this happens almost instantly because someone in every region views it within seconds.

**Feed/timeline data:** Propagated via fan-out (push to followers' Redis feeds for regular users, pulled at read time for celebrities). Redis instances in each region are updated via async replication or feeds are computed locally.

**The principle:** Not every piece of data needs to be everywhere instantly. Text replicates fast (small). Media is pulled on demand (large, CDN handles it). Feeds are pre-computed or computed at read time. Each layer uses the propagation strategy that fits its size, access pattern, and consistency needs.

**How CDN edge servers work with each other:** They don't share caches. Each edge server caches independently — miss → pull from origin → cache locally. The CDN in China fetching an image doesn't push it to the CDN in Japan. Japan pulls its own copy when someone there requests it.

Some CDNs (CloudFront, Cloudflare) have a **mid-tier regional cache** between edge servers and the origin. Instead of every edge in Asia independently crossing the ocean to S3 in the US, they check a regional cache first:

```
Edge in China → miss → Regional cache in Asia → miss → S3 in US (caches in regional)
Edge in Japan → miss → Regional cache in Asia → hit (China already triggered the fetch) → served
```

Reduces cross-ocean requests, but still entirely pull-based — nothing is proactively pushed to edge servers.

---

### CDN vs Application Cache (Redis) — Know the Difference

These are two different caching layers that solve different problems. In interviews, mention both.

**CDN — caches the finished output:**

- Sits at the **edge**, geographically close to users (hundreds of locations worldwide)
- Caches **the full response** — images, CSS, JS, HTML pages, cacheable API responses. The finished product that gets sent to the user's browser.
- "Has someone already asked for this exact thing?" If yes, serve the cached result. The request never reaches your infrastructure.
- Works best for static or rarely-changing content. Can't cache personalized/dynamic content (different for every user).
- Cache invalidation is slow (must propagate to hundreds of edge nodes)

**Application Cache (Redis) — caches the raw data your app needs:**

- Sits **inside your infrastructure**, next to your application servers
- Caches **data objects and query results** — the raw ingredients your app logic needs to build a response (user profiles, product records, query results)
- The request hits your server, but instead of querying the database, your code checks Redis first: "Do I already have the data I need to build this response?"
- Works for both static and dynamic/personalized content — your app logic decides what to cache
- Cache invalidation is fast (you directly control it)

**How they work together:**

```
User → CDN (full response already cached? serve it, done)
        → miss → Your API server → Redis (data needed to build response cached? use it)
                                     → miss → Database (last resort)
```

CDN catches the request before it reaches your servers. Redis catches it before it reaches the database. Each layer saves the next layer from unnecessary work.

**Interview pattern:** For any read-heavy, globally distributed system (product catalog, user profiles, content feeds), mention BOTH layers: CDN for static/cacheable responses at the edge, Redis for dynamic data inside your infrastructure. Missing either one is a gap at the $200K+ level.

---

### Blob/Object Storage

Store unstructured data (files, images, videos) separately from your database.

**S3 (Simple Storage Service):**

- Unlimited storage, 99.999999999% (11 nines) durability
- Pay for what you use
- Storage classes: Standard (frequent access), Infrequent Access (cheaper, retrieval fee), Glacier (archival, hours to retrieve)

**Never store large files in your database.** Store the file in S3, store the S3 URL in the database.

**Pre-signed URLs:** Generate a temporary URL that gives the client direct access to upload/download from S3 without going through your server. Reduces server load. The URL is scoped to a specific S3 path, expires after N minutes, and only allows the specified HTTP method (PUT for upload, GET for download). Your API server generates the URL, then the client uploads/downloads directly to/from S3 — the API server is completely out of the data transfer path.

---

### Media Processing — Transcoding & Adaptive Bitrate Streaming

**General principle:** Raw uploaded files are never served directly. They go through a processing pipeline before being delivered to users. Images get resized into thumbnails. Videos get transcoded into multiple quality levels.

**Adaptive bitrate streaming:** A single movie is transcoded into multiple quality levels:

- 4K (20+ Mbps) — smart TV on fiber
- 1080p (5-8 Mbps) — laptop on decent wifi
- 720p (2-3 Mbps) — phone on 4G
- 480p (1 Mbps) — phone on 3G

Each quality level is broken into small chunks (5-10 second segments). The video player on the client monitors bandwidth in real-time and switches between quality levels seamlessly. Buffering? Drop to 720p. Bandwidth recovered? Switch back to 1080p. The user never chooses — it adapts automatically. This is what Netflix, YouTube, and every streaming platform does.

**The full upload-to-streaming flow:**

1. Content team hits API server → API server generates a pre-signed URL
2. Content team uploads raw file (50GB) directly to S3
3. S3 fires an event on upload completion → triggers transcoding pipeline (via SQS → worker, or Lambda)
4. Transcoding workers convert the raw file into multiple bitrate/resolution versions and chunk each into segments — heavy compute, runs on spot instances or AWS MediaConvert
5. Transcoded chunks are stored back in S3, a manifest file is generated listing all quality levels and chunk URLs
6. For high-profile releases: CDN pre-warming triggers requests to expected regional edge servers, causing them to pull content from S3 and cache it before users arrive
7. Movie is marked as available in the catalog database
8. Users stream from CDN — player reads the manifest and adaptively selects quality based on current bandwidth

The entire pipeline after upload is event-driven and async. The user uploads and sees "processing your video." They don't wait for transcoding or CDN warming.

**CDN pre-warming:** Proactively trigger requests to CDN edge servers in expected regions before launch. The CDN pulls from S3 and caches the content so real users get cache hits on day one. Use for scheduled releases (midnight show drops, product launches). For everything else, pull-based caching handles it — content only gets cached in regions where users actually request it.

**Why pull-based over push-based for CDNs:** Push would copy content to every edge server globally — wasteful when a Korean drama is popular in Asia but not South America. Pull-based means content only ends up where there's demand. Pre-warm the edges where you expect demand, let the CDN handle the rest naturally.

---

## 9. Estimation Cheat Sheet

### Powers of 2


| Power | Value       | Approx             |
| ----- | ----------- | ------------------ |
| 2^10  | 1,024       | ~1 thousand (1 KB) |
| 2^20  | 1,048,576   | ~1 million (1 MB)  |
| 2^30  | ~1 billion  | 1 GB               |
| 2^40  | ~1 trillion | 1 TB               |


### Latency Numbers


| Operation               | Time   |
| ----------------------- | ------ |
| L1 cache reference      | 1 ns   |
| L2 cache reference      | 4 ns   |
| RAM reference           | 100 ns |
| SSD random read         | 16 μs  |
| HDD random read         | 2 ms   |
| Send packet SF → NYC    | 40 ms  |
| Send packet SF → London | 80 ms  |


### Quick Math

- **QPS (Queries per second):** DAU × avg queries per user / 86,400 seconds
- **Peak QPS:** QPS × 2-3 (assume peak is 2-3x average)
- **Storage:** Num records × avg record size × retention period
- **Bandwidth:** QPS × avg response size

### Common Estimates

- 1 million users × 10 requests/day = ~100 QPS average, ~300 QPS peak
- 1 tweet = ~300 bytes, 1 image = ~300 KB, 1 video = ~300 MB
- 1 server can handle ~10K-50K concurrent connections
- MySQL: ~5K-10K QPS for simple queries on decent hardware
- Redis: ~100K QPS

---

## 10. Common Interview Scenarios & Patterns (SRE / DevOps / Platform / Cloud)

These are framed the way infra interviews actually pose them — **operability, reliability, deployment, debugging, cost** — not FAANG algorithm puzzles. For each, lead with a **mitigate-first** mindset and name the trade-offs. The universal SWE-style questions (TinyURL, feeds) are condensed at the bottom under "know just enough."

---

### Debugging a Latency / Error Spike (the #1 SRE question)

**"Service p99 latency tripled / error rate spiked — walk me through it."**

- **Mitigate before root-cause.** First question: *did anything change?* Recent deploy, config push, feature flag, traffic surge, dependency incident. If a deploy correlates → roll back first, investigate after.
- **Triage by the golden signals** (latency, traffic, errors, saturation), then narrow the layer: LB → app → cache → DB → downstream dependency. Use **traces** to find *where* time is spent, **logs** to find *why*.
- **Common culprits:** a slow/degraded dependency holding threads, DB connection-pool exhaustion, a hot key, cache stampede after a flush, GC pauses, noisy neighbor, saturated CPU/disk/network.
- **Frameworks to name-drop:** USE (Utilization, Saturation, Errors) for resources; RED (Rate, Errors, Duration) for services. Tie decisions to the **error budget** — how aggressively you page depends on how much budget is left.

---

### Troubleshooting a Down Service (website / server / pod)

**"A site/server/pod is down — how do you troubleshoot it?"** Walk the request path from the outside in, isolating *which layer* fails. State it as a systematic method:

1. **Scope it.** Is it down for everyone or just you? One region/instance or all? Check from another network/`curl`, a status page, and dashboards. (Rules out client/DNS-cache/local issues.)
2. **Did anything change?** Recent deploy, config, cert expiry, DNS change, infra change. Correlate with the outage start → roll back if so.
3. **DNS** — does the name resolve to the right IP? (`dig`/`nslookup`). Expired domain, bad record, propagation.
4. **Network / connectivity** — can you reach the host/port? (`ping`, `curl -v`, `telnet host port`, `traceroute`). Security group / NACL / firewall blocking? LB reachable?
5. **Load balancer / ingress** — are targets **healthy**? Failing health checks pull all targets → 503. Check the target group / Ingress backend.
6. **The host / process** — is the app actually running? Crashed, OOM, disk full (`df -h`), CPU pegged, port not listening (`ss -tlnp`)? Check service status and resource usage.
7. **Application logs** — the actual error: failed dependency, bad config, unhandled exception, connection refused.
8. **Dependencies** — DB/cache/downstream API down or maxed (connection pool exhausted, credentials expired)? A dependency being down often *looks* like your service being down.

**For a pod specifically:**

```
kubectl get pods                 # status: CrashLoopBackOff? ImagePullBackOff? Pending? OOMKilled?
kubectl describe pod <pod>       # Events: failed schedule, probe failures, image pull, OOMKilled (137)
kubectl logs <pod> --previous    # why the last container died
kubectl get events --sort-by=.lastTimestamp
```

- **Pending** → can't schedule (no node capacity, unsatisfiable requests, taints). **ImagePullBackOff** → bad image/tag or registry auth. **CrashLoopBackOff** → app crashes on start (bad config/secret) or a failing **liveness probe** killing it. **OOMKilled** → raise memory limit or fix the leak. **Running but no traffic** → **readiness probe** failing or Service selector mismatch.

**The one-liner:** *"I isolate which layer is failing by walking the request path — client → DNS → network/LB → host/process → app → dependencies — checking health at each hop, after first ruling out a recent change. For a pod I start with describe/logs/events to classify the failure state."*

---

### Incident Response & On-Call

**"How do you handle a production outage?"**

1. **Declare & assign roles** — Incident Commander, comms, ops. Don't debug silently.
2. **Stop the bleeding (mitigate):** roll back, fail over to another region/AZ, scale out, shed load, or flip a feature flag off. Restoring service beats finding root cause.
3. **Communicate** — status page, stakeholders, regular updates. Reduce the "is anyone on this?" noise.
4. **Restore & verify** with dashboards.
5. **Blameless postmortem** — timeline, contributing factors, concrete action items with owners. Optimize for **MTTR**, not blame.

---

### Design a Monitoring & Alerting Stack

**"Design observability for a 200-service platform."**

- **Three pillars:** metrics (Prometheus + Thanos/Mimir for long-term/global), traces (OpenTelemetry → Jaeger/Tempo), logs (Loki or ELK), unified in Grafana.
- **Alert on symptoms, not causes** — page on SLO burn (user-facing latency/errors), not on "CPU is 80%." Route via Alertmanager → PagerDuty with severity tiers.
- **Control cardinality** — no unbounded labels (user_id, request_id) on metrics; that's what logs/traces are for.
- **SLIs/SLOs/error budgets** as the backbone: define what "healthy" means, alert when the budget is burning too fast (multi-window burn-rate alerts). See §6.

---

### Safe Deployment / Progressive Rollout

**"Roll out a risky change across many services."**

- **CI gates** (tests, scans) → deploy to staging → **canary** (1–5% of traffic) → watch golden signals → progressive ramp → **automated rollback** if SLOs breach.
- **Decouple deploy from release** with feature flags — ship code dark, turn it on gradually, kill instantly without a redeploy.
- **Schema/data changes:** expand-and-contract (add new, dual-write/backfill, migrate reads, drop old) so deploys stay backward-compatible and rollbackable.
- Know the trade-offs: **canary** (fast, cheap, granular, but rollback ≠ instant traffic drain) vs **blue-green** (instant clean cutover, double the infra). See §4.

---

### Design a CI/CD Pipeline

**"Design CI/CD for a microservices org."**

- **CI:** on every PR — lint → unit tests → build → security/dependency scan → publish artifact to a registry. Branch protection makes it an **unbypassable gate**.
- **CD:** deploy to staging → integration/e2e → promote to prod with canary. **GitOps** (ArgoCD/Flux) for K8s — Git is the source of truth, the cluster reconciles to match.
- **IaC** (Terraform) for infra changes through the same review/pipeline discipline.
- Test-pyramid ordering: cheap/fast first (fail fast). In a monorepo, a build system (Bazel) only re-runs affected tests. See §13.

---

### Multi-Region / High-Availability Architecture

**"Design a resilient multi-region system. RPO seconds, RTO minutes."**

- **Active-passive** (warm standby): cheaper, simpler, failover has some RTO. **Active-active:** both regions serve traffic, near-zero RTO, but you inherit cross-region data consistency problems.
- **Data:** async replication (fast, eventual, risk of small data loss = your RPO) vs sync (strong, but latency + availability cost). Pick per PACELC.
- **Traffic:** Route 53 failover (DNS, TTL delay) vs **Global Accelerator** (network-level, instant failover).
- **Redundancy math:** N+1 across AZs so losing one AZ doesn't lose capacity. Map the four DR strategies (backup-restore → pilot light → warm standby → active-active) to RPO/RTO/cost. See §12.

---

### Kubernetes Debugging

**"A pod is stuck in CrashLoopBackOff — diagnose it."**

- `kubectl describe pod` → check **Events** (image pull error, failed mount, OOMKilled, probe failures) and last state/exit code.
- `kubectl logs <pod> --previous` → the crashed container's logs.
- **Common causes:** bad config/secret, missing env, failing liveness probe (killing a healthy-but-slow app — check probe timing), OOMKilled (bump memory limit), readiness probe never passing (dependency not ready), wrong image tag.
- Broaden out: node pressure/capacity (`kubectl describe node`), PVC binding, NetworkPolicy blocking a dependency. See §11.

---

### Capacity Planning / Scaling

**"How many instances do you need, and how does this scale?"**

- Measure **per-instance throughput** (load test to find the knee where latency degrades), then size for peak + headroom (**N+1/N+2**).
- **Autoscale:** HPA on CPU/RPS/custom metrics for pods, Cluster Autoscaler/Karpenter for nodes. Scale-to-zero for spiky/batch.
- **Stateless app tier** so you can scale horizontally freely; push state to DB/cache. Watch the real bottleneck — usually the DB, not the app tier (add read replicas, cache, shard).

---

### Internal Developer Platform (Platform Engineering)

**"Design a self-service platform for developers."**

- **Golden paths / paved roads** — opinionated, pre-approved templates so teams ship without reinventing CI/CD, observability, or security each time.
- **Self-service** via templates, CRDs/operators, and a portal (Backstage). Developers request infra through Git, not tickets.
- **Guardrails as code** — policy engines (OPA/Gatekeeper, Kyverno) enforce standards automatically; observability, secrets, and security baked into the platform, not bolted on.
- The goal: **reduce cognitive load** — abstract the platform so app teams focus on product, not plumbing.

---

### Secrets Management at Scale

**"How do teams handle secrets safely across the org?"**

- Never in code or plaintext env. Use a secrets manager (Vault, AWS Secrets Manager) with **envelope encryption** via KMS.
- Prefer **short-lived, dynamic credentials** over long-lived keys. In K8s: **IRSA / EKS Pod Identity** so pods assume IAM roles — no static keys — and **External Secrets Operator** to sync into the cluster.
- Rotation, least privilege, and audit logging. See §5 and §11.

---

### Cost Optimization

**"This cloud bill is too high — bring it down."**

- **Right-size** over-provisioned instances (metrics-driven). **Reserved Instances / Savings Plans** for steady baseline, **Spot** for fault-tolerant/batch, On-Demand for spiky.
- **Autoscaling + scale-to-zero** so you're not paying for idle.
- **S3 lifecycle tiering** (Standard → IA → Glacier) for aging data.
- Watch **data-transfer/egress** costs — keep traffic in-region / on the backbone, cache at the edge. Tagging + cost dashboards for visibility. See §12.
- **VPC endpoints** to bypass **NAT Gateway** data-processing charges for AWS-service traffic (S3/DynamoDB gateway endpoints are free; interface endpoints for ECR/Secrets Manager/KMS). Cost *and* security win. See §12.

---

### Classic Design Scenarios (practical framing)

These "design X" questions still show up, and they're genuinely useful practice. Skip the SWE trivia (base62 encoding, trie implementation, exact algorithms) — **lead with requirements → the bottleneck → trade-offs, then pivot to how you'd operate it** (monitor, deploy, fail over). That framing is what separates an infra candidate from a pure SWE.

**URL Shortener**
- *Requirements:* read-heavy (clicks ≫ creates), low-latency redirects **for a global audience**, unique short keys, high availability.
- *Key decision:* generating unique keys — a global counter with pre-allocated ID ranges per server (no coordination, no collisions) beats hashing-and-collision-checking. Don't rabbit-hole on the encoding.
- *Operate/scale:* KV store (key → URL), cache hot keys in Redis, shard by key. Bottleneck is read throughput → caching.
- *Global / multi-region (the part interviewers push on):* the mapping is **immutable** — once `abc123 → long-url` is created it never changes. That makes global distribution easy and is the key insight to state:
  - **Async replication to read replicas in every region.** Writes go to the primary region; the mapping propagates to other regions within seconds. **Eventual consistency is totally fine** — the only risk is a brand-new link not existing in a far region for a second or two, which is imperceptible for a share-then-click flow. No conflict resolution needed because nothing is ever updated.
  - **Geo-route reads** with latency-based DNS (Route 53) or Global Accelerator so a click resolves at the nearest region — the redirect is served locally, not across an ocean.
  - **CDN/edge caching** for the redirect itself: because entries are immutable, you can cache the 301/302 aggressively at the edge with long TTLs (no invalidation headaches). Most clicks never touch your backend.
  - *Contrast:* if links were editable/deletable you'd need short TTLs + cache invalidation and would care about read-after-write consistency. Immutability is what lets you lean fully on async replication + edge caching.

**Chat / Messaging**
- *Requirements:* real-time delivery, offline users, ordering, presence.
- *Key decisions:* WebSocket for live connections; a queue for offline delivery; NoSQL for the write-heavy message store, SQL for user data; heartbeat for presence.
- *Operate/scale:* connection state is the hard part — how do you route a message to the server holding the recipient's socket? (connection registry in Redis). Fan-out on write vs read for group chats.

**News Feed / Timeline**
- *Requirements:* fast feed loads, handle both normal users and celebrities.
- *Key decision:* **fan-out on write** (push into follower feeds → instant reads, but write storms for celebrities) vs **fan-out on read** (build at read time → cheap writes, slow reads). Real answer is **hybrid**.
- *Operate/scale:* Redis for pre-computed feeds, stampede protection (request coalescing) for viral posts, CDN for static assets only (feeds are personalized).

**Rate Limiter**
- *Requirements:* per-user/per-tenant limits, distributed, low overhead.
- *Key decision:* token bucket or sliding window; state in Redis; key = `user:endpoint:window`. Directly relevant to API gateways and per-tenant quotas.

**Notification System**
- *Requirements:* multi-channel (push/SMS/email), reliable, respect user prefs.
- *Key decisions:* always **async** via a queue (never block the request); priority tiers (password reset > marketing); per-user throttling; retry with backoff + **DLQ**; delivery tracking. This is a queues + reliability question — squarely in your wheelhouse.

**File Storage / Sync (Drive/Dropbox)**
- *Requirements:* multi-device sync, large files, concurrent edits.
- *Key decisions:* blob store (S3) for bytes + DB for metadata; **chunking** (resumable uploads, efficient sync, parallelism); hash-based **deduplication**; conflict resolution (last-write-wins → keep-both → CRDT/OT for real-time merge).

**Search Autocomplete**
- *Requirements:* sub-100ms suggestions ranked by popularity.
- *Key decision (concept only):* a trie for prefix lookups — you don't implement it. What matters: cache popular prefixes in Redis, update the index asynchronously from search logs (batch, not real-time), CDN for the most common short prefixes.

The pattern across all of these: **CDN → Redis → DB** caching layers, async work behind queues, and picking the read/write strategy that fits the access pattern. Master those and you can reason through any "design X" question without memorizing trivia.

---

## Failure Modes — The Checklist

When you finish a design, the interviewer will ask "what breaks first?" Run through this list and call out the top 2-3 risks for your specific design.

1. **Slow dependency** — more dangerous than a dead one. Holds connections/threads hostage. Fix: timeouts, circuit breakers.
2. **Cascading failure** — one service goes down, takes others with it. Fix: circuit breakers, bulkheads (isolate connection pools per dependency), timeouts.
3. **Cache failure** — cache goes down, all traffic hits the DB. Fix: layered caching and graceful degradation (see below).
4. **Cache stampede** — popular key expires, thousands of requests hit DB simultaneously. Fix: locking.
5. **Cache avalanche** — many keys expire at the same time. Fix: jitter on TTLs.
6. **Hot key / hot partition** — one shard or cache key gets disproportionate traffic. Fix: replicate hot keys, add local caching, split hot shards.
7. **Connection pool exhaustion** — all connections held by slow/hanging requests. Fix: timeouts on outbound calls, separate pools per dependency.
8. **Single point of failure** — one component dies, everything dies. Fix: redundancy at every layer.
9. **Split brain** — two nodes both think they're the primary. Fix: quorum-based leader election, fencing tokens.
10. **Data corruption during migration** — bad conversion, missed rows, inconsistent state. Fix: expand and contract, dual-write, verify before cutover.

### Kubernetes-Specific Failure Modes

When running in Kubernetes and "nothing was deployed" but things are broken, check these:

1. **CPU throttling** — pod is hitting its CPU limit. Kubernetes throttles it instead of killing it. The pod is alive and passing health checks, but every request is slow. This is the sneaky one — nothing looks "broken."
2. **OOM kills** — pod exceeds memory limit, gets killed and restarted. During restart, other pods absorb the load, potentially getting overwhelmed too. Look for frequent pod restarts.
3. **Noisy neighbor** — another pod on the same node is consuming excessive resources, starving your service. Happens when resource requests are too low and pods get scheduled on overcommitted nodes.
4. **Node pressure** — a node runs low on disk or memory. Kubernetes starts evicting pods. Your pods get rescheduled elsewhere, causing disruption.
5. **HPA flapping** — HPA scales pods down overnight (low traffic), morning traffic spikes before pods scale back up. The gap between traffic arriving and HPA reacting causes latency.
6. **Cache eviction** — Redis or in-memory cache hit memory pressure overnight and evicted keys. Requests that were cache hits are now cache misses hitting the database. Sudden spike in DB load without any code change.
7. **Connection pool exhaustion** — a downstream dependency slows down, connections pile up waiting for responses, pool fills up, new requests queue behind them. Everything looks slow even though your service's code is fine.

### Layered Caching

Multiple cache layers, each catching requests before they hit the next. If one layer goes down, the next absorbs the traffic instead of everything hitting the database.

```
CDN (edge) → Local in-memory cache (per pod) → Redis → Database
```

If Redis goes down, the CDN still serves static content and the local pod cache still serves the hottest data. The database gets more traffic than usual, but not 100% of it. You degrade, you don't collapse. Without layers (just Redis → DB), Redis dying means the database gets hammered with all traffic instantly.

### Graceful Degradation

When something fails, return a reduced experience instead of an error. Something useful is always better than a 500.

- Redis is down → serve slightly stale data from local pod cache instead of returning an error
- Payment service is down → circuit breaker trips → "Your cart has been saved, try again in a few minutes" instead of a generic error page
- Recommendation engine is down → show generic "top products" instead of personalized recommendations
- Image processing is slow → show the original image instead of the optimized thumbnail

The principle: design every component with a fallback for when its dependencies fail. Users would rather see stale data or generic content than an error page.

Layered caching is a form of graceful degradation — each layer is a fallback for the one above it. The system gets progressively slower as layers fail, but keeps serving something useful instead of dying.

---

## When to Shard — The Decision Progression

Sharding is the last resort, not the first move. Exhaust simpler options first:

```
Query is slow
  → Optimize the query (fix N+1 queries, better WHERE clauses)
    → Add indexes
      → Vertical scaling (bigger machine — more CPU, RAM)
        → Read replicas (offload reads)
          → Caching (Redis — reduce DB load)
            → STILL not enough? → Shard
```

**You shard when:**

- **Write throughput exceeds what a single primary can handle.** Read replicas only help reads. Caching only helps repeated reads. If you need 50,000 writes/second and a single instance maxes out at 10,000 — you need to split writes across machines.
- **Data is too large for one machine.** 10TB on a single database — backups take forever, queries scan too much data, storage is maxed. Split the data across machines.

**You don't shard when:**

- Read replicas can solve your problem (read-heavy workload)
- Caching can solve your problem (repeated reads)
- Vertical scaling can solve your problem (haven't tried a bigger instance yet)
- Your data fits on one machine comfortably

**One sentence for interviews:** "I'd exhaust simpler options first — query optimization, indexing, vertical scaling, read replicas, caching — and only shard when write throughput or data volume exceeds what a single machine can handle."

---

## Interview Tips

1. **Always clarify requirements first.** Never jump into design. Ask: "How many users? Read-heavy or write-heavy? What's the latency requirement? What's the availability target?"
2. **Start simple, then optimize.** Single server → add LB → add cache → add replicas → shard. Show you know the progression.
3. **Talk about trade-offs, not just solutions.** "I'd use Cassandra because we need high write throughput, but we lose strong consistency and complex queries."
4. **Use numbers.** "With 10M DAU at 50 requests/day, that's ~6K QPS average, ~18K peak. A single MySQL instance handles ~10K QPS, so we need read replicas or caching."
5. **Address failure modes.** "What happens if the cache goes down? What if the primary database fails? What if this service is slow?"
6. **Know the difference between microservices and monoliths.** Don't default to microservices. A monolith is simpler and faster to build. Microservices add complexity (service discovery, distributed transactions, network latency). Use microservices when teams need to deploy independently or services have very different scaling needs.
7. **Don't over-engineer.** If the question says "1 million users," you don't need 50 shards and 3 regions. Design for the stated scale, then discuss how you'd evolve.

---

## 11. Kubernetes

### When to Use Kubernetes

Kubernetes is not always the right answer. Know the trade-offs.


| Option                    | Use When                                                                                                      | Avoid When                                                                                |
| ------------------------- | ------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| **Kubernetes (EKS, GKE)** | Multiple services, team needs fine-grained control over networking/scaling/deployments, complex orchestration | Small team, simple app, don't want to manage cluster overhead                             |
| **ECS/Fargate**           | Container workloads on AWS, simpler than K8s, less operational overhead                                       | Need multi-cloud or advanced scheduling/networking                                        |
| **Lambda / Serverless**   | Event-driven, sporadic traffic, simple functions, want zero infrastructure management                         | Long-running processes, steady high traffic (gets expensive), need persistent connections |
| **Plain EC2 / VMs**       | Legacy apps, specific OS/hardware needs, simple single-server deployments                                     | Anything that needs auto-scaling, self-healing, or orchestration                          |


**Interview tip:** Don't default to Kubernetes for every design. "I'd use Kubernetes because..." should always have a reason — multiple services with different scaling needs, team needs deployment flexibility, need service mesh, etc.

---

### Core Concepts

**Pod:** Smallest deployable unit. One or more containers that share networking and storage. Usually one container per pod. Ephemeral — pods can be killed and recreated at any time. Never rely on a pod being permanent.

**Deployment:** Manages a set of identical pods. Handles rolling updates, scaling, and self-healing (restarts failed pods). Use for stateless workloads — API servers, web apps, workers.

**StatefulSet:** Like a Deployment but for stateful workloads. Each pod gets a stable identity (pod-0, pod-1, pod-2), stable persistent storage, and ordered startup/shutdown. Use for databases, Kafka brokers, ZooKeeper — anything that needs stable identity or persistent disk.

**DaemonSet:** Runs exactly one pod on every node in the cluster. Use for node-level agents — log collectors (Fluentd), monitoring agents (Datadog agent), network plugins.

**Job:** Runs a pod (or several) to **completion** for a one-off batch task, then stops — a database migration, a data-processing batch, a backfill. Kubernetes tracks success/failure and retries (`backoffLimit`) until it completes. Unlike a Deployment (which keeps pods running forever), a Job is done when the work is done.

**CronJob:** A Job on a **schedule** (cron syntax) — nightly backups, hourly report generation, periodic cleanup. It creates a new Job at each scheduled time. Key fields: `schedule`, `concurrencyPolicy` (Allow/Forbid/Replace — whether overlapping runs are permitted), and `startingDeadlineSeconds`.

**Service:** Stable networking endpoint for a set of pods. Pods come and go, but the Service IP stays the same.

- **ClusterIP** — Internal only. Other services in the cluster can reach it. Default type.
- **NodePort** — Exposes on a static port on every node. Rarely used in production.
- **LoadBalancer** — Provisions a cloud load balancer (ALB/NLB). Use for external traffic.

**Ingress:** HTTP/HTTPS routing layer for exposing multiple services externally through a single load balancer. The Ingress controller creates and manages the load balancer — you don't create it separately.

```
Internet → Load Balancer (created by Ingress controller) → Ingress routing rules → Services → Pods
```

Route based on hostname (`api.example.com → api-service`) or path (`/api → api-service`, `/web → web-service`). Requires an Ingress Controller (NGINX, ALB Ingress Controller, Traefik).

**When to use Ingress:**

- Multiple services need external HTTP/HTTPS access — one Ingress, one LB, routes to many services. Without Ingress, each service gets its own LB (expensive).
- You want centralized TLS termination (one place to manage SSL certs)
- You want path-based or host-based routing

**When you don't need Ingress:**

- One service exposed externally — a single LoadBalancer Service is fine
- Services only communicate internally — use ClusterIP
- Using a service mesh that handles ingress (Istio Gateway replaces Ingress)

**Namespace:** Logical isolation within a cluster. Use to separate environments (`dev`, `staging`, `prod`) or teams (`team-a`, `team-b`). Not a security boundary — use NetworkPolicies for that.

**ConfigMap / Secret:** Inject configuration and sensitive data into pods as environment variables or mounted files. Never hardcode config in container images.

---

### Scaling

**Horizontal Pod Autoscaler (HPA):**

- Scales the number of pods based on CPU, memory, or custom metrics
- Example: "if average CPU across all pods > 70%, add a pod"
- Good for: handling traffic spikes, scaling stateless workloads
- Limitation: takes 30-60 seconds to react — can't handle instant traffic spikes. Set minimum replicas high enough to survive sudden bursts.

**HPA defaults to CPU only.** Memory is not included unless you explicitly configure it. This is a common misconfiguration that causes real outages — pods get OOM-killed while HPA does nothing because CPU is fine.

**When to scale on memory:**

- Memory usage correlates with request volume — more traffic means more data held in memory per pod. Adding pods spreads the load and memory per pod drops. Example: a service that holds request data in memory for processing. More concurrent requests = more memory. Scaling on memory works here.

**When NOT to scale on memory:**

- Memory growth is independent of traffic — a memory leak causes memory to climb regardless of request volume. Adding pods just gives you more leaking pods that will all eventually OOM. Scaling on memory masks the bug by throwing money at it instead of fixing it.

**Quick test:** If you double the pod count and memory per pod drops proportionally, memory is a valid scaling metric. If memory per pod stays the same regardless of replica count, it's a bug, not a scaling problem.

**Interview tip:** Don't just say "I'd add HPA." Say "I'd configure HPA to scale on both CPU and memory, with thresholds based on observed usage." That shows you know HPA defaults to CPU-only and that the right metric depends on the workload.

**Vertical Pod Autoscaler (VPA):**

- Adjusts CPU and memory requests/limits on individual pods
- Example: "this pod keeps using 400m CPU but only requested 100m — increase the request"
- Good for: right-sizing pods you don't know the resource needs of yet
- Limitation: requires pod restart to apply new limits. Don't use alongside HPA on the same metric.

**Cluster Autoscaler:**

- Scales the number of nodes in the cluster
- When pods can't be scheduled (not enough node capacity), it adds nodes. When nodes are underutilized, it removes them.
- Works with HPA: HPA adds pods → pods can't fit → Cluster Autoscaler adds nodes.

**Scaling flow:**

```
Traffic increases → HPA adds pods → no room on existing nodes → Cluster Autoscaler adds nodes
Traffic decreases → HPA removes pods → nodes underutilized → Cluster Autoscaler removes nodes
```

---

### Scheduling & Placement

How you control *which node* a pod lands on. Interviewers love "how do you keep pods off certain nodes / spread them / co-locate them?"

**nodeSelector:** The simplest — schedule a pod only on nodes with a matching label (`disktype: ssd`). Hard requirement, exact match, no flexibility.

**Node affinity / anti-affinity:** A richer nodeSelector. Attracts (or repels) pods to nodes based on labels, with two strengths:

- `requiredDuringScheduling...` — **hard** rule; pod won't schedule if unmet.
- `preferredDuringScheduling...` — **soft** rule; scheduler tries, but places it anyway if it can't. 

Use for: "run GPU workloads only on GPU nodes," "prefer nodes in AZ-a," "keep this workload on the `memory-optimized` node group."

**Pod affinity / anti-affinity:** Schedule pods relative to *other pods*, not nodes.

- **Pod affinity** — co-locate: "put this cache pod on the same node/zone as the app it serves" (reduce latency).
- **Pod anti-affinity** — spread apart: "never put two replicas of this database on the same node" (survive a node failure). `topologyKey` sets the scope (node, zone).

**Taints & tolerations — the inverse mechanism.** Affinity is a pod *choosing* nodes; taints are a node *repelling* pods.

- A **taint** on a node says "don't schedule anything here unless it explicitly tolerates me." (`kubectl taint nodes node1 gpu=true:NoSchedule`)
- A **toleration** on a pod says "I'm allowed on nodes with that taint."
- **Key point:** a toleration doesn't *attract* — it only *permits*. To both repel others *and* pull specific pods in, combine a **taint** (keep everyone else off) with **node affinity** (pull the right pods on).
- Effects: `NoSchedule` (block new pods), `PreferNoSchedule` (soft), `NoExecute` (also evict already-running pods that don't tolerate).
- Common uses: dedicated node pools (GPU, licensed software), keeping workloads off control-plane nodes (a built-in taint), draining nodes for maintenance.

**Quick contrast:** affinity = the pod's preference for *where to go*; taints/tolerations = the node's rule for *who's allowed*. Anti-affinity spreads for HA; `topologySpreadConstraints` (see §4) is the newer, more flexible way to do even spreading.

---

### Networking

**Service Mesh (Istio, Linkerd):**

- **Data plane — Envoy:** a sidecar proxy injected next to every pod that intercepts *all* inbound/outbound traffic. It does the actual work per request — mTLS encryption, retries, timeouts, circuit breaking, load balancing, and emitting metrics/traces. The app talks to localhost; Envoy handles the network.
- **Control plane — Istio (istiod):** the brain that *configures* all the Envoy proxies. You declare intent (routing rules, mTLS policy, access rules) via Kubernetes CRDs (VirtualService, DestinationRule, PeerAuthentication); Istio translates that into Envoy config and pushes it to every sidecar. It also distributes the certificates that make mTLS work. Istiod does **not** sit in the request path — it only programs the proxies.
- **The split:** Envoy = per-request enforcement (data plane, in the path); Istio = centralized policy/config distribution (control plane, out of the path). Same pattern as the general service-mesh section in §1.
- Provides: mTLS (automatic encryption between services), traffic management (retries, timeouts, circuit breaking), observability (metrics/traces for all traffic), access control (Service A can talk to B but not C)
- Use when: you have many microservices and need consistent networking policies without changing application code

**NetworkPolicies:**

- Firewall rules at the pod level. By default, all pods can talk to all other pods. NetworkPolicies restrict that.
- Example: "only pods in the `frontend` namespace can talk to pods in the `api` namespace on port 8080"
- Use for: defense in depth, restricting blast radius. If an attacker compromises one pod, they can't reach everything.

**DNS within the cluster:**

- Services are reachable by name: `my-service.my-namespace.svc.cluster.local`
- Short form within same namespace: `my-service`
- This is how services discover each other — no hardcoded IPs.

---

### Storage

**PersistentVolume (PV):** A piece of storage provisioned in the cluster (EBS volume, EFS share, etc.).

**PersistentVolumeClaim (PVC):** A pod's request for storage. "I need 10GB of SSD storage." Kubernetes matches it to an available PV.

**StorageClass:** Defines the type of storage (gp3, io2, efs). Enables dynamic provisioning — when a PVC is created, Kubernetes automatically provisions the underlying volume.

**When you need persistent storage:** Databases (though managed DB like RDS is usually better), message brokers (Kafka), anything in a StatefulSet that needs data to survive pod restarts.

**Interview tip:** For most workloads, prefer managed services (RDS, ElastiCache, MSK) over running stateful workloads in Kubernetes. K8s is great for stateless workloads. Running a database in K8s adds operational complexity — backups, failover, storage management — that managed services handle for you.

---

### Security

**RBAC (Role-Based Access Control):**

- **Role/ClusterRole:** Defines what actions are allowed (get, list, create, delete) on what resources (pods, services, secrets).
- **RoleBinding/ClusterRoleBinding:** Assigns a Role to a user or ServiceAccount.
- Role = scoped to a namespace. ClusterRole = cluster-wide.
- Example: "developers can view pods and logs in the `dev` namespace but can't delete anything in `prod`"

**Where do users come from?** Kubernetes doesn't manage users. Authentication is delegated to external systems. Kubernetes only handles authorization (RBAC).

- **Cloud IAM (most common):** map AWS IAM users/roles to Kubernetes identities in EKS. Two mechanisms:
  - **EKS Access Entries (newer, AWS-recommended):** an AWS API on the cluster itself — you attach an IAM principal to an *access entry* and either associate a managed **access policy** (e.g., `AmazonEKSClusterAdminPolicy`, `AmazonEKSViewPolicy`) or map it to K8s groups for RBAC. Managed via API/Console/Terraform, no in-cluster YAML edits. Auth modes: `API`, `API_AND_CONFIG_MAP`, or `CONFIG_MAP`.
  - **`aws-auth` ConfigMap (legacy):** the original method — a ConfigMap in `kube-system` mapping IAM ARNs to K8s users/groups (e.g., IAM role `developer` → group `developers`). Still widely seen, but error-prone (one bad edit can lock everyone out) and being superseded by access entries. Know it exists; prefer access entries for new clusters.
- **OIDC provider:** Kubernetes trusts an external IDP (Okta, Azure AD). Users authenticate with the IDP, get a token, present it to Kubernetes. Kubernetes validates and maps identity to RBAC.
- **ServiceAccounts:** The exception — these ARE managed by Kubernetes, but they're for pods, not humans.

```
Human user → authenticates with external IDP (AWS IAM, Okta)
           → gets a token → presents to Kubernetes API server
           → Kubernetes validates with external IDP
           → maps identity to a user/group
           → RBAC checks RoleBinding → allow or deny
```

**ServiceAccounts:**

- Identity for pods. Each pod runs as a ServiceAccount.
- Combine with IRSA (IAM Roles for Service Accounts) or **EKS Pod Identity** on AWS — each pod gets its own AWS IAM role. Pod A can access S3, Pod B can access DynamoDB. No shared credentials. (Mechanics and the IRSA-vs-Pod-Identity trade-off: §12.)

**Pod Security:**

- **Run as non-root:** Containers should not run as root. If compromised, the attacker has limited privileges.
- **Read-only filesystem:** Mount the container filesystem as read-only where possible. Prevents attackers from writing malicious files.
- **Resource limits:** Always set CPU and memory limits. A runaway process without limits can starve other pods on the same node.

---

### Operational Patterns

**Resource requests and limits:**

- **Requests:** "I need at least this much CPU/memory." The scheduler uses this to place pods on nodes with enough capacity.
- **Limits:** "Never exceed this much." If a pod exceeds its memory limit, it gets OOM-killed. If it exceeds CPU limit, it gets throttled.
- Always set both. Without requests, the scheduler can't make good decisions. Without limits, one pod can starve others.

**Topology spread constraints:** Already covered in Section 4. Ensures pods are spread evenly across AZs.

**Pod Disruption Budgets (PDB):**

- "At least 3 of my 5 pods must be running at all times." During a node drain, Kubernetes kills one pod, waits for its replacement to be healthy on another node, then kills the next — never dropping below the PDB minimum at any point.
- Without a PDB, a node drain can evict all your pods on that node at once — your app is down for 30-60+ seconds until replacements spin up. With a PDB, your app stays up throughout routine operations like node upgrades, maintenance, or spot instance reclaims. Users never notice.

**Readiness gates / init containers:**

- **Init containers:** Run before the main container starts. Use for: database migrations, config fetching, waiting for a dependency to be ready.
- **Readiness gates:** Additional conditions that must be true before a pod is considered ready for traffic. Use with service mesh or custom health checks.

**Health probes:** Already covered in detail in Section 4 (Health Checks). Liveness = is the process alive (restart if not). Readiness = can it handle traffic (remove from service if not). Startup = has it finished starting (protect slow starters from liveness kills).

---

### Helm — Package & Manifest Management

**The problem Helm solves:** raw YAML doesn't scale. A real app is many manifests (Deployment, Service, Ingress, ConfigMap, HPA...), and you need slightly different values per environment (dev/staging/prod) and per release. Copy-pasting YAML per environment is error-prone.

**Helm is the package manager for Kubernetes.** Core concepts:

- **Chart** — a package: a templated bundle of manifests plus metadata. Think "npm package / apt package for K8s apps."
- **Templates** — manifests with placeholders (`{{ .Values.image.tag }}`) instead of hardcoded values.
- **`values.yaml`** — the configuration fed into the templates. Override per environment: `helm install -f values-prod.yaml`. Same chart, different values → dev vs prod.
- **Release** — a specific deployed instance of a chart (with a version history).

**Why it matters operationally:**

- **Templating + env overrides** — one chart, many environments via different values files. No YAML duplication.
- **Versioned releases + rollback** — `helm rollback <release> <revision>` reverts to a previous release atomically. Every upgrade is tracked.
- **Reuse** — install community charts (Prometheus, cert-manager, ingress-nginx) instead of writing manifests from scratch.
- **Dependencies** — a chart can depend on subcharts (your app + its Redis + its Postgres).

**Helm vs Kustomize (the common comparison):**

- **Helm** — templating with variables + packaging + release lifecycle. Best for distributing reusable apps and when you need parameterization and rollback.
- **Kustomize** — template-free; start from a **base** and apply **overlays** that patch it per environment. Built into `kubectl` (`kubectl apply -k`). Best when you dislike templating and just need environment variants.
- Not mutually exclusive — teams often use Helm for third-party apps and Kustomize for their own, or Helm to render + Kustomize to patch.

**Interview relevance:** *"How do you manage manifests across environments?"* → "Helm charts with per-environment values files, versioned releases with rollback, and community charts for off-the-shelf components — or Kustomize overlays when I want template-free base+patch. In practice these are wrapped in GitOps (ArgoCD/Flux) so the chart+values in Git are the source of truth."

---

### Operators & Custom Resources

**Custom Resource Definitions (CRDs):** Kubernetes has built-in resource types (Pods, Services, Deployments). CRDs let you define your own resource types. Example: you create a `Database` resource type so you can write:

```yaml
apiVersion: mycompany.com/v1
kind: Database
metadata:
  name: users-db
spec:
  engine: postgresql
  version: "15"
  storage: 100Gi
  replicas: 3
```

Kubernetes doesn't know how to create a PostgreSQL database. The CRD just defines the schema — what fields exist and what they mean.

**Operators:** A controller that watches for CRDs and does the actual work. The operator sees the `Database` CRD above and:

1. Provisions a PostgreSQL StatefulSet with 3 replicas
2. Configures replication between them
3. Sets up automated backups
4. Handles failover if the primary dies
5. Manages version upgrades

The CRD is the "what" (I want a 3-replica PostgreSQL database). The operator is the "how" (provisions it, manages it, heals it).

**Why operators matter:** They encode operational knowledge into software. Instead of an engineer manually setting up a database, configuring replication, writing backup scripts, and handling failover — the operator does all of it automatically and consistently. It turns complex day-2 operations into a Kubernetes-native resource.

**Common operators you should know:**

- **ArgoCD** — GitOps operator (you use this). Watches a git repo, syncs desired state to the cluster.
- **External Secrets Operator** — syncs secrets from AWS Secrets Manager / Vault into Kubernetes Secrets (you use this too).
- **Prometheus Operator** — manages Prometheus instances, ServiceMonitors, alerting rules.
- **Cert-Manager** — automates TLS certificate issuance and renewal (Let's Encrypt).
- **Database operators** — CloudNativePG (PostgreSQL), Percona (MySQL), Strimzi (Kafka). Manage databases running in Kubernetes.

**Interview relevance:** "How would you manage stateful workloads in Kubernetes?" The answer is either "use a managed service (RDS, ElastiCache)" or "use an operator that handles provisioning, replication, backups, and failover." Operators are how you run complex software in Kubernetes without manual ops work.

---

### Admission Control & Policy as Code

Every create/update request to the cluster passes through an **admission** phase *before* it's persisted:

```
request → authentication → authorization (RBAC) → ADMISSION → stored in etcd
```

At admission, Kubernetes decides whether to accept, modify, or reject the object. This is how you enforce org standards automatically so bad config never lands in the cluster.

**Two kinds of admission webhooks (the extension mechanism):**

- **Validating** — accept or reject a request (e.g., "reject any pod without resource limits").
- **Mutating** — modify a request in flight (e.g., inject a sidecar or a default label).

**Key distinction — Kubernetes provides the *hook*, not the *rules*.** A webhook config just tells the API server "POST this object to an endpoint and do what it says." You must supply the endpoint + logic, OR install a policy engine that is that endpoint:

- **OPA / Gatekeeper** — general-purpose policy engine (OPA) specialized for K8s (Gatekeeper). Policies written in **Rego**, installed as CRDs. Validation-focused.
- **Kyverno** — K8s-native policy engine; policies written as **YAML** (no new language). Can **validate, mutate, and generate** resources.
- Common policies: no root/privileged containers, images only from an approved registry, every pod must have limits, required labels.

**Increasingly built in (no external tool needed):**

- **Pod Security Admission (PSA)** — built-in controller (GA v1.25) that enforces the Pod Security Standards via a namespace label. Replaced the deprecated PodSecurityPolicy. Covers the common "no privileged/root pods" case.
- **ValidatingAdmissionPolicy (VAP)** — GA v1.30. Write validation rules in **CEL** inline in a manifest, evaluated in-process by the API server — no webhook or external pod. (A MutatingAdmissionPolicy is following.)

**When to use what:**

| Need | Use |
| ---- | --- |
| Basic "no root/privileged pods" | Pod Security Admission (built-in) |
| Simple field validation, no add-ons | ValidatingAdmissionPolicy (CEL, built-in) |
| Mutation (inject sidecar/labels), cross-object logic, policy libraries, audit reports, multi-cluster GitOps, policy outside K8s | Kyverno / OPA / Gatekeeper |

**Interview relevance:** "How do you enforce standards across many teams on a shared cluster?" → **policy as code at the admission layer**. "Kubernetes gives the admission-webhook mechanism plus native options (Pod Security Admission, CEL-based ValidatingAdmissionPolicy) for simple rules. For mutation, rich policy libraries, or audit mode, I'd run Kyverno or OPA/Gatekeeper. Use audit mode to onboard existing workloads before enforcing." This is core **platform engineering** — self-service for developers with automatic guardrails.

---

## 12. Cloud Architecture & Engineering

### Infrastructure as Code (IaC)

All infrastructure should be defined in code, version-controlled, and deployed through automated pipelines. Never click through the console to create production resources.

**Tools:**

- **Terraform** — Cloud-agnostic, declarative, uses HCL. The industry standard. State file tracks what exists vs what's defined. Supports AWS, GCP, Azure, and hundreds of providers.
- **CloudFormation** — AWS-native, declarative, JSON/YAML. Tightly integrated with AWS but locked to AWS only.
- **Pulumi** — Like Terraform but you write real code (Python, TypeScript, Go) instead of HCL. Good for teams that prefer general-purpose languages.
- **CDK (AWS Cloud Development Kit)** — Write infrastructure in TypeScript/Python, compiles to CloudFormation under the hood. AWS-only.

**Key concepts:**

- **Declarative vs Imperative:** Declarative (Terraform, CloudFormation) = "here's what I want, figure out how to get there." Imperative (scripts, Pulumi) = "here are the steps to execute." Declarative is preferred for infrastructure — it's idempotent and handles drift.
- **State management (Terraform):** Terraform tracks the current state of your infrastructure in a state file. Remote state (S3 + DynamoDB lock) is required for team use — local state causes conflicts.
- **Modules:** Reusable infrastructure components. A VPC module, an EKS cluster module, a database module. Build once, reuse across environments.
- **Drift detection:** Infrastructure can drift from the code (someone manually changes a security group). Terraform plan shows the diff between code and reality.

**Interview relevance:** Cloud architect roles will ask "how do you manage infrastructure?" The answer is always IaC with Terraform (or CloudFormation if AWS-only), stored in git, deployed through CI/CD, with remote state and module reuse.

---

### AWS Networking Deep Dive

**VPC (Virtual Private Cloud):**

- Your own isolated network in AWS. All resources live inside a VPC.
- You define the IP range (CIDR block, e.g., `10.0.0.0/16` = 65,536 IPs).

**Subnets:**

- **Public subnet:** Has a route to an Internet Gateway. Resources here can be reached from the internet (load balancers, bastion hosts).
- **Private subnet:** No direct internet access. Resources here are protected (app servers, databases). This is where your workloads should live.
- Spread subnets across multiple AZs for redundancy.

**Routing traffic from private subnets to the internet:**

- **NAT Gateway:** Allows resources in private subnets to make outbound requests (pull packages, call external APIs) without being directly reachable from the internet. One-way door — traffic goes out, nothing uninvited comes in.

**Security layers:**

- **Security Groups:** Firewall rules attached to individual resources (EC2, RDS, etc.). Stateful — if you allow inbound traffic, the response is automatically allowed out. Operate at the instance level.
- **NACLs (Network ACLs):** Firewall rules attached to subnets. Stateless — you must explicitly allow both inbound and outbound. Operate at the subnet level. Use as a coarse-grained second layer.
- **Rule of thumb:** Security groups are your primary firewall (fine-grained, per-resource). NACLs are a backup safety net (broad rules, per-subnet).

**Connecting networks:**

- **VPC Peering:** Direct connection between two VPCs. Traffic stays on AWS backbone. Simple but doesn't scale — peering is 1-to-1, with 20 VPCs you need 190 peering connections.
- **Transit Gateway:** Hub-and-spoke model. All VPCs connect to one central hub. Scales cleanly — adding a new VPC is one connection, not N connections.
- **PrivateLink & VPC Endpoints:** VPC endpoints let you access AWS services privately — traffic never touches the public internet. PrivateLink is the underlying AWS networking technology; VPC endpoints are what you actually create. Two types:
  - **Gateway endpoints** — S3 and DynamoDB only. Free. Adds a route table entry.
  - **Interface endpoints** — everything else (SQS, Secrets Manager, ECR, cross-account services). Creates an ENI with a private IP in your subnet. Powered by PrivateLink. Costs ~$7-8/month per endpoint per AZ.
  - **Should you add interface endpoints for every service?** No. Do the math: NAT Gateway charges $0.045/GB processed. If a service only sends a few GB/month through NAT, the interface endpoint costs more than the NAT traffic. If a service sends hundreds of GB (ECR image pulls, heavy CloudWatch logging), the endpoint pays for itself quickly. Always add gateway endpoints (free). For interface endpoints, add them for high-traffic services where NAT costs exceed the endpoint cost — typically ECR, STS (high volume with IRSA), and CloudWatch Logs.

**Common architecture pattern:**

```
Internet → Internet Gateway → Public Subnet (ALB)
                                    ↓
                              Private Subnet (App Servers / EKS nodes)
                                    ↓
                              Private Subnet (RDS / ElastiCache)
                                    ↓
                              NAT Gateway → Internet (outbound only)
```

Load balancer is the only thing publicly accessible. Everything else is private.

---

### IAM & Access Control

**Core principle: least privilege.** Every user, service, and application gets only the permissions it needs to do its job. Nothing more.

**IAM concepts:**

- **Users** — Human identities. Should have MFA enabled. Avoid long-lived access keys — use SSO/federated access instead.
- **Roles** — Assumed by services, not humans. An EC2 instance assumes a role to access S3. A Lambda assumes a role to write to DynamoDB. No hardcoded credentials.
- **Policies** — JSON documents that define what actions are allowed on what resources. Attached to users, roles, or groups.
- **Groups** — Collection of users with shared permissions. "Developers" group gets read access to production, "SRE" group gets admin access to infrastructure.

**Service-to-service access (Kubernetes):**

- **IRSA (IAM Roles for Service Accounts):** Each Kubernetes pod gets its own IAM role via its ServiceAccount. Pod A can access S3 but not DynamoDB. Pod B can access DynamoDB but not S3. No shared credentials, no overprivileged nodes.
- This is what you have in your own project — the `roleArn` in your ServiceAccount config.
- **How IRSA works under the hood:** EKS acts as an OIDC identity provider. When a pod starts, Kubernetes mounts a JWT token inside it identifying its ServiceAccount. The pod presents this token to AWS STS (Security Token Service) to assume its mapped IAM role. STS verifies the token against the EKS OIDC provider and returns temporary AWS credentials (access key, secret key, session token). The pod uses those to call AWS services. No hardcoded credentials — just a token, a trust policy, and temporary creds that auto-refresh.
- **EKS Pod Identity (newer, AWS-recommended):** same outcome — a pod assumes an IAM role and gets temporary credentials — but the wiring is simpler. Install the **EKS Pod Identity Agent** add-on, then create a **Pod Identity Association** (cluster + namespace + ServiceAccount → IAM role) via the AWS API/Console/Terraform. The agent runs as a DaemonSet and serves credentials to the pod locally; no OIDC provider to create, no `eks.amazonaws.com/role-arn` annotation on the ServiceAccount.

| | IRSA | EKS Pod Identity |
| --- | --- | --- |
| Setup | Create an IAM OIDC provider **per cluster**; annotate the ServiceAccount | Install the agent add-on; create an association |
| Trust policy | Must reference each cluster's OIDC issuer URL + `sub` condition — rewritten per cluster | One reusable trust policy: `pods.eks.amazonaws.com` — the **same role works across clusters** |
| Role reuse | Painful at scale (N clusters = N trust-policy entries) | Designed for it |
| Works outside EKS | Yes — any OIDC-capable cluster (self-managed K8s, other clouds) | EKS only |

**When to use which:** Pod Identity for new EKS clusters, especially with many clusters sharing roles. IRSA if you need one identity mechanism across EKS *and* non-EKS clusters, or for older EKS versions / EKS Fargate. Both can coexist in a cluster; if a ServiceAccount has both, Pod Identity wins.

**Don't confuse the two "EKS identity" features** — they solve opposite directions:

- **EKS Access Entries** = *who outside the cluster can call the Kubernetes API* (IAM principal → K8s RBAC). Replaces the `aws-auth` ConfigMap. See §11.
- **IRSA / Pod Identity** = *what AWS resources a pod inside the cluster can reach* (K8s ServiceAccount → IAM role).

**Cross-account access:**

- Use **IAM roles with trust policies.** Account A trusts Account B to assume a role. Account B's service assumes the role in Account A to access resources. No credentials shared between accounts.

**RBAC (Role-Based Access Control):**

- Define roles (admin, developer, viewer) with specific permissions. Assign users to roles. Changes to a role automatically apply to everyone in it.
- In Kubernetes: ClusterRole/Role + ClusterRoleBinding/RoleBinding.

**How SSO works with AWS (IAM Identity Center):**

1. Connect your IdP (Okta, Azure AD) to AWS IAM Identity Center.
2. In the IdP, users belong to groups (`SRE-Team`, `Developers`, `Managers`).
3. In AWS, create **Permission Sets** — IAM role templates (e.g., `SREAccess`, `DeveloperAccess`, `ReadOnlyAccess`).
4. Map IdP groups to Permission Sets per account — e.g., `SRE-Team` → `SREAccess` in Production, `Developers` → `ReadOnlyAccess` in Production, `Developers` → `DeveloperAccess` in Dev.
5. At login: engineer goes to AWS SSO portal → redirected to IdP → authenticates (MFA) → IdP sends a **SAML assertion** back to AWS ("this is John, he's in SRE-Team") → AWS looks up the mapping and creates a **temporary IAM role session** with scoped permissions (1-12 hours).

- No permanent IAM credentials. Every session is temporary and tied to the IdP.
- When someone leaves the company, disable them in Okta — they instantly lose access to everything. No AWS keys to rotate.

**Interview relevance:** "How do your services authenticate to AWS?" Answer: IRSA or EKS Pod Identity for Kubernetes workloads, IAM roles for EC2/Lambda, no hardcoded credentials anywhere. "How do you manage access across teams?" Answer: RBAC with groups, least privilege, separate roles per environment. "How do humans access AWS?" Answer: SSO through a central IdP — no IAM users, no long-lived credentials, temporary role sessions scoped per account.

---

### Cost Optimization

Cloud architects are expected to design for cost, not just functionality. "It works" is not enough — "it works and costs $X/month because of these decisions" is the expectation.

**Compute pricing models:**

- **On-demand:** Pay by the hour/second. Full price, no commitment. Use for unpredictable workloads, dev/test environments.
- **Reserved Instances / Savings Plans:** Commit to 1 or 3 years, get 30-60% discount. Use for steady-state production workloads you know will run 24/7.
- **Spot Instances:** Up to 90% discount, but AWS can reclaim them with 2 minutes notice. Use for batch processing, CI/CD runners, stateless workers that can tolerate interruption.

**Quick decision:**


| Workload                        | Pricing model                        |
| ------------------------------- | ------------------------------------ |
| Production DB, always running   | Reserved / Savings Plan              |
| Web servers with auto-scaling   | On-demand (base) + Spot (burst)      |
| Dev/test environments           | On-demand, shut down nights/weekends |
| Batch processing, CI runners    | Spot                                 |
| Unpredictable short-lived tasks | On-demand                            |


**Storage optimization:**

- **S3 lifecycle policies:** Move objects from Standard → Infrequent Access → Glacier automatically based on age. Logs older than 30 days → IA. Older than 90 days → Glacier.
- **EBS volume right-sizing:** Don't provision 500GB gp3 volumes for databases using 50GB. Monitor usage and resize.
- **Data transfer costs:** Cross-AZ transfer costs money. Cross-region transfer costs more. Design to minimize data movement — keep compute and storage in the same AZ when possible.

**Network cost optimization — VPC endpoints:**

By default, traffic from a private subnet to AWS services (S3, DynamoDB, ECR, Secrets Manager, etc.) goes out through a **NAT Gateway** — which charges both an hourly fee *and* a per-GB data-processing fee. At scale (e.g., nodes constantly pulling images from ECR or reading from S3), that per-GB charge dominates the bill. **VPC endpoints** keep this traffic on the AWS private network and bypass the NAT Gateway entirely:

- **Gateway endpoints (S3, DynamoDB): free.** No hourly charge, no data-processing charge. There's essentially no reason not to add them — pure savings on any S3/DynamoDB traffic from private subnets.
- **Interface endpoints (PrivateLink — ECR, Secrets Manager, KMS, most other services):** small hourly + per-GB fee, but usually **far cheaper than routing the same traffic through a NAT Gateway**, and they cut inter-AZ/egress charges too.
- **Bonus:** traffic never traverses the public internet — a **security win** (no NAT/IGW exposure) on top of the cost win.

Rule of thumb: high-volume S3/DynamoDB access from private subnets → always add the (free) gateway endpoints; heavy ECR/Secrets Manager/KMS traffic → interface endpoints to shrink NAT Gateway data-processing costs.

**Common cost traps:**

- Idle resources — dev environments running 24/7, unattached EBS volumes, unused Elastic IPs
- Over-provisioned databases — db.r5.4xlarge running at 10% CPU
- NAT Gateway data processing — charges per GB processed, can be surprisingly expensive at scale. **Fix with VPC endpoints (above)** so service traffic bypasses the NAT Gateway.
- CloudWatch Logs — storing everything forever adds up fast. Set retention policies.

**Interview relevance:** When designing a system, mention cost trade-offs: "I'd use reserved instances for the database since it runs 24/7, spot instances for the batch workers since they're stateless and can tolerate interruption, and S3 lifecycle policies to tier old data to Glacier."

---

### Multi-Account Strategy

At scale, everything shouldn't live in one AWS account. Cloud architects are expected to know how to organize accounts.

**Why multiple accounts:**

- **Blast radius isolation.** A misconfigured IAM policy in dev can't accidentally delete production resources.
- **Billing separation.** Clear cost attribution per team or environment.
- **Security boundaries.** Production has stricter controls than dev.

**Common structure:**

```
AWS Organizations (management account)
├── Security account (GuardDuty, CloudTrail, Security Hub)
├── Logging account (centralized logs from all accounts)
├── Shared Services account (CI/CD, container registry, DNS)
├── Production account
├── Staging account
└── Development account
```

**SCPs (Service Control Policies):** Organization-wide guardrails. Example: "No account can launch resources outside us-east-1 and eu-west-1." Applied at the organizational unit level, overrides individual account permissions. Even an admin in the dev account can't violate an SCP.

**Interview relevance:** "How do you organize your AWS infrastructure?" Answer: "Multiple accounts under AWS Organizations — separate accounts for prod, staging, dev, security, and logging. SCPs enforce guardrails. Cross-account access via IAM role assumption."

---

### Disaster Recovery Patterns

**RPO and RTO — know these two numbers:**

- **RPO (Recovery Point Objective):** How much data can you afford to lose? "RPO of 1 hour" means if disaster strikes, you might lose up to 1 hour of data.
- **RTO (Recovery Time Objective):** How fast must you be back online? "RTO of 15 minutes" means the system must be serving traffic within 15 minutes of failure.

These two numbers drive every DR decision. Lower RPO/RTO = more expensive.

**DR strategies (cheapest → most expensive, slowest → fastest recovery):**

**Backup & Restore:**

- Regular backups to S3/Glacier. On disaster, spin up new infrastructure and restore from backup.
- RPO: hours (depends on backup frequency). RTO: hours (time to provision and restore).
- Cheapest. Use for non-critical systems where hours of downtime are acceptable.

**Pilot Light:**

- Core infrastructure is always running in the DR region (database replica), but app servers are off. On disaster, spin up the app servers and route traffic.
- RPO: minutes (continuous replication). RTO: 10-30 minutes (time to launch servers).
- Moderate cost — you're paying for the DB replica but not idle compute.

**Warm Standby:**

- Scaled-down version of the full production environment running in the DR region. On disaster, scale it up and route traffic.
- RPO: seconds (continuous replication). RTO: minutes (scale up existing infrastructure).
- Higher cost — running a smaller copy of everything 24/7.

**Multi-Site Active-Active:**

- Full production environment in both regions, both serving traffic all the time. On disaster, one region absorbs the other's traffic.
- RPO: near zero. RTO: near zero (just DNS failover).
- Most expensive — double infrastructure. But no downtime.


| Strategy         | RPO       | RTO       | Relative Cost |
| ---------------- | --------- | --------- | ------------- |
| Backup & Restore | Hours     | Hours     | $             |
| Pilot Light      | Minutes   | 10-30 min | $$            |
| Warm Standby     | Seconds   | Minutes   | $$$           |
| Active-Active    | Near zero | Near zero | $$$$          |


**Interview relevance:** "What's your DR strategy?" Answer by matching to the business requirement: "Our payment service has an RTO of 5 minutes and RPO of zero, so we run active-active across two regions. Our analytics platform has an RTO of 4 hours, so we use backup and restore to save cost."

---

### AWS Well-Architected Framework

AWS's five pillars for evaluating architectures. Cloud architect interviews reference these directly. Know the pillars and be able to tie your design decisions to them.

1. **Operational Excellence** — Automate everything, IaC, CI/CD, runbooks, observability. "Can you operate this system without heroics?"
2. **Security** — Least privilege, encryption at rest and in transit, IAM roles, audit logging. "Is this system secure by default?"
3. **Reliability** — Multi-AZ, auto-scaling, health checks, circuit breakers, backups. "Does this system survive failures?" (This is everything we've been studying in Section 4.)
4. **Performance Efficiency** — Right-sizing instances, caching, CDN, choosing the right database for the access pattern. "Are you using the right resources for the job?"
5. **Cost Optimization** — Reserved instances, spot, lifecycle policies, shutting down unused resources. "Are you spending wisely?"

**Interview tip:** When you finish a design, frame your summary around these pillars: "For reliability, we have multi-AZ with auto-failover. For security, all traffic is encrypted via mTLS and services use IRSA for AWS access. For cost, the base load uses reserved instances and burst capacity uses spot." Shows the interviewer you think like a cloud architect, not just a developer.

---

## 13. Testing & CI/CD

### Where Tests Run — The Layered Model

Tests run in multiple places, each catching problems earlier or more authoritatively. The same test suite runs at several stages:

```
1. Local dev machine     → while writing code (fastest feedback, watch mode)
2. Pre-commit / pre-push  → git hook, before code leaves your machine
3. CI on every PR         → the mandatory, unbypassable gate (most important)
4. CI on merge to main    → final confirmation on the integration branch
```

- **Locally** — Developers run tests constantly during development (`pytest`, `npm test`, `go test ./...`), ideally in watch mode. Fastest feedback loop — catch bugs seconds after writing them.
- **Pre-commit/push hook** (optional) — A git hook runs a quick subset before code is pushed. Keep it fast or developers bypass it with `--no-verify`. Don't run the full suite here.
- **CI on every PR** (essential) — The authoritative, non-bypassable gate. Configure branch protection so a PR **cannot merge** unless tests pass. This is what turns tests from "a good habit" into an enforced quality gate.
- **CI on merge to main** — Catches integration issues: two PRs that each passed alone but conflict when combined.

---

### Git Hooks (layer 2)

**Git hooks** are scripts Git runs automatically at lifecycle events (commit, push, receive). They live in `.git/hooks/`, can be written in any language, and a **non-zero exit aborts the operation** — that's how they enforce rules.

- **Client-side** (`pre-commit`, `pre-push`, `commit-msg`) — local checks: lint, format, quick tests, commit-message format.
- **Server-side** (`pre-receive`, `post-receive`) — policy enforcement on the remote, or triggering CI/CD and deploys.

**Key limitation:** `.git/hooks/` is **not committed** (the `.git/` dir isn't version-controlled), so raw hooks aren't shared across a team. Use a hook manager that stores config *in* the repo — **pre-commit** (`.pre-commit-config.yaml`) or **Husky** (JS/Node) — so everyone gets the same checks.

**Hooks vs CI — the critical distinction:**

- Hooks are a **convenience — bypassable** with `git commit --no-verify`. Great for fast local feedback (catch a lint error in 2 seconds instead of waiting 5 minutes for CI).
- CI is the **enforcement — unbypassable** (branch protection). 

Use hooks to make developers faster; rely on CI as the real gate. Never trust client-side hooks alone for anything quality- or security-critical, precisely because `--no-verify` exists.

---

### Why CI Is Non-Negotiable

Running tests locally isn't enough on its own:

| Local-only problem              | CI solves it by...                          |
| ------------------------------- | ------------------------------------------- |
| "I forgot to run tests"         | Running them automatically, always          |
| "Works on my machine" (drift)   | Running in a clean, consistent environment  |
| Someone bypasses the git hook   | Being unbypassable (branch protection)      |
| No shared record of pass/fail   | Reporting status visibly on the PR          |
| A teammate's change broke yours | Testing the integrated result               |

CI is the **single source of truth** for "do the tests pass?" — neutral, reproducible, and enforced.

---

### The Test Pyramid & Pipeline Ordering

Tests come in types that vary wildly in **speed, cost, and how much they cover**. The "pyramid" describes both how many of each you should have and how they stack:

- **Unit tests** — Test one function/class in isolation, no network or DB. **Milliseconds each; you have thousands.** The wide base of the pyramid.
- **Integration tests** — Test components working together (app + real DB + queue + APIs). **Seconds each; fewer of them.** The middle.
- **End-to-end (E2E) tests** — Drive the whole system like a real user (spin everything up, click through a browser). **Minutes each; very few, and the most brittle.** The narrow top.

The shape is a pyramid on purpose: lots of fast unit tests at the base, progressively fewer/slower tests toward the top. Inverting it (many slow E2E tests, few unit tests) is the "ice-cream cone" anti-pattern — slow, flaky, expensive CI.

**Pipeline ordering — run cheapest/fastest first so you "fail fast":**

```
lint (2s) → UNIT (30s) → build (2m) → integration (5m) → e2e (15m) → deploy
             ↑
   if a cheap unit test catches the bug here, stop immediately —
   don't waste 15 minutes spinning up DBs and browsers for e2e tests that were doomed anyway
```

**Why ordering matters:** if a bug can be caught by a 10-second unit test, you want it to fail the pipeline *before* you spend time and money on the expensive stages. Slow-first ordering means you might burn 15 minutes on E2E only to fail on a typo a unit test would have caught instantly. Fail fast = fastest feedback, lowest cost.

---

### Build System vs CI/CD (the division of labor)

The same split applies to testing as to builds:

- **CI/CD system (GitHub Actions, Jenkins)** = the orchestrator. Decides *when* tests run (on PR, on merge) and reports status.
- **The test runner (Bazel, pytest, go test)** = actually *executes* the tests.

```yaml
# GitHub Actions — CI orchestrates, the runner executes
on: [pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: bazel test //...        # or pytest / npm test / go test
```

**Why Bazel matters at scale — the monorepo problem:** A **monorepo** is one giant repository holding all of a company's code (hundreds of services, tens of thousands of test files) instead of many small repos. If CI naively "runs all the tests" on every PR, a one-line change triggers 50,000 tests and takes hours — unworkable.

Bazel solves this because it understands the **dependency graph** — which code depends on which. When you change a file, it computes exactly which tests could possibly be affected (directly or transitively) and runs *only those*, skipping everything else. It also **caches results**: if a test passed and nothing it depends on changed, Bazel reuses the previous "pass" instead of re-running it.

```
You edit:  services/checkout/pricing.go

Naive CI:  run all 50,000 tests               → ~3 hours
Bazel CI:  "what depends on pricing.go?"       → run ~40 affected tests → ~2 minutes
           (the other 49,960 = cached passes, skipped)
```

**How this pairs with pipeline ordering:** they solve fast CI at two different levels. Test-pyramid ordering makes a *single* pipeline fail fast (cheap tests first). Bazel's affected-test analysis keeps CI fast in a *huge codebase* by never re-testing things your change couldn't have broken. Together they're the answer to the classic interview prompt: *"Your CI takes an hour and developers are frustrated — what do you do?"* → order tests to fail fast, and use a build system that only runs affected tests and caches the rest.

---

### Best Practices

- Keep unit tests **fast, isolated, and deterministic** — no flaky tests, no external network/DB (that's what integration tests are for).
- Block merges on failing CI via **branch protection**.
- Run unit tests **early** in the pipeline; save slow e2e tests for later stages.
- Fail fast — a red pipeline should stop before wasting time/money on build and deploy stages.
- A flaky test is worse than no test — it trains people to ignore failures. Fix or quarantine it.

**Interview relevance:** "How do you ensure code quality?" Answer with the layers: "Tests run locally in watch mode for fast feedback, a pre-push hook catches obvious breakage, and CI runs the full suite on every PR as an unbypassable gate via branch protection. Unit tests run first to fail fast, then integration and e2e. In a monorepo I'd use a build system like Bazel so CI only re-runs tests affected by the change and caches the rest." Ties directly to the Well-Architected "Operational Excellence" pillar.

---

## Patterns from Scenarios

**How do you scale a rule/job evaluation system?**

When a single evaluator processes thousands of rules and can't keep up, partition the rules evenly across multiple evaluator instances (by service name, team, or rule ID hash — not by priority/severity, which creates uneven load). Each evaluator handles a subset independently. If one crashes, use consumer-group-style rebalancing — the remaining evaluators pick up the orphaned rules. Same pattern as Kafka consumer groups: even distribution, automatic failover on failure.

---

**How do you implement time-based escalation (e.g., "if not acknowledged in 5 minutes, escalate")?**

Use a delayed queue/scheduled job. When an alert fires: (1) notify the on-call, (2) schedule a delayed message for 5 minutes from now. When it fires, check an acknowledgment status field in the DB. If acknowledged → do nothing. If not → notify the next person in the escalation chain and schedule another delayed job. The delayed message is the mechanism — SQS delay timers, scheduled jobs, or cron-based checks. Use this pattern anytime you need "if X doesn't happen within Y minutes, do Z."

---

**How do you deduplicate alerts during an ongoing incident?**

Track incident state: firing → acknowledged → resolved. The first time a rule breaches, create an incident and notify. Subsequent evaluations that find the same rule still breaching check Redis for an open incident — if one exists, increment the occurrence counter silently (no new notification). Only send new notifications on state changes: firing (new incident) and resolved (incident over). This prevents the on-call from getting hundreds of duplicate pages for the same outage.

---

**How do you make dashboards fast under heavy concurrent load?**

Cache query results in Redis with a short TTL (30-60s). Dashboard data can be slightly stale — this is the browse pattern. Better yet, use a background pre-computation job that runs every 30-60 seconds, queries the TSDB for all active dashboard panels, and writes results to Redis. The cache is always warm — no user ever hits the TSDB directly. Every dashboard load is a pure Redis read. Same principle as pre-computing recommendations: move expensive work off the user's request path into a background job.

---

## AI / LLM Tidbits & Claude Skills

> Scratch section for AI concepts that come up in interviews and practical tips for using Claude/AI as a tool. Add to it as you learn.

### AI/LLM concepts worth knowing for infra/platform interviews

- **LLM (Large Language Model)** — A model trained on huge text corpora that predicts the next token. It doesn't "know" facts; it produces statistically likely text. Everything below exists to make that useful and grounded.
- **Token** — The unit an LLM reads/writes (~¾ of a word in English). Billing, context limits, and latency are all measured in tokens. "Cost" ≈ input tokens + output tokens.
- **Context window** — The max tokens a model can consider at once (input + output). Exceed it and you must truncate, summarize, or chunk. This is *the* scaling constraint for LLM systems — analogous to memory limits.
- **Prompt engineering** — Structuring input (instructions, examples, constraints) to steer output. Cheapest lever; try before fine-tuning.
- **Few-shot / zero-shot** — Zero-shot = just ask. Few-shot = include example input/output pairs in the prompt to demonstrate the pattern.
- **Temperature** — Randomness knob. Low (0–0.3) = deterministic, factual. High (0.7–1.0) = creative/varied. Use low for code/extraction, higher for brainstorming.
- **Embeddings** — Converting text into fixed-length vectors where semantic similarity = geometric closeness. Foundation of semantic search and RAG.
- **Vector database** — Stores embeddings and does approximate nearest-neighbor (ANN) search to find similar vectors fast (pgvector, Pinecone, Weaviate, OpenSearch k-NN). Think "index for meaning" rather than exact match.
- **RAG (Retrieval-Augmented Generation)** — Instead of relying on the model's frozen training data: embed your docs → store in a vector DB → at query time, retrieve the most relevant chunks → stuff them into the prompt as context → model answers *grounded* in your data. This is how you give an LLM private/current knowledge without retraining. **Most common enterprise LLM architecture.**
- **Fine-tuning** — Further-training a base model on your own labeled data to change its behavior/style. Expensive, slow, and data-hungry. Prefer prompt engineering + RAG first; fine-tune only when you need consistent format/tone or domain behavior that prompting can't achieve.
- **Hallucination** — The model confidently generating false info. Mitigations: RAG grounding, citations, lower temperature, "say I don't know" instructions, output validation.
- **Inference vs training** — Training = building the model (huge, one-time, GPU-heavy). Inference = running it to answer requests (ongoing, latency-sensitive, what you scale and pay for in prod). As an SRE/platform person, you mostly operate **inference** infrastructure.
- **Model serving / inference infra** — Serving LLMs is GPU-bound and expensive. Key concerns: GPU autoscaling (scale-to-zero is hard — cold starts are slow), batching requests for throughput, KV-cache memory, token streaming (SSE) to reduce perceived latency, and cost per token. Tools: vLLM, TGI, Triton, SageMaker, Bedrock.
- **Guardrails** — Input/output filtering for safety, PII, prompt injection. Treat model output as untrusted user input, especially if it feeds tools or shells.
- **Prompt injection** — The LLM security threat: malicious instructions hidden in data the model reads (a doc, a webpage, a tool result) that hijack its behavior. Never let raw model output trigger privileged actions without validation. The "SQL injection of the LLM era."
- **Agent / tool use** — An LLM that can call functions/APIs (tools) in a loop to accomplish tasks. Reliability, idempotency, timeouts, and blast-radius limits matter exactly like any distributed system — plus the model can be wrong, so add validation and human-in-the-loop for destructive actions.
- **MCP (Model Context Protocol)** — Open protocol for connecting LLMs/agents to external tools and data sources in a standardized way. Think "USB-C for AI tools" — a server exposes tools/resources, the model calls them.

---

### RAG pipeline (the one architecture to be able to draw)

```
Ingest (offline):
  docs → chunk → embed → store vectors + metadata in vector DB

Query (online):
  user question → embed → ANN search in vector DB → top-k chunks
              → build prompt (question + retrieved context) → LLM → answer (+ citations)
```

**Interview relevance:** This maps cleanly to systems you already know — it's just an indexing + read path. Chunking strategy, embedding cost, vector DB sharding, retrieval latency, and caching frequent queries are all the same trade-offs from Parts 2 and 3.

---

### Using Claude / AI effectively (workflow tidbits)

- **Give context, not just a task** — Paste the relevant files, errors, and constraints. The model can't see your repo unless you show it (or it has tools). Garbage/no context in → generic answer out.
- **Be specific about the output you want** — Format, length, language, "concise," "just the diff." Vague asks get vague answers.
- **Iterate in small steps** — For big changes, plan first, then implement piece by piece. Easier to verify and correct than one giant dump.
- **Verify, don't trust** — Treat generated code/answers as a confident junior engineer's first draft. Run it, test it, read it. Hallucinations look plausible.
- **Use it for the boring 80%** — Boilerplate, glue code, test scaffolding, config, docs, translating between languages/tools, explaining unfamiliar code. Keep your judgment for architecture and trade-offs.
- **Ask "why," not just "what"** — For learning, make it justify trade-offs and push back on your reasoning (exactly how you're using it for interview prep).

---

### Cursor Skills (`SKILL.md`)

A **Skill** is a reusable capability you define once and the agent invokes when relevant. It's a folder with a `SKILL.md` that has YAML frontmatter (`name`, `description`) plus instructions/steps the agent follows.

- **What it's for** — Encapsulate a repeatable workflow (e.g., "create a hook," "split work into PRs," "review with Bugbot") so you don't re-explain it every time. The `description` tells the agent *when* to use it.
- **How the agent uses it** — It reads the relevant `SKILL.md` and follows the instructions inside. Skills can reference scripts and other files by absolute path.
- **Related Cursor constructs** — **Rules** (`.cursor/rules/`, persistent guidance/coding standards), **Hooks** (`hooks.json`, automate behavior around agent events), and **AGENTS.md** (project conventions). Skills = "how to do a task," Rules = "constraints to always follow," Hooks = "run this on event X."