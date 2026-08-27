# Study Plan — $200-300K+ SRE / Platform / Cloud Architect Roles

## Weekly Structure

4 sessions per week. 3 scenario sessions, 1 consolidation session.

### Scenario Sessions (3x per week, 2 hours each)

AI asks realistic multi-part infrastructure/platform scenarios. You answer as if whiteboarding with an interview panel. AI pushes back, asks follow-ups, and grades your answers.

**How it works:**
- AI presents a scenario with 3-4 questions covering infrastructure design, scaling, security, cost, deployment, and incident response
- You ask clarifying questions before answering (this is expected and graded positively)
- AI gives detailed feedback after each answer — what you got right, what you missed, and what the strong answer looks like
- New concepts that come up are added to `systems-design-guide.md` during the session
- Jot down any new concepts you learned (just the name and a one-liner) so you can make proper flashcards later

**What gets tested:**
- Architectural decision-making and trade-offs
- Specific tools and services (AWS, Kubernetes, databases, queues, CDNs)
- Incident response and debugging methodology
- Cost optimization
- Security and compliance
- Data flow design (caching, replication, queues, streaming)

### Consolidation Session (1x per week, 2 hours)

| Block | Duration | Activity |
|-------|----------|----------|
| 1 | 60 min | **Flashcard review.** Review existing flashcards first. Then create new flashcards from the concepts you jotted down during the week's scenario sessions. |
| 2 | 60 min | **Doc review.** Pick 1-2 sections of `systems-design-guide.md` you haven't reviewed recently. Read through them, make flashcards for any key concepts you don't have cards for yet. This catches blind spots that scenarios haven't covered. |

---

## Phase 1: Building Foundation (Current Phase)

**Goal:** Learn concepts through applied scenarios, build flashcard deck, fill knowledge gaps.

### Phase 1 is done when:
- Scenarios mostly cover things you already know (fewer than 2-3 new concepts per session)
- You can explain all flashcard concepts without looking at the doc
- Consistent B+ or higher on scenario grades
- You naturally mention caching, data layer, failure modes, and cost without being prompted

### Phase 1 Goals
- [ ] Complete all flashcards from notecard list below + new concepts from scenarios
- [ ] Review all 12 sections of the doc at least once during consolidation sessions
- [ ] Watch 5-7 NeetCode system design videos (one per week, in addition to sessions)
- [ ] Consistent B+ or higher on scenario questions

---

## Phase 2: Full Mock Interviews (After Phase 1)

**Goal:** Full end-to-end system design practice. You lead the design, AI plays interviewer.

### Mock Interview Format (45 minutes)
1. **Requirements (2-3 min)** — You ask clarifying questions. AI answers as interviewer.
2. **Estimation (2-3 min)** — Back-of-envelope math out loud.
3. **High-Level Design (5 min)** — Describe the architecture. AI asks follow-ups.
4. **Deep Dive (15-20 min)** — Go deep on the hardest parts. AI pushes back, throws curveballs.
5. **Trade-offs & Failure Modes (5 min)** — What breaks first? What would you change at 10x scale?
6. **Feedback & Grade (5 min)** — AI grades each section separately.

### Phase 2 Goals
- [ ] Complete 10-15 full mock interviews
- [ ] Consistent A- or higher on mock interviews
- [ ] Can articulate trade-offs without being prompted
- [ ] Always mentions data layer, caching, failure modes, deployment strategy unprompted
- [ ] Comfortable leading the conversation for 45 minutes

### Phase 2 is done when:
- You consistently score A- or higher
- You can design any system without freezing or going blank
- You feel bored by the questions because the patterns keep repeating

---

## Weekly NeetCode Schedule

Watch one system design video per week throughout both phases. After watching:
1. Close the video
2. Try to design the same system from memory
3. Compare your design to theirs
4. Note what you missed

---

## Notecard List

These are the baseline patterns to card. New concepts from scenarios get added to this list during consolidation sessions.

| Front (Pattern Name) | Back (One Sentence + When to Use) |
|-----------------------|-----------------------------------|
| Expand and contract | Support old and new simultaneously, migrate, remove old. Use for any schema, API, or event format change. |
| Browse vs commit | Serve stale on browse, check source of truth on commit. Use when users view data then act on it. |
| Circuit breaker | Stop calling a failing service, fail fast, test recovery. Use between any two services. |
| Cache stampede / locking | Many requests miss cache simultaneously — lock so only one hits DB. Use for popular cache keys with expiry. |
| Cache avalanche | Many keys expire at once — add jitter to TTLs. Use when setting TTLs on cached data. |
| Fan-out on write vs read | Push to followers on post vs pull on feed load. Use hybrid for social feeds (push for regular, pull for celebrities). |
| Read-after-write consistency | Route user's reads to the node they just wrote to. Use after any user-facing write. |
| Saga pattern | Chain of local transactions with compensating undos. Use for multi-service workflows (checkout, booking). |
| CQRS | Separate read and write databases. Use when read/write patterns are fundamentally different. |
| Event sourcing | Store events, derive state by replaying. Use for audit-heavy domains (banking, finance). |
| Dead letter queue | Failed messages move to separate queue after N retries. Use for any queue where losing messages is unacceptable. |
| Shadow traffic / dark launching | Copy requests to new service, compare responses, user unaffected. Use for service migrations. |
| Envelope encryption | KMS generates data key, encrypt locally, store encrypted key alongside. Use for bulk data encryption with centralized key management. |
| Refresh token pattern | Short-lived access token + long-lived revocable refresh token. Use for any token-based auth system. |
| N+1 AZ redundancy | Each AZ handles full load on its own. Use for any critical service in multi-AZ deployment. |
| Dual-write | Write to both old and new during transitions. Use during data migrations. |
| Graceful degradation | Return fallback response instead of error when dependency is down. Use for every user-facing service. |
| Layered caching | CDN → local cache → Redis → DB. Each layer catches requests before the next. Use for any read-heavy system. |
| Pre-signed URLs | S3 generates temporary scoped URL for direct upload/download. Use to keep API servers out of file transfers. |
| Adaptive bitrate streaming | Transcode video into multiple quality levels, client picks based on bandwidth. Use for any video/streaming platform. |
| Geospatial indexing | Redis GEORADIUS or PostGIS for "find nearby X" queries. Use instead of brute-force distance calculation. |
| Signed URLs (CloudFront) | Temporary access to private files served from CDN edge. Use for large/frequent private file access with edge caching. |
| SQS visibility timeout | Message stays invisible during processing; reappears if not deleted. Use with max receive count + DLQ for automatic retry. |
| Idempotency keys | Unique key per operation so retries don't cause duplicates. Use for any payment, order, or critical write with retries. |
| HPA metric selection | HPA defaults to CPU only — add memory when memory correlates with traffic. Don't scale on memory for leaks. |
| Global Accelerator | Anycast IPs route traffic onto AWS backbone at nearest edge. Use for consistent latency and instant failover. |
| WebRTC vs WebSocket | WebSocket for messages, WebRTC for audio/video. WebRTC has built-in adaptive bitrate. |
| Account-origin routing | Route by user's home region (from JWT), not physical location. Use for data residency compliance with traveling users. |
| DB scaling order | Indexes → caching → read replicas → vertical scale → connection pooling → sharding. Always exhaust simpler options first. |

---

## Interview Readiness Checklist

Before scheduling interviews, verify:

- [ ] Can explain all flashcard concepts without looking at the doc
- [ ] Completed 10+ full mock interviews with consistent A- grades
- [ ] Can trace a failure chain hop-by-hop for any incident scenario
- [ ] Always mentions: caching layers, data layer, failure modes, deployment strategy
- [ ] Comfortable with the 5-step framework: requirements → estimation → high-level → deep dive → trade-offs
- [ ] Can push back on interviewer suggestions with reasoning
- [ ] Specific with tools and services (not "DNS routing" but "Route 53 geolocation policy")
- [ ] Distinguishes between failure types and matches solutions accordingly (deployment rollback vs regional failover vs data corruption)
