# LocalFile — CRDs, Operators & Admission Control Lab

A minimal end-to-end lab for the three Kubernetes extension points. You create a
`LocalFile` resource; an operator writes a real file to your Mac's `/tmp/localfiles`;
admission webhooks stamp it with a timestamp and reject bad filenames.

## What each piece teaches

| Layer | What it does here | Concept |
| ----- | ----------------- | ------- |
| **CRD** (`manifests/crd.yaml`) | Defines a new `LocalFile` type the API server accepts | Extending the API with your own resource — schema only, no behavior |
| **Operator** (`operator/handlers.py`) | Watches `LocalFile` and reconciles the filesystem to match | The reconciliation loop: desired state (the resource) vs actual state (the file) |
| **Mutating webhook** (`policies/mutate-timestamp.yaml`) | Adds a `mehdi.dev/created-at` annotation at admission | Modifying an object *in flight*, before it's persisted |
| **Validating webhook** (`policies/validate-suffix.yaml`) | Rejects filenames not ending in `-mehdik8s` | Blocking bad config so it never reaches etcd |

## Request flow

```
kubectl apply -f localfile.yaml
   |
   v
API server
   |-- authentication -> authorization (RBAC)
   |-- ADMISSION:
   |      mutating   -> Kyverno adds mehdi.dev/created-at
   |      validating -> Kyverno checks filename ends in -mehdik8s  --(fail)--> REJECTED, done
   v
   etcd  (object persisted)
   |
   v
Operator (watching) -> reconcile() -> writes /tmp/localfiles/<filename> on your Mac
                                   -> patches .status with the path
```

## Quickstart

Requires Docker Desktop installed, signed in, and running. In its settings, give it
at least 4 CPU / 6 GB, and make sure `/private/tmp` is listed under
Resources -> File Sharing (otherwise kind's `extraMounts` will fail).

```bash
make prereqs   # one time: kind + kubectl + helm
make up        # cluster -> kyverno -> CRD -> policies -> operator
make demo      # apply a bad resource (rejected), then a good one (file appears)
```

Then confirm the file really is on your Mac:

```bash
cat /tmp/localfiles/hello-mehdik8s
```

## How the file reaches your Mac

kind runs the "node" as a container, so it takes two hops:

```
Mac /tmp/localfiles  --(kind extraMounts)-->  node /mnt/localfiles  --(hostPath volume)-->  pod /data
```

Configured in `kind-config.yaml` and `manifests/operator.yaml`. The operator writes to
`$LOCALFILE_DIR` (`/data` in-cluster).

Prefer a faster loop? `make run-local` runs the operator directly on your Mac against the
same cluster, writing straight to `/tmp/localfiles` with no image build and no mounts.
This is how operators are normally developed.

## Things to actually try

1. **See the reconcile loop.** `make watch` — delete the resource, watch the file vanish.
   Then edit `content:` in `examples/localfile-good.yaml`, re-apply, and `cat` the file again.
2. **Break the validation.** `kubectl apply -f examples/localfile-bad.yaml` and read the
   rejection message. Note the resource does not exist afterward — `kubectl get localfiles`.
3. **Switch Enforce to Audit.** In `policies/validate-suffix.yaml`, set
   `validationFailureAction: Audit`, then:

   ```bash
   kubectl apply -f policies/
   kubectl apply -f examples/localfile-bad.yaml   # now ALLOWED
   kubectl get policyreport -A                     # violation recorded instead (wait ~15s)
   ```

   This is how you roll a policy out to an existing cluster without breaking anyone —
   you get visibility first, then flip to Enforce. Note the side effect: because the
   object is admitted, the operator happily creates `hello.txt`, the very file the rule
   exists to prevent.

   Two gotchas worth understanding (both cost real debugging time):
   - **Kyverno needs RBAC to report on custom resources.** It ships permissions for
     built-in kinds only. `manifests/kyverno-rbac.yaml` grants read access to
     `localfiles` via label-based ClusterRole aggregation. Without it, admission still
     works (the webhook receives the object in the request) but **no report is ever
     generated**, because reporting has to *read* the resource from the API.
   - **Reports are asynchronous.** They're written by the reports controller after
     admission returns, and the periodic background scan defaults to 1 hour. Touching
     the resource (`kubectl annotate localfile bad-name trigger=1 --overwrite`) forces
     a fresh evaluation if you don't want to wait.
4. **Prove the mutation happened.** Remove the mutating policy
   (`kubectl delete clusterpolicy localfile-add-timestamp`), re-create the good resource,
   and the file will say `admission-stamped-at: <not mutated>`.
5. **Three ways to validate the same rule.** Uncomment the `pattern:` line in
   `manifests/crd.yaml` to enforce the suffix in the CRD's own OpenAPI schema — no webhook
   involved at all. Compare that error message to Kyverno's. This is the clearest way to
   see the boundary between *schema validation* and *admission control*.
6. **Look at the plumbing.** `make webhooks` shows the webhook configurations Kyverno
   registered for itself — the endpoint and `caBundle` the API server was told to trust.

## Notes

- `validationFailureAction` at the policy level is deprecated in very recent Kyverno in
  favor of per-rule `failureAction`. If your version warns, move the field into the rule.
- The operator runs with `--standalone` (no kopf peering CRD) since there's one replica.
- Kyverno registers its own webhooks and manages its own CA — nothing to configure.
