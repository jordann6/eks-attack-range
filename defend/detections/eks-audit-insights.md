# EKS audit log queries (CloudWatch Logs Insights)

The cluster writes control-plane audit events to the log group
`/aws/eks/<cluster-name>/cluster` because `cluster_enabled_log_types` includes
`audit`. Run these in CloudWatch Logs Insights against that group. They surface
stages 4 and 5 of the kill chain: the pod's ServiceAccount acting as
cluster-admin.

## Stage 4: the app ServiceAccount listing secrets cluster-wide

A web app's identity should never enumerate secrets. This returns every such
call.

```
fields @timestamp, user.username, verb, objectRef.resource, objectRef.namespace
| filter user.username = "system:serviceaccount:summarizer:summarizer"
| filter objectRef.resource = "secrets"
| filter verb in ["list", "get", "watch"]
| sort @timestamp desc
```

## Stage 5: the exact trophy read

```
fields @timestamp, user.username, verb, objectRef.namespace, objectRef.name
| filter objectRef.resource = "secrets" and objectRef.name = "summarizer-key"
| filter verb = "get"
| sort @timestamp desc
```

## Any ServiceAccount token used from an unexpected source

Broader hunt: a SA identity doing high-value verbs it has no business doing.

```
fields @timestamp, user.username, verb, objectRef.resource, sourceIPs.0
| filter user.username like /system:serviceaccount:summarizer/
| filter verb in ["list", "get", "create", "delete"] and objectRef.resource in ["secrets", "pods", "clusterrolebindings"]
| stats count(*) as calls by user.username, verb, objectRef.resource
| sort calls desc
```

## Why the hardened cluster produces nothing here

After the `hardened/` overlay, the SA has no cluster-admin binding, so these
same calls appear in the audit log as `forbid` decisions with
`annotations.authorization.k8s.io/decision = "forbid"` instead of succeeding.
That flip, from allowed to forbidden, is the before/after screenshot for the
write-up.
