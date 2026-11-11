# Detection, Session A (EKS 1.36, 2026-11-11)

GuardDuty is ENABLED in the lab account. No InstanceCredentialExfiltration
finding was created or updated in the hour around this run. The one existing
finding of that type is from 2026-11-03 against a different, since-destroyed
node instance. Recorded as a miss: GuardDuty's anomaly detector did not fire
within this session's window for this run's node-credential theft.

EKS audit log queries from defend/detections/eks-audit-insights.md for stages
4/5 (filtering user.username = system:serviceaccount:summarizer:summarizer)
return zero matches, confirmed by direct CloudWatch Logs Insights query
(0 of 1850+ records). Root cause found: demo.py exercises stages 4/5 via
`kubectl auth can-i --as=<SA>`, an assume-breach impersonation check run as
the operator's own IAM identity. That generates a SubjectAccessReview, not an
actual secrets get/list call by the SA, and EKS's default audit policy does
not log SubjectAccessReview/TokenReview events at all (confirmed: the only
subjectaccessreviews-create audit entries in the window are from
eks:certificate-controller, none from this session). This is a real gap
between the documented detection queries and the assume-breach testing
method, not a transient miss. Record in ADR-0004 as a known limitation:
the documented audit queries only catch a REAL impersonated call with the
SA's own token, not the can-i simulation this demo uses.
