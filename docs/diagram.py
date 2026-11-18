"""Architecture + kill-chain diagram for the EKS Attack Range.

Renders docs/architecture.png with official AWS service icons (mingrammer
diagrams). Run: python3 docs/diagram.py  (needs graphviz `dot` on PATH).
"""
from diagrams import Diagram, Cluster, Edge
from diagrams.aws.compute import EKS, EC2, Lambda
from diagrams.aws.security import SecretsManager, Guardduty, IAM
from diagrams.aws.network import NLB
from diagrams.aws.management import Cloudtrail, CloudwatchLogs
from diagrams.aws.integration import SNS
from diagrams.aws.storage import S3
from diagrams.onprem.client import User
from diagrams.k8s.compute import Pod
from diagrams.k8s.podconfig import Secret

graph_attrs = {"fontsize": "13", "bgcolor": "white", "pad": "0.5", "splines": "ortho"}
node_attrs = {"fontsize": "11"}

red = Edge(color="firebrick", fontcolor="firebrick")
blue = Edge(color="royalblue", fontcolor="royalblue", style="dashed")
green = Edge(color="forestgreen", fontcolor="forestgreen")

with Diagram(
    "EKS Attack Range: kill chain (red) and detection (blue)",
    filename="docs/architecture",
    show=False,
    direction="LR",
    graph_attr=graph_attrs,
    node_attr=node_attrs,
):
    attacker = User("attack box\n(authorized, /32 allow-listed)")
    nlb = NLB("public LoadBalancer")
    eks = EKS("EKS control plane\n(public endpoint, audit log on)")
    guard = Guardduty("GuardDuty + Falco\nruntime")

    with Cluster("VPC (lab)"):
        node = EC2("managed node (EC2)\nIMDSv2, hop limit 2, broad role")
        with Cluster("namespace: summarizer"):
            pod = Pod("summarizer pod\n(cluster-admin SA)")
            trophy = Secret("Secret: CANARY_TOKEN\n(synthetic, plaintext in etcd)")
            d1 = Secret("D1: decoy AWS key\n(/root/.aws/credentials)")
            d34 = Secret("D3/D4: decoy Secret\n+ unbound SA token")
        loot = SecretsManager("Secrets Manager\nprod/db-backup (decoy)")
        responder = Pod("incident responder\n(labels + quarantines)")

    with Cluster("detection + response"):
        trail = Cloudtrail("CloudTrail\n(all mgmt events)")
        auditlogs = CloudwatchLogs("audit log\nsubscription filter")
        alert = Lambda("alert function\nattribute + dedupe")
        records = S3("alert + quarantine\nrecords")
        sns = SNS("alert topic")
        decoy_user = IAM("zero-policy user\nsvc-backup-sync")

    attacker >> red << nlb
    nlb >> Edge(label="1. RCE via cmd injection", **red.attrs) >> pod
    pod >> Edge(label="2. SSRF + IMDSv2 handshake", **red.attrs) >> node
    node >> Edge(label="3. stolen node creds", **red.attrs) >> loot
    pod >> Edge(label="4. SA token -> cluster-admin", **red.attrs) >> eks
    eks >> Edge(label="5. get secret (trophy)", **red.attrs) >> trophy

    # Deception: any use of a planted credential is caught and contained.
    d1 >> Edge(label="use key", **red.attrs) >> decoy_user >> blue >> trail
    d34 >> blue >> eks >> Edge(label="audit", **blue.attrs) >> auditlogs
    trail >> blue >> alert
    auditlogs >> blue >> alert
    alert >> blue >> records
    alert >> blue >> sns
    records >> Edge(label="poll", **green.attrs) >> responder
    responder >> Edge(label="deny-all NetworkPolicy", **green.attrs) >> pod

    eks >> Edge(color="royalblue", style="dashed", label="detect") >> guard
    pod >> blue >> guard
