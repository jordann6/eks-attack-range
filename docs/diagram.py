"""Architecture + kill-chain diagram for the EKS Attack Range.

Renders docs/architecture.png with official AWS service icons (mingrammer
diagrams). Run: python3 docs/diagram.py  (needs graphviz `dot` on PATH).
"""
from diagrams import Diagram, Cluster, Edge
from diagrams.aws.compute import EKS, EC2
from diagrams.aws.security import SecretsManager, Guardduty
from diagrams.aws.network import NLB
from diagrams.onprem.client import User
from diagrams.k8s.compute import Pod
from diagrams.k8s.podconfig import Secret

graph_attrs = {"fontsize": "13", "bgcolor": "white", "pad": "0.5", "splines": "ortho"}
node_attrs = {"fontsize": "11"}

red = Edge(color="firebrick", fontcolor="firebrick")

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
    guard = Guardduty("GuardDuty + Falco\naudit log")

    with Cluster("VPC (lab)"):
        node = EC2("managed node (EC2)\nIMDSv1, broad role")
        with Cluster("namespace: summarizer"):
            pod = Pod("summarizer pod\n(cluster-admin SA)")
            trophy = Secret("Secret: ANTHROPIC_API_KEY\n(plaintext in etcd)")
        loot = SecretsManager("Secrets Manager\nprod/db-backup (decoy)")

    attacker >> red << nlb
    nlb >> Edge(label="1. RCE via cmd injection", **red.attrs) >> pod
    pod >> Edge(label="2. SSRF to IMDS", **red.attrs) >> node
    node >> Edge(label="3. stolen node creds", **red.attrs) >> loot
    pod >> Edge(label="4. SA token -> cluster-admin", **red.attrs) >> eks
    eks >> Edge(label="5. get secret (trophy)", **red.attrs) >> trophy

    eks >> Edge(color="royalblue", style="dashed", label="detect") >> guard
    pod >> Edge(color="royalblue", style="dashed") >> guard
