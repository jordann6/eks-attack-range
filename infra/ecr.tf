# Registry for the deliberately-vulnerable summarizer image. Scan-on-push is ON
# so the known-CVE base image shows up as an ECR finding, which is the "the
# scanner already knew" beat of the blue-team write-up. force_delete lets
# `make destroy` remove the repo with images still in it.
resource "aws_ecr_repository" "app" {
  name                 = "${local.name}/summarizer"
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = local.tags
}
