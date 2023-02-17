data "aws_eks_cluster" "cluster" {
  name = module.eks.cluster_id
}

data "aws_eks_cluster_auth" "cluster" {
  name = module.eks.cluster_id
}
data "aws_availability_zones" "available" {}

data "aws_route53_zone" "this" {
  # name         = "edu.provectus.io."
  zone_id      = var.zone_id
  private_zone = false
}

locals {
  tags = {
    environment = local.environment
    project     = local.project
  }
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "v2.64.0"

  name = "${local.environment}-${local.cluster_name}"

  cidr = local.cidr

  azs             = local.zones
  private_subnets = local.private
  public_subnets  = local.public

  enable_nat_gateway = true
  single_nat_gateway = var.single_nat

  enable_dns_hostnames = true
  enable_dns_support   = true

  public_subnet_tags = {
    Name                                          = "${local.environment}-${local.cluster_name}-public"
    KubernetesCluster                             = local.cluster_name
    Environment                                   = local.environment
    Project                                       = local.project
    "kubernetes.io/role/elb"                      = "1"
    "kubernetes.io/cluster/${local.cluster_name}" = "owned"
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
  }

  private_subnet_tags = {
    Name                                          = "${local.environment}-${local.cluster_name}-private"
    "kubernetes.io/role/elb-internal"             = "1"
    "kubernetes.io/cluster/${local.cluster_name}" = "owned"
  }

  tags = {
    Name        = "${local.environment}-${local.cluster_name}"
    Environment = local.environment
    Project     = local.project
    Terraform   = "true"
  }
}


module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "18.30.2"

  cluster_version = var.cluster_version
  cluster_name    = local.cluster_name

  prefix_separator                   = ""
  iam_role_name                      = local.cluster_name
  cluster_security_group_name        = local.cluster_name
  cluster_security_group_description = "EKS cluster security group."

  subnet_ids  = local.subnets
  vpc_id      = module.vpc.vpc_id
  enable_irsa = false


  manage_aws_auth_configmap = true
  create_aws_auth_configmap = true
  # NOTE:
  #  enable cloudwatch logging
  cluster_enabled_log_types              = var.cloudwatch_logging_enabled ? var.cloudwatch_cluster_log_types : []
  cloudwatch_log_group_retention_in_days = var.cloudwatch_logging_enabled ? var.cloudwatch_cluster_log_retention_days : 90

  tags = {
    Environment = local.environment
    Project     = local.project
  }


  self_managed_node_group_defaults = {
    update_launch_template_default_version = true
    iam_role_additional_policies = [
      "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
      "arn:aws:iam::aws:policy/ElasticLoadBalancingFullAccess",
      "arn:aws:iam::aws:policy/AmazonRoute53FullAccess",
      "arn:aws:iam::aws:policy/AmazonRoute53AutoNamingFullAccess",
      "arn:aws:iam::aws:policy/AmazonElasticFileSystemFullAccess",
      "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryFullAccess",
    ]
    additional_userdata  = "sudo yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm && sudo systemctl enable amazon-ssm-agent && sudo systemctl start amazon-ssm-agent"
    bootstrap_extra_args = (var.container_runtime == "containerd") ? "--container-runtime containerd" : "--docker-config-json ${local.docker_config_json}"
  }

  # Note:
  #   If you add here worker groups with GPUs or some other custom resources make sure
  #   to start the node in ASG manually once or cluster autoscaler doesn't find the resources.
  #
  #   After that autoscaler is able to see the resources on that ASG.
  #
  self_managed_node_groups = {
    memory-optimized = {
      # expected length of name to be in the range (1 - 38)
      name         = "${local.environment}-${local.cluster_name}-memory"
      max_size     = 3
      desired_size = 1

      use_mixed_instances_policy = true
      mixed_instances_policy = {
        instances_distribution = {
          on_demand_base_capacity                  = 0
          on_demand_percentage_above_base_capacity = 10
          spot_allocation_strategy                 = "capacity-optimized"
        }

        override = [
          {
            instance_type     = "m5.large"
            weighted_capacity = "1"
          },
          {
            instance_type     = "m6i.large"
            weighted_capacity = "2"
          },
        ]
      }
    }
    # worker_group = concat(local.common, local.cpu, local.gpu)
  }
}

# OIDC cluster EKS settings
resource "aws_iam_openid_connect_provider" "cluster" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"]
  url             = module.eks.cluster_oidc_issuer_url
}

module "argocd" {
  depends_on = [module.vpc.vpc_id, module.eks.cluster_id, data.aws_eks_cluster.cluster]
  source     = "/Users/hovhannes/Documents/Work/Provectus/sak-argocd"

  branch       = var.argocd.branch
  owner        = var.argocd.owner
  repository   = var.argocd.repository
  cluster_name = module.eks.cluster_id
  path_prefix  = "examples/argocd/"

  domains = local.domain
  ingress_annotations = {
    "nginx.ingress.kubernetes.io/ssl-redirect" = "false"
  }
  conf = {
    "server.service.type"     = "ClusterIP"
    "server.ingress.paths[0]" = "/"
  }
}
module "nginx-ingress" {
  #depends_on   = [module.clusterwide]
  source       = "/Users/hovhannes/Documents/Work/Provectus/sak-nginx"
  argocd       = module.argocd.state
  conf = {
    "controller.service.targetPorts.http"                                                                = "http"
    "controller.service.targetPorts.https"                                                               = "http"
    #"controller.service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-ssl-cert"         = "arn:aws:acm:eu-north-1:641456973426:certificate/a73031f2-e5ee-4ecc-9a73-e0b5658608fc" #module.clusterwide.this_acm_certificate_arn
    "controller.service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-backend-protocol" = "http"
    "controller.service.annotations.service\\.beta\\.kubernetes\\.io/aws-load-balancer-ssl-ports"        = "https"
  }
  tags = local.tags
}
module "external_dns" {
  depends_on = [module.argocd]

  source       = "/Users/hovhannes/Documents/Work/Provectus/sak-external-dns"
  cluster_name = module.eks.cluster_id
  argocd       = module.argocd.state
  mainzoneid   = data.aws_route53_zone.this.zone_id
  hostedzones  = local.domain
  tags         = local.tags
}

module oauth {
  depends_on     = [module.argocd]
  source         = "/Users/hovhannes/Documents/Work/Provectus/sak-oauth"
  cluster_name   = module.eks.cluster_id
  namespace_name = "oauth"
  domains        = local.domain
  argocd         = module.argocd.state
  client_id      = "exampleid"
  client_secret  = "examplesecret"
  cookie_secret  = "examplecookie"
}

module "alb-ingress" {
  depends_on   = [module.argocd]
  source       = "/Users/hovhannes/Documents/Work/Provectus/sak-alb-controller"
  cluster_name = module.eks.cluster_id
  vpc_id       = module.vpc.vpc_id
  argocd       = module.argocd.state
}
module "cert-manager" {
  depends_on   = [module.argocd]

  source       = "/Users/hovhannes/Documents/Work/Provectus/sak-cert-manager"
  cluster_name = module.eks.cluster_id
  argocd       = module.argocd.state
  email        = "hkhalatyan@provectus.com"
  zone_id      = data.aws_route53_zone.this.zone_id
  vpc_id       = module.vpc.vpc_id
  domains      = local.domain
}
module external_secrets {
  source            = "/Users/hovhannes/Documents/Work/Provectus/sak-external-secrets"
  argocd            = module.argocd.state
  cluster_name      = module.eks.cluster_id
  cluster_oidc_url  = module.eks.cluster_oidc_issuer_url
}

module "loki" {
  module_depends_on = [module.argocd]
  source            = "/Users/hovhannes/Documents/Work/Provectus/sak-loki"
  cluster_name      = module.eks.cluster_id
  argocd            = module.argocd.state
  domains           = local.domain
}

###################################################################################
/*
module acm {
  source  = "terraform-aws-modules/acm/aws"
  version = "~> v2.0"

  domain_name               = var.domain_name
  subject_alternative_names = ["*.${var.domain_name}"]
  zone_id                   = module.external_dns.zone_id
  validate_certificate      = false
  tags                      = local.tags
}
module kubeflow {
  source = "/Users/hovhannes/Documents/Work/Provectus/sak-kubeflow"
  cluster_name = module.eks.cluster_id

  ingress_annotations = {
    "kubernetes.io/ingress.class"               = "alb"
    "alb.ingress.kubernetes.io/scheme"          = "internet-facing"
    "alb.ingress.kubernetes.io/certificate-arn" = module.acm.this_acm_certificate_arn
    "alb.ingress.kubernetes.io/auth-type"       = "cognito"
    "alb.ingress.kubernetes.io/auth-idp-cognito" = jsonencode({
      "UserPoolArn"      = module.cognito.pool_arn
      "UserPoolClientId" = aws_cognito_user_pool_client.this.id
      "UserPoolDomain"   = module.cognito.domain
    })
    "alb.ingress.kubernetes.io/listen-ports" = jsonencode(
      [{ "HTTPS" = 443 }]
    )
  }
  domain = "kubeflow.${local.domain}"
  argocd = module.argocd.state
}

module cluster_autoscaler {
  source            = "git::https://github.com/provectus/swiss-army-kube.git//modules/system/cluster-autoscaler?ref=feature/argocd"
  image_tag         = "v1.15.7"
  cluster_name      = module.eks.cluster_name
  module_depends_on = [module.eks]
  argocd            = module.argocd.state
}

module "cognito" {
  source       = "/Users/hovhannes/Documents/Work/Provectus/sak-cognito"
  cluster_name = module.eks.cluster_id
  domain       = "hovoexample.com"
  zone_id      = "Z077774642JFDT3T2B1Z"
}

resource aws_cognito_user_pool_client "kubeflow" {
  name                                 = "kubeflow"
  user_pool_id                         = module.cognito.pool_id
  callback_urls                        = ["https://kubeflow.hovoexample.com/oauth2/idpresponse"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_scopes                 = ["email", "openid", "profile", "aws.cognito.signin.user.admin"]
  allowed_oauth_flows                  = ["code"]
  supported_identity_providers         = ["COGNITO"]
  generate_secret                      = true
}
resource aws_cognito_user_pool_client "argocd" {
  name                                 = "argocd"
  user_pool_id                         = module.cognito.pool_id
  callback_urls                        = ["https://argocd.hovoexample.com/auth/callback"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_scopes                 = ["openid", "profile", "email"]
  allowed_oauth_flows                  = ["code"]
  supported_identity_providers         = ["COGNITO"]
  generate_secret                      = true
}

resource "aws_cognito_user_group" "this" {
  for_each = toset(distinct(values(
    {
      for k, v in var.cognito_users :
      k => lookup(v, "group", "read-only")
    }
  )))
  name         = each.value
  user_pool_id = module.cognito.pool_id
}

resource "null_resource" "cognito_users" {
  depends_on = [module.cognito.pool_id, aws_cognito_user_group.this]
  for_each = {
    for k, v in var.cognito_users :
    format("%s:%s:%s", var.region, module.cognito.pool_id, v.username) => v

  }
  provisioner "local-exec" {
    command = "aws --region ${element(split(":", each.key), 0)} cognito-idp admin-create-user --user-pool-id ${element(split(":", each.key), 1)} --username ${element(split(":", each.key), 2)} --user-attributes Name=email,Value=${each.value.email}"
  }
  provisioner "local-exec" {
    command = "aws --region ${element(split(":", each.key), 0)} cognito-idp admin-add-user-to-group --user-pool-id ${element(split(":", each.key), 1)} --username ${element(split(":", each.key), 2)} --group-name ${lookup(each.value, "group", "read-only")}"
  }
  provisioner "local-exec" {
    when    = destroy
    command = "aws --region ${element(split(":", each.key), 0)} cognito-idp admin-delete-user --user-pool-id ${element(split(":", each.key), 1)} --username ${element(split(":", each.key), 2)}"
  }
}
*/