#################################################
##AWS Provider and AWS Subscription credentials##
#################################################
terraform {
  required_providers {
     aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
    kubernetes =  {
      version                = "~> 1.3"
    }
  }
  
}

provider "aws" {
  access_key = var.access_key
  secret_key = var.secret_key
  region     = var.region
}

data "aws_eks_cluster_auth" "cluster" {
  name = aws_eks_cluster.eksCluster.id
}


provider "kubernetes" {
  host                   = aws_eks_cluster.eksCluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.eksCluster.certificate_authority.0.data)
  token                  = data.aws_eks_cluster_auth.eksCluster.token
  load_config_file       = false
  version                = "~> 1.11"
}



######################################
##IAM Role for managing EKS Cluster ##
######################################

resource "aws_iam_role" "eksRole" {
  name = var.eksRoleName
  tags = var.tags

assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role" "eksNodeRole" {
  name = var.eksNodeRole
  tags = var.tags

assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

########################
##IAM Policies for EKS##
########################

resource "aws_iam_role_policy_attachment" "eksPolicy1" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eksRole.name
}

resource "aws_iam_role_policy_attachment" "eksResourceController" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.eksRole.name
}


resource "aws_iam_role_policy_attachment" "eksAmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.eksNodeRole.name
}

resource "aws_iam_role_policy_attachment" "eksAmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.eksNodeRole.name
}

resource "aws_iam_role_policy_attachment" "eksAmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.eksNodeRole.name
}

resource "aws_iam_instance_profile" "eksNodeRole" {
  name = "eksNodeRole"
  role = aws_iam_role.eksNodeRole.name
}

#######################
##EKS VPC and Subnets##
#######################
resource "aws_vpc" "eksVpc" {
    cidr_block           = var.cidrVPC
    enable_dns_hostnames = true
    enable_dns_support   = true
    instance_tenancy     = "default"
    tags = var.tags
}

resource "aws_subnet" "eksClusterSubnet1" {
    vpc_id                  = aws_vpc.eksVpc.id
    cidr_block              = var.cidrSubnet1
    availability_zone       = var.aZone1
    map_public_ip_on_launch = true

    tags = var.tags
}

resource "aws_subnet" "eksClusterSubnet2" {
    vpc_id                  = aws_vpc.eksVpc.id
    cidr_block              = var.cidrSubnet2
    availability_zone       = var.aZone2
    map_public_ip_on_launch = true

    tags = var.tags
}

resource "aws_subnet" "eksClusterSubnet3" {
    vpc_id                  = aws_vpc.eksVpc.id
    cidr_block              = var.cidrSubnet3
    availability_zone       = var.aZone3
    map_public_ip_on_launch = true

    tags = var.tags
}

###############
##EKS Cluster##
###############
resource "aws_eks_cluster" "eksCluster" {
  name     = "eksCluster"
  role_arn = aws_iam_role.eksRole.arn


  vpc_config {
    subnet_ids = [aws_subnet.eksClusterSubnet1.id, aws_subnet.eksClusterSubnet2.id, aws_subnet.eksClusterSubnet3.id]
    endpoint_private_access = true
    endpoint_public_access  = true
  }

  depends_on = [
    aws_iam_role_policy_attachment.eksPolicy1,
    aws_iam_role_policy_attachment.eksResourceController,
    aws_iam_role_policy_attachment.eksAmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.eksAmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.eksAmazonEC2ContainerRegistryReadOnly,
  ]


  enabled_cluster_log_types = var.clusterLogs
  tags = var.tags
}

#################
##EKS Node Pool##
#################
resource "aws_eks_node_group" "nodeEksPool" {
  cluster_name    = aws_eks_cluster.eksCluster.name
  node_group_name = var.eksNodesName
  node_role_arn   = aws_iam_role.eksNodeRole.arn
  subnet_ids      = [aws_subnet.eksClusterSubnet2.id, aws_subnet.eksClusterSubnet3.id]
  instance_types     = var.instance_types
  disk_size          = var.disk_size
 
 dynamic "remote_access" {
    for_each = var.ec2_ssh_key != null && var.ec2_ssh_key != "" ? ["true"] : []
    content {
      ec2_ssh_key               = var.ec2_ssh_key
    }
 }


 lifecycle {
    create_before_destroy = true
  }

  scaling_config {
    desired_size = var.desired_size
    max_size     = var.max_size
    min_size     = var.min_size
  }
  depends_on = [
    aws_iam_role_policy_attachment.eksPolicy1,
    aws_iam_role_policy_attachment.eksResourceController,
    aws_iam_role_policy_attachment.eksAmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.eksAmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.eksAmazonEC2ContainerRegistryReadOnly,
  ]
}


##################
##SSH Key to EKS##
##################
resource "tls_private_key" "ssh" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "ssh" {
  key_name = "eksNode"
  public_key = tls_private_key.ssh.public_key_openssh
}

resource "local_file" "private_key" { 
    content = tls_private_key.ssh.private_key_pem
    filename = "private_key.pem" 
    }

resource "local_file" "public_key" { 
    content = tls_private_key.ssh.public_key_openssh
    filename = "public_key.pem" 
  }


####################
##Internet Gateway##
####################

resource "aws_internet_gateway" "eksGw" {
   vpc_id = aws_vpc.eksVpc.id

}

###############
##NAT Gateway##
###############
resource "aws_nat_gateway" "gw" {
  allocation_id = aws_eip.nat_gateway.id
  subnet_id     = aws_subnet.eksClusterSubnet1.id
  depends_on = [aws_internet_gateway.eksGw]
}

#######
##EIP##
#######
resource "aws_eip" "nat_gateway" {
  vpc = true
  depends_on                = [aws_internet_gateway.eksGw]
}


#################
##Routing Table##
#################

resource "aws_route_table" "eksRoutingTable" {
    vpc_id = aws_vpc.eksVpc.id

   route {
     cidr_block = "0.0.0.0/0"
     gateway_id = aws_internet_gateway.eksGw.id
   }

   route {
     ipv6_cidr_block = "::/0"
     gateway_id      = aws_internet_gateway.eksGw.id
   }

  tags = var.tags
 }
 

#######################################
##Subnet with Route Table association##
#######################################


resource "aws_route_table_association" "a" {
   subnet_id      = aws_subnet.eksClusterSubnet1.id
   route_table_id = aws_route_table.eksRoutingTable.id
 }

resource "aws_route_table_association" "b" {
   subnet_id      = aws_subnet.eksClusterSubnet2.id
   route_table_id = aws_route_table.eksRoutingTable.id
 }

resource "aws_route_table_association" "c" {
   subnet_id      = aws_subnet.eksClusterSubnet3.id
   route_table_id = aws_route_table.eksRoutingTable.id
 }


##################
##Security Group##
##################

 resource "aws_security_group" "eksSG" {
   name        = var.sGName
   description = "Allow Web inbound traffic"
   vpc_id      = aws_vpc.eksVpc.id

#Traffic ingress rules
   ingress {
     description = "HTTPS"
     from_port   = 443
     to_port     = 443
     protocol    = "tcp"
     #cidr_blocks = ["0.0.0.0/0"]
     #type = "ingress"
   }

   ingress {
     description = "HTTP"
     from_port   = 80
     to_port     = 80
     protocol    = "tcp"
     #cidr_blocks = ["0.0.0.0/0"]
   }

   ingress {
     description = "SSH"
     from_port   = 22
     to_port     = 22
     protocol    = "tcp"
     #cidr_blocks = ["0.0.0.0/0"]
   }

   
   ingress {
     description = "Allow node to communicate with each other"
     from_port   = 0
     protocol    = "-1"
     to_port     = 65535
     #type        = "ingress"
   }

   ingress {
     description = "Allow worker Kubelets and pods to receive communication from the cluster control plane"
     from_port   = 1025
     protocol    = "tcp"
     to_port     = 65535
     #type        = "ingress"
   }

#Traffic egress rules
   egress {
     from_port   = 0
     to_port     = 0
     protocol    = "-1"
     #cidr_blocks = ["0.0.0.0/0"]
   }

  tags = var.tags
 }


locals {
  config_map_aws_auth = <<CONFIGMAPAWSAUTH
apiVersion: v1
data:
  mapRoles: |
    - rolearn: {aws_iam_role.eksNodeRole.arn}
      username: system:node:{{EC2PrivateDNSName}}
      groups:
      - system:bootsrappers
      - system:nodes
kind: ConfigMap
metadata:
  name: aws-auth
  namespace: kube-system
CONFIGMAPAWSAUTH
}

output "config_map_aws_auth" {
  value = "${local.config_map_aws_auth}"
}

data "aws_region" "current" {}

locals {
  demo-node-userdata = <<USERDATA
#!/bin/bash
set -o xtrace
/etc/eks/bootstrap.sh --apiserver-endpoint '${aws_eks_cluster.eksCluster.endpoint}' --b64-cluster-ca '${aws_eks_cluster.eksCluster.certificate_authority.0.data}' '${var.cluster-name}'
USERDATA
}