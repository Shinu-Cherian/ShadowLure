# Production Terraform Infrastructure as Code for ShadowLure on AWS
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  default = "eu-west-1"
}

# VPC & Networking
resource "aws_vpc" "shadowlure_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags = {
    Name = "shadowlure-vpc"
  }
}

resource "aws_subnet" "public_1" {
  vpc_id                  = aws_vpc.shadowlure_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true
}

resource "aws_subnet" "public_2" {
  vpc_id                  = aws_vpc.shadowlure_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = true
}

# Security Group for Application Load Balancer
resource "aws_security_group" "alb_sg" {
  name        = "shadowlure-alb-sg"
  vpc_id      = aws_vpc.shadowlure_vpc.id
  description = "Allow HTTP inbound traffic"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    ="-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ECS Cluster & Task Definition
resource "aws_ecs_cluster" "cluster" {
  name = "shadowlure-cluster"
}

resource "aws_ecs_task_definition" "app" {
  family                   = "shadowlure-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"

  container_definitions = jsonencode([
    {
      name      = "shadowlure-api"
      image     = "ghcr.io/shadowlure/shadowlure-api:latest"
      essential = true
      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
        }
      ]
    }
  ])
}
