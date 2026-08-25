# Production Terraform Infrastructure as Code for ShadowLure on AWS ECS Fargate
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

# -----------------------------------------------------------------------------
# VPC and Networking Infrastructure
# -----------------------------------------------------------------------------

resource "aws_vpc" "shadowlure_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "shadowlure-vpc"
    Environment = var.environment
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.shadowlure_vpc.id

  tags = {
    Name = "shadowlure-igw"
  }
}

resource "aws_subnet" "public_1" {
  vpc_id                  = aws_vpc.shadowlure_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "shadowlure-public-1"
  }
}

resource "aws_subnet" "public_2" {
  vpc_id                  = aws_vpc.shadowlure_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "${var.aws_region}b"
  map_public_ip_on_launch = true

  tags = {
    Name = "shadowlure-public-2"
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.shadowlure_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "shadowlure-public-rt"
  }
}

resource "aws_route_table_association" "public_1" {
  subnet_id      = aws_subnet.public_1.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "public_2" {
  subnet_id      = aws_subnet.public_2.id
  route_table_id = aws_route_table.public_rt.id
}

# -----------------------------------------------------------------------------
# Security Groups
# -----------------------------------------------------------------------------

resource "aws_security_group" "alb_sg" {
  name        = "shadowlure-alb-sg"
  description = "Allow HTTP inbound traffic to Load Balancer"
  vpc_id      = aws_vpc.shadowlure_vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "shadowlure-alb-sg"
  }
}

resource "aws_security_group" "ecs_sg" {
  name        = "shadowlure-ecs-sg"
  description = "Allow inbound traffic from ALB only"
  vpc_id      = aws_vpc.shadowlure_vpc.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "shadowlure-ecs-sg"
  }
}

# -----------------------------------------------------------------------------
# Elastic Container Registry (ECR)
# -----------------------------------------------------------------------------

resource "aws_ecr_repository" "app" {
  name                 = "shadowlure-api"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = "shadowlure-ecr"
  }
}

# -----------------------------------------------------------------------------
# Application Load Balancer (ALB)
# -----------------------------------------------------------------------------

resource "aws_lb" "app" {
  name               = "shadowlure-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.public_1.id, aws_subnet.public_2.id]

  tags = {
    Name = "shadowlure-alb"
  }
}

resource "aws_lb_target_group" "app" {
  name        = "shadowlure-tg"
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = aws_vpc.shadowlure_vpc.id
  target_type = "ip"

  health_check {
    path                = "/metrics"
    healthy_threshold   = 2
    unhealthy_threshold = 5
    timeout             = 5
    interval            = 30
    matcher             = "200"
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# -----------------------------------------------------------------------------
# CloudWatch Log Group & IAM Roles
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/shadowlure-api"
  retention_in_days = 30
}

resource "aws_iam_role" "ecs_execution_role" {
  name = "shadowlure-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution_policy" {
  role       = aws_iam_role.ecs_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# The managed execution-role policy above only grants ECR pull + log group
# access. Reading task secrets (DB connection string, Groq/operator keys)
# via the container definition's `secrets` block requires an explicit grant.
resource "aws_iam_role_policy" "ecs_secrets_access" {
  name = "shadowlure-ecs-secrets-access"
  role = aws_iam_role.ecs_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = [
          var.db_connection_string_secret_arn,
          var.groq_api_key_secret_arn,
          var.operator_api_key_secret_arn
        ]
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# ECS Cluster, Task Definition & Service
# -----------------------------------------------------------------------------

resource "aws_ecs_cluster" "cluster" {
  name = "shadowlure-cluster"
}

resource "aws_ecs_task_definition" "app" {
  family                   = "shadowlure-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn

  container_definitions = jsonencode([
    {
      name      = "shadowlure-api"
      image     = "${aws_ecr_repository.app.repository_url}:latest"
      essential = true
      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
        }
      ]
      environment = [
        { name = "ASPNETCORE_ENVIRONMENT", value = var.environment == "production" ? "Production" : "Staging" }
      ]
      secrets = [
        { name = "ConnectionStrings__DefaultConnection", valueFrom = var.db_connection_string_secret_arn },
        { name = "GROQ_API_KEY", valueFrom = var.groq_api_key_secret_arn },
        { name = "OPERATOR_API_KEY", valueFrom = var.operator_api_key_secret_arn }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "app" {
  name            = "shadowlure-service"
  cluster         = aws_ecs_cluster.cluster.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [aws_subnet.public_1.id, aws_subnet.public_2.id]
    security_groups  = [aws_security_group.ecs_sg.id]
    assign_public_ip = true
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = "shadowlure-api"
    container_port   = 5246
  }

  depends_on = [aws_lb_listener.http]
}
