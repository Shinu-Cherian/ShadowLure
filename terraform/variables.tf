variable "aws_region" {
  description = "Target AWS region for infrastructure deployment"
  type        = string
  default     = "eu-west-1"
}

variable "environment" {
  description = "Deployment environment stage"
  type        = string
  default     = "production"
}
