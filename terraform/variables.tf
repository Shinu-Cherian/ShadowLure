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

variable "db_connection_string_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the PostgreSQL ConnectionStrings__DefaultConnection value"
  type        = string
}

variable "groq_api_key_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the GROQ_API_KEY value"
  type        = string
}

variable "operator_api_key_secret_arn" {
  description = "ARN of the Secrets Manager secret holding the OPERATOR_API_KEY value used to authenticate canary management requests"
  type        = string
}
