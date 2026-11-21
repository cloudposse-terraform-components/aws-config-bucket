variable "region" {
  type        = string
  description = "AWS Region"
}

variable "lifecycle_rule_enabled" {
  type        = bool
  description = "Enable lifecycle events on this bucket"
  default     = true
}

variable "noncurrent_version_expiration_days" {
  type        = number
  default     = 90
  description = "Specifies when noncurrent object versions expire"
}

variable "noncurrent_version_transition_days" {
  type        = number
  default     = 30
  description = "Specifies when noncurrent object versions transition to a different storage tier"
}

variable "standard_transition_days" {
  type        = number
  default     = 30
  description = "Number of days to persist in the standard storage tier before moving to the infrequent access tier"
}

variable "glacier_transition_days" {
  type        = number
  default     = 60
  description = "Number of days after which to move the data to the glacier storage tier"
}

variable "enable_glacier_transition" {
  type        = bool
  default     = true
  description = "Enables the transition to AWS Glacier (note that this can incur unnecessary costs for huge amount of small files"
}

variable "expiration_days" {
  type        = number
  default     = 90
  description = "Number of days after which to expunge the objects"
}

variable "access_log_bucket_name" {
  type        = string
  default     = ""
  description = "Name of the S3 bucket where s3 access log will be sent to"
}

variable "acl" {
  type        = string
  description = "The canned ACL to apply. We recommend log-delivery-write for compatibility with AWS services"
  default     = "log-delivery-write"
}

variable "sse_algorithm" {
  type        = string
  description = "The server-side encryption algorithm to use for the bucket's default encryption. Valid values are `AES256` and `aws:kms`"
  default     = "AES256"

  validation {
    condition     = contains(["AES256", "aws:kms"], var.sse_algorithm)
    error_message = "sse_algorithm must be one of 'AES256' or 'aws:kms'."
  }
}

variable "kms_master_key_arn" {
  type        = string
  description = <<-EOT
    The ARN of the AWS KMS key used for default SSE-KMS encryption of the bucket. Only used when `sse_algorithm` is `aws:kms`.
    If empty while `sse_algorithm` is `aws:kms`, the AWS managed `aws/s3` key is used.
    The key policy must allow AWS Config to use the key (`kms:GenerateDataKey` and `kms:Decrypt`), either for the IAM role
    that delivers configuration items or for the `config.amazonaws.com` service principal when Config delivers with its
    service-linked role.
  EOT
  default     = ""
}

variable "allow_ssl_requests_only" {
  type        = bool
  description = "Set to `true` to add a bucket policy statement that denies any request made without TLS (`aws:SecureTransport` is `false`)"
  default     = false
}
