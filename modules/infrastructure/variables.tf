variable "cluster_name" {
  type        = string
  description = "Name of cluster."
  default     = "test"
}

variable "cluster_size" {
  type        = string
  description = "Number of desired instances."
  default     = "1"
}

variable "spot_price" {
  type    = string
  default = ""
}

variable "network" {
  type        = string
  description = "Number would be used to template CIDR 10.X.0.0/16."
  default = 10
}

variable "admin_arns" {
  type        = list(string)
  description = "ARNs of users which would have admin permissions."
  default     = []
}

