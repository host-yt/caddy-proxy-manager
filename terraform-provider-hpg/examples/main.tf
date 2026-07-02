# Worked example for the Hostyt Proxy Gateway Terraform provider.
# The provider is published from a separate repository; this file documents the
# intended resource graph and maps 1:1 to REST API v1 (see docs/TERRAFORM.md).

terraform {
  required_providers {
    hpg = {
      source  = "host-yt/hpg"
      version = "~> 0.1"
    }
  }
}

variable "hpg_api_key" {
  type      = string
  sensitive = true
}

provider "hpg" {
  endpoint = "https://panel.example.com"
  api_key  = var.hpg_api_key
}

# --- Infrastructure (platform-admin key only) ------------------------------

resource "hpg_node_pool" "edge" {
  name = "edge-eu"
  mode = "active_active"
}

resource "hpg_node" "eu1" {
  name          = "eu1"
  api_url       = "https://10.10.0.11:2019"
  node_group_id = hpg_node_pool.edge.id
  max_routes    = 500
  priority      = 100
}

# --- Catalog ---------------------------------------------------------------

resource "hpg_plan" "pro" {
  name          = "pro"
  max_domains   = 25
  max_ports     = 5
  node_group_id = hpg_node_pool.edge.id

  ssl_enabled          = true
  path_routing_enabled = true
  websocket_enabled    = true
  rate_limit_rpm       = 600
}

# --- Tenant ----------------------------------------------------------------

resource "hpg_client" "acme" {
  email        = "ops@acme.example"
  name         = "Acme Corp"
  password     = var.acme_initial_password # write-only, >= 12 chars
  external_ref = "billing-acme-001"        # idempotent external mapping
}

resource "hpg_service" "acme_web" {
  client_id          = hpg_client.acme.id
  name               = "acme-web"
  backend_ip         = "10.20.0.5"
  allowed_port_start = 8000
  allowed_port_end   = 8999
  plan_id            = hpg_plan.pro.id
  external_reference = "svc-acme-web"
}

resource "hpg_route" "acme_www" {
  service_id    = hpg_service.acme_web.id
  domain        = "www.acme.example"
  upstream_port = 8080
  ssl           = true
  force_https   = true
  websocket     = true
  # status + caddy_node_id are computed; SSL provisioning is asynchronous.
}

variable "acme_initial_password" {
  type      = string
  sensitive = true
}
