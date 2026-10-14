output "dns_records_count" {
  description = "Number of local DNS records configured"
  value       = length(pihole_dns_record.clients)
}
