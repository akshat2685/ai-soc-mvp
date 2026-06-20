package edysor.kill_switch

default trigger_shutdown = false

# Trigger shutdown automatically if compromised Crown Jewels exceed threshold
trigger_shutdown {
    input.compromised_crown_jewel_count >= 5
}

# Allow manual trigger only if multi-sig is met (2 admins)
trigger_shutdown {
    input.manual_override == true
    input.admin_approvals >= 2
}

# Always deny standard network traffic if kill switch is active
deny {
    trigger_shutdown
}
