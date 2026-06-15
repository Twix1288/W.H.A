package wh-agent.registry

default allow_install = false

# Allow installation if all checks pass
allow_install {
    not is_quarantined
    signature_valid
    conformance_score_sufficient
}

# Quarantine check
is_quarantined {
    input.package.registry_source == "public"
    input.package.age_days < 14
    input.package.weekly_downloads < 100
}

is_quarantined {
    input.package.registry_source == "public"
    not input.package.maintainer_verified
    input.package.age_days < 30
}

# Signature must be valid
signature_valid {
    input.package.signature_status == "valid"
}

# Conformance score threshold
conformance_score_sufficient {
    input.package.conformance_score >= 70
}

# Warnings (non-blocking)
warnings[msg] {
    input.package.conformance_score >= 70
    input.package.conformance_score < 85
    msg := sprintf("Low conformance score: %v/100", [input.package.conformance_score])
}
