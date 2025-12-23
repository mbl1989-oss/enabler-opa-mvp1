package enabler

# Always return a decision object
default decision := {
  "result": "DENY",
  "reason_codes": ["DEFAULT_DENY"],
  "policy_ref": "baseline:v1"
}

# SANDBOX permissive (still logged)
decision := {
  "result": "ALLOW",
  "reason_codes": ["SANDBOX_PERMISSIVE"],
  "policy_ref": "sandbox:v1"
} {
  input.env == "SANDBOX"
}

# PROD deny if any required signal is missing
decision := {
  "result": "DENY",
  "reason_codes": ["MISSING_REQUIRED_SIGNAL"],
  "policy_ref": "baseline:v1"
} {
  input.env == "PROD"
  required := {
    "data_contains_pii",
    "data_residency_region",
    "vendor_allowed_in_prod"
  }

  key := required[_]
  not input.signals[key]
}

# PROD deny if vendor not approved
decision := {
  "result": "DENY",
  "reason_codes": ["VENDOR_NOT_APPROVED_FOR_PROD"],
  "policy_ref": "baseline:v1"
} {
  input.env == "PROD"
  input.signals.data_contains_pii == true
  input.signals.vendor_allowed_in_prod == false
}

# PROD allow only when all conditions are satisfied
decision := {
  "result": "ALLOW",
  "reason_codes": [],
  "policy_ref": "tenant:v1"
} {
  input.env == "PROD"
  input.operation == "SUMMARIZE_BANK_DATA"
  input.signals.data_contains_pii == true
  input.signals.vendor_allowed_in_prod == true
  input.signals.data_residency_region == "EU"
}
