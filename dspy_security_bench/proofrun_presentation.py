"""Shared fixed language for presentations of freshly computed review decisions."""

BOUNDARY = "Review success is not deployment approval, proof of complete requirements, or independent execution reproduction."

ENTRY_REASONS = {
    "invalid_input": "Required input could not be read as bounded strict JSON from an ordinary local file.",
    "pin_mismatch": "Required artifact bytes do not match the owner's exact file pin.",
    "bundle_type_mismatch": "The pinned artifact has a different bundle type than the required evidence slot.",
    "byte_budget_exceeded": "Required evidence was not reviewed within the input byte budget; it is an error, not a skipped requirement.",
}

ADVICE = {
    "invalid_input": "Check the retained file and local path without publishing its contents.",
    "invalid_plan": "Correct the owner-controlled plan; keep every required evidence slot visible.",
    "invalid_policy": "Correct the explicitly selected policy before retrying.",
    "policy_not_applicable": "Select the appropriate structural or repeated-trial review policy.",
    "pin_mismatch": "Restore the expected artifact or obtain an independently approved pin change.",
    "plan_pin_mismatch": "Restore the expected plan or obtain an independently approved requirement change.",
    "bundle_type_mismatch": "Supply the artifact type required by the owner-controlled plan.",
    "not_eligible": "Review native limitations and eligibility rules; do not omit unfavorable evidence.",
    "attestation_unverified": "Establish the required provenance; offline consistency is not a substitute for authentication.",
    "byte_budget_exceeded": "Reduce artifact size within the protocol and rerun the complete plan; do not drop requirements.",
}
