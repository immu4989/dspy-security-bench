import hashlib
import json
from html.parser import HTMLParser
from pathlib import Path

from scripts.generate_site_data import (
    AUTHORITY_SUBMISSIONS_DIR,
    BENIGN_DIR,
    CAUSAL_SUBMISSIONS_DIR,
    COLLECTIVE_SUBMISSIONS_DIR,
    CONTROL_SUBMISSIONS_DIR,
    DEFAULT_OUT,
    DEFENSE_SUBMISSIONS_DIR,
    INCIDENT_SUBMISSIONS_DIR,
    RESULTS_DIR,
    SOURCE_SUBMISSIONS_DIR,
    TRACE_SUBMISSIONS_DIR,
    _control_evidence_results,
    _defense_evidence_results,
    _incident_evidence_results,
    _proofrun_results,
    _source_evidence_results,
    _trace_evidence_results,
    build_payload,
)

SITE = Path(DEFAULT_OUT).parent


class _AssetCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.paths = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag in {"img", "script"} and attributes.get("src"):
            self.paths.append(attributes["src"])
        if tag == "link" and attributes.get("href"):
            self.paths.append(attributes["href"])


class _AccessibilityCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.skip_targets = []
        self.buttons = []
        self.html_lang = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if attributes.get("id"):
            self.ids.add(attributes["id"])
        if tag == "html":
            self.html_lang = attributes.get("lang")
        if tag == "a" and attributes.get("class") == "skip-link":
            self.skip_targets.append(attributes.get("href"))
        if tag == "button":
            self.buttons.append(attributes)


def test_site_payload_covers_committed_non_smoke_results():
    payload = build_payload()
    expected = sum(
        not json.loads(path.read_text()).get("smoke") for path in RESULTS_DIR.glob("*.json")
    )
    assert payload["modelCount"] == expected
    assert payload["familyCount"] == len({model["family"] for model in payload["models"]})


def test_site_payload_is_ranked_and_preserves_provisional_status():
    payload = build_payload()
    scores = [model["robustness"] for model in payload["models"]]
    assert scores == sorted(scores, reverse=True)
    assert all(
        model["classification"] == "Provisional"
        for model in payload["models"]
        if model["status"] != "confirmed"
    )


def test_site_capability_is_joined_from_no_attack_evidence():
    payload = build_payload()
    by_model = {model["modelId"]: model for model in payload["models"]}
    for path in BENIGN_DIR.glob("*.json"):
        benign = json.loads(path.read_text())
        if benign["model_id"] in by_model:
            assert by_model[benign["model_id"]]["capability"] == benign["combined_U_benign"]


def test_committed_site_data_matches_result_json():
    assert json.loads(Path(DEFAULT_OUT).read_text()) == build_payload()


def test_site_payload_exposes_the_open_control_evidence_registry():
    payload = build_payload()
    assert payload["controlEvidenceCount"] == len(payload["controlEvidence"])
    assert CONTROL_SUBMISSIONS_DIR.name == "control"


def test_site_payload_exposes_the_open_incident_evidence_registry():
    payload = build_payload()
    assert payload["incidentEvidenceCount"] == len(payload["incidentEvidence"])
    assert INCIDENT_SUBMISSIONS_DIR.name == "incident"


def test_site_payload_exposes_the_open_source_evidence_registry():
    payload = build_payload()
    assert payload["sourceEvidenceCount"] == len(payload["sourceEvidence"])
    assert SOURCE_SUBMISSIONS_DIR.name == "source"


def test_site_payload_exposes_the_open_authority_evidence_registry():
    payload = build_payload()
    assert payload["authorityEvidenceCount"] == len(payload["authorityEvidence"])
    assert AUTHORITY_SUBMISSIONS_DIR.name == "authority"


def test_site_payload_exposes_the_open_trace_evidence_registry():
    payload = build_payload()
    assert payload["traceEvidenceCount"] == len(payload["traceEvidence"])
    assert TRACE_SUBMISSIONS_DIR.name == "trace"


def test_site_payload_exposes_the_open_causal_evidence_registry():
    payload = build_payload()
    assert payload["causalEvidenceCount"] == len(payload["causalEvidence"])
    assert CAUSAL_SUBMISSIONS_DIR.name == "causal"


def test_site_payload_exposes_the_open_collective_evidence_registry():
    payload = build_payload()
    assert payload["collectiveEvidenceCount"] == len(payload["collectiveEvidence"])
    assert COLLECTIVE_SUBMISSIONS_DIR.name == "collective"


def test_site_payload_exposes_the_verified_defense_registry():
    payload = build_payload()
    assert payload["defenseEvidenceCount"] == len(payload["defenseEvidence"])
    assert DEFENSE_SUBMISSIONS_DIR.name == "defense"


def test_site_presents_verified_defense_as_effect_and_continuity_evidence():
    html = (SITE / "index.html").read_text()
    for value in (
        'id="verified-defense"',
        "Close the path.",
        "DEFENDERTWIN::VERIFIED-REMEDIATION::V1",
        "EFFECTIVE + SAFE",
        "EFFECTIVE + REGRESSION",
        "INSUFFICIENT EVIDENCE",
        "MISSION CONTINUITY",
        "community hospital",
        "water utility",
        "data-defense-evidence-count",
        'id="defense-evidence-results"',
        "dspy-security-bench defend demo --out-dir artifacts/verified-defense",
    ):
        assert value in html
    script = (SITE / "app.js").read_text()
    assert 'bindCommandCopy("#defense-copy"' in script
    assert "renderDefenseEvidence" in script
    assert "safeDefenseResultUrl(result.result)" in script


def test_site_presents_resiliencegraph_as_an_exact_owner_governed_frontier():
    html = (SITE / "index.html").read_text()
    for value in (
        'id="resiliencegraph"',
        "Scarce resources.",
        "RESILIENCEGRAPH::FRONTIER::V1",
        "32 SUBSETS → 13 FEASIBLE → 10 FRONTIER",
        "DECLARED DEPENDENCY GRAPH",
        "Direct protection",
        "NON-DOMINATED FRONTIER",
        "REFERENCE · NOT A RECOMMENDATION",
        "disruptive hospital",
        "dspy-security-bench portfolio demo --out-dir artifacts/resiliencegraph",
    ):
        assert value in html
    script = (SITE / "app.js").read_text()
    assert 'bindCommandCopy("#resilience-copy"' in script
    commons = build_payload()["missionAssuranceCommons"]["resilienceGraph"]
    assert commons == {
        "protocolVersion": "resiliencegraph-v1",
        "exactActionLimit": 18,
        "referenceIsRecommendation": False,
    }


def test_site_presents_assurancegraph_as_a_non_certifying_evidence_compiler():
    html = (SITE / "index.html").read_text()
    for value in (
        'id="assurancegraph"',
        "Nine proofs.",
        "ASSURANCEGRAPH::CLAIM-EVIDENCE::V1",
        "NATIVE EVIDENCE VERIFIERS",
        "EXECUTABLE CLAIM GRAPH",
        "CONTRADICTED",
        "AUTOMATIC DEPLOYMENT ACTIONS: 0",
        "dspy-security-bench assure demo --out-dir artifacts/assurancegraph",
    ):
        assert value in html
    script = (SITE / "app.js").read_text()
    assert 'bindCommandCopy("#assurance-copy"' in script
    commons = build_payload()["missionAssuranceCommons"]["assuranceGraph"]
    assert commons == {
        "protocolVersion": "assurancegraph-v1",
        "profileCount": 4,
        "evidenceKindCount": 9,
        "sectorStarterCount": 7,
        "federalReviewPackFileCount": 8,
        "claimStatuses": [
            "supported",
            "violated",
            "contradicted",
            "stale_evidence",
            "missing_evidence",
        ],
        "automaticDeploymentActions": 0,
    }


def test_site_presents_evalintegrityproof_as_content_free_process_evidence():
    html = (SITE / "index.html").read_text()
    for value in (
        'id="evalintegrity"',
        "First prove the test.",
        "EVALINTEGRITYPROOF::V1 / 13 CONTROLS / ZERO ACTIONS",
        "COMMIT / RUN / REVEAL ORDER",
        "INDEPENDENT MONITOR",
        "13 / 13 EVIDENCED",
        "INTEGRITY VIOLATED",
        "NO PROMPTS",
        "dspy-security-bench evalguard demo --out-dir artifacts/eval-integrity",
    ):
        assert value in html
    script = (SITE / "app.js").read_text()
    assert 'bindCommandCopy("#eval-integrity-copy"' in script
    commons = build_payload()["missionAssuranceCommons"]["evalIntegrityProof"]
    assert commons == {
        "protocolVersion": "evalintegrityproof-v1",
        "controlCount": 13,
        "rawEvaluationContentAccepted": False,
        "automaticActions": 0,
    }


def test_site_presents_assurancequorum_as_role_separated_review_evidence():
    html = (SITE / "index.html").read_text()
    for value in (
        'id="assurancequorum"',
        "Trust needs witnesses.",
        "ASSURANCEQUORUM::IN-TOTO::DSSE::V1",
        "AUTHORIZED REVIEW FUNCTIONS",
        "5 ORGANIZATIONS",
        "CLAIM SEPARATION POLICY",
        "EVIDENCE GAP",
        "Additional “sufficient” statements cannot erase",
        "SIGNATURE ≠ AUTHORITY",
        "dspy-security-bench quorum demo --out-dir artifacts/assurance-quorum",
    ):
        assert value in html
    script = (SITE / "app.js").read_text()
    assert 'bindCommandCopy("#quorum-copy"' in script
    commons = build_payload()["missionAssuranceCommons"]["assuranceQuorum"]
    assert commons == {
        "protocolVersion": "assurancequorum-v1",
        "statementType": "https://in-toto.io/Statement/v1",
        "envelopeType": "DSSE",
        "referenceReviewerOrganizations": 5,
        "evidenceGapCanBeOutvoted": False,
        "automaticDeploymentActions": 0,
    }


def test_site_presents_assuranceledger_as_witnessed_key_lifecycle_evidence():
    html = (SITE / "index.html").read_text()
    for value in (
        'id="assuranceledger"',
        "Trust can expire.",
        "ASSURANCELEDGER::MERKLE+WITNESS::V1",
        "APPEND-ONLY PREFIX VERIFIED",
        "COMPLETE LOG / CHECKPOINT 01",
        "2 / 2 WITNESSES",
        "COMPROMISE SINCE",
        "INVALIDATES 1 REVIEW",
        "OBSERVER CHANNEL A",
        "EQUIVOCATION EVIDENCED",
        "2 SIGNED CHECKPOINTS",
        "OFFLINE FORK PROOF",
        "0 LOG ENTRIES · 0 REVIEW ENVELOPES",
        "4 MERKLE NODES",
        "APPEND-ONLY EXTENSION PROVED",
        "0 LOG ENTRIES DISCLOSED",
        "OBSERVER RECEIPT A",
        "2 ORGS · 2 CHANNELS",
        "INDEPENDENTLY OBSERVED",
        "W1 SIGNED BOTH",
        "2 KEYS · 2 ORGANIZATIONS ATTRIBUTED",
        "0 AUTO-REVOCATIONS",
        "14 / 14 REHASHED MUTATIONS REJECTED",
        "CLEAN SOURCES NATIVE · OFFLINE",
        "OWNER-PINNED PARTNER CONTRACT",
        "14 OFFLINE VERIFIERS",
        "25 SCHEMA DIGESTS",
        "9 STANDALONE",
        "INDEPENDENTLY BOUNDED TIME",
        "3 / 3 SIGNED SOURCES",
        "4 SECOND CONSERVATIVE INTERVAL",
        "PINNED BOOTSTRAP",
        "OLD 2/2",
        "NEW 2/2",
        "DUAL THRESHOLD VERIFIED",
        "STALE CLIENT TRUST CATCH-UP",
        "2 / 2 TRANSITIONS VERIFIED",
        "MINIMUM FINAL VERSION 3 REACHED",
        "TRUSTED CHAIN",
        "ROOT COMPROMISE RECOVERY DRILL",
        "13 / 13 READINESS CHECKS",
        "9 STAGES · 5 ROLES · 3 ORGANIZATIONS",
        "0 ROOTS ACTIVATED",
        "AUTHENTICATED RECOVERY HANDOFFS",
        "10 / 10 CHECKS",
        "9 / 9 DSSE SIGNATURES",
        "9 UNIQUE NONCES",
        "0 ROOT ACTIONS",
        "0 DRIFT · 0 ACTIONS",
        "8 OF 9 REOPENED",
        "0 PEOPLE SELECTED · 0 ACTIONS",
        "WITNESS ≠ AUTHORITY",
        "dspy-security-bench ledger demo --out-dir artifacts/assurance-ledger",
    ):
        assert value in html
    script = (SITE / "app.js").read_text()
    assert 'bindCommandCopy("#ledger-copy"' in script
    commons = build_payload()["missionAssuranceCommons"]["assuranceLedger"]
    assert commons == {
        "protocolVersion": "assuranceledger-v1",
        "merkleConstruction": "RFC6962-style-domain-separated",
        "referenceWitnessOrganizations": 2,
        "retirementDistinctFromCompromise": True,
        "globalConsistencyClaimed": False,
        "gossipProtocolVersion": "assuranceledger-gossip-v1",
        "forkEvidenceRequiresValidViews": True,
        "forkProofProtocolVersion": "assuranceledger-fork-proof-v1",
        "forkProofEmbeddedLogEntries": 0,
        "forkProofOperatorSignatures": 2,
        "consistencyProofProtocolVersion": "assuranceledger-consistency-proof-v1",
        "consistencyProofEmbeddedLogEntries": 0,
        "referenceConsistencyPathNodes": 4,
        "observerReceiptProtocolVersion": "assuranceledger-observer-receipt-v1",
        "referenceObserverOrganizations": 2,
        "referenceObserverChannels": 2,
        "rawChannelLocatorsDisclosed": False,
        "witnessConflictProtocolVersion": "assuranceledger-witness-conflict-v1",
        "referenceDoubleSigningWitnessKeys": 2,
        "automaticWitnessRevocations": 0,
        "trustRootProtocolVersion": "assuranceledger-trust-root-v1",
        "referenceRootSignatureThreshold": 2,
        "referenceRootOrganizationThreshold": 2,
        "supportedRootSignatureSchemes": [
            "ecdsa-sha2-nistp256",
            "ed25519",
            "rsassa-pss-sha256",
        ],
        "bootstrapDigestRequired": True,
        "dualThresholdRotationRequired": True,
        "trustRootChainProtocolVersion": "assuranceledger-trust-root-chain-v1",
        "referenceRootChainRoots": 3,
        "referenceRootChainTransitions": 2,
        "referenceExpiredIntermediateRoots": 2,
        "maximumRootChainLength": 64,
        "currentFinalRootRequired": True,
        "minimumFinalVersionSupported": True,
        "trustRecoveryProtocolVersion": "assuranceledger-trust-recovery-drill-v1",
        "referenceRecoveryChecks": 13,
        "referenceRecoveryEvents": 9,
        "referenceRecoveryOrganizations": 3,
        "recoveryContentFieldsProcessed": 0,
        "replacementRootsActivated": 0,
        "trustRecoveryAttestationProtocolVersion": "assuranceledger-trust-recovery-attestation-v1",
        "referenceRecoveryAttestationChecks": 10,
        "referenceRecoveryAttestations": 9,
        "referenceRecoveryAttesterOrganizations": 3,
        "referenceRecoveryReplayNonces": 9,
        "recoveryAttestationContentFieldsProcessed": 0,
        "recoveryAttestationRootsActivated": 0,
        "timeQuorumProtocolVersion": "assuranceledger-time-quorum-v1",
        "referenceTimeQuorumChecks": 10,
        "referenceTimeSources": 3,
        "referenceTimeSourceOrganizations": 3,
        "referenceTimeIntervalWidthSeconds": 4,
        "timeQuorumContentFieldsProcessed": 0,
        "timeQuorumClockAdjustments": 0,
        "conformanceProtocolVersion": "assuranceledger-verifier-conformance-v7",
        "referenceConformanceCases": 14,
        "referenceUnexpectedAcceptances": 0,
        "conformanceCleanSourcesNativelyVerified": True,
        "capabilityManifestProtocolVersion": "assuranceledger-capability-manifest-v1",
        "capabilityProtocolCount": 14,
        "capabilitySchemaCount": 25,
        "standaloneVerifierCount": 9,
        "integrationLockProtocolVersion": "assuranceledger-integration-lock-v1",
        "referenceCapabilityDriftFindings": 0,
        "rereviewProtocolVersion": "assuranceledger-rereview-v1",
        "referenceInvalidatedReviews": 1,
        "referenceClaimsRequiringRereview": 8,
        "replacementReviewersSelected": 0,
        "automaticDeploymentActions": 0,
    }


def test_site_payload_exposes_the_nonranking_assurance_exchange_and_control_plane():
    payload = build_payload()
    assert payload["assuranceExchange"] == {
        "entryCount": 0,
        "activeEntryCount": 0,
        "independentReproductionCount": 0,
        "sectorCount": 0,
        "rankingEnabled": False,
        "automaticEndorsements": 0,
    }
    commons = payload["missionAssuranceCommons"]
    assert commons["containmentProof"] == {
        "protocolVersion": "containmentproof-v1",
        "canaryProbeCount": 8,
        "automaticResponseActions": 0,
    }
    assert commons["agentBOM"]["protocolVersion"] == "agentbom-claimimpact-v1"
    assert commons["probeContract"]["thirdPartyCodeLoading"] is False

    html = (SITE / "index.html").read_text()
    for value in (
        'id="control-plane"',
        "Prove the boundary.",
        "CONTROLPLANE::CANARIES+AGENTBOM::V1",
        "Runtime control pulse",
        "Dependency-to-claim ripple",
        "VIOLATION ≠ MONITOR FAILURE ≠ INCOMPLETE EVIDENCE",
        "AUTOMATIC SHUTDOWNS: 0",
        "AUTOMATIC DEPLOYMENTS: 0",
        "data-assurance-exchange-count",
        "dspy-security-bench contain demo --out-dir artifacts/containmentproof",
    ):
        assert value in html
    script = (SITE / "app.js").read_text()
    assert 'bindCommandCopy("#control-plane-copy"' in script


def test_defense_registry_only_exposes_recomputable_public_patterns(tmp_path):
    from dspy_security_bench.defend.evidence import build_evidence_bundle
    from dspy_security_bench.defend.protocol import (
        analyze_remediation,
        built_in_mission,
        built_in_proposal,
    )

    mission = built_in_mission("community-hospital")
    report = analyze_remediation(mission, built_in_proposal(mission))
    bundle = build_evidence_bundle(
        report,
        submitter="<independent-team>",
        runtime="defender <runtime>@1",
        source_repository="https://github.com/example/defender/tree/commit",
        deployment_class="synthetic",
    )
    submissions = tmp_path / "defense"
    submissions.mkdir()
    (submissions / "valid.json").write_text(json.dumps(bundle))

    private = build_evidence_bundle(
        report,
        submitter="private-team",
        runtime="private-runtime",
        source_repository="https://github.com/example/private/tree/commit",
        deployment_class="synthetic",
        disclosure_status="private",
    )
    (submissions / "private.json").write_text(json.dumps(private))

    rows = _defense_evidence_results(submissions)
    assert len(rows) == 1
    assert rows[0]["outcome"] == "effective_and_safe"
    assert rows[0]["runtime"] == "defender <runtime>@1"
    assert rows[0]["pathsClosed"] == rows[0]["pathCount"]


def test_site_exposes_native_causal_runtime_bridges_and_accessible_graph_toggle():
    html = (SITE / "index.html").read_text()
    assert "CausalProof native runtime bridges" in html
    assert "OPENAI AGENTS SDK" in html
    assert "LANGGRAPH" in html
    assert 'data-causal-view="proof" aria-pressed="true"' in html
    assert "causalproof-runtime-integrations.md" in html


def test_site_presents_collectiveguard_as_content_free_containment_evidence():
    html = (SITE / "index.html").read_text()
    for value in (
        'id="collectiveguard"',
        "One run was isolated.",
        "COLLECTIVEGUARD::CONTAINMENT-PLANE::V1",
        "CG001",
        "CG003",
        "CG006",
        "EARLIEST VISIBLE INTERVENTION",
        "CONTENT FIELDS",
        "prompts · reasoning · messages · secrets · payloads",
        "dspy-security-bench collective demo --out-dir artifacts/collectiveguard",
        "collectiveguard.md",
    ):
        assert value in html
    script = (SITE / "app.js").read_text()
    assert 'bindCommandCopy("#collective-copy"' in script


def test_site_presents_the_provenance_aware_evidence_plane():
    html = (SITE / "index.html").read_text()
    for value in (
        "COLLECTIVEGUARD V2 / EVIDENCE PLANE",
        "A clean result now has to earn its provenance.",
        "PROVENANCE GATE",
        "INSUFFICIENT EVIDENCE",
        "IDENTITY PASSPORT",
        "ADOPTION PROFILES",
        "zero production actions",
        "data-collective-evidence-count",
        'id="collective-evidence-results"',
    ):
        assert value in html
    script = (SITE / "app.js").read_text()
    assert 'bindCommandCopy("#evidence-plane-copy"' in script
    assert "renderCollectiveEvidence" in script


def test_site_payload_exposes_commons_protocol_not_product_claims():
    commons = build_payload()["missionAssuranceCommons"]
    assert commons["agentGraphTwin"]["pairCount"] == 6
    assert commons["authorityBridges"] == ["opa", "cedar", "openfga", "oauth-mcp", "spiffe"]
    assert "not executed" in commons["fixtureClaim"]


def test_site_evidence_links_are_deployable_urls():
    for model in build_payload()["models"]:
        assert model["result"].startswith("https://github.com/immu4989/dspy-security-bench/")


def test_site_referenced_assets_exist():
    collector = _AssetCollector()
    collector.feed((SITE / "index.html").read_text())
    local_paths = [path for path in collector.paths if not path.startswith(("http://", "https://"))]
    assert local_paths
    assert all((SITE / path).is_file() for path in local_paths)


def test_site_presents_impact_twin_without_mislabeling_fixture_as_model_result():
    page = (SITE / "index.html").read_text()
    assert 'id="impact"' in page
    assert "Same facts." in page
    assert "dspy-security-bench impact repeat --trials 10" in page
    assert "95% Wilson interval" in page
    assert "content addressed" in page
    assert "Reference fixture, not a model result" in page
    assert "not predicted loss or a compliance certification" in page


def test_site_presents_framework_onboarding_without_surprise_model_spend():
    page = (SITE / "index.html").read_text()
    assert 'id="connect"' in page
    assert "dspy-security-bench integrate" in page
    assert "dspy-security-bench doctor" in page
    for framework in ("OpenAI", "LangChain", "Pydantic AI", "CrewAI", "AutoGen", "MCP"):
        assert framework in page
    assert "without invoking the agent run loop" in page
    assert "cannot unexpectedly spend model credits" in page


def test_site_presents_control_twin_as_harm_utility_and_recovery_evidence():
    page = (SITE / "index.html").read_text()
    assert 'id="control"' in page
    assert "Policy off" in page
    assert "Policy on" in page
    assert "5<span>/5</span>" in page
    assert "0<span>/5</span>" in page
    assert "$3.69M" in page
    assert "Clean mission utility" in page
    assert "recovery gap" in page
    assert "dspy-security-bench impact control-demo" in page
    assert "not a model result" in page

    script = (SITE / "app.js").read_text()
    assert 'document.querySelector("#control-copy")' in script
    assert "dspy-security-bench impact control-demo" in script


def test_site_presents_repeat_control_uncertainty_without_population_overclaim():
    page = (SITE / "index.html").read_text()
    assert "RepeatControlTwin · v0.10" in page
    assert "One delta can be luck" in page
    assert "25/25 · lower bound 86.7%" in page
    assert "15/25 · 40.7%–76.6%" in page
    assert "exact McNemar p" in page
    assert "fresh agent · every case · every condition" in page
    assert "fixed synthetic suite" in page
    assert "not a model result, population estimate" in page
    assert "dspy-security-bench impact control-repeat-demo --trials 5" in page

    script = (SITE / "app.js").read_text()
    assert 'document.querySelector("#repeat-control-copy")' in script
    assert "dspy-security-bench impact control-repeat-demo --trials 5" in script


def test_site_presents_authoritytwin_as_conformance_not_certification():
    page = (SITE / "index.html").read_text()
    assert 'id="authority-twin"' in page
    assert "Prove the agent" in page
    assert "Ten ways ambient authority breaks" in page
    assert "Identity<br>substitution" in page
    assert "Approval<br>replay" in page
    assert "dspy-security-bench authority demo" in page
    assert "not a new authorization protocol" in page
    assert "authorization to operate" in page

    script = (SITE / "app.js").read_text()
    assert 'document.querySelector("#authority-evidence-results")' in script
    assert 'bindCommandCopy("#authority-copy"' in script
    assert "safeAuthorityResultUrl(result.result)" in script


def test_site_presents_mission_assurance_commons_with_accountable_boundaries():
    page = (SITE / "index.html").read_text()
    for value in (
        'id="commons"',
        "InventoryForge",
        "AgentGraphTwin",
        "ContinuousProof",
        "AcquisitionProof",
        "FIRST UNSAFE EDGE",
        "OPA",
        "Cedar",
        "OpenFGA",
        "SPIFFE",
    ):
        assert value in page
    assert "do not execute, certify, or endorse the named backend" in page
    assert "automating the accountable decision" in page
    assert "mission-assurance-commons-v015.png" in page
    script = (SITE / "app.js").read_text()
    assert 'bindCommandCopy("#graph-copy"' in script


def test_site_presents_scheduleproof_as_bounded_model_not_probability():
    page = (SITE / "index.html").read_text()
    assert 'id="scheduleproof"' in page
    for value in (
        "The happy path is",
        "SCHEDULEPROOF::TOPOLOGICAL_EXPLORER::V1",
        "7 / 7",
        "SP001 · stale authority",
        "Probability?",
        "A truncated search without a finding is review",
        "dspy-security-bench schedule demo",
    ):
        assert value in page
    script = (SITE / "app.js").read_text()
    assert 'bindCommandCopy("#schedule-copy"' in script


def test_site_presents_traceproof_as_local_privacy_bounded_evidence():
    page = (SITE / "index.html").read_text()
    assert 'id="traceproof"' in page
    assert "Bring the trace" in page
    assert "OFFLINE / LOCAL CUSTODY" in page
    assert "TRACEPROOF::SANITIZER::V1" in page
    assert "Raw prompts" in page
    assert "SARIF" in page
    assert "OSCAL 1.2.2" in page
    assert "dspy-security-bench trace demo --out-dir artifacts/traceproof" in page
    assert "Open TraceProof evidence ledger" in page
    assert 'id="trace-evidence-results"' in page
    assert "MCP 2025-11-25 probes" in page

    script = (SITE / "app.js").read_text()
    assert 'bindCommandCopy("#trace-copy"' in script
    assert 'document.querySelector("#trace-evidence-results")' in script
    assert "safeTraceResultUrl(result.result)" in script


def test_trace_registry_rows_are_privacy_bounded_and_escape_ready(tmp_path):
    from dspy_security_bench.trace.evidence import build_trace_submission_bundle
    from dspy_security_bench.trace.proof import analyze_trace_evidence, build_trace_evidence
    from dspy_security_bench.trace.runtime import TraceRecorder

    recorder = TraceRecorder(service_name="independent-runtime")
    recorder.record(operation="invoke_agent", agent_name="agent")
    evidence = build_trace_evidence(recorder.to_otlp_json())
    report = analyze_trace_evidence(evidence)
    bundle = build_trace_submission_bundle(
        evidence,
        report,
        submitter="<independent-team>",
        runtime="runtime <unsafe>@1",
        source_repository_url="https://github.com/example/runtime/tree/commit",
    )
    submissions = tmp_path / "trace"
    submissions.mkdir()
    (submissions / "runtime.json").write_text(json.dumps(bundle))

    rows = _trace_evidence_results(submissions)
    assert rows[0]["runtime"] == "runtime <unsafe>@1"
    assert rows[0]["spanCount"] == 1
    assert rows[0]["mcpRequiredPass"] is None
    assert rows[0]["evidenceTier"] == "self_attested"


def test_site_presents_control_registry_as_evidence_not_certification():
    page = (SITE / "index.html").read_text()
    assert 'id="control-registry"' in page
    assert "Which guardrail works?" in page
    assert "Validity, not victory" in page
    assert "containment · recovery · utility" in page
    assert "A failing control can belong here" in page
    assert "not certification" in page
    assert 'id="control-evidence-results"' in page
    assert 'id="control-registry-copy"' in page


def test_site_presents_incidenttwin_and_federalproof_with_honest_boundaries():
    page = (SITE / "index.html").read_text()
    assert 'id="mission-assurance"' in page
    assert "IncidentTwin" in page
    assert "FederalProof" in page
    assert "OSCAL 1.2.2" in page
    assert "secret → outside.test" in page
    assert "dspy-security-bench incident demo" in page
    assert "dspy-security-bench federal init" in page
    assert "no automatic ATO or procurement decision" in page
    assert 'id="incident-evidence-results"' in page
    assert "Open IncidentTwin ledger" in page
    script = (SITE / "app.js").read_text()
    assert 'bindCommandCopy("#incident-copy"' in script
    assert 'bindCommandCopy("#federal-copy"' in script


def test_site_presents_missionforge_source_twin_and_grounding_ledger():
    page = (SITE / "index.html").read_text()
    script = (SITE / "app.js").read_text()
    assert 'id="source-twin"' in page
    assert "Trace the answer" in page
    assert "Five controlled interventions" in page
    assert "Fabricated authority" in page
    assert "Material omission" in page
    assert "Deterministic probes" in page
    assert "not a legal interpretation" in page
    assert 'id="source-evidence-results"' in page
    assert 'bindCommandCopy("#source-copy"' in script
    assert "safeSourceResultUrl" in script


def test_source_registry_rows_only_upgrade_tiers_from_reviewed_registry(tmp_path):
    submissions = tmp_path / "source"
    submissions.mkdir()
    estimate = {"rate": 0.8, "lower": 0.6, "upper": 0.9}
    bundle = {
        "bundle_type": "dspy-security-bench-source-evidence-submission",
        "submission": {"submitter": "<source-team>", "created_at": "2026-08-18T00:00:00Z"},
        "report": {
            "agent": "source-agent <unsafe>",
            "pack_id": "agency-pack <unsafe>",
            "pack_sha256": "b" * 64,
            "trial_isolation": "fresh_agent_per_case",
            "summary": {
                "trials": 5,
                "case_errors": 0,
                "unstable_pairs": 0,
                "attack_resistance": estimate,
                "citation_faithfulness": estimate,
                "citation_completeness": estimate,
                "citation_sufficiency": estimate,
                "authoritative_source_preference": estimate,
            },
            "trials": [{}, {}, {}, {}, {}],
        },
        "provenance": {"provider": "github_actions"},
    }
    encoded = json.dumps(
        bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()
    digest = hashlib.sha256(encoded).hexdigest()
    bundle["bundle_sha256"] = digest
    (submissions / "source-agent.json").write_text(json.dumps(bundle))
    reproductions = tmp_path / "reproductions.json"
    reproductions.write_text('{"schema_version": 1, "reproductions": {}}')
    attestations = tmp_path / "attestations.json"
    attestations.write_text('{"schema_version": 1, "attestations": {}}')

    rows = _source_evidence_results(submissions, reproductions, attestations)
    assert rows[0]["evidenceTier"] == "github_attestation_unverified"
    assert rows[0]["faithfulness"]["lower"] == 0.6

    attestations.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "attestations": {digest: {"evidence_tier": "trusted_builder"}},
            }
        )
    )
    rows = _source_evidence_results(submissions, reproductions, attestations)
    assert rows[0]["evidenceTier"] == "trusted_builder"


def test_incident_registry_rows_only_upgrade_tiers_from_reviewed_registry(tmp_path):
    submissions = tmp_path / "incident"
    submissions.mkdir()
    bundle = {
        "bundle_type": "dspy-security-bench-incident-evidence-submission",
        "submission": {
            "submitter": "<soc-team>",
            "created_at": "2026-08-18T00:00:00Z",
        },
        "report": {
            "agent": "incident-agent <unsafe>",
            "trial_isolation": "fresh_agent_per_case",
            "summary": {
                "trials": 5,
                "case_errors": 0,
                "unstable_pairs": 0,
                "attack_resistance": {"rate": 0.8, "lower": 0.6, "upper": 0.9},
                "harm_free": {"rate": 0.8, "lower": 0.6, "upper": 0.9},
                "clean_mission_utility": {"rate": 1, "lower": 0.8, "upper": 1},
            },
            "trials": [{}, {}, {}, {}, {}],
        },
        "provenance": {"provider": "github_actions"},
    }
    encoded = json.dumps(
        bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()
    digest = hashlib.sha256(encoded).hexdigest()
    bundle["bundle_sha256"] = digest
    (submissions / "incident-agent.json").write_text(json.dumps(bundle))
    reproductions = tmp_path / "reproductions.json"
    reproductions.write_text('{"schema_version": 1, "reproductions": {}}')
    attestations = tmp_path / "attestations.json"
    attestations.write_text('{"schema_version": 1, "attestations": {}}')

    rows = _incident_evidence_results(submissions, reproductions, attestations)
    assert rows[0]["evidenceTier"] == "github_attestation_unverified"
    assert rows[0]["attackResistance"]["lower"] == 0.6

    attestations.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "attestations": {digest: {"evidence_tier": "trusted_builder"}},
            }
        )
    )
    rows = _incident_evidence_results(submissions, reproductions, attestations)
    assert rows[0]["evidenceTier"] == "trusted_builder"


def test_site_has_basic_keyboard_and_landmark_accessibility_contract():
    collector = _AccessibilityCollector()
    collector.feed((SITE / "index.html").read_text())
    assert collector.html_lang == "en"
    assert collector.skip_targets == ["#top"]
    assert "top" in collector.ids
    assert all(button.get("type") == "button" for button in collector.buttons)
    menu = next(button for button in collector.buttons if button.get("class") == "menu-button")
    assert menu["aria-controls"] == "nav-links"
    assert menu["aria-expanded"] == "false"


def test_control_registry_rows_only_upgrade_tiers_from_reviewed_registry(tmp_path):
    submissions = tmp_path / "control"
    submissions.mkdir()
    bundle = {
        "bundle_type": "dspy-security-bench-control-evidence-submission",
        "submission": {
            "submitter": "<control-team>",
            "agent_source_url": "https://github.com/example/agent",
            "policy_source_url": "https://github.com/example/agent/policy.yaml",
            "created_at": "2026-08-18T00:00:00Z",
        },
        "report": {
            "agent": "agent <unsafe>",
            "trial_isolation": "fresh_agent_per_case_and_condition",
            "policy": {
                "name": "policy <unsafe>",
                "sha256": "b" * 64,
                "arguments_captured": False,
            },
            "summary": {
                "trials": 5,
                "unstable_pairs": 0,
                "harm_containment_efficacy": {"rate": 0.8, "lower": 0.6, "upper": 0.9},
                "safe_mission_recovery": {"rate": 0.6, "lower": 0.4, "upper": 0.8},
                "clean_utility_preservation": {"rate": 1, "lower": 0.8, "upper": 1},
                "controlled_attack_resistance": {"rate": 0.8, "lower": 0.6, "upper": 0.9},
                "mean_synthetic_funds_risk_reduction_usd": 1000,
                "usage": {},
            },
            "trials": [{}, {}, {}, {}, {}],
        },
        "provenance": {"provider": "github_actions"},
    }
    encoded = json.dumps(
        bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()
    digest = hashlib.sha256(encoded).hexdigest()
    bundle["bundle_sha256"] = digest
    (submissions / "agent-policy.json").write_text(json.dumps(bundle))
    reproductions = tmp_path / "reproductions.json"
    reproductions.write_text('{"schema_version": 1, "reproductions": {}}')
    attestations = tmp_path / "attestations.json"
    attestations.write_text('{"schema_version": 1, "attestations": {}}')

    rows = _control_evidence_results(submissions, reproductions, attestations)
    assert rows[0]["evidenceTier"] == "github_attestation_unverified"
    assert rows[0]["containment"]["lower"] == 0.6

    attestations.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "attestations": {digest: {"evidence_tier": "trusted_builder"}},
            }
        )
    )
    rows = _control_evidence_results(submissions, reproductions, attestations)
    assert rows[0]["evidenceTier"] == "trusted_builder"


def test_site_never_upgrades_a_claimed_attestation_without_registry_verification(
    tmp_path, monkeypatch
):
    submissions = tmp_path / "impact"
    submissions.mkdir()
    digest = "a" * 64
    (submissions / "agent.json").write_text(
        json.dumps(
            {
                "bundle_sha256": digest,
                "submission": {"submitter": "<unsafe>"},
                "report": {
                    "agent": "agent <unsafe>",
                    "summary": {
                        "trials": 10,
                        "unstable_pairs": 0,
                        "attack_resistance": {"rate": 1, "lower": 0.9, "upper": 1},
                        "usage": {},
                    },
                },
                "provenance": {
                    "provider": "github_actions",
                    "builder_kind": "dspy_security_bench_reusable_workflow",
                },
            }
        )
    )
    reproductions = tmp_path / "reproductions.json"
    reproductions.write_text('{"schema_version": 1, "reproductions": {}}')
    attestations = tmp_path / "attestations.json"
    attestations.write_text('{"schema_version": 1, "attestations": {}}')
    monkeypatch.setattr(
        "scripts.generate_site_data._site_eligible",
        lambda _: True,
    )

    rows = _proofrun_results(submissions, reproductions, attestations)
    assert rows[0]["evidenceTier"] == "github_attestation_unverified"

    attestations.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "attestations": {digest: {"evidence_tier": "trusted_builder"}},
            }
        )
    )
    rows = _proofrun_results(submissions, reproductions, attestations)
    assert rows[0]["evidenceTier"] == "trusted_builder"


def test_site_escapes_untrusted_community_fields_before_rendering():
    script = (SITE / "app.js").read_text()
    assert "escapeHtml(result.agent)" in script
    assert "escapeHtml(result.submitter)" in script
    assert "safeResultUrl(result.result)" in script
    assert "safeControlResultUrl(result.result)" in script
    assert "safeSourceResultUrl(result.result)" in script
    assert "safeAuthorityResultUrl(result.result)" in script
    assert "escapeHtml(result.adapter)" in script
    assert "escapeHtml(result.packId)" in script
    assert "escapeHtml(result.policy)" in script
    assert "const button = event.currentTarget;" in script
    assert "setTimeout(() => { event.currentTarget" not in script
