"""Deterministic, explainable Workex firewall checks for the hackathon MVP."""

import base64
import re
import unicodedata


# Scores are additive evidence weights, capped at 100. A confirmed attack is
# blocked independent of its numeric score; severity is raised to at least Medium.
SIGNAL_WEIGHTS = {
    "instruction_override": 25,
    "system_prompt_extraction": 30,
    "role_manipulation": 25,
    "jailbreak": 30,
    "sensitive_information": 20,
    "indirect_prompt_injection": 30,
    "unauthorized_data_request": 25,
    "external_destination": 12,
    "obfuscation": 15,
    "social_engineering": 10,
}

PATTERNS: dict[str, tuple[re.Pattern, ...]] = {
    "instruction_override": (
        re.compile(r"\b(?:ignore|disregard|forget|drop|discard)\s+(?:all\s+)?(?:the\s+)?(?:everything|all messages?|all instructions?)\s+(?:above|before|so far)\b", re.I),
        re.compile(r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:preceding|earlier)\s+(?:messages?|context|conversation)\b", re.I),
        re.compile(r"\b(?:ignore|disregard|forget|discard)\b.{0,90}\b(?:instructions?|rules?|guidance|constraints?)\b.{0,40}\b(?:do not|don't|no longer|not)\s+(?:apply|matter|count|relevant)\b", re.I),
        re.compile(r"\b(?:previous|prior|earlier|initial|system|developer)\s+(?:instructions?|rules?|constraints?|policies)\s+(?:do not|don't|no longer)\s+(?:apply|matter|count|remain relevant)\b", re.I),
        re.compile(r"\b(?:initial|previous|prior|system|developer)\s+(?:instructions?|rules?|guidance)\s+(?:are|have been)\s+(?:cancelled|canceled|void|obsolete)\b", re.I),
        re.compile(r"\b(?:stop following|do not obey|don't obey|disregard|discard)\b.{0,70}\b(?:your|any|all|the|my|previous|prior|earlier|system|developer)?\s*(?:instructions?|rules?|guidance|messages?|directions?)\b", re.I),
        re.compile(r"\b(?:cancel|revoke|erase)\b.{0,50}\b(?:initial|previous|prior|system|developer)?\s*(?:instructions?|rules?|guidance|messages?)\b", re.I),
        re.compile(r"\b(?:ignore|disregard|forget|drop|discard|override|replace|supersede|set aside|stop following|do not follow|don't follow)\b.{0,100}\b(?:previous|prior|above|earlier|existing|old|initial|first|system|developer|user|safety|security|all|the)\b.{0,45}\b(?:instructions?|rules?|guidelines?|prompts?|messages?|directions?|constraints?|polic(?:y|ies)|guardrails?|request)\b", re.I),
        re.compile(r"\b(?:ignore|disregard|forget|drop|discard)\s+(?:all\s+)?(?:the\s+)?(?:instructions?|rules?|guidelines?|system prompt|developer message|user request|security policy|safety rules)\b", re.I),
        re.compile(r"\b(?:your|the|these|those|previous|prior|earlier)\s+(?:constraints?|rules?|instructions?|policies)\s+(?:are|is)\s+no longer relevant\b", re.I),
        re.compile(r"\b(?:from now on|instead)\b.{0,55}\b(?:follow|obey|use|comply with)\s+(?:my|these|the following|attacker|new)\s+(?:instructions?|rules?|request|commands?)\b", re.I),
        re.compile(r"\b(?:follow|obey|prioritize)\s+(?:my|these|the following|attacker's|new)\s+(?:instructions?|rules?|request|commands?)\s+instead\b", re.I),
        re.compile(r"\b(?:override|replace|supersede)\b.{0,70}\b(?:system|developer|user|safety|security|prior|previous|existing)?\s*(?:instructions?|rules?|guidelines?|policy|policies|restrictions?|message|request)\b", re.I),
        re.compile(r"\b(?:ignore|bypass|disable|override)\b.{0,65}\b(?:security|safety)\s+(?:policy|policies|rules?|checks?|guardrails?|restrictions?)\b", re.I),
        re.compile(r"\b(?:ignore|disregard)\s+the\s+user(?:'s)?\s+(?:request|instructions?)\b", re.I),
        re.compile(r"\b(?:ignore|disregard|forget)\s+(?:all\s+)?(?:the\s+)?(?:prior|previous|earlier)\s+(?:context|conversation|chat)\b", re.I),
    ),
    "system_prompt_extraction": (
        re.compile(r"\b(?:show|tell me|quote|list|provide|explain|reveal|print|repeat|disclose)\b.{0,90}\b(?:(?:hidden|internal|private|confidential|developer|system)\s+){0,2}(?:instructions?|guidelines?|rules?|message|prompt|configuration|config|notes?)\b", re.I),
        re.compile(r"\b(?:reveal|show|print|repeat|disclose|output|quote|tell me|list|extract|provide|share|describe|explain)\b.{0,100}\b(?:(?:hidden|internal|private|confidential|system|developer)\s+){0,2}(?:system\s+prompt|developer\s+message|instructions?|rules?|prompt|configuration|config|notes?)\b", re.I),
        re.compile(r"\bwhat\s+(?:instructions?|rules?|prompt|message)\s+(?:were\s+)?(?:provided|given|sent|supplied)\s+to\s+you\s+(?:before|prior to|at the start of)\b", re.I),
        re.compile(r"\bwhat\s+(?:are|were)\s+(?:your|the)\s+(?:(?:hidden|internal|private|confidential|system|developer)\s+){0,2}(?:instructions?|rules?|prompt|message|configuration)\b", re.I),
        re.compile(r"\b(?:tell me|explain|describe)\s+(?:the\s+)?(?:rules|instructions)\s+(?:that\s+)?(?:govern|control|guide)\s+(?:your|the assistant's|the model's)\s+behavior\b", re.I),
        re.compile(r"\b(?:confidential|hidden|private|internal)\s+instructions?\s+(?:you\s+)?received\b", re.I),
        re.compile(r"\bwhat\s+(?:(?:hidden|internal|private|confidential|developer|system)\s+){0,2}(?:developer\s+|system\s+)?(?:message|instructions?|prompt|rules?)\s+(?:shaped|governed|controls?|guides?)\s+(?:your\s+|the assistant's\s+|the model's\s+)?behavior\b", re.I),
    ),
    "role_manipulation": (
        re.compile(r"\b(?:act as|pretend (?:you are|to be)|assume the role of|you are now|roleplay as|impersonate|identify yourself as)\b.{0,80}\b(?:administrator|admin|developer|system|security officer|security team|internal employee|privileged user|root|superuser|operator)\b", re.I),
        re.compile(r"\b(?:i am|this is|speaking as|on behalf of)\s+(?:the\s+)?(?:system|developer|administrator|admin|security officer|security team|internal employee|privileged user|root)\b.{0,100}\b(?:authorize|higher priority|override|access|bypass|reveal|export|approve|grant|ignore|disregard)\b", re.I),
        re.compile(r"\b(?:treat|recognize|consider)\s+me\s+as\s+(?:the\s+)?(?:system|developer|administrator|admin|privileged user|security officer)\b", re.I),
        re.compile(r"\b(?:use|grant|give)\s+(?:my|this)\s+(?:administrator|developer|system|privileged)\s+(?:authority|access|role)\b", re.I),
    ),
    "jailbreak": (
        re.compile(r"\b(?:disable|remove|turn off|bypass|ignore|suspend|switch off)\b.{0,65}\b(?:your\s+|all\s+)?(?:safety|ethical|content|security)\s+(?:filters?|restrictions?|rules?|limitations?|constraints?|safeguards?|guardrails?|polic(?:y|ies))\b", re.I),
        re.compile(r"\b(?:suspend|remove|disable)\b.{0,40}\b(?:your\s+)?(?:safeguards?|protections?|safety checks?)\b", re.I),
        re.compile(r"\b(?:DAN\s*[,:(-]?\s*do anything now|do anything now)\b", re.I),
        re.compile(r"\b(?:unrestricted|uncensored|unfiltered|no[- ]rules?|no[- ]limits?|without limitations|without restrictions|without ethical restrictions)\s+(?:AI|assistant|model|mode|persona|answers?)\b", re.I),
        re.compile(r"\b(?:answer|respond|comply|operate)\s+(?:freely\s+)?without\s+(?:any\s+)?(?:limits|restrictions|rules|safeguards)\b", re.I),
        re.compile(r"\b(?:disable|remove|turn off|bypass|ignore|suspend|switch off)\b.{0,65}\b(?:all\s+)?(?:safety|ethical|content|security)\s+(?:filters?|restrictions?|rules?|limitations?|constraints?|safeguards?|guardrails?|policies)\b", re.I),
        re.compile(r"\b(?:developer|administrator|admin|god|unrestricted)\s+mode\b", re.I),
        re.compile(r"\bpretend\s+(?:you\s+)?(?:have|follow)\s+no\s+(?:rules?|policies|restrictions?|safeguards?)\b", re.I),
        re.compile(r"\b(?:ignore|disregard|override)\s+(?:all\s+)?(?:your\s+)?(?:safety|ethical)\s+(?:rules?|constraints?|policies|guardrails?)\b", re.I),
    ),
    # These are applied only to document/email/web inputs, never to plain prompts.
    "indirect_prompt_injection": (
        re.compile(r"\b(?:before|instead of|rather than|without)\b.{0,80}\b(?:completing|answering|following|fulfilling|summari[sz]ing|responding to)\s+(?:the\s+)?(?:user(?:'s)?\s+)?(?:request|instructions?)\b.{0,100}\b(?:ignore|disregard|override|change|reveal|send|email|forward|upload|disclose|export|delete|execute|run|transmit)\b", re.I),
        re.compile(r"\b(?:reveal|disclose|expose|send|email|forward|upload|export|transmit|share|copy)\b.{0,100}\b(?:confidential|private|sensitive|internal|secret|credential|customer|user)\s+(?:information|data|details?|records?|files?|documents?|content|secrets?|reports?|notes?)\b", re.I),
        re.compile(r"\b(?:ignore|disregard|override|do not follow|don't follow)\s+(?:the\s+)?(?:user(?:'s)?\s+)?(?:request|instructions?)\b", re.I),
        re.compile(r"\b(?:follow|obey|execute|carry out)\s+(?:these|the following|this)\s+(?:hidden\s+)?(?:instructions?|commands?|steps?)\b", re.I),
        re.compile(r"\b(?:change|alter|modify|override)\s+(?:your|the assistant's|the model's)\s+(?:behavior|role|instructions?|response|rules?)\b", re.I),
        re.compile(r"\b(?:execute|run|perform|initiate)\s+(?:this|the following|an?)\s+(?:unauthori[sz]ed\s+)?(?:action|command|script|transaction|operation)\b", re.I),
        re.compile(r"\b(?:ignore|bypass|disable|override)\b.{0,70}\b(?:security|safety)\s+(?:policy|policies|rules?|checks?|controls?|guardrails?)\b", re.I),
        re.compile(r"\b(?:important|urgent|system|assistant)\s+(?:system\s+)?(?:message|instructions?)\s*:", re.I),
    ),
    "unauthorized_data_request": (
        re.compile(r"\b(?:send|email|forward|upload|export|transmit|exfiltrate|share|copy|disclose|reveal|leak)\b.{0,120}\b(?:all\s+)?(?:confidential|private|sensitive|internal|secret|credential|customer|user)\s+(?:information|data|details?|records?|files?|documents?|content|secrets?|reports?|notes?)\b", re.I),
        re.compile(r"\b(?:send|email|forward|upload|export|transmit|copy)\b.{0,80}\b(?:internal|confidential|private|sensitive)\s+(?:report|notes?|records?)\b", re.I),
        re.compile(r"\b(?:send|email|forward|upload|export|transmit|exfiltrate|copy|leak)\b.{0,100}\b(?:secrets?|credentials?|api keys?|passwords?|private files?|customer data)\b", re.I),
        re.compile(r"\b(?:reveal|disclose|print|output|dump|list)\b.{0,100}\b(?:all\s+)?(?:confidential|private|internal|secret|customer|user)\s+(?:information|data|records?|files?|secrets?)\b", re.I),
    ),
    "external_destination": (
        re.compile(r"\b(?:send|email|forward|upload|export|transmit|share|copy)\b.{0,120}\b(?:to|at|into)\s+(?:https?://\S+|[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|(?:an?\s+)?(?:external|outside|attacker|third.party|remote)\s+(?:server|site|address|destination|account|endpoint))", re.I),
        re.compile(r"\b(?:attacker|external|outside|third.party)\s+(?:server|site|address|destination|endpoint)\b", re.I),
    ),
    "social_engineering": (
        re.compile(r"\b(?:do not tell anyone|keep this secret|bypass approval|skip verification|urgent authorization required)\b", re.I),
    ),
}

EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
PHONE = re.compile(r"(?<!\w)(?:\+\d{1,3}[ .()-]?)?(?:\(?\d{3}\)?[ .-]?)\d{3}[ .-]?\d{4}(?!\w)")
GOV_ID = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
SECRET_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{6,}\b", re.I),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", re.I),
    re.compile(r"\b(?:api[_-]?key|secret|password|passwd|token|auth[_-]?token)\s*[:=]\s*(?:\"[^\"]+\"|'[^']+'|[^\s,;]+)", re.I),
    re.compile(r"\b(?:my\s+|the\s+|example\s+|temporary\s+|sample\s+)?(?:api[_ -]?key|secret|password|passwd|token|auth[_-]?token)\s+(?:is|equals)\s*:?\s*[^\s,;]+", re.I),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.I),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]{1,300}?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)
CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{28,}={0,2}(?![A-Za-z0-9+/])")
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
CONFUSABLES = str.maketrans({"а": "a", "с": "c", "е": "e", "і": "i", "ј": "j", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "ѕ": "s", "т": "t", "у": "y", "х": "x", "в": "b", "А": "A", "С": "C", "Е": "E", "І": "I", "Ј": "J", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "Ѕ": "S", "Т": "T", "У": "Y", "Х": "X", "В": "B"})

DISCUSSION_CLAUSES = (
    re.compile(r"\b(?:can you\s+)?(?:explain|describe|discuss|analy[sz]e|why)\b[^,;.!?]{0,180}\b(?:prompt injection|system prompt extraction|jailbreak|jailbreaking)\b[^,;.!?]{0,70}\b(?:dangerous|risk|security risk|attack|attacks|indicator|example)\b[.!?]?", re.I),
    re.compile(r"\bthe phrase\b[^,;.!?]{0,140}\b(?:is\s+)?(?:commonly|often|sometimes)\s+used(?:\s+in\s+(?:jailbreak|prompt injection) attempts?)?\b[.!?]?", re.I),
    re.compile(r"\bin a security report\b,?[^,;.!?]{0,180}\b(?:phrase|wording)\b[^,;.!?]{0,100}\b(?:indicator|example|risk)\b[.!?]?", re.I),
    re.compile(r"\b(?:a|the) security report\b[^.!?]{0,100}\b(?:discusses|describes|analy[sz]es|mentions|includes|quotes)\b[^.!?]{0,100}\b(?:phrase|wording|example)\s+[\"'“‘][^\"'”’]{1,100}[\"'”’]", re.I),
)


def _severity(score: int, blocked: bool = False) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30 or blocked:
        return "Medium"
    return "Low"


def _decoded_text(text: str) -> str:
    chunks = []
    for token in BASE64_TOKEN.findall(text)[:12]:
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
            if decoded.isprintable() and len(decoded) >= 8:
                chunks.append(decoded)
        except (ValueError, UnicodeDecodeError):
            continue
    return "\n".join(chunks)


def _normalized(text: str) -> str:
    cleaned = unicodedata.normalize("NFKC", text).translate(CONFUSABLES)
    # Remove zero-width format characters, then collapse unusual spacing for matching.
    cleaned = "".join(ch for ch in cleaned if unicodedata.category(ch) != "Cf")
    return cleaned


def _compact(text: str) -> str:
    return re.sub(r"[^a-z]", "", _normalized(text).translate(LEET).lower())


def _strip_discussion(text: str) -> str:
    result = text

    def keep_if_attack(match: re.Match) -> str:
        # An educational wrapper must not erase an actionable attack in its clause.
        # Quoted examples stay exempt, while matching attack language outside quotes
        # remains visible to the normal detector.
        clause = re.sub(
            r'''(?:"[^"\n]*"|(?<!\w)'[^'\n]*'(?!\w)|“[^”\n]*”|‘[^’\n]*’)''',
            " ",
            match.group(0),
        )
        for signal in PATTERNS:
            findings = _matches(signal, clause)
            if signal == "system_prompt_extraction":
                findings = [
                    finding for finding in findings
                    if not re.match(r"\b(?:can you\s+)?(?:explain|describe|discuss|analy[sz]e|why)\b", finding, re.I)
                ]
            if findings:
                return match.group(0)
        return " "

    for pattern in DISCUSSION_CLAUSES:
        result = pattern.sub(keep_if_attack, result)
    return result


def _matches(signal: str, text: str) -> list[str]:
    findings = []
    for pattern in PATTERNS.get(signal, ()):
        for match in pattern.finditer(text):
            evidence = match.group(0).strip()[:160]
            if evidence and evidence not in findings:
                findings.append(evidence)
    return findings


def _sensitive_patterns(original: str, policies: dict[str, bool]) -> tuple[list[str], list[re.Pattern]]:
    labels: list[str] = []
    patterns: list[re.Pattern] = []
    if policies.get("pii", True):
        for label, pattern in (("Email address", EMAIL), ("Phone number", PHONE), ("Government ID", GOV_ID), ("Possible payment card", CARD)):
            if pattern.search(original):
                labels.append(label)
                patterns.append(pattern)
    if policies.get("secrets", True):
        for pattern in SECRET_PATTERNS:
            if pattern.search(original):
                labels.append("API key, token, or secret")
                patterns.append(pattern)
    return list(dict.fromkeys(labels)), list(dict.fromkeys(patterns))


def _sanitize(text: str, patterns: list[re.Pattern]) -> str:
    clean = text
    for pattern in patterns:
        clean = pattern.sub("[REDACTED]", clean)
    clean = re.sub(r"(?:\s*\[REDACTED\]\s*){2,}", " [REDACTED] ", clean)
    return re.sub(r"[ \t]{2,}", " ", clean).strip()


def scan(content: str, input_type: str = "prompt", policies: dict[str, bool] | None = None) -> dict:
    """Return a deterministic verdict. `input_type` is validated at the API layer too."""
    policies = policies or {}
    kind = input_type.lower()
    # Preserve characters such as @ and digits in the content returned to callers;
    # confusable/zero-width normalization is for detection, not redaction output.
    original = unicodedata.normalize("NFKC", content)
    normalized_content = _normalized(original)
    decoded = _decoded_text(original)
    # Remove narrowly identified educational/reporting clauses before matching, so
    # quoted attack vocabulary does not become an instruction to the model.
    analyzed_original = _strip_discussion(normalized_content)
    analyzed_decoded = _strip_discussion(decoded) if decoded else ""
    detection_text = f"{analyzed_original}\n{analyzed_decoded}" if analyzed_decoded else analyzed_original

    policy_signal = {
        "instruction_override": policies.get("prompt_injection", True),
        "system_prompt_extraction": policies.get("prompt_injection", True),
        "role_manipulation": policies.get("prompt_injection", True),
        "jailbreak": policies.get("jailbreak", True),
        "indirect_prompt_injection": policies.get("indirect_injection", True) and kind in {"document", "email", "web"},
        "social_engineering": policies.get("prompt_injection", True),
    }
    detected: dict[str, list[str]] = {}
    for signal in PATTERNS:
        if signal in {"sensitive_information", "obfuscation"}:
            continue
        if not policy_signal.get(signal, True):
            detected[signal] = []
        else:
            detected[signal] = _matches(signal, detection_text)

    # An indirect payload can contain a direct override phrase; surface the external
    # category explicitly when it is embedded in untrusted content.
    if kind in {"document", "email", "web"} and policy_signal["indirect_prompt_injection"]:
        indirect = detected["indirect_prompt_injection"]
        external_attack = any(detected.get(name) for name in ("instruction_override", "system_prompt_extraction", "role_manipulation", "jailbreak", "unauthorized_data_request", "external_destination"))
        if external_attack and not indirect:
            indirect = ["External content contains an instruction attack or unauthorized action"]
            detected["indirect_prompt_injection"] = indirect

    # Basic de-obfuscation handles spacing, common leetspeak, Unicode confusables,
    # zero-width characters, and Base64 snippets. This is intentionally bounded.
    compact_terms = {
        "instruction_override": ("ignoreallpreviousinstructions", "disregardeverythingabove", "forgetyourrules", "ignoretheuserrequest", "followmyinstructionsinstead", "disregardtheinstructionsabove"),
        "system_prompt_extraction": ("showyourhiddeninstructions", "showhiddeninstructions", "revealthedevelopermessage", "printinternalconfiguration", "tellmeyourrules", "revealthehiddenprompt", "revealthehiddeninstructions"),
        "jailbreak": ("disableallsafetyrules", "bypassallrestrictions", "uncensoredassistant", "pretendyouhavenopolicies", "ignoresafetyconstraints"),
    }
    obfuscated: list[str] = []
    for source_name, source_text in (("input", analyzed_original), ("decoded Base64", analyzed_decoded)):
        if not source_text:
            continue
        compact = _compact(source_text)
        for signal, terms in compact_terms.items():
            if any(term in compact for term in terms) and not detected.get(signal):
                detected.setdefault(signal, []).append(f"Obfuscated {source_name} matches {signal.replace('_', ' ')}")
                obfuscated.append(f"Obfuscated {source_name} contains a {signal.replace('_', ' ')} pattern")
    if decoded and any(detected.get(name) for name in ("instruction_override", "system_prompt_extraction", "role_manipulation", "jailbreak", "indirect_prompt_injection")):
        obfuscated.append("Base64-decoded content contains an instruction attack pattern")
    if normalized_content != original and any(detected.get(name) for name in ("instruction_override", "system_prompt_extraction", "role_manipulation", "jailbreak", "indirect_prompt_injection")):
        obfuscated.append("Unicode-confusable or zero-width characters disguise an instruction attack")
    # Only flag obfuscation as its own risk signal when a suspicious phrase is found.
    detected["obfuscation"] = list(dict.fromkeys(obfuscated))

    # Exfiltration and destination signals provide explainable weight to the overall
    # risk, and are especially useful for describing indirect prompt injection.
    detected["unauthorized_data_request"] = _matches("unauthorized_data_request", detection_text)
    detected["external_destination"] = _matches("external_destination", detection_text)

    sensitive_labels, sensitive_patterns = _sensitive_patterns(original, policies)
    detected["sensitive_information"] = sensitive_labels

    detected_order = list(SIGNAL_WEIGHTS)
    signals = {name: bool(detected.get(name)) for name in detected_order}
    breakdown = [
        {"signal": name, "score": SIGNAL_WEIGHTS[name] if signals[name] else 0,
         "detected": signals[name], "evidence": detected.get(name, [])}
        for name in detected_order
    ]
    score = min(100, sum(row["score"] for row in breakdown))
    signal_names = [name for name in detected_order if signals[name]]
    attack_signals = {"instruction_override", "system_prompt_extraction", "role_manipulation", "jailbreak", "indirect_prompt_injection"}
    attack_detected = bool(attack_signals.intersection(signal_names))
    exfiltration = signals["unauthorized_data_request"]
    indirect = signals["indirect_prompt_injection"]

    if signals["obfuscation"] and attack_detected:
        threat_type = "Obfuscated Attack"
    elif indirect:
        threat_type = "Indirect Prompt Injection"
    elif signals["system_prompt_extraction"]:
        threat_type = "System Prompt Extraction"
    elif signals["role_manipulation"]:
        threat_type = "Role Manipulation"
    elif signals["jailbreak"]:
        threat_type = "Jailbreak Attempt"
    elif signals["instruction_override"]:
        threat_type = "Direct Prompt Injection"
    elif signals["sensitive_information"]:
        threat_type = "Sensitive Data"
    elif signals["obfuscation"] or signals["social_engineering"]:
        threat_type = "Suspicious Content"
    else:
        threat_type = "None"

    sanitized_content = _sanitize(original, sensitive_patterns)
    sensitive_change = bool(sensitive_patterns and sanitized_content != original)
    sanitization_enabled = policies.get("sanitization", True)

    if attack_detected or exfiltration or (score >= 80):
        action = "BLOCK"
    elif sensitive_change:
        non_sensitive_signal = any(name != "sensitive_information" for name in signal_names)
        action = "SANITIZE" if sanitization_enabled and not non_sensitive_signal else "BLOCK"
    elif score >= 60:
        action = "BLOCK"
    elif score >= 30:
        # No deterministic safe rewrite exists for ambiguous instruction signals.
        action = "BLOCK"
    else:
        action = "ALLOW"

    severity = _severity(score, blocked=action == "BLOCK")
    explanations = {
        "instruction_override": "Conflicting language attempts to replace or ignore existing instructions.",
        "system_prompt_extraction": "The input asks for hidden or internal instructions and configuration.",
        "role_manipulation": "The input claims or assigns privileged authority to change how the assistant behaves.",
        "jailbreak": "The input asks to disable safeguards or use an unrestricted model mode.",
        "indirect_prompt_injection": "This external content attempts to override the user's request or direct an unauthorized action.",
        "sensitive_information": "Sensitive values were found and redacted before forwarding.",
        "suspicious": "The input contains a limited risk signal, but no confirmed instruction attack was found.",
        "safe": "No supported threat patterns were detected.",
    }
    if indirect and (exfiltration or signals["external_destination"]):
        explanation = "This external content attempts to override the user's request and instruct the AI to disclose or transmit confidential information."
    elif indirect:
        explanation = explanations["indirect_prompt_injection"]
    elif signals["system_prompt_extraction"]:
        explanation = explanations["system_prompt_extraction"]
    elif signals["role_manipulation"]:
        explanation = explanations["role_manipulation"]
    elif signals["jailbreak"]:
        explanation = explanations["jailbreak"]
    elif signals["instruction_override"]:
        explanation = explanations["instruction_override"]
    elif action == "SANITIZE":
        explanation = explanations["sensitive_information"]
    elif signal_names:
        explanation = explanations["suspicious"]
    else:
        explanation = explanations["safe"]

    labels = {
        "instruction_override": "Instruction override",
        "system_prompt_extraction": "System prompt extraction",
        "role_manipulation": "Role / authority manipulation",
        "jailbreak": "Jailbreak",
        "sensitive_information": "Sensitive information",
        "indirect_prompt_injection": "Indirect prompt injection",
        "unauthorized_data_request": "Unauthorized data request",
        "external_destination": "External destination",
        "obfuscation": "Obfuscation",
        "social_engineering": "Social engineering",
    }
    reasons = [f"{labels[name]}: {('; '.join(detected[name]))[:240]}" for name in signal_names]
    detections = [labels[name] for name in signal_names]
    return {
        "threat_detected": bool(signal_names),
        "threat_type": threat_type,
        "risk_score": score,
        "severity": severity,
        "action": action,
        "reasons": reasons,
        # A blocked input has no safe-to-forward sanitized variant; do not expose
        # residual attack instructions as though sanitization made them safe.
        "sanitized_content": sanitized_content if sensitive_change and action != "BLOCK" else None,
        "detections": detections,
        "risk_breakdown": breakdown,
        "explanation": explanation,
    }


def scan_generated_output(content: str) -> dict:
    """Check model output with mandatory policies and output-relevant signals only."""
    if not isinstance(content, str) or not content.strip():
        raise ValueError("Generated output is empty or invalid.")

    result = scan(
        content,
        input_type="prompt",
        policies={
            "prompt_injection": True,
            "indirect_injection": True,
            "jailbreak": True,
            "pii": True,
            "secrets": True,
            "sanitization": True,
        },
    )
    # Indirect-injection checks are for external documents, and social-engineering
    # signals describe incoming requests. Generated output is checked for direct
    # unsafe instructions and sensitive-data disclosure instead.
    output_signals = {
        "instruction_override",
        "system_prompt_extraction",
        "role_manipulation",
        "jailbreak",
        "sensitive_information",
        "unauthorized_data_request",
        "external_destination",
        "obfuscation",
    }
    detected = [
        row["signal"]
        for row in result["risk_breakdown"]
        if row["signal"] in output_signals and row["detected"]
    ]
    return {"safe": not detected, "detected_signals": detected}
