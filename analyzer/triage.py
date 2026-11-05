"""Triage: read the question before any tool runs (keywords in rules mode, the LLM in agent mode)."""
import logging
import re

from analyzer import prompts

log = logging.getLogger(__name__)

PREFIX_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")
ROUTE_WORD_RE = re.compile(r"\broutes?\b|\bprefix(?:es)?\b|\bpaths?\b|\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}")


def triage(question: str) -> str:
    q = question.lower()
    if any(w in q for w in ("interface", "link", "cable")):
        return "interface_check"
    if any(w in q for w in ("tcp", "179", "reachab", "firewall")):
        return "tcp_port_check"
    if any(w in q for w in ("config", "mismatch", "remote-as", "as number")):
        return "config_check"
    return "bgp_state_check"   # default: start from BGP session state


def extract_prefix(question: str) -> str | None:
    """The first prefix (a.b.c.d/len) in the question, if any."""
    m = PREFIX_RE.search(question)
    return m.group(1) if m else None


def route_intent(question: str) -> str | None:
    """The route rule a question is about, or None for a session question.

    The rules engine still checks the session first (bgp_state) and only moves
    to this rule when the session is Established.
    """
    q = question.lower()
    about_routes = bool(ROUTE_WORD_RE.search(q))
    if re.search(r"best[ -]?path|which path|path selection|preferred path|tie-?break"
                 r"|why\b.*\b(?:prefers?|preferred|chooses?|chosen|selects?|selected|picks?|picked|wins?|winning)\b", q):
        return "route_best_path_selection"
    if about_routes and re.search(r"not (?:being )?(?:selected|chosen|preferred|used|best|installed|received|"
                                  r"learn(?:ed|t)?|showing|there|in the table)|isn'?t (?:selected|chosen|there)"
                                  r"|(?:not|n't) (?:\w+ )?(?:receiv|learn|get|see|accept)\w*"
                                  r"|\bno (?:routes?|prefix(?:es)?|paths?)\b|\bzero (?:routes|prefixes)\b"
                                  r"|missing|disappear|gone|lost|filtered|dropped|withdrawn|denied|rejected", q):
        return "route_received_not_selected"
    if re.search(r"route-?map|route map|prefix-?list|prefix list|filter-?list", q):
        return "route_map_check"
    if about_routes or re.search(r"local[- ]?pref|\bmed\b|as[- ]?path|next[- ]?hop|\bweight\b", q):
        return "route_leading_case"
    return None


def route_context(question: str) -> dict:
    """The route-question keys the rules engine reads from ctx."""
    intent, prefix = route_intent(question), extract_prefix(question)
    return {"route_question": bool(intent or prefix),
            "route_intent": intent or ("route_received_not_selected" if prefix else None),
            "prefix": prefix}


def llm_triage(question: str, host: str, peer: str | None, registry) -> dict:
    """Build a fast, deterministic triage card before device checks.

    Triage is only routing metadata; spending a full local-model inference here
    added latency without adding device evidence. The agent still uses the LLM
    to interpret ambiguous evidence after the real tools have run.
    """
    intents = registry.intents()
    q = question.strip()
    low = q.lower()
    plan = list(dict.fromkeys(i for i in ("bgp_state_check", triage(question)) if i in intents))
    hypotheses = []
    def add(label: str, why: str):
        if label in prompts.FAULT_CLASSES and all(h["fault_class"] != label for h in hypotheses):
            hypotheses.append({"fault_class": label, "why": why})

    if any(word in low for word in ("passive", "never comes up", "won't come up", "will not come up")):
        add("config_drift", "A peer configuration may prevent either router from initiating the session.")
    if any(word in low for word in ("active", "connect", "tcp", "reach", "firewall")):
        add("tcp_unreachable", "The TCP session to the peer may not be forming.")
    if any(word in low for word in ("remote-as", "asn", "autonomous system")):
        add("remote_as_mismatch", "The configured peer AS may not match the remote router.")
    if any(word in low for word in ("shutdown", "admin down")):
        add("neighbor_shutdown", "The neighbor may be administratively disabled.")
    if ROUTE_WORD_RE.search(low):
        if re.search(r"\b(no|missing|not receiving|not getting|not learning|not seeing)\b", low):
            add("route_filtered", "An inbound or outbound eBGP policy may be withholding the expected routes.")
            add("route_not_received", "The peer may not be advertising the expected routes.")
        else:
            add("route_not_received", "Check whether the peer advertises the expected routes.")
    if any(word in low for word in ("stuck", "never comes up", "not established", "won't come up")):
        add("tcp_unreachable", "The BGP session may be unable to form its TCP connection.")
        add("remote_as_mismatch", "The peer AS configuration may not match.")
    if any(phrase in low for phrase in ("neighbor missing", "missing neighbor", "not configured", "peer missing")):
        add("neighbor_missing", "The peer configuration may be missing on one router.")
    if not hypotheses:
        add("tcp_unreachable", "The session transport may not be forming; check the live peer state first.")
    result = {
        "method": "rules",
        "in_scope": any(token in low for token in ("bgp", "peer", "neighbor", "frr", "router", "route", "asn")),
        "symptom": q,
        "claimed_state": next((state for state in prompts.STATES if state.lower() in low), "none"),
        "interface": None,
        "hypotheses": hypotheses[:4],
        "plan": plan,
    }
    log.info("Triage: %s", result)
    return result
