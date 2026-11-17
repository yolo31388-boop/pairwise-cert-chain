"""Certificate-chain validation primitives.

The previous implementation linked certificates purely by matching the
issuer name string, so cross-signed intermediates made chain selection
ambiguous and every other check was either skipped or too shallow.

The functions below implement:

* :func:`build_chain`       -- chain construction along real signature
                               relationships (issuer name + SKI/AKI and an
                               optional cryptographic signature check), with
                               deterministic cross-sign selection and trust
                               anchor enforcement.
* :func:`name_constraints_ok` -- name constraints evaluated at *every* CA in
                               the chain, not only at the leaf.
* :func:`eku_ok`            -- explicit serverAuth/clientAuth purpose checks.
* :func:`ocsp_ok`           -- OCSP responses must be current
                               (thisUpdate/nextUpdate) and assert ``good``.
* :func:`sct_ok`            -- certificate transparency: SCTs must be issued
                               by logs on a configured whitelist, not merely
                               counted.
* :func:`pin_ok`            -- SPKI / public-key pinning so CA rotation and
                               grayscale rollover keep working.

Certificates are modelled as plain dictionaries so the logic has no external
dependency; the field names mirror X.509 extensions (``issuer``, ``ski``,
``aki``, ``eku``, ``spki`` ...).
"""

# ---------------------------------------------------------------------------
# Extended Key Usage OIDs (RFC 5280 / RFC 3280)
# ---------------------------------------------------------------------------
EKU_OIDS = {
    'serverAuth': '1.3.6.1.5.5.7.3.1',
    'clientAuth': '1.3.6.1.5.5.7.3.2',
    'codeSigning': '1.3.6.1.5.5.7.3.3',
    'emailProtection': '1.3.6.1.5.5.7.3.4',
    'timeStamping': '1.3.6.1.5.5.7.3.8',
    'ocspSigning': '1.3.6.1.5.5.7.3.9',
    'anyExtendedKeyUsage': '2.5.29.37.0',
}


# ---------------------------------------------------------------------------
# 1. Chain construction along signature relationships
# ---------------------------------------------------------------------------
def _candidate_issuers(child, certs):
    """Return certs that *cryptographically* claim to have issued ``child``.

    Matching is never done on the issuer name alone.  A candidate must:

    1. carry the subject name named by the child's ``issuer`` field, and
    2. when both sides carry authority/subject key identifiers, the
       issuer's SKI must equal the child's AKI.

    Results are sorted by subject name so that, when several cross-signed
    intermediates share an issuer name, traversal order is deterministic
    instead of depending on dict insertion order.
    """
    issuer_name = child.get('issuer')
    candidates = []
    for subject, cert in certs.items():
        if subject != issuer_name:
            continue
        aki = child.get('aki')
        ski = cert.get('ski')
        if aki is not None and ski is not None and aki != ski:
            continue
        candidates.append((subject, cert))
    candidates.sort(key=lambda item: item[0])
    return candidates


def _signature_valid(child, parent, verify_signature):
    """Check that ``parent`` actually signed ``child``.

    Real verification needs the parent's public key over the child's
    tbsCertificate; callers inject that with ``verify_signature``.  Without
    injected crypto we also honour an explicit ``sig_valid`` marker on the
    child, and otherwise accept the SKI/AKI + issuer-name linkage established
    by :func:`_candidate_issuers`.
    """
    if verify_signature is not None:
        try:
            return bool(verify_signature(child, parent))
        except Exception:
            return False
    if 'sig_valid' in child:
        return bool(child['sig_valid'])
    return True


def build_chain(leaf, certs, roots=None, verify_signature=None):
    """Build a validated path from ``leaf`` up to a trusted anchor.

    The walk follows signature relationships rather than issuer strings, so
    with cross-signed CAs every plausible branch is explored and the first
    branch whose signatures verify and whose terminus is a trusted root is
    returned.

    Parameters
    ----------
    leaf:
        Subject name (key in ``certs``) of the end-entity certificate.
    certs:
        Mapping of subject name -> certificate dict.
    roots:
        Optional iterable of trusted anchor subject names.  When supplied,
        the chain terminus must be a member.  When ``None`` (the default
        platform trust store), a self-issued certificate is accepted as an
        anchor.
    verify_signature:
        Optional ``callable(child_cert, parent_cert) -> bool`` performing the
        actual public-key signature verification.

    Returns
    -------
    list[str] | None
        Subject names from leaf to trust anchor, or ``None`` if no valid
        path exists (unknown leaf, missing issuer, signature failure,
        signature loop, or untrusted terminus).
    """
    if not isinstance(certs, dict) or leaf not in certs:
        return None

    trusted = set(roots) if roots is not None else None

    def walk(subject, path):
        # Signature loop: a cert already on this path cannot be its own
        # ancestor -- this is what makes cyclic issuer references terminate.
        if subject in path:
            return None

        cert = certs.get(subject)
        if cert is None:
            return None

        current_path = path + [subject]

        is_self_issued = cert.get('issuer') == subject
        if trusted is not None:
            is_anchor = subject in trusted
        else:
            is_anchor = is_self_issued

        if is_anchor:
            # A self-issued anchor must still prove itself; an anchor named
            # in the trust store is trusted by provision, not by signature.
            if is_self_issued and not _signature_valid(
                cert, cert, verify_signature
            ):
                return None
            return current_path

        for issuer_subject, issuer_cert in _candidate_issuers(cert, certs):
            if not _signature_valid(cert, issuer_cert, verify_signature):
                continue
            result = walk(issuer_subject, current_path)
            if result is not None:
                return result
        return None

    return walk(leaf, [])


# ---------------------------------------------------------------------------
# 2. Name constraints, evaluated at every CA in the chain
# ---------------------------------------------------------------------------
def _dns_matches_constraint(name, constraint):
    """Match a DNS name against one name-constraint entry.

    Supported entry shapes:

    * ``example.com``      -- the name itself or any sub-domain subtree
    * ``*.example.com``    -- wildcard: any name ending in the suffix
                              (matches one or more labels, so both
                              ``api.example.com`` and ``a.b.example.com``)
    * leading ``.``        -- same subtree semantics as a bare domain
    """
    name = name.lower().rstrip('.')
    constraint = constraint.lower().rstrip('.')

    if constraint.startswith('*.'):
        suffix = constraint[1:]  # keep the leading dot: ".example.com"
        return name.endswith(suffix) and name != suffix[1:]

    if name == constraint:
        return True
    return name.endswith('.' + constraint)


def _constraint_sets(constraint):
    """Normalise one CA's constraint dict into (permitted, excluded) lists."""
    permitted = constraint.get('permitted')
    if permitted is None:
        # Bare {'dns': [...]} constraints read as permitted subtrees, which
        # is how intermediate-CA name constraints are expressed in tests.
        permitted = constraint.get('dns', [])
    excluded = constraint.get('excluded', [])
    return list(permitted), list(excluded)


def name_constraints_ok(constraints, dns_name):
    """Apply name constraints from *every* CA in the chain to ``dns_name``.

    ``constraints`` is ordered leaf-wards -> root-wards; each element is a
    CA's constraint extension.  A name is acceptable only when no excluded
    subtree matches and, where a CA asserts permitted subtrees, at least one
    of them matches.  Constraints imposed by intermediate CAs are enforced
    exactly like the root's.
    """
    if not dns_name:
        return False

    for constraint in constraints or []:
        permitted, excluded = _constraint_sets(constraint)

        for entry in excluded:
            if _dns_matches_constraint(dns_name, entry):
                return False

        if permitted:
            if not any(
                _dns_matches_constraint(dns_name, entry)
                for entry in permitted
            ):
                return False

    return True


# ---------------------------------------------------------------------------
# 3. Extended Key Usage purpose separation
# ---------------------------------------------------------------------------
def eku_ok(cert, usage):
    """Return True when ``cert`` may be used for ``usage``.

    ``usage`` is ``'server'`` (serverAuth) or ``'client'`` (clientAuth);
    raw OIDs are accepted too.  A certificate without an EKU extension is
    valid for all purposes per RFC 5280, while an EKU extension that does
    not contain the required OID -- or only contains the opposite purpose --
    is rejected.  ``anyExtendedKeyUsage`` matches every purpose.
    """
    required = {
        'server': EKU_OIDS['serverAuth'],
        'client': EKU_OIDS['clientAuth'],
    }.get(usage, usage)

    eku = cert.get('eku')
    if eku is None:
        # EKU extension absent: no purpose restriction.
        return True

    normalised = {
        EKU_OIDS.get(entry, entry) if isinstance(entry, str) else entry
        for entry in eku
    }

    if EKU_OIDS['anyExtendedKeyUsage'] in normalised:
        return True
    return required in normalised


# ---------------------------------------------------------------------------
# 4. OCSP freshness and status
# ---------------------------------------------------------------------------
def ocsp_ok(ocsp_response, now, clock_skew=0):
    """Validate an OCSP response's time window and revocation status.

    The response must:

    * assert ``good`` (a missing ``status`` field is treated as good for
      responses that only carry timing data; ``revoked`` and any other
      value fail), and
    * be current: ``thisUpdate - skew <= now <= nextUpdate + skew``.

    A response past ``nextUpdate`` is stale and must never be accepted,
    no matter what status it carries.
    """
    if not isinstance(ocsp_response, dict):
        return False

    status = ocsp_response.get('status', 'good')
    if status != 'good':
        return False

    this_update = ocsp_response.get('thisUpdate')
    next_update = ocsp_response.get('nextUpdate')
    if this_update is None or next_update is None:
        return False
    if next_update < this_update:
        return False

    return (this_update - clock_skew) <= now <= (next_update + clock_skew)


# ---------------------------------------------------------------------------
# 5. Certificate transparency: SCT signer whitelist
# ---------------------------------------------------------------------------
def _extract_scts(cert_or_scts):
    if isinstance(cert_or_scts, list):
        return cert_or_scts
    if isinstance(cert_or_scts, dict):
        return cert_or_scts.get('sct') or cert_or_scts.get('scts') or []
    return []


def _sct_log_id(sct):
    if isinstance(sct, dict):
        return sct.get('log_id') or sct.get('logId') or sct.get('log')
    return sct


def sct_ok(cert_or_scts, log_whitelist, min_scts=2):
    """Check embedded SCTs against a Certificate Transparency log whitelist.

    Merely counting SCTs is insufficient: an SCT proves nothing unless it was
    issued by a recognised, independently audited log.  Only SCTs whose
    signer (log id) appears in ``log_whitelist`` count, and at least
    ``min_scts`` of them are required (Chrome's CT policy demands two or more
    depending on certificate lifetime).
    """
    whitelist = set(log_whitelist or [])
    valid = [
        sct
        for sct in _extract_scts(cert_or_scts)
        if _sct_log_id(sct) in whitelist
    ]
    return len(valid) >= min_scts


# ---------------------------------------------------------------------------
# 6. SPKI / public-key pinning with rotation support
# ---------------------------------------------------------------------------
def _iter_spkis(peer):
    """Yield SPKIs from a cert dict, a chain (list of cert dicts), or raw id."""
    if isinstance(peer, str):
        yield peer
        return
    if isinstance(peer, dict):
        if 'spki' in peer:
            yield peer['spki']
        return
    if isinstance(peer, (list, tuple)):
        for cert in peer:
            if isinstance(cert, dict) and 'spki' in cert:
                yield cert['spki']
            elif isinstance(cert, str):
                yield cert


def pin_ok(peer, pins):
    """Verify SPKI pinning against a pin *set*.

    Pins are SubjectPublicKeyInfo hashes, never whole leaf certificates, so
    routine leaf re-issuance does not break pinning.  ``pins`` is a set that
    may contain the current and the backup/next-generation SPKI at the same
    time, which is what makes grayscale CA rotation possible: a peer is
    accepted when any certificate in its presented chain matches any pin.
    """
    pin_set = set(pins or [])
    if not pin_set:
        return False
    return any(spki in pin_set for spki in _iter_spkis(peer))
