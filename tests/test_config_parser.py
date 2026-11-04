from CVEVerdict.parsing.config import parse_configurations


def test_acceptance_a1_arts_package_on_linux():
    """
    Acceptance Test A1:
    An AND configuration where aRts 1.0 and 1.2 are vulnerable (app),
    and Linux kernel >= 2.6.0 is platform context (vulnerable: false).
    """
    raw_configs = [
        {
            "operator": "AND",
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:arts:arts:1.0:*:*:*:*:*:*:*",
                        },
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:arts:arts:1.2:*:*:*:*:*:*:*",
                        },
                    ],
                },
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": False,
                            "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "2.6.0",
                        }
                    ],
                },
            ],
        }
    ]

    res = parse_configurations(raw_configs)
    assert res.is_success
    configs = res.unwrap()
    assert len(configs) == 1

    config = configs[0]
    assert config.operator == "AND"
    assert len(config.nodes) == 2

    # Verify helper methods correctly separate vulnerable apps from platform context
    vuln_matches = config.vulnerable_matches
    platform_matches = config.platform_context_matches

    assert len(vuln_matches) == 2
    assert all(m.vulnerable is True for m in vuln_matches)
    assert vuln_matches[0].cpe.product == "arts"
    assert vuln_matches[0].cpe.version == "1.0"
    assert vuln_matches[1].cpe.version == "1.2"

    assert len(platform_matches) == 1
    assert platform_matches[0].vulnerable is False
    assert platform_matches[0].cpe.product == "linux_kernel"
    assert platform_matches[0].cpe.is_operating_system is True
    assert platform_matches[0].version_start_including == "2.6.0"


def test_authentik_pattern_no_config_operator():
    """Authentik pattern: single node, no top-level configuration operator."""
    raw_configs = [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:goauthentik:authentik:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "2023.10.0",
                            "versionEndExcluding": "2023.10.7",
                        }
                    ],
                }
            ]
        }
    ]

    res = parse_configurations(raw_configs)
    assert res.is_success
    configs = res.unwrap()
    assert configs[0].operator is None
    assert len(configs[0].warnings) == 0
    assert len(configs[0].vulnerable_matches) == 1
    assert configs[0].vulnerable_matches[0].version_start_including == "2023.10.0"
    assert configs[0].vulnerable_matches[0].version_end_excluding == "2023.10.7"


def test_ambiguous_operator_warning():
    """Multiple nodes without an operator produces an explicit warning."""
    raw_configs = [
        {
            "nodes": [
                {"operator": "OR", "cpeMatch": []},
                {"operator": "OR", "cpeMatch": []},
            ]
        }
    ]
    res = parse_configurations(raw_configs)
    assert res.is_success
    configs = res.unwrap()
    assert len(configs[0].warnings) == 1
    assert "ambiguous" in configs[0].warnings[0]


def test_negate_warning():
    """Negate=True produces an explicit node warning."""
    raw_configs = [
        {
            "nodes": [
                {"operator": "OR", "negate": True, "cpeMatch": []}
            ]
        }
    ]
    res = parse_configurations(raw_configs)
    assert res.is_success
    configs = res.unwrap()
    assert len(configs[0].nodes[0].warnings) == 1
    assert "negate=True" in configs[0].nodes[0].warnings[0]