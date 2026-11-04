from __future__ import annotations

from typing import Any

from CVEVerdict.models import ConfigNode, Configuration, CpeMatch
from CVEVerdict.parsing.cpe import parse_cpe23
from CVEVerdict.result import FailureKind, Result, fail, ok


def parse_configurations(raw_configs: list[dict[str, Any]]) -> Result[list[Configuration]]:
    """
    Parses the NVD 2.0 'configurations' JSON array into structured Configuration trees.
    Does NOT flatten the tree, keeping the logical relationships intact.
    """
    if not isinstance(raw_configs, list):
        return fail(FailureKind.INVALID_RESPONSE, "Configurations must be a JSON array.")

    parsed_configurations: list[Configuration] = []

    for raw_config in raw_configs:
        config_operator = raw_config.get("operator")
        raw_nodes = raw_config.get("nodes", [])
        config_warnings: list[str] = []

        # If there are multiple nodes but no configuration-level operator, it is ambiguous
        if len(raw_nodes) > 1 and not config_operator:
            config_warnings.append(
                f"Configuration has {len(raw_nodes)} nodes but no operator; combination logic is ambiguous."
            )

        parsed_nodes: list[ConfigNode] = []

        for raw_node in raw_nodes:
            node_operator = raw_node.get("operator", "OR")
            negate = bool(raw_node.get("negate", False))
            node_warnings: list[str] = []

            if negate:
                node_warnings.append("Node has negate=True; inversion logic requires careful verification.")

            raw_matches = raw_node.get("cpeMatch", [])
            cpe_matches: list[CpeMatch] = []

            for raw_match in raw_matches:
                criteria = raw_match.get("criteria", "")
                vulnerable = bool(raw_match.get("vulnerable", False))

                cpe_result = parse_cpe23(criteria)
                if cpe_result.is_failure:
                    # Record warning or skip malformed CPE entries without breaking the whole tree
                    node_warnings.append(f"Skipping malformed CPE '{criteria}': {cpe_result.message}")
                    continue

                parsed_cpe = cpe_result.unwrap()

                match_item = CpeMatch(
                    cpe=parsed_cpe,
                    vulnerable=vulnerable,
                    version_start_including=raw_match.get("versionStartIncluding"),
                    version_start_excluding=raw_match.get("versionStartExcluding"),
                    version_end_including=raw_match.get("versionEndIncluding"),
                    version_end_excluding=raw_match.get("versionEndExcluding"),
                    match_criteria_id=raw_match.get("matchCriteriaId"),
                )
                cpe_matches.append(match_item)

            parsed_nodes.append(
                ConfigNode(
                    operator=node_operator,
                    negate=negate,
                    cpe_matches=cpe_matches,
                    warnings=node_warnings,
                )
            )

        parsed_configurations.append(
            Configuration(
                operator=config_operator,
                nodes=parsed_nodes,
                warnings=config_warnings,
            )
        )

    return ok(parsed_configurations)