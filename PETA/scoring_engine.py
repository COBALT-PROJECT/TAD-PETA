def score_mitigations(attack_mapping, attack_type, target_node, nodes, links):
    """
    Evaluates mitigations for the target node, and if the score is low due to 
    high criticality, dynamically traverses the graph upstream to find better alternatives.
    """
    impact_scores = {"Low": 80, "Medium": 50, "High": 20, "Critical": -50}
    effectiveness_scores = {"Low": 10, "Medium": 50, "High": 90}
    
    # Extract contextual mitigations for a specific node and score them
    def evaluate_node(node):
        node_criticality = node.get("criticality", 5)
        asset_type = node.get("type", "Unknown")
        mitigations = attack_mapping.get(attack_type, {}).get("contexts", {}).get(asset_type, [])
        
        best = None
        high = -9999
        for mit in mitigations:
            # Copy to avoid mutating the original mapping dictionary
            mit_copy = dict(mit) 
            
            score = effectiveness_scores.get(mit_copy.get("effectiveness", "Medium"), 50)
            impact_base = impact_scores.get(mit_copy.get("impact_level", "Medium"), 50)
            
            if impact_base < 50:
                 score += (impact_base * (node_criticality / 5.0))
            else:
                 score += impact_base
                 
            mit_copy["_calculated_score"] = score
            mit_copy["_target_node_id"] = node.get("id") # Track which node this applies to
            
            if score > high:
                high = score
                best = mit_copy
        return best

    # 1. Score the direct Target Node
    best_overall = evaluate_node(target_node)
    
    # 2. Dynamic Upstream Traversal
    # If the target node's best mitigation is heavily penalized (e.g. Critical impact on Critical Node)
    # Check if there are generic upstream mitigations available.
    
    # Find all nodes that link TO the target node
    upstream_node_ids = [link["source"] for link in links if link.get("target") == target_node.get("id")]
    
    for up_id in upstream_node_ids:
        upstream_node = next((n for n in nodes if n.get("id") == up_id), None)
        if upstream_node:
            upstream_best = evaluate_node(upstream_node)
            
            # If mitigating upstream yields a higher score (e.g. filtering at WAF instead of dropping DB)
            if upstream_best and best_overall:
                if upstream_best.get("_calculated_score", 0) > best_overall.get("_calculated_score", 0):
                    best_overall = upstream_best
            elif upstream_best and not best_overall:
                best_overall = upstream_best

    return best_overall if best_overall else {}
