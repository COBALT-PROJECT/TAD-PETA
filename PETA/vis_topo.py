import json
import networkx as nx
import matplotlib.pyplot as plt

def create_nx_graph(json_path):
    # 1. Load the PETA JSON
    with open(json_path, 'r') as f:
        data = json.load(f)
    
    # 2. Initialize a Directed Graph
    G = nx.DiGraph()

    # 3. Add Nodes with attributes
    for node in data['topology']['nodes']:
        G.add_node(
            node['id'], 
            name=node.get('name'), 
            type=node.get('type'),
            criticality=node.get('criticality'),
            role=node.get('role')
        )

    # 4. Add Edges
    for link in data['topology']['links']:
        G.add_edge(link['source'], link['target'])

    return G

def draw_graph(G):
    plt.figure(figsize=(12, 8))
    
    # Define layout (Spring layout helps separate clusters)
    pos = nx.spring_layout(G, k=0.5)

    # Color nodes by type (e.g., Frontend vs Database)
    color_map = []
    for node in G:
        ntype = G.nodes[node].get('type', 'Unknown')
        if ntype == 'Frontend':
            color_map.append('skyblue')
        elif ntype == 'Database':
            color_map.append('orange')
        else:
            color_map.append('lightgrey')

    # Draw nodes, edges, and labels
    nx.draw(G, pos, with_labels=True, node_color=color_map, 
            node_size=2000, font_size=8, arrowsize=20)
    
    plt.title("NCSRD Proxmox Testbed Topology (PETA View)")
    plt.show()

if __name__ == "__main__":
    topology_file = "ncsrd_topology_peta.json"
    graph = create_nx_graph(topology_file)
    
    # Print some stats
    print(f"Nodes: {graph.number_of_nodes()}")
    print(f"Edges: {graph.number_of_edges()}")
    
    # Draw it
    draw_graph(graph)
