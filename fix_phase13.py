import os, json, glob

def load_vhosts_from_phase12(domain, output_dir):
    target_dir = os.path.join(output_dir, domain)
    if not os.path.exists(target_dir):
        return []
    # Find all phase_12_vhosts_*.json files
    files = glob.glob(os.path.join(target_dir, "phase_12_vhosts_*.json"))
    if not files:
        return []
    # Load each and pick the one with the most entries (non-empty)
    best_data = []
    best_file = None
    for f in files:
        with open(f, 'r') as fp:
            try:
                data = json.load(fp)
                if isinstance(data, list) and len(data) > len(best_data):
                    best_data = data
                    best_file = f
            except:
                pass
    if best_file:
        print(f"{Fore.CYAN}[*] Using vhosts file: {best_file} ({len(best_data)} hosts){Fore.RESET}")
    return best_data
