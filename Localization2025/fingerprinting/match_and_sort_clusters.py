import json

# Load configuration
def load_config(filename="config.json"):
    with open(filename, "r") as file:
        return json.load(file)
config = load_config()

# Accessing values from the config
#required_matches_config = config["fingerprint"]["required_matches"]
#time_window = config["fingerprint"]["time_window"]  # Time window in seconds   

from difflib import SequenceMatcher

def compute_similarity_score(old, new):
    def jaccard_similarity(list1, list2):
        set1, set2 = set(list1), set(list2)
        if not set1 and not set2:
            return 1.0
        return len(set1 & set2) / len(set1 | set2)

    mac_similarity = jaccard_similarity(old["MAC"], new["MAC"])
    ssid_similarity = jaccard_similarity(old["SSID"], new["SSID"])

    feature_similarity = SequenceMatcher(None, old["Features"], new["Features"]).ratio()

    # Weighted sum (you can tweak weights here)
    score = (
        0.4 * mac_similarity +
        0.4 * ssid_similarity +
        0.2 * feature_similarity
    )
    return score


def match_and_sort_fuzzy(previous, current, threshold=0.7):
    matched = []
    unmatched = current.copy()
    used_new = set()

    for old in previous:
        best_match = None
        best_score = 0.0

        for i, new in enumerate(unmatched):
            if i in used_new:
                continue
            score = compute_similarity_score(old, new)
            if score > best_score:
                best_score = score
                best_match = (i, new)

        if best_match and best_score >= threshold:
            i, match = best_match
            match["Device_Name"] = old["Device_Name"]
            matched.append(match)
            used_new.add(i)

    # Add unmatched with new names
    next_id = len(matched) + 1
    for i, new in enumerate(unmatched):
        if i in used_new:
            continue
        new["Device_Name"] = f"Device {next_id}"
        matched.append(new)
        next_id += 1

    return matched
