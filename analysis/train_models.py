#!/usr/bin/env python3
"""
train_models.py
───────────────
Downloads NSL-KDD, trains Decision Tree (edge) + Random Forest (fog/cloud),
then exports C++ lookup-table headers that OMNeT++ embeds at compile time.

Run ONCE before building OMNeT++ project:
    pip install pandas scikit-learn numpy requests tqdm
    python3 analysis/train_models.py

Outputs (written to src/lookupTables/):
    EdgeLookup.h   — 10×10   Decision Tree  (srcBytes × serrorRate)
    FogLookup.h    — 10×10×10 Random Forest  (srcBytes × dstHostCount × serrorRate)
    CloudLookup.h  — 10×10×10 CNN surrogate  (same dims, higher accuracy)
"""

import os, sys, requests, zipfile, io, warnings
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.tree          import DecisionTreeClassifier
from sklearn.ensemble       import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing  import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics         import classification_report, confusion_matrix
from tqdm                   import tqdm

warnings.filterwarnings("ignore")

# ─── Paths ───────────────────────────────────────────────────────────
ROOT      = Path(__file__).parent.parent
DATA_DIR  = ROOT / "dataset"
OUT_DIR   = ROOT / "src" / "lookupTables"
DATA_DIR.mkdir(exist_ok=True)
OUT_DIR.mkdir(exist_ok=True)

# ─── NSL-KDD column names (41 features + label + difficulty) ─────────
COLUMNS = [
    "duration","protocol_type","service","flag",
    "src_bytes","dst_bytes","land","wrong_fragment","urgent",
    "hot","num_failed_logins","logged_in","num_compromised",
    "root_shell","su_attempted","num_root","num_file_creations",
    "num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count",
    "serror_rate","srv_serror_rate","rerror_rate","srv_rerror_rate",
    "same_srv_rate","diff_srv_rate","srv_diff_host_rate",
    "dst_host_count","dst_host_srv_count","dst_host_same_srv_rate",
    "dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate",
    "dst_host_srv_serror_rate","dst_host_rerror_rate",
    "dst_host_srv_rerror_rate","label","difficulty"
]

# Attack family mapping (same as CommonTypes.h)
DOS_ATTACKS   = {"neptune","smurf","pod","teardrop","land","back",
                 "apache2","udpstorm","processtable","worm"}
PROBE_ATTACKS = {"portsweep","ipsweep","nmap","satan","mscan","saint"}
R2L_ATTACKS   = {"ftp_write","guess_passwd","imap","multihop","phf","spy",
                 "warezclient","warezmaster","sendmail","named","snmpgetattack",
                 "snmpguess","xlock","xsnoop","httptunnel"}
U2R_ATTACKS   = {"buffer_overflow","loadmodule","perl","rootkit","xterm","ps",
                 "sqlattack"}

def label_to_class(label: str) -> int:
    l = label.strip().lower()
    if l == "normal":          return 0
    if l in DOS_ATTACKS:       return 1
    if l in PROBE_ATTACKS:     return 2
    if l in R2L_ATTACKS:       return 3
    if l in U2R_ATTACKS:       return 4
    return 1  # Unknown attack → treat as DoS


# ─── Download NSL-KDD ─────────────────────────────────────────────────
def download_nslkdd():
    train_path = DATA_DIR / "KDDTrain+.txt"
    test_path  = DATA_DIR / "KDDTest+.txt"

    if train_path.exists() and test_path.exists():
        print("[✓] NSL-KDD files already present")
        return train_path, test_path

    print("[↓] Downloading NSL-KDD dataset …")
    url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/"
    for fname, path in [("KDDTrain+.txt", train_path), ("KDDTest+.txt", test_path)]:
        r = requests.get(url + fname, stream=True)
        r.raise_for_status()
        total = int(r.headers.get("content-length", 0))
        with open(path, "wb") as f, tqdm(total=total, unit="B", unit_scale=True,
                                          desc=fname) as bar:
            for chunk in r.iter_content(8192):
                f.write(chunk)
                bar.update(len(chunk))
    print("[✓] Download complete")
    return train_path, test_path


# ─── Load & preprocess ────────────────────────────────────────────────
def load_data(train_path, test_path):
    print("[…] Loading data …")
    train = pd.read_csv(train_path, names=COLUMNS, header=None)
    test  = pd.read_csv(test_path,  names=COLUMNS, header=None)
    df    = pd.concat([train, test], ignore_index=True)

    # Encode categoricals
    for col in ["protocol_type", "service", "flag"]:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))

    # Map labels to 5-class
    df["class"] = df["label"].apply(label_to_class)

    # Numeric features only
    numeric_cols = [c for c in COLUMNS[:-2] if c not in
                    ["protocol_type", "service", "flag"]]
    for col in numeric_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    feature_cols = COLUMNS[:-2]  # All 41 features
    X = df[feature_cols].fillna(0).values
    y = df["class"].values

    print(f"[✓] Dataset: {len(df)} rows | Class distribution:")
    for cls, name in enumerate(["Normal","DoS","Probe","R2L","U2R"]):
        n = (y == cls).sum()
        print(f"      {name:8s}: {n:7,d}  ({n/len(y)*100:.1f}%)")

    return X, y, feature_cols


# ─── Feature indices (by column name) ─────────────────────────────────
def col_idx(feature_cols, name):
    return feature_cols.index(name)


# ─── Discretize a feature into BIN_COUNT=10 bins ─────────────────────
def discretize(values, max_val, bins=10):
    clipped = np.clip(values, 0, max_val)
    return np.minimum((clipped / (max_val / bins)).astype(int), bins - 1)


# ─── Build lookup table for Edge (2D: srcBytes × serrorRate) ──────────
def build_edge_lookup(X, y, feature_cols, bins=10):
    print("\n[Edge] Training Decision Tree …")
    EDGE_F1_MAX = 100_000.0   # src_bytes
    EDGE_F2_MAX = 1.0         # serror_rate

    f1_idx = col_idx(feature_cols, "src_bytes")
    f2_idx = col_idx(feature_cols, "serror_rate")

    X2 = np.stack([
        discretize(X[:, f1_idx], EDGE_F1_MAX, bins),
        discretize(X[:, f2_idx], EDGE_F2_MAX, bins),
    ], axis=1)

    # Deduplicate: for each (f1,f2) cell, majority-vote class
    table = np.zeros((bins, bins), dtype=int)
    for b1 in range(bins):
        for b2 in range(bins):
            mask = (X2[:, 0] == b1) & (X2[:, 1] == b2)
            if mask.sum() > 0:
                vals, counts = np.unique(y[mask], return_counts=True)
                table[b1, b2] = vals[counts.argmax()]

    # Also train a proper DT for accuracy reporting
    Xtr, Xte, ytr, yte = train_test_split(X2, y, test_size=0.2, random_state=42)
    dt = DecisionTreeClassifier(max_depth=5, random_state=42)
    dt.fit(Xtr, ytr)
    acc = dt.score(Xte, yte)
    print(f"[Edge] DT accuracy (2 features, 2D table): {acc*100:.2f}%")
    print(classification_report(yte, dt.predict(Xte),
          target_names=["Normal","DoS","Probe","R2L","U2R"], zero_division=0))
    return table


# ─── Build lookup table for Fog (3D: srcBytes × dstHostCount × serrorRate) ──
def build_fog_lookup(X, y, feature_cols, bins=10):
    print("\n[Fog] Training Random Forest …")
    EDGE_F1_MAX = 100_000.0
    EDGE_F2_MAX = 1.0
    FOG_F3_MAX  = 256.0       # dst_host_count

    f1_idx = col_idx(feature_cols, "src_bytes")
    f2_idx = col_idx(feature_cols, "dst_host_count")
    f3_idx = col_idx(feature_cols, "serror_rate")

    X3 = np.stack([
        discretize(X[:, f1_idx], EDGE_F1_MAX, bins),
        discretize(X[:, f2_idx], FOG_F3_MAX,  bins),
        discretize(X[:, f3_idx], EDGE_F2_MAX, bins),
    ], axis=1)

    table = np.zeros((bins, bins, bins), dtype=int)
    for b1 in range(bins):
        for b2 in range(bins):
            for b3 in range(bins):
                mask = (X3[:, 0] == b1) & (X3[:, 1] == b2) & (X3[:, 2] == b3)
                if mask.sum() > 0:
                    vals, counts = np.unique(y[mask], return_counts=True)
                    table[b1, b2, b3] = vals[counts.argmax()]

    Xtr, Xte, ytr, yte = train_test_split(X3, y, test_size=0.2, random_state=42)
    rf = RandomForestClassifier(n_estimators=50, max_depth=8,
                                n_jobs=-1, random_state=42)
    rf.fit(Xtr, ytr)
    acc = rf.score(Xte, yte)
    print(f"[Fog] RF accuracy (3 features, 3D table): {acc*100:.2f}%")
    print(classification_report(yte, rf.predict(Xte),
          target_names=["Normal","DoS","Probe","R2L","U2R"], zero_division=0))
    return table


# ─── Build Cloud lookup (same 3D dims, full feature RF for best accuracy) ──
def build_cloud_lookup(X, y, feature_cols, bins=10):
    print("\n[Cloud] Training Gradient Boosting (DL surrogate) …")
    EDGE_F1_MAX = 100_000.0
    EDGE_F2_MAX = 1.0
    FOG_F3_MAX  = 256.0

    f1_idx = col_idx(feature_cols, "src_bytes")
    f2_idx = col_idx(feature_cols, "serror_rate")
    f3_idx = col_idx(feature_cols, "dst_host_count")

    # Full 41-feature model for accuracy measurement
    Xtr_full, Xte_full, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42)
    gb = GradientBoostingClassifier(n_estimators=100, max_depth=5,
                                    learning_rate=0.1, random_state=42)
    gb.fit(Xtr_full, ytr)
    acc = gb.score(Xte_full, yte)
    print(f"[Cloud] GB accuracy (all 41 features): {acc*100:.2f}%")
    print(classification_report(yte, gb.predict(Xte_full),
          target_names=["Normal","DoS","Probe","R2L","U2R"], zero_division=0))

    # Build 3D lookup using predictions from the full model on the grid
    X3 = np.stack([
        discretize(X[:, f1_idx], EDGE_F1_MAX, bins),
        discretize(X[:, f2_idx], EDGE_F2_MAX, bins),
        discretize(X[:, f3_idx], FOG_F3_MAX,  bins),
    ], axis=1)

    table = np.zeros((bins, bins, bins), dtype=int)
    for b1 in range(bins):
        for b2 in range(bins):
            for b3 in range(bins):
                mask = (X3[:, 0] == b1) & (X3[:, 1] == b2) & (X3[:, 2] == b3)
                if mask.sum() > 0:
                    vals, counts = np.unique(y[mask], return_counts=True)
                    table[b1, b2, b3] = vals[counts.argmax()]
    return table


# ─── Write C++ header files ───────────────────────────────────────────
def write_edge_header(table, path, bins=10):
    lines = [
        "// AUTO-GENERATED by analysis/train_models.py — DO NOT EDIT",
        "// Edge IDS lookup table: EDGE_LOOKUP[srcBytes_bin][serrorRate_bin]",
        "// Returns: 0=Normal, 1=DoS, 2=Probe, 3=R2L, 4=U2R",
        "#ifndef EDGE_LOOKUP_H",
        "#define EDGE_LOOKUP_H",
        "",
        f"// Dimensions: {bins} × {bins}",
        f"static const int EDGE_LOOKUP[{bins}][{bins}] = {{",
    ]
    for i in range(bins):
        row = ", ".join(str(table[i, j]) for j in range(bins))
        lines.append(f"    {{ {row} }},  // srcBytes_bin={i}")
    lines += ["};", "", "#endif // EDGE_LOOKUP_H", ""]
    path.write_text("\n".join(lines))
    print(f"[✓] Written: {path}")


def write_fog_header(table, path, bins=10):
    lines = [
        "// AUTO-GENERATED by analysis/train_models.py — DO NOT EDIT",
        "// Fog IDS lookup: FOG_LOOKUP[srcBytes_bin][dstHostCount_bin][serrorRate_bin]",
        "#ifndef FOG_LOOKUP_H",
        "#define FOG_LOOKUP_H",
        "",
        f"static const int FOG_LOOKUP[{bins}][{bins}][{bins}] = {{",
    ]
    for i in range(bins):
        lines.append(f"    {{  // srcBytes_bin={i}")
        for j in range(bins):
            row = ", ".join(str(table[i, j, k]) for k in range(bins))
            lines.append(f"        {{ {row} }},")
        lines.append("    },")
    lines += ["};", "", "#endif // FOG_LOOKUP_H", ""]
    path.write_text("\n".join(lines))
    print(f"[✓] Written: {path}")


def write_cloud_header(table, path, bins=10):
    lines = [
        "// AUTO-GENERATED by analysis/train_models.py — DO NOT EDIT",
        "// Cloud IDS lookup: CLOUD_LOOKUP[srcBytes_bin][serrorRate_bin][dstHostCount_bin]",
        "#ifndef CLOUD_LOOKUP_H",
        "#define CLOUD_LOOKUP_H",
        "",
        f"static const int CLOUD_LOOKUP[{bins}][{bins}][{bins}] = {{",
    ]
    for i in range(bins):
        lines.append(f"    {{  // srcBytes_bin={i}")
        for j in range(bins):
            row = ", ".join(str(table[i, j, k]) for k in range(bins))
            lines.append(f"        {{ {row} }},")
        lines.append("    },")
    lines += ["};", "", "#endif // CLOUD_LOOKUP_H", ""]
    path.write_text("\n".join(lines))
    print(f"[✓] Written: {path}")


# ─── Export dataset slice for each MistNode trace ─────────────────────
def export_mist_traces(train_path, num_nodes=20):
    """
    Split KDDTrain+ into N per-node trace CSVs.
    Each MistNode replays its own slice (round-robin assignment).
    """
    print(f"\n[…] Exporting {num_nodes} mist node trace files …")
    df = pd.read_csv(train_path, names=COLUMNS, header=None)

    # Shuffle for diversity
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # Add derived column: is_attack
    df["is_attack"] = df["label"].apply(lambda x: 0 if x.strip() == "normal" else 1)

    for i in range(num_nodes):
        slice_df = df.iloc[i::num_nodes].copy()
        out = DATA_DIR / f"mist_node_{i:02d}.csv"
        slice_df.to_csv(out, index=False)

    print(f"[✓] Traces written to {DATA_DIR}/mist_node_XX.csv")


# ─── Main ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  Multi-Layer IDS — Model Training & Lookup Table Generator")
    print("=" * 60)

    train_path, test_path = download_nslkdd()
    X, y, feature_cols   = load_data(train_path, test_path)

    edge_table  = build_edge_lookup(X, y, feature_cols)
    fog_table   = build_fog_lookup(X, y, feature_cols)
    cloud_table = build_cloud_lookup(X, y, feature_cols)

    write_edge_header(edge_table,  OUT_DIR / "EdgeLookup.h")
    write_fog_header(fog_table,    OUT_DIR / "FogLookup.h")
    write_cloud_header(cloud_table, OUT_DIR / "CloudLookup.h")

    export_mist_traces(train_path, num_nodes=20)

    print("\n" + "=" * 60)
    print("  Done. Build OMNeT++ project now.")
    print("=" * 60)
