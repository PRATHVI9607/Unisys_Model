#!/usr/bin/env python3 
"""kernel_monitor.py — reads eBPF stdout, computes features, publishes to Redis""" 
import sys, time, re, math, json, os 
import psutil 
import redis 
from collections import defaultdict, deque 
 
REDIS_HOST = 'localhost' 
REDIS_PORT = 6379 
CHANNEL    = 'kubeheal:kernel_events' 
WINDOW_SEC = 5 
 
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True) 
 
# Per-window counters 
stats = defaultdict(lambda: {'writes':0,'renames':0,'deletes':0,'opens':0}) 
renamed_files = [] 
deleted_files = [] 
window_start  = time.time() 
 
RENAME_RE = re.compile(r'^RENAME\|(\d+)\|(\S+)\|(.+)\|(.+)$') 
DELETE_RE = re.compile(r'^DELETE\|(\d+)\|(\S+)\|(.+)$') 
STATS_RE  = re.compile(r'^@writes\[(\d+),\s*(\S+)\]:\s*(\d+)$') 
 
def compute_entropy(filepath, read_tail=8192): 
    """Compute Shannon entropy from file tail (last 8 KB)""" 
    try: 
        with open(filepath, 'rb') as f: 
            f.seek(max(0, os.path.getsize(filepath) - read_tail)) 
            data = f.read(read_tail) 
        if not data: return 0.0 
        freq = defaultdict(int) 
        for b in data: freq[b] += 1 
        total = len(data) 
        return -sum((c/total)*math.log2(c/total) for c in freq.values()) 
    except Exception: 
        return 0.0 
 
def get_ext_change(old_path, new_path): 
    old_ext = os.path.splitext(old_path)[1].lower() 
    new_ext = os.path.splitext(new_path)[1].lower() 
    suspicious = ['.enc','.locked','.crypt','.ransom','.cry','.ryk','.wncry'] 
    return 1 if new_ext in suspicious else 0 
 
def flush_window(): 
    global stats, renamed_files, deleted_files, window_start 
    now    = time.time() 
    dt     = max(now - window_start, 1) 
 
    total_writes  = sum(v['writes']  for v in stats.values()) 
    total_renames = sum(v['renames'] for v in stats.values()) 
    total_deletes = sum(v['deletes'] for v in stats.values()) 
    total_ops     = max(total_writes + total_renames + total_deletes, 1) 
 
    # Entropy: sample recently-renamed files 
    entropies = [compute_entropy(f[1]) for f in renamed_files[:10]] 
    entropy_mean  = sum(entropies)/len(entropies) if entropies else 0.0 
    entropy_delta = entropy_mean - 5.5   # baseline normal entropy 
 
    ext_changes = sum(get_ext_change(f[0],f[1]) for f in renamed_files) 
 
    cpu   = psutil.cpu_percent(interval=None) 
    pids  = len(stats) 
 
    feature_vector = { 
        'timestamp':      now, 
        'writes_per_sec': round(total_writes / dt, 2), 
        'rename_rate':    round(total_renames / total_ops, 4), 
        'delete_rate':    round(total_deletes / total_ops, 4), 
        'entropy_mean':   round(entropy_mean, 4), 
        'entropy_delta':  round(entropy_delta, 4), 
        'file_churn':     round((total_writes+total_renames+total_deletes)/max(total_writes,1), 4), 
        'ext_change_ratio': round(ext_changes / max(total_renames,1), 4), 
        'pid_count':      pids, 
        'cpu_usage':      cpu, 
        'open_files_count': sum(v['opens'] for v in stats.values()), 
    } 
 
    print(json.dumps(feature_vector), flush=True) 
    r.publish(CHANNEL, json.dumps(feature_vector)) 
 
    # Reset 
    stats.clear(); renamed_files.clear(); deleted_files.clear() 
    window_start = now 
 
print('[KernelMonitor] Started, publishing to Redis channel:', CHANNEL) 
for line in sys.stdin: 
    line = line.strip() 
    m = RENAME_RE.match(line) 
    if m: 
        pid, comm, old, new = m.groups() 
        stats[pid]['renames'] += 1 
        renamed_files.append((old, new)) 
 
    m = DELETE_RE.match(line) 
    if m: 
        pid, comm, path = m.groups() 
        stats[pid]['deletes'] += 1 
        deleted_files.append(path) 
 
    m = STATS_RE.match(line) 
    if m: 
        pid, comm, cnt = m.groups() 
        stats[pid]['writes'] += int(cnt) 
 
    if time.time() - window_start >= WINDOW_SEC: 
        flush_window() 
