import asyncio
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EntropyCalculator:
    """Compute Shannon entropy for file samples."""
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0.0
        
        byte_freq = {}
        for byte in data:
            byte_freq[byte] = byte_freq.get(byte, 0) + 1
        
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_freq.values():
            p = count / data_len
            if p > 0:
                entropy -= p * (p.bit_length() - 1)
        
        import math
        entropy = 0.0
        for count in byte_freq.values():
            p = count / data_len
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    @staticmethod
    def calculate_file_entropy(file_path: str, sample_size: int = 4096) -> float:
        """Calculate entropy from file sample."""
        try:
            with open(file_path, "rb") as f:
                data = f.read(sample_size)
                return EntropyCalculator.calculate_entropy(data)
        except Exception as e:
            logger.debug(f"Entropy calc error: {e}")
            return 0.0


class InotifyWatcher:
    """Watch filesystem with inotify for ransomware patterns."""
    
    def __init__(self, watch_paths: List[str]):
        self.watch_paths = watch_paths
        self.rename_burst_threshold = 10
        self.suspicious_extensions = [
            ".encrypted", ".locked", ".crypt", ".locked",
            "DECRYPT_FILES.txt", "README_DECRYPT.txt"
        ]
    
    def check_rename_burst(self, events: List[Dict]) -> float:
        """Check for rename burst pattern."""
        rename_count = sum(1 for e in events if e.get("mask") in ["IN_MOVED_FROM", "IN_MOVED_TO"])
        
        if rename_count > self.rename_burst_threshold:
            return 0.50
        
        return 0.0
    
    def check_suspicious_filename(self, filename: str) -> float:
        """Check for suspicious filename pattern."""
        for ext in self.suspicious_extensions:
            if ext.lower() in filename.lower():
                return 0.65
        
        return 0.0


class ProcessScanner:
    """Scan /proc for PID → pod mapping."""
    
    @staticmethod
    async def scan_pids() -> Dict[int, Dict[str, str]]:
        """Scan /proc for process information."""
        import os
        
        pid_map = {}
        
        try:
            for pid_dir in os.listdir("/proc"):
                if not pid_dir.isdigit():
                    continue
                
                pid = int(pid_dir)
                
                try:
                    with open(f"/proc/{pid}/cgroup", "r") as f:
                        cgroup = f.read()
                        
                        if "kubepods" in cgroup:
                            parts = cgroup.strip().split("/")
                            
                            pod_name = ""
                            container_id = ""
                            
                            for i, part in enumerate(parts):
                                if part.startswith("pod"):
                                    pod_name = part.split("-")[1] if len(part.split("-")) > 1 else part
                                if part.startswith("containerd"):
                                    container_id = part
                            
                            pid_map[pid] = {
                                "pid": pid,
                                "pod": pod_name,
                                "container": container_id
                            }
                except (FileNotFoundError, PermissionError):
                    continue
        
        except Exception as e:
            logger.debug(f"PID scan error: {e}")
        
        return pid_map