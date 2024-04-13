import subprocess
import sys
import os
import json

def generate_noise_file(size):
    with open('noise.bin', 'wb') as f:
        f.write(os.urandom(size))

def run_command_and_extract_latencies():
    cmd = [
        "target/release/examples/client",
        "https://localhost:4433/noise.bin",
        "https://localhost:4433/noise.bin",
        "--0rtt",
        "--suppress"
    ]
    process = subprocess.Popen(cmd, stderr=subprocess.PIPE, text=True)
    stderr = process.communicate()[1]

    latencies = {"1-RTT start latency": None, "1-RTT end latency": None,
                 "0-RTT start latency": None, "0-RTT end latency": None}
    for line in stderr.split('\n'):
        if "first response byte at" in line:
            if latencies["1-RTT start latency"] is None:
                latencies["1-RTT start latency"] = float(line.split()[-1].split('ms')[0].strip())
            else:
                latencies["0-RTT start latency"] = float(line.split()[-1].split('ms')[0].strip())
        elif "last response byte at" in line:
            if latencies["1-RTT end latency"] is None:
                latencies["1-RTT end latency"] = float(line.split()[-1].split('ms')[0].strip())
            else:
                latencies["0-RTT end latency"] = float(line.split()[-1].split('ms')[0].strip())

    print(json.dumps(list(latencies.values())))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: command.py <number_of_bytes>")
        sys.exit(1)
    
    number_of_bytes = int(sys.argv[1])
    generate_noise_file(number_of_bytes)
    run_command_and_extract_latencies()
