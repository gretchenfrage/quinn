import subprocess
import json

def run_benchmark(start, end, step):
    with open('results.jsonl', 'w') as file:
        for i in range(start, end + 1, step):
            process = subprocess.run(['python3', 'command.py', str(i)], capture_output=True, text=True)
            output = process.stdout.strip()
            latencies = json.loads(output)
            # Writing input and latencies as JSON Lines
            file.write(json.dumps([i] + latencies) + '\n')
            file.flush()

# Example usage
start = 1  # Starting number
end = 10000  # End number
step = 100  # Step
run_benchmark(start, end, step)
