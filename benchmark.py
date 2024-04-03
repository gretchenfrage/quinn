import subprocess
import json
import time

def run_benchmark(start, end, step, iterations=10, sleep_interval=10):
    with open('results.jsonl', 'w') as file:
        for _ in range(iterations):
            for i in range(start, end + 1, step):
                process = subprocess.run(['python3', 'command.py', str(i)], capture_output=True, text=True)
                output = process.stdout.strip()
                latencies = json.loads(output)
                # Including iteration information might be helpful for data rearrangement in plotting
                result_line = json.dumps({"iteration": _, "input_size": i, "latencies": latencies}) + '\n'
                file.write(result_line)
                file.flush()
            time.sleep(sleep_interval)  # Sleep only after completing a full sweep of input sizes

# Adjusted starting parameters
start = 0  # Starting number
end = 10000  # End number
step = 100  # Step
run_benchmark(start, end, step)
