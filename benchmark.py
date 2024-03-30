import subprocess
import json

def run_benchmark(start, end, step):
    with open('results.jsonl', 'w') as file:
        for i in range(start, end + 1, step):
            print(f"i = {i}")
            command = f"python3 command.py {i}"
            process = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, text=True)
            output = process.stdout.strip()
            # Writing as JSON Lines
            file.write(json.dumps((i, float(output))) + '\n')
            file.flush()

# Example usage
start = 0  # Starting number
end = 10000  # End number
step = 100  # Step
run_benchmark(start, end, step)
