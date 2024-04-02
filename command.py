import subprocess
import sys
import os

def generate_noise_file(size):
    with open('noise.bin', 'wb') as f:
        f.write(os.urandom(size))

def run_command_and_extract_number():
    cmd = [
        "target/release/examples/client",
        "https://localhost:4433/noise.bin",
        "https://localhost:4433/noise.bin",
        "--0rtt",
        "--suppress"
    ]
    process = subprocess.Popen(cmd, stderr=subprocess.PIPE, text=True)
    stderr = process.communicate()[1]

    # Extracting the number from the second occurrence of "first response byte at"
    search_phrase = "last response byte at"
    occurrences = [line for line in stderr.split('\n') if search_phrase in line]

    if len(occurrences) >= 2:
        second_occurrence = occurrences[1]
        number_str = second_occurrence.split(search_phrase)[-1].strip().split('ms')[0].strip()
        print(number_str)
    else:
        print("The phrase was not found twice in the output.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: script.py <number_of_bytes>")
        sys.exit(1)
    
    number_of_bytes = int(sys.argv[1])
    generate_noise_file(number_of_bytes)
    run_command_and_extract_number()
