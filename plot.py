import matplotlib.pyplot as plt
import json

def plot_results(filename):
    inputs = []
    outputs = []

    with open(filename, 'r') as file:
        for line in file:
            input, output = json.loads(line)
            inputs.append(input)
            outputs.append(output)

    plt.figure(figsize=(10, 6))
    plt.plot(inputs, outputs, marker='o')
    plt.xlabel('Response Size')
    plt.ylabel('Latency')
    plt.title('0-RTT benchmark')
    plt.grid(True)
    plt.show()

# After running the benchmark and saving the results
plot_results('results.jsonl')
