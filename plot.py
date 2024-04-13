import matplotlib.pyplot as plt
import json
from collections import defaultdict

def plot_results(filename):
    latencies_by_input = defaultdict(lambda: defaultdict(list))  # input_size -> latency type -> values

    with open(filename, 'r') as file:
        for line in file:
            data = json.loads(line)
            input_size = data["input_size"]
            for i, latency in enumerate(data["latencies"]):
                latencies_by_input[input_size][i].append(latency)

    # Determine global min and max for y-axis range
    all_latencies = [latency for latencies in latencies_by_input.values() for latency_list in latencies.values() for latency in latency_list]
    y_min, y_max = min(all_latencies), max(all_latencies)

    fig, axs = plt.subplots(2, 2, figsize=(12, 12))  # 2x2 grid
    axs = axs.flatten()  # Flatten to iterate easily
    labels = ["1-RTT start latency", "0-RTT start latency", "1-RTT end latency", "0-RTT end latency"]
    colors = ['blue', 'red', 'green', 'purple']

    for i, (label, color) in enumerate(zip(labels, colors)):
        inputs = sorted(latencies_by_input.keys())
        latencies = [latencies_by_input[input_size][i][0] for input_size in inputs if latencies_by_input[input_size][i]]
        axs[i].plot(inputs, latencies, marker='o', color=color, label=label)
        axs[i].set_title(label)
        axs[i].set_xlabel('Response Size')
        axs[i].set_ylabel('Latency (ms)')
        axs[i].set_ylim([y_min, y_max])  # Set common y-axis range
        axs[i].grid(True)
        axs[i].legend()

    plt.tight_layout()
    plt.show()

# After running the benchmark and saving the results
plot_results('results.jsonl')
