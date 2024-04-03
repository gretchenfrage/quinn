import matplotlib.pyplot as plt
import json

def plot_results(filename):
    inputs = []
    latencies = [[] for _ in range(4)]  # Four lists to store each type of latency

    with open(filename, 'r') as file:
        for line in file:
            data = json.loads(line)
            inputs.append(data[0])
            for i, latency in enumerate(data[1:]):
                latencies[i].append(latency)

    fig, axs = plt.subplots(2, 1, figsize=(14, 16))  # Create two vertically stacked subplots
    labels = ["1-RTT start latency", "0-RTT start latency", "1-RTT end latency", "0-RTT end latency"]
    colors = ['blue', 'red', 'green', 'purple']
    
    # Start latency subplot
    axs[0].plot(inputs, latencies[0], marker='o', color=colors[0], label=labels[0])
    axs[0].plot(inputs, latencies[1], marker='o', color=colors[1], label=labels[1])
    axs[0].set_title('Start Latency')
    axs[0].set_xlabel('Response Size')
    axs[0].set_ylabel('Latency (ms)')
    axs[0].legend()
    axs[0].grid(True)
    
    # End latency subplot
    axs[1].plot(inputs, latencies[2], marker='o', color=colors[2], label=labels[2])
    axs[1].plot(inputs, latencies[3], marker='o', color=colors[3], label=labels[3])
    axs[1].set_title('End Latency')
    axs[1].set_xlabel('Response Size')
    axs[1].set_ylabel('Latency (ms)')
    axs[1].legend()
    axs[1].grid(True)

    plt.tight_layout()
    plt.show()

# After running the benchmark and saving the results
plot_results('results.jsonl')
