import hashlib
import requests
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import os
import random
import struct
from math import ceil
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import subprocess
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from bitcoinrpc.authproxy import AuthServiceProxy

def my_api(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        # process data and return a response
        response_data = {'result': 'success'}
        return JsonResponse(response_data)
    else:
        return JsonResponse({'error': 'Method not allowed'}, status=405)


def get_block_data(block_height, rpc_user, rpc_password, rpc_host='127.0.0.1', rpc_port=8332):
    try:
        url = f'http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}'
        rpc_connection = AuthServiceProxy(url)

        block_hash = rpc_connection.getblockhash(block_height)
        block = rpc_connection.getblock(block_hash)

        print(f"Connected to Bitcoin node successfully. Fetched data for block height {block_height}.")

        return block['hash'], block['nonce'], block['merkleroot']
    except Exception as e:
        print(f"Failed to connect to Bitcoin node: {e}")
        raise

def generate_seed(block_height, rpc_user, rpc_password, rpc_host='127.0.0.1', rpc_port=8332):
    block_hash, nonce, merkle_root = get_block_data(block_height, rpc_user, rpc_password, rpc_host, rpc_port)
    combined_data = f"{block_hash}{nonce}{merkle_root}"
    sha256 = hashlib.sha256()
    sha256.update(combined_data.encode('utf-8'))
    seed = sha256.digest()
    return seed

def generate_random_numbers(seed, count):
    backend = default_backend()
    salt = os.urandom(16)  # Generate a random salt
 
    random_numbers = []

    # The maximum number of random numbers that can be derived in one go
    max_derivable_numbers = (255 * 32) // 4
   # iterations = count // max_derivable_numbers + 1
    iterations = ceil(count / max_derivable_numbers)
    for i in range(iterations):
        info = b"Bitcoin Entropy Random Numbers" + i.to_bytes(1, 'big')
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=min(max_derivable_numbers * 4, (count - len(random_numbers)) * 4),
            salt=salt,
            info=info,
            backend=backend,
        )
        random_bytes = hkdf.derive(seed)
   #     derived_numbers = [int.from_bytes(random_bytes[i:i + 4], 'big') / (2**32 - 1) for i in range(0, len(random_bytes), 4)]
   #     derived_numbers = [(int.from_bytes(random_bytes[i:i + 4], 'big') / (2**32 - 1)) * 200 - 100 for i in range(0, len(random_bytes), 4)]
        derived_numbers = [(int.from_bytes(random_bytes[i:i + 4], 'big') / (2**32 - 1)) * 2 - 1 for i in range(0, len(random_bytes), 4)]

        random_numbers.extend(derived_numbers)

    return random_numbers[:count]


def scatter_and_histogram_plot(random_numbers_x, random_numbers_y, plot_index):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4), num=plot_index)

    # Scatter plot
    ax1.scatter(random_numbers_x, random_numbers_y, s=10, alpha=0.6, edgecolor='k')
    ax1.set_xlabel('Random Number X')
    ax1.set_ylabel('Random Number Y')
    ax1.set_title('Scatter Plot of Random Points')

    # Histogram plot
    ax2.hist(random_numbers_x + random_numbers_y, bins=50, alpha=0.6)
    ax2.set_xlabel('Random Number Value')
    ax2.set_ylabel('Frequency')
    ax2.set_title('Histogram of Random Numbers')

    plt.tight_layout()
    plt.show(block=False)
    

def write_binary_file(filename, random_numbers):
    with open(filename, 'wb') as file:
        for number in random_numbers:
            packed_number = struct.pack('f', number)
            file.write(packed_number)

def convert_to_text_file(input_file, output_file, bits_per_row=32):
    with open(input_file, 'rb') as infile, open(output_file, 'w') as outfile:
        binary_data = infile.read()
        binary_digits = ''.join('{:08b}'.format(byte) for byte in binary_data)

        for i in range(0, len(binary_digits), bits_per_row):
            line = binary_digits[i:i + bits_per_row]
            outfile.write(line)
            if i + bits_per_row < len(binary_digits):
                outfile.write('\n')

def combine_text_files(input_files, output_file, bits_per_row=32, total_bits=None):
    written_bits = 0
    with open(output_file, 'w') as outfile:
        for input_file in input_files:
            with open(input_file, 'r') as infile:
                for line in infile:
                    if total_bits is None or written_bits < total_bits:
                        outfile.write(line)
                        written_bits += bits_per_row
                    else:
                        break

def main():
    rpc_user = "rpc_user"
    rpc_password = "rpc_password"
    rpc_host = "127.0.0.1"  # or the IP address of your Bitcoin node
    rpc_port = 8332

    # Fetch the latest block height
    url = f'http://{rpc_user}:{rpc_password}@{rpc_host}:{rpc_port}'
    rpc_connection = AuthServiceProxy(url)
    latest_block_height = rpc_connection.getblockcount()
    print(f"Latest block height: {latest_block_height}")
    
    block_height = latest_block_height  # Example block height
    num_random_numbers = 1000000 // 32  # Each random number contains 32 bits
    
    # Calculate the seed using the single block
    seed = generate_seed(block_height, rpc_user, rpc_password, rpc_host, rpc_port)

    # Generate the random numbers
    random_numbers_x = generate_random_numbers(seed, num_random_numbers)
    random_numbers_y = generate_random_numbers(seed, num_random_numbers)

    # Print the number of generated random numbers
    print(f"Generated {len(random_numbers_x)} random numbers for x and {len(random_numbers_y)} random numbers for y.")

    # Save random_numbers_x and random_numbers_y to a file
    with open("random_numbers_xy.txt", "w") as f:
        for x, y in zip(random_numbers_x, random_numbers_y):
            f.write(f"{x} {y}\n")


    current_dir = os.path.abspath(os.path.dirname(__file__))
    random_numbers_x_bin = os.path.join(current_dir, 'random_numbers_x.bin')
    random_numbers_y_bin = os.path.join(current_dir, 'random_numbers_y.bin')
    random_numbers_x_txt = os.path.join(current_dir, 'random_numbers_x.txt')
    random_numbers_y_txt = os.path.join(current_dir, 'random_numbers_y.txt')
    random_numbers_combined_txt = os.path.join(current_dir, 'random_numbers_combined.txt')

    # Write random_numbers_x and random_numbers_y to binary files
    write_binary_file(random_numbers_x_bin, random_numbers_x)
    write_binary_file(random_numbers_y_bin, random_numbers_y)

    # Convert binary files to text files with binary digits
    convert_to_text_file(random_numbers_x_bin, random_numbers_x_txt)
    convert_to_text_file(random_numbers_y_bin, random_numbers_y_txt)

    # Combine the output text files into a single file
    combine_text_files([random_numbers_x_txt, random_numbers_y_txt], random_numbers_combined_txt)

if __name__ == "__main__":
    main()

