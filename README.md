## LWE Algorithm
Implementation of a simple LWE algorithms using numpy to demonstrate the underlying techniques used in LWE.

### Setup
Using the terminal, setup your Python virtual environment

Create a virtual environment `.venv`:
```
python3 -m venv .venv
```
Activate the virtual environment `.venv`:
```
source .venv/bin/activate
```
If you have done this correctly you will see something similar to at the start of your command line:
```
(.venv) jeremysavage@Jeremys-MacBook-Pro-2 research_proj
```
Now you can install the requirements from the `requirements.txt` using `pip`:
```
pip install -r requirements.txt
```

If you have already created your virtual environment, you will only need to perform the activation step.

### Usage
Once you have activated your virtual environment and installed the necessary requirements you will be able to run the algorithm.

```
python lwe.py
```

Below are detailed some questions that you may want to answer as part of your research project. 

### LWE Potential Extension Tasks

* **Use of Larger Parameters:** Increase the lattice dimension (n) and modulus (q) to make the algorithm more realistic and secure. For instance, try values like n=256 and q ≈ 2^12.
* **Error Distribution:** Replace the simple noise generation with a discrete Gaussian distribution for added security. Libraries like PyCrypto or custom implementations can help.
* **Expand the Algorithm to Encode Entire Words:** Currently the algorithm I have provided encodes a single bit (0 or 1), which isn’t very useful. Modify the algorithm to encode and decode multiple bits, so you can encode messages.
* **Key Compression:** Instead of storing the entire matrix A, explore techniques to represent it more efficiently, such as storing a seed or using structured matrices (e.g., Toeplitz or cyclic matrices).
* **Ciphertext Compression:** Investigate methods to reduce the size of the ciphertext by applying modular reductions or encoding techniques like polynomial ring representations.
* **Error Correction:** Add error-correcting codes (e.g., BCH or Reed-Solomon) to improve the robustness of decryption.
* **Ring-LWE or Module-LWE:** Experiment with these optimized variants by replacing random matrices with structured ones derived from polynomial rings. This can make your implementation faster and closer to real-world PQC algorithms.
* **Resistance to Side-Channel Attacks:** Research ways to prevent potential side-channel attacks, such as using constant-time arithmetic or introducing blinding techniques.


**Math-Focused Questions for LWE and Cryptography**

* How do matrix operations, such as multiplication, contribute to the encryption and decryption process in LWE?
* What is the role of the dot product in computing b = A⋅s + e mod q?
* Why is modular arithmetic critical for cryptography, and how does it ensure encryption remains within a bounded range?
* What happens mathematically when b is reduced modulo q?
* How does the distribution of noise e (e.g., uniform vs. Gaussian) affect the security of the system?
* What is the expected value of the noise vector e if sampled from {-1, 0, 1}, and why is this significant for decryption?
* Why must q (the modulus) be a prime or carefully chosen composite number?
* How does increasing n (dimension) or q (modulus) impact computational complexity?
* Compare the mathematical principles behind LWE and RSA encryption. How does modular exponentiation differ from matrix operations in cryptographic systems?
* How does the magnitude of noise (e) influence accuracy?