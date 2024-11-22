import numpy as np
from typing import Tuple


# Helper Function
def reduce_mod_q(vector: np.int64 | np.ndarray, modulus_q: int) -> np.ndarray | np.int64:
    """
    Ensure all entries in the vector are reduced modulo q.

    Args:
        vector: The input number or array to reduce modulo q.
        modulus_q: The modulus value.

    Returns:
        The vector with all elements reduced modulo q.
    """
    return vector % modulus_q


# Key Generation
def generate_lwe_public_key(
    secret_key: np.ndarray,
    modulus_q: int,
    num_samples: int = 10
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generate public key pairs (A, b) based on the secret key.

    Args:
        secret_key: The private key vector.
        modulus_q: The modulus for arithmetic operations.
        num_samples: Number of equations to generate.

    Returns:
        A tuple containing:
            - A: The public matrix (lattice basis).
            - b: The public vector with added noise.
    """
    public_matrix: np.ndarray = np.random.randint(0, modulus_q,
                                                  (num_samples, lattice_dimension))  # Random lattice basis
    noise_vector: np.ndarray = np.random.randint(-1, 2, num_samples)  # Small random noise (e.g., -1, 0, 1)

    # Compute the noisy vector: b = (A * secret_key + error) mod q
    # Here, `@` computes the matrix-vector product: public_matrix @ secret_key
    public_vector: np.ndarray = reduce_mod_q(public_matrix @ secret_key + noise_vector, modulus_q)

    return public_matrix, public_vector


# Encryption
def lwe_encrypt(
    public_key: Tuple[np.ndarray, np.ndarray],
    modulus_q: int,
    message_bit: int
) -> Tuple[np.ndarray, np.int64]:
    """
    Encrypt a single message bit (0 or 1) using the public key.

    Args:
        public_key: A tuple of (A, b), the public key.
        modulus_q: The modulus for arithmetic operations.
        message_bit: The bit to encrypt (0 or 1).

    Returns:
        A tuple containing:
            - u: The masked lattice vector.
            - v: The encrypted value of the message.
    """
    public_matrix, public_vector = public_key
    num_samples = public_matrix.shape[0]

    # Select a random subset of rows using a binary vector (s)
    selection_vector: np.ndarray = np.random.randint(0, 2, num_samples)  # Random binary vector (selector)

    # Compute the "mask" vector u
    # Here, `@` computes the matrix-vector product: selection_vector @ public_matrix
    masked_vector: np.ndarray = reduce_mod_q(selection_vector @ public_matrix, modulus_q)

    # Add noise and embed the message into v
    noise_value: int = np.random.randint(-1, 2)  # Small random noise
    encrypted_value: np.int64 = reduce_mod_q(
        selection_vector @ public_vector + noise_value + (modulus_q // 2) * message_bit,
        modulus_q
    )

    return masked_vector, encrypted_value


# Decryption
def lwe_decrypt(
    secret_key: np.ndarray,
    modulus_q: int,
    ciphertext: Tuple[np.ndarray, np.int64]
) -> int:
    """
    Decrypt the ciphertext to recover the original message bit.

    Args:
        secret_key: The private key vector.
        modulus_q: The modulus for arithmetic operations.
        ciphertext: A tuple containing (u, v), the ciphertext.

    Returns:
        The decrypted message bit (0 or 1).
    """
    masked_vector, encrypted_value = ciphertext

    # Compute the inner (dot) product between the secret key and u
    # Here, `@` computes the dot product: masked_vector @ secret_key
    decoded_value: np.int64 = reduce_mod_q(encrypted_value - masked_vector @ secret_key, modulus_q)

    # Decode the message: Check if the result is closer to 0 or q/2
    return int(decoded_value > modulus_q // 4 and decoded_value < 3 * modulus_q // 4)


# Example Usage
if __name__ == "__main__":
    # Parameters (small for simplicity, not secure in real applications)
    lattice_dimension: int = 5  # Dimension of the lattice (number of variables)
    modulus_q: int = 23  # Modulus for arithmetic operations
    secret_key: np.ndarray = np.random.randint(0, modulus_q, lattice_dimension)  # Random secret key (vector)

    # Generate keys
    public_matrix, public_vector = generate_lwe_public_key(secret_key, modulus_q)
    public_key = (public_matrix, public_vector)

    # Encrypt a message
    message_bit: int = 1  # Message to encrypt (either 0 or 1)
    ciphertext = lwe_encrypt(public_key, modulus_q, message_bit)
    print("Ciphertext:", ciphertext)

    # Decrypt the message
    decrypted_message: int = lwe_decrypt(secret_key, modulus_q, ciphertext)
    print("Decrypted Message:", decrypted_message)
