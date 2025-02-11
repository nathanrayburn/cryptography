import unidecode
import re
from statistics import mean


# IMPORTANT
# IL EST PRIMORDIAL DE NE PAS CHANGER LA SIGNATURE DES FONCTIONS
# SINON LES CORRECTIONS RISQUENT DE NE PAS FONCTIONNER CORRECTEMENT

def normalizeText(text):
    if not text:
        raise ValueError("Text cannot be empty")
    regex = re.compile("[^a-zA-Z]")
    return regex.sub('', unidecode.unidecode(text).upper())


def caesar_encrypt(text, key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    key: the shift which is a number

    Returns
    -------
    the ciphertext of <text> encrypted with Caesar under key <key>
    """

    filtered_text = normalizeText(text)
    ciphered_text = ""

    ascii_ref = ord('A')
    for letter in filtered_text:
        if letter.isalpha():
            ascii_letter = ord(letter)
            ciphered_text += chr((ascii_letter - ascii_ref + key) % 26 + ascii_ref)
        if letter.isspace():
            ciphered_text += letter
    return ciphered_text


def caesar_decrypt(text, key):
    """
    Parameters
    ----------
    text: the ciphertext to decrypt
    key: the shift which is a number

    Returns
    -------
    the plaintext of <text> decrypted with Caesar under key <key>
    """
    #
    plain_text = ""
    ciphered_text = normalizeText(text)
    ascii_ref = ord('A')
    for letter in ciphered_text:
        if letter.isalpha():
            ascii_letter = ord(letter)
            plain_text += chr((ascii_letter - ascii_ref - key) % 26 + ascii_ref)
        if letter.isspace():
            plain_text += letter

    return plain_text


def freq_analysis(text):
    """
    Parameters
    ----------
    text: the text to analyse

    Returns
    -------
    list
        the frequencies of every letter (a-z) in the text.

    """
    # Each value in the vector should be in the range [0, 1]
    freq_vector = [0] * 26
    filtered_text = normalizeText(text)
    ascii_ref = ord('A')
    total = 0
    for letter in filtered_text:
        if letter.isalpha():
            freq_vector[ord(letter) - ascii_ref] += 1
            total += 1

    result = [i / total for i in freq_vector]
    return result


def calculate_chi_squared(observed_freq, expected_freq):
    """
    Parameters
    ----------
    observed_freq: the observed frequencies
    expected_freq: the expected frequencies

    Returns
    -------
    the chi-squared statistic
    """
    ALPHA_SIZE = 26
    current_distance = 0
    for i in range(ALPHA_SIZE):
        Oi = observed_freq[i]
        Ei = expected_freq[i]
        current_distance += ((Oi - Ei) ** 2) / Ei
    return current_distance


def find_best_shift(text, ref_freq):
    """
    Parameters
    ----------
    text: the text to analyze
    ref_freq: the output of the freq_analysis function on a reference text

    Returns
    -------
    the shift that gives the smallest chi-squared statistic
    """
    ALPHA_SIZE = 26
    minimum_distance = float('inf')
    supposed_shift = 0
    text = normalizeText(text)
    for shift in range(ALPHA_SIZE):
        decrypted_text = caesar_decrypt(text, shift)
        freq_dist = freq_analysis(decrypted_text)
        current_distance = calculate_chi_squared(freq_dist, ref_freq)

        if current_distance < minimum_distance:
            minimum_distance = current_distance
            supposed_shift = shift

    return supposed_shift


def caesar_break(text, ref_freq):
    """
    Parameters
    ----------
    text: the ciphertext to break
    ref_freq: the output of the freq_analysis function on a reference text

    Returns
    -------
    a number corresponding to the caesar key
    """
    if not all(value != 0.0 for value in ref_freq):
        raise ValueError("Text and reference frequencies cannot be empty")

    text = normalizeText(text)

    if not text or not ref_freq:
        raise ValueError("Text and key cannot be empty")

    return find_best_shift(text, ref_freq)


def vigenere_encrypt(text, key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    key: the keyword used in Vigenere (e.g. "pass")

    Returns
    -------
    the ciphertext of <text> encrypted with Vigenere under key <key>
    """
    text = normalizeText(text)
    key = normalizeText(key)

    ciphered_text = ""
    ascii_ref = ord('A')
    key_length = len(key)
    if len(key) > len(text):
        key = key[:len(text)]
    for i, letter in enumerate(text):
        if letter.isalpha():
            ascii_letter = ord(letter)
            ascii_key = ord(key[i % key_length])
            ciphered_text += chr((ascii_letter - ascii_ref + ascii_key - ascii_ref) % 26 + ascii_ref)
        else:
            ciphered_text += letter
    return ciphered_text


def vigenere_decrypt(text, key):
    """
    Parameters
    ----------
    text: the ciphertext to decrypt
    key: the keyword used in Vigenere (e.g. "pass")

    Returns
    -------
    the plaintext of <text> decrypted with Vigenere under key <key>
    """

    text = normalizeText(text)
    key = normalizeText(key)

    deciphered_text = ""
    ascii_ref = ord('A')
    key_length = len(key)
    if len(key) > len(text):
        key = key[:len(text)]
    for i, letter in enumerate(text):
        if letter.isalpha():
            ascii_letter = ord(letter)
            ascii_key = ord(key[i % key_length])
            deciphered_text += chr((ascii_letter - ascii_ref - ascii_key + ascii_ref) % 26 + ascii_ref)
        else:
            deciphered_text += letter
    return deciphered_text


def coincidence_index(text):
    """
    Parameters
    ----------
    text: the text to analyse

    Returns
    -------
    the index of coincidence of the text
    """
    text = normalizeText(text)

    if len(text) < 2:
        return 0
    letter_counts = [text.count(chr(i)) for i in range(ord('A'), ord('Z') + 1)]

    N = sum(letter_counts)

    return (len(letter_counts) * sum(ni * (ni - 1) for ni in letter_counts)) / (N * (N - 1))


def find_key_length(text, max_key_length, ref_ic):
    text = normalizeText(text)
    min_ic = float("inf")
    supposed_length = 0
    for i in range(1, max_key_length + 1):
        ic = coincidence_index(text[::i])
        is_closer = (min_ic < ic and ic < ref_ic) or (min_ic < ic and ic < ref_ic)
        is_first = (supposed_length == 0)
        if (is_first or is_closer):
            supposed_length = i
            min_ic = ic
    return supposed_length


def vigenere_break(text, ref_freq, ref_ci):
    """
    Parameters
    ----------
    text: the ciphertext to break
    ref_freq: the output of the freq_analysis function on a reference text
    ref_ci: the output of the coincidence_index function on a reference text

    Returns
    -------
    the keyword corresponding to the encryption key used to obtain the ciphertext
    """
    text = normalizeText(text)
    key_length = find_key_length(text, 20, ref_ci)
    key = ""
    ascii_ref = ord('A')
    for i in range(key_length):
        shift = caesar_break(text[i::key_length], ref_freq)
        key += chr(shift % 26 + ascii_ref)
    return key


def vigenere_caesar_encrypt(text, vigenere_key, caesar_key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    vigenere_key: the keyword used in Vigenere (e.g. "pass")
    caesar_key: a number corresponding to the shift used to modify the vigenere key after each use.

    Returns
    -------
    the ciphertext of <text> encrypted with improved Vigenere under keys <key_vigenere> and <key_caesar>
    """
    text = normalizeText(text)
    vigenere_key = normalizeText(vigenere_key)
    ascii_ref = ord('A')
    ALPHA_SIZE = 26
    shift = 0
    ciphered_text = ""

    for i, char in enumerate(text):
        if char.isalpha():
            vig_key_index = i % len(vigenere_key)  # Adjust the index for the shift
            vig_char = ord(vigenere_key[vig_key_index]) - ascii_ref
            char_shift = (ord(char) - ascii_ref + vig_char + shift) % ALPHA_SIZE
            ciphered_text += chr(char_shift + ascii_ref)
            if (i + 1) % len(vigenere_key) == 0:
                shift = (shift + caesar_key) % ALPHA_SIZE

    return ciphered_text


def vigenere_caesar_decrypt(text, vigenere_key, caesar_key):
    """
    Parameters
    ----------
    text: the plaintext to decrypt
    vigenere_key: the keyword used in Vigenere (e.g. "pass")
    caesar_key: a number corresponding to the shift used to modify the vigenere key after each use.

    Returns
    -------
    the plaintext of <text> decrypted with improved Vigenere under keys <key_vigenere> and <key_caesar>
    """
    text = normalizeText(text)
    vigenere_key = normalizeText(vigenere_key)
    ascii_ref = ord('A')
    ALPHA_SIZE = 26
    shift = 0
    plain_text = ""
    for i, char in enumerate(text):
        if char.isalpha():
            vig_key_index = i % len(vigenere_key)
            vig_char = ord(vigenere_key[vig_key_index]) - ascii_ref
            char_shift = (ord(char) - ascii_ref - vig_char - shift + ALPHA_SIZE) % ALPHA_SIZE
            plain_text += chr(char_shift + ascii_ref)
            if (i + 1) % len(vigenere_key) == 0:
                shift = (shift + caesar_key) % ALPHA_SIZE
    return plain_text


def vigenere_caesar_break(text, ref_freq, ref_ci):
    """
    Parameters
    ----------
    text: the ciphertext to break
    ref_freq: the output of the freq_analysis function on a reference text
    ref_ci: the output of the coincidence_index function on a reference text

    Returns
    -------
    pair
        the keyword corresponding to the vigenere key used to obtain the ciphertext
        the number corresponding to the caesar key used to obtain the ciphertext
    """
    max_key_size = 20
    ALPHA_SIZE = 26
    closest_text = ""
    min_ic = float("inf")
    caesar_key = 0
    key_length = 0
    for length in range(1, max_key_size + 1):
        for shift in range(ALPHA_SIZE):
            final_text = ""
            for chunk_start_index in range(0, len(text), length):
                chunk = text[chunk_start_index:chunk_start_index + length]
                shift_key = (shift * (chunk_start_index // length)) % ALPHA_SIZE
                shifted_chunk = caesar_decrypt(chunk, shift_key)
                final_text += shifted_chunk

            ics = []
            for index in range(length):
                chunk = final_text[index::length]
                ics.append(coincidence_index(chunk))

            ic_mean = abs(mean(ics))
            is_closer = (abs(min_ic - ref_ci)) > (abs(ic_mean - ref_ci))
            is_first = (key_length == 0)
            if is_first or is_closer:
                closest_text = final_text
                min_ic = ic_mean
                caesar_key = shift
                key_length = length

    print(f"Min IC {min_ic}")
    print(f"Ic ref {ref_ci}")
    key_vigenere = ""
    ascii_ref = ord('A')
    for i in range(key_length):
        shift = caesar_break(closest_text[i::key_length], ref_freq)
        key_vigenere += chr(shift % 26 + ascii_ref)

    return key_vigenere, caesar_key


def detect_language(text):
    """Detect if the text is closer to English or French based on chi-squared statistic."""
    # Normalize the text to lowercase to simplify analysis.
    text = normalizeText(text)
    observed_freqs = freq_analysis(text)
    with open("text_fr.txt", 'r', encoding='utf-8') as file:
        french_text = file.read()
    with open("text_en.txt", 'r', encoding='utf-8') as file:
        english_text = file.read()

    english_profile = freq_analysis(english_text)
    french_profile = freq_analysis(french_text)

    chi_squared_english = calculate_chi_squared(observed_freqs, english_profile)
    chi_squared_french = calculate_chi_squared(observed_freqs, french_profile)

    if chi_squared_english < chi_squared_french:
        print('English')
    else:
        print('French')
def display_reference_frequencies(reference_frequencies):
    for i, freq in enumerate(reference_frequencies):
        letter = chr(i + ord('A'))
        print(f"{letter}: {freq}")

def main():
    print("Welcome to the Vigenere breaking tool")

    # Load reference data
    reference_text = 'text_fr.txt'
    with open(reference_text, 'r', encoding='utf-8') as file:
        french_text = file.read()
    print(f"Reference text file : {reference_text}")
    reference_frequencies = freq_analysis(french_text)
    reference_coincidence_index = coincidence_index(french_text)

    display_reference_frequencies(reference_frequencies)
    print(f"Reference CI {reference_coincidence_index}")

    # Test Caesar cipher
    print("\nTesting Caesar cipher...")
    plaintext = "The quick brown fox jumps over the lazy dog"
    caesar_key = 3
    caesar_ciphered_text = caesar_encrypt(plaintext, caesar_key)
    print(f"Ciphered text: {caesar_ciphered_text}")
    found_caesar_key = caesar_break(caesar_ciphered_text, reference_frequencies)
    print(f"Found key: {found_caesar_key}")
    caesar_decrypted_text = caesar_decrypt(caesar_ciphered_text, found_caesar_key)
    print(f"Decrypted text: {caesar_decrypted_text}")

    # Test Vigenere cipher
    print("\nTesting Vigenere cipher...")
    with open('vigenere.txt', 'r', encoding='utf-8') as file:
        vigenere_ciphered_text = file.read()
    vigenere_key = vigenere_break(vigenere_ciphered_text, reference_frequencies, reference_coincidence_index)
    print(f"Found key : {vigenere_key}")
    vigenere_decrypted_text = vigenere_decrypt(vigenere_ciphered_text, vigenere_key)
    print(f"Decrypted text: {vigenere_decrypted_text}")
    print("\nTesting an other vigenere")
    vigenere_plaintext = "Vigenere caesar  en cryptographie décide d’améliorer le chiffre de Vigenère. Son raisonnement est le suivant : le problème avec le chiffre de Vigenère est la réutilisation de la clef. Il décide donc, après chaque utilisation de la clef de la changer en la chiffrant avec le chiffre de César généralisé. Par exemple,si la clef initiale est la clef MAISON et la clef du chiffre de César est 2, les six premières lettres du texte clair sont chiffrées avec MAISON, les suivantes avec OCKUQP, puis QEMWSR"
    ciphered = vigenere_encrypt(vigenere_plaintext, "assbas")
    print(f"Ciphered text: {ciphered}")
    key = vigenere_break(ciphered, reference_frequencies, reference_coincidence_index)
    print(f"Found key Vigenere : {key}")
    print(f"Decrypted text: {vigenere_decrypt(ciphered, key)}")

    # Test Vigenere Caesar cipher
    print("\nTesting Vigenere Caesar cipher...")

    ciphered = vigenere_caesar_encrypt(vigenere_plaintext,"monster", 7)
    found_vigenere_key, found_caesar_key = vigenere_caesar_break(ciphered,reference_frequencies,reference_coincidence_index)
    print(f"Ciphered text : {ciphered}")
    print(f"Found Vigenere key: {found_vigenere_key}")
    print(f"Found Caesar key: {found_caesar_key}")
    print(f"Decrypted text : {vigenere_caesar_decrypt(ciphered,found_vigenere_key,found_caesar_key)}")

    # Test Vigenere Caesar cipher with external file
    print("\nTesting Vigenere Caesar cipher with external file...")
    with open('vigenereAmeliore.txt', 'r', encoding='utf-8') as file:
        external_vigenere_caesar_ciphered_text = file.read()
    found_vigenere_key, found_caesar_key = vigenere_caesar_break(external_vigenere_caesar_ciphered_text,
                                                                 reference_frequencies, reference_coincidence_index)
    print(f"Found Vigenere key: {found_vigenere_key}")
    print(f"Found Caesar key: {found_caesar_key}")
    external_vigenere_caesar_decrypted_text = vigenere_caesar_decrypt(external_vigenere_caesar_ciphered_text,
                                                                      found_vigenere_key, found_caesar_key)
    print(f"Decrypted text: {external_vigenere_caesar_decrypted_text}")

    # is text english or french

    detect_language("Ce text est enorme")
    detect_language("This text is huge")

if __name__ == "__main__":
    main()
