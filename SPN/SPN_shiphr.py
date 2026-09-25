import random

# ============================================================
# S-BOX из шифра PRESENT
# Источник: Bogdanov et al., "PRESENT: An Ultra-Lightweight Block Cipher" (2007)
# ============================================================
S_BOX = {
    "0000": "1100", "0001": "0101", "0010": "0110", "0011": "1011",
    "0100": "1001", "0101": "0000", "0110": "1010", "0111": "1101",
    "1000": "0011", "1001": "1010", "1010": "0110", "1011": "1100",
    "1100": "0101", "1101": "1001", "1110": "0000", "1111": "0111",
}
INV_S_BOX = {v: k for k, v in S_BOX.items()}

BLOCK_SIZE = 64
NUM_ROUNDS = 10


# ============================================================
# Базовые операции
# ============================================================
def xor_bits(a, b):
    return "".join("0" if a[i] == b[i] else "1" for i in range(len(a)))


def rotl(bits, n):
    n = n % len(bits)
    return bits[n:] + bits[:n]


# ============================================================
# Key schedule: 10 подключей из ключа >= 128 бит
# ============================================================
def generate_subkeys(master_key, num_rounds=NUM_ROUNDS):
    if len(master_key) < 128:
        raise ValueError("Мастер-ключ должен быть не менее 128 бит.")

    L = master_key[:64]
    R = master_key[64:128]

    rest = master_key[128:]
    if rest:
        if len(rest) % 64 != 0:
            rest = rest.ljust((len(rest) // 64 + 1) * 64, "0")
        for i in range(0, len(rest), 64):
            chunk = rest[i:i + 64]
            if (i // 64) % 2 == 0:
                L = xor_bits(L, chunk)
            else:
                R = xor_bits(R, chunk)

    subkeys = []
    for r in range(1, num_rounds + 1):
        L = xor_bits(L, rotl(R, r))
        R = xor_bits(R, rotl(L, r))
        round_counter = format(r, "064b")
        subkey = xor_bits(xor_bits(L, R), round_counter)
        subkeys.append(subkey)
    return subkeys


# ============================================================
# Раундовые преобразования SPN
# ============================================================
def s_box(block):
    return "".join(S_BOX[block[i:i + 4]] for i in range(0, len(block), 4))


def inv_s_box(block):
    return "".join(INV_S_BOX[block[i:i + 4]] for i in range(0, len(block), 4))


def permutation(block):
    return block[-3:] + block[:-3]


def inv_permutation(block):
    return block[3:] + block[:3]


def encrypt_block(block, subkeys, verbose=False):
    current = block
    for r, subkey in enumerate(subkeys):
        if verbose and r == 0:
            print("\n--- РАУНД 1 (подробно) ---")
            print("Подключ:", subkey)
        current = xor_bits(current, subkey)
        if verbose and r == 0:
            print("После XOR:", current)
        if r != len(subkeys) - 1:
            current = s_box(current)
            if verbose and r == 0:
                print("После S-box:", current)
            current = permutation(current)
            if verbose and r == 0:
                print("После сдвига вправо на 3:", current)
    return current


def decrypt_block(block, subkeys, verbose=False):
    current = block
    reversed_subkeys = list(reversed(subkeys))
    for r, subkey in enumerate(reversed_subkeys):
        if verbose and r == 0:
            print("\n--- РАУНД 1 расшифрования (подробно) ---")
            print("Подключ:", subkey)
        if r != 0:
            current = inv_permutation(current)
            if verbose and r == 0:
                print("После обратного сдвига:", current)
            current = inv_s_box(current)
            if verbose and r == 0:
                print("После обратного S-box:", current)
        current = xor_bits(current, subkey)
        if verbose and r == 0:
            print("После XOR:", current)
    return current


# ============================================================
# Разбиение на блоки и утилиты hex
# ============================================================
def split_blocks(bits):
    blocks = []
    for i in range(0, len(bits), BLOCK_SIZE):
        b = bits[i:i + BLOCK_SIZE]
        if len(b) < BLOCK_SIZE:
            b = b.ljust(BLOCK_SIZE, "0")
        blocks.append(b)
    return blocks


def hex_to_bits(h):
    h = h.replace(" ", "").replace("\n", "").lower()
    if not h or any(c not in "0123456789abcdef" for c in h):
        raise ValueError("Некорректная hex-строка.")
    return "".join(format(int(c, 16), "04b") for c in h)


def bits_to_hex(b):
    if len(b) % 4 != 0:
        b = b.ljust((len(b) // 4 + 1) * 4, "0")
    return "".join(format(int(b[i:i + 4], 2), "x") for i in range(0, len(b), 4))


def random_iv():
    return "".join(random.choice("01") for _ in range(BLOCK_SIZE))


# ============================================================
# Режим ECB
# ============================================================
def ecb_encrypt(message, subkeys):
    out = ""
    for i, p in enumerate(split_blocks(message)):
        out += encrypt_block(p, subkeys, verbose=(i == 0))
    return out


def ecb_decrypt(ciphertext, subkeys):
    out = ""
    for i, c in enumerate(split_blocks(ciphertext)):
        out += decrypt_block(c, subkeys, verbose=(i == 0))
    return out


# ============================================================
# Режим PCBC
# ============================================================
def pcbc_encrypt(message, subkeys, iv):
    blocks = split_blocks(message)
    prev_c = iv
    prev_p = "0" * BLOCK_SIZE
    out = ""
    for i, p in enumerate(blocks):
        if i == 0:
            x = xor_bits(p, prev_c)
        else:
            x = xor_bits(xor_bits(p, prev_p), prev_c)
        c = encrypt_block(x, subkeys, verbose=(i == 0))
        out += c
        prev_c = c
        prev_p = p
    return out


def pcbc_decrypt(ciphertext, subkeys, iv):
    blocks = split_blocks(ciphertext)
    prev_c = iv
    prev_p = "0" * BLOCK_SIZE
    out = ""
    for i, c in enumerate(blocks):
        x = decrypt_block(c, subkeys, verbose=(i == 0))
        if i == 0:
            p = xor_bits(x, prev_c)
        else:
            p = xor_bits(xor_bits(x, prev_p), prev_c)
        out += p
        prev_c = c
        prev_p = p
    return out


# ============================================================
# Универсальные обёртки
# ============================================================
def encrypt_message(message, subkeys, mode="ECB", iv=None):
    if mode == "ECB":
        return ecb_encrypt(message, subkeys), None
    if mode == "PCBC":
        if iv is None:
            iv = random_iv()
        return pcbc_encrypt(message, subkeys, iv), iv
    raise ValueError("Неизвестный режим: " + mode)


def decrypt_message(ciphertext, subkeys, mode="ECB", iv=None):
    if mode == "ECB":
        return ecb_decrypt(ciphertext, subkeys)
    if mode == "PCBC":
        if iv is None:
            raise ValueError("Для PCBC нужен IV.")
        return pcbc_decrypt(ciphertext, subkeys, iv)
    raise ValueError("Неизвестный режим: " + mode)


# ============================================================
# Ввод и меню
# ============================================================
def input_hex_bits(prompt, min_bits, must_be_multiple_of=None):
    while True:
        v = input(prompt).replace(" ", "").replace("\n", "")
        if not v:
            print("Ошибка: пусто.")
            continue
        try:
            bits = hex_to_bits(v)
        except ValueError as e:
            print(f"Ошибка: {e}")
            continue
        if len(bits) < min_bits:
            print(f"Ошибка: нужно ≥ {min_bits} бит (сейчас {len(bits)}).")
            continue
        if must_be_multiple_of and len(bits) % must_be_multiple_of != 0:
            print(f"Ошибка: длина должна быть кратна {must_be_multiple_of} битам.")
            continue
        return bits


def choose_mode():
    while True:
        print("\nВыбор режима:")
        print("1. ECB")
        print("2. PCBC")
        m = input("Режим (1/2): ").strip()
        if m == "1":
            return "ECB"
        if m == "2":
            return "PCBC"
        print("Ошибка: введите 1 или 2.")


def main():
    while True:
        print("\n" + "=" * 60)
        print("     SPN + PRESENT S-Box")
        print("=" * 60)
        print("1. Зашифровать")
        print("2. Расшифровать")
        print("3. Выйти")
        choice = input("Выбор: ").strip()

        if choice == "1":
            mode = choose_mode()
            msg = input_hex_bits("Сообщение (hex, ≥ 64 символа = 256 бит):\n", 256)
            key = input_hex_bits("Ключ (hex, ≥ 32 символа = 128 бит, кратно 16):\n", 128, 64)
            subkeys = generate_subkeys(key)
            ct, iv = encrypt_message(msg, subkeys, mode=mode)
            print(f"\nРежим: {mode}")
            if iv:
                print("IV (hex):", bits_to_hex(iv))
            print("ШИФРОТЕКСТ HEX:", bits_to_hex(ct))
            print("ШИФРОТЕКСТ BIN:", ct)
            n_blocks = len(split_blocks(msg))
            print(f"Блоков: {n_blocks}, раундов на блок: {NUM_ROUNDS}, всего: {n_blocks * NUM_ROUNDS}")

        elif choice == "2":
            mode = choose_mode()
            ct = input_hex_bits("Шифротекст (hex):\n", 256)
            key = input_hex_bits("Ключ (hex, ≥ 32 символа, кратно 16):\n", 128, 64)
            subkeys = generate_subkeys(key)
            iv = None
            if mode == "PCBC":
                iv_hex = input("IV (hex, 16 символов):\n").strip()
                try:
                    iv = hex_to_bits(iv_hex)
                except ValueError as e:
                    print(f"Ошибка IV: {e}")
                    continue
                if len(iv) != BLOCK_SIZE:
                    print("Ошибка: IV должен быть 64 бита (16 hex).")
                    continue
            pt = decrypt_message(ct, subkeys, mode=mode, iv=iv)
            print(f"\nРежим: {mode}")
            print("РАСШИФРОВАНО HEX:", bits_to_hex(pt))
            print("РАСШИФРОВАНО BIN:", pt)

        elif choice == "3":
            print("Выход.")
            break


main()