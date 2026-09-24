import random

# ============================================================
# S-Box из шифра PRESENT (Bogdanov et al., 2007)
# ============================================================
S_BOX = {
    "0000": "1100", "0001": "0101", "0010": "0110", "0011": "1011",
    "0100": "1001", "0101": "0000", "0110": "1010", "0111": "1101",
    "1000": "0011", "1001": "1110", "1010": "1111", "1011": "1000",
    "1100": "0100", "1101": "0111", "1110": "0001", "1111": "0010",
}
INV_S_BOX = {v: k for k, v in S_BOX.items()}
assert len(INV_S_BOX) == 16, "S-box не биекция!"

BLOCK_SIZE = 64
NUM_ROUNDS = 10
INPUT_FORMAT = "BIN"


# ============================================================
# Паддинг по стандарту ISO 7816-4 (OneAndZeroes)
# ============================================================
def pad_iso7816(data_bits):
    """
    Добавляет '1', затем '0' до кратности BLOCK_SIZE.
    Всегда добавляет минимум один бит (даже если длина уже кратна).
    """
    padded = data_bits + "1"
    remainder = len(padded) % BLOCK_SIZE
    if remainder != 0:
        padded += "0" * (BLOCK_SIZE - remainder)
    return padded


def unpad_iso7816(padded_bits):
    """
    Убирает '0' с конца до последнего '1', затем удаляет этот '1'.
    """
    idx = padded_bits.rfind("1")
    if idx == -1:
        raise ValueError("Некорректный паддинг: не найден разделитель '1'.")
    return padded_bits[:idx]


# ============================================================
# Базовые операции
# ============================================================
def xor_bits(a, b):
    return "".join("0" if a[i] == b[i] else "1" for i in range(len(a)))


def rotl(bits, n):
    n = n % len(bits)
    return bits[n:] + bits[:n]


# ============================================================
# Генерация подключей: 10 штук по 64 бита
# ============================================================
def generate_subkeys(master_key, num_rounds=NUM_ROUNDS):
    if len(master_key) < 128:
        raise ValueError("Мастер-ключ должен быть не менее 128 бит.")

    L, R = master_key[:64], master_key[64:128]

    # Остаток ключа (если больше 128 бит) XOR-им по кругу
    rest = master_key[128:]
    if rest:
        if len(rest) % 64 != 0:
            rest = rest.ljust((len(rest) // 64 + 1) * 64, "0")
        for i in range(0, len(rest), 64):
            chunk = rest[i:i+64]
            if (i // 64) % 2 == 0:
                L = xor_bits(L, chunk)
            else:
                R = xor_bits(R, chunk)

    subkeys = []
    for r in range(1, num_rounds + 1):
        L = xor_bits(L, rotl(R, r))
        R = xor_bits(R, rotl(L, r))
        subkeys.append(xor_bits(xor_bits(L, R), format(r, "064b")))
    return subkeys


# ============================================================
# Раундовые преобразования
# ============================================================
def s_box(b):
    return "".join(S_BOX[b[i:i+4]] for i in range(0, len(b), 4))


def inv_s_box(b):
    return "".join(INV_S_BOX[b[i:i+4]] for i in range(0, len(b), 4))


def permutation(b):
    return b[-3:] + b[:-3]      # сдвиг вправо на 3


def inv_permutation(b):
    return b[3:] + b[:3]        # сдвиг влево на 3


def encrypt_block(block, subkeys):
    cur = block
    for r, k in enumerate(subkeys):
        cur = xor_bits(cur, k)
        if r != len(subkeys) - 1:
            cur = permutation(s_box(cur))
    return cur


def decrypt_block(block, subkeys):
    cur = block
    for r, k in enumerate(reversed(subkeys)):
        if r != 0:
            cur = inv_s_box(inv_permutation(cur))
        cur = xor_bits(cur, k)
    return cur


# ============================================================
# Разбиение на блоки
# ============================================================
def split_blocks(bits):
    return [bits[i:i+BLOCK_SIZE] for i in range(0, len(bits), BLOCK_SIZE)]


# ============================================================
# Режим PCBC с паддингом
# ============================================================
def pcbc_encrypt(message, subkeys, iv):
    padded = pad_iso7816(message)          # 1. Паддинг
    blocks = split_blocks(padded)          # 2. Разбиение

    prev_c, prev_p = iv, "0" * BLOCK_SIZE
    ct = ""
    for i, p in enumerate(blocks):
        x = xor_bits(p, prev_c) if i == 0 else xor_bits(xor_bits(p, prev_p), prev_c)
        c = encrypt_block(x, subkeys)
        ct += c
        prev_c, prev_p = c, p
    return ct


def pcbc_decrypt(ct, subkeys, iv):
    blocks = split_blocks(ct)
    prev_c, prev_p = iv, "0" * BLOCK_SIZE
    pt_padded = ""
    for i, c in enumerate(blocks):
        x = decrypt_block(c, subkeys)
        p = xor_bits(x, prev_c) if i == 0 else xor_bits(xor_bits(x, prev_p), prev_c)
        pt_padded += p
        prev_c, prev_p = c, p
    return unpad_iso7816(pt_padded)        # Убираем паддинг


# ============================================================
# Hex <-> биты
# ============================================================
def hex_to_bits(h):
    h = h.replace(" ", "").lower()
    if not h or any(c not in "0123456789abcdef" for c in h):
        raise ValueError("Некорректная hex-строка.")
    return "".join(format(int(c, 16), "04b") for c in h)


def bits_to_hex(b):
    if len(b) % 4:
        b = b.ljust((len(b) // 4 + 1) * 4, "0")
    return "".join(format(int(b[i:i+4], 2), "x") for i in range(0, len(b), 4))


def random_iv():
    return "".join(random.choice("01") for _ in range(BLOCK_SIZE))


# ============================================================
# Ввод
# ============================================================
def parse_input(v, fmt):
    v = v.replace(" ", "").replace("\n", "")
    if not v:
        raise ValueError("Пусто.")
    if fmt == "BIN":
        if any(c not in "01" for c in v):
            raise ValueError("Для BIN допустимы только 0 и 1.")
        return v
    else:
        if any(c not in "0123456789abcdef" for c in v.lower()):
            raise ValueError("Для HEX допустимы только 0-9, a-f.")
        return hex_to_bits(v)


def input_bits(prompt, min_bits, must_be_multiple_of=None):
    while True:
        v = input(prompt)
        if not v.strip():
            print("Ошибка: пусто."); continue
        try:
            bits = parse_input(v, INPUT_FORMAT)
        except ValueError as e:
            print(f"Ошибка: {e}"); continue
        if len(bits) < min_bits:
            print(f"Ошибка: нужно ≥ {min_bits} бит (сейчас {len(bits)})."); continue
        if must_be_multiple_of and len(bits) % must_be_multiple_of:
            print(f"Ошибка: длина должна быть кратна {must_be_multiple_of} битам."); continue
        return bits


# ============================================================
# Автотест (проверка обратимости)
# ============================================================
def selftest():
    msg = (
        "1010011110100111101001111010011110100111101001111010011110100111"
        "0011110000111100001111000011110000111100001111000011110000111100"
        "1100110011001100110011001100110011001100110011001100110011001100"
        "0101010101010101010101010101010101010101010101010101010101010101"
    )
    key = (
        "1001110001101011010011100011010110011100011010110100111000110101"
        "1001001111000110010110011100011001011001110001100101100111000110"
    )
    iv = "1011010010110100101101001011010010110100101101001011010010110100"
    sk = generate_subkeys(key)
    ct = pcbc_encrypt(msg, sk, iv)
    pt = pcbc_decrypt(ct, sk, iv)
    ok = (pt == msg)
    print("Автотест:", "OK" if ok else "ПРОВАЛ")
    if not ok:
        print("  Ожидалось:", msg)
        print("  Получено: ", pt)
    return ok


# ============================================================
# Меню
# ============================================================
def main():
    global INPUT_FORMAT
    print("Автотест при запуске:")
    selftest()
    print()

    while True:
        print("\n" + "=" * 55)
        print("   SPN + PCBC + PRESENT S-Box + ISO 7816-4")
        print(f"   Формат ввода: {INPUT_FORMAT}")
        print("=" * 55)
        print("1. Зашифровать")
        print("2. Расшифровать")
        print(f"3. Переключить формат (сейчас {INPUT_FORMAT})")
        print("4. Выйти")
        ch = input("Выбор: ")

        if ch == "1":
            msg = input_bits("Сообщение (≥ 256 бит):\n", 256)
            key = input_bits("Ключ (≥ 128 бит, кратно 64):\n", 128, 64)
            sk = generate_subkeys(key)
            iv = random_iv()
            ct = pcbc_encrypt(msg, sk, iv)

            n_padded = len(pad_iso7816(msg)) // BLOCK_SIZE
            n_original = len(msg) // BLOCK_SIZE

            print(f"\nФормат ввода: {INPUT_FORMAT}")
            print(f"\nИсходная длина: {len(msg)} бит")
            print(f"После паддинга: {len(pad_iso7816(msg))} бит")
            print(f"Блоков: {n_padded}")
            print("\nIV:")
            print("  BIN:", iv)
            print("  HEX:", bits_to_hex(iv))
            print("\nШИФРОТЕКСТ:")
            print("  BIN:", ct)
            print("  HEX:", bits_to_hex(ct))

        elif ch == "2":
            ct = input_bits("Шифротекст:\n", 64)
            key = input_bits("Ключ (≥ 128 бит, кратно 64):\n", 128, 64)
            iv = input_bits("IV (ровно 64 бита):\n", 64)
            if len(iv) != 64:
                print(f"Ошибка: IV = 64 бита, введено {len(iv)}."); continue
            sk = generate_subkeys(key)
            pt = pcbc_decrypt(ct, sk, iv)
            print("\nРАСШИФРОВАНО:")
            print("  BIN:", pt)
            print("  HEX:", bits_to_hex(pt))
            print(f"  Длина: {len(pt)} бит")

        elif ch == "3":
            INPUT_FORMAT = "HEX" if INPUT_FORMAT == "BIN" else "BIN"
            print(f"\nФормат ввода теперь: {INPUT_FORMAT}")

        elif ch == "4":
            break


main()