import dh

private_key1, _ = dh.generate_keys()
n, public_key2 = dh.generate_keys()
n1, public_key3 = dh.generate_keys()

print(private_key1.exchange(public_key2).hex())
print(private_key1.exchange(public_key3).hex())