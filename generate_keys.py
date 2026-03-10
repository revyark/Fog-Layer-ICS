import rsa

# Generate RSA key pair
public_key, private_key = rsa.newkeys(1024)

# Save public key
with open("edge_public_key.pem", "wb") as f:
    f.write(public_key.save_pkcs1())

# Save private key
with open("edge_private_key.pem", "wb") as f:
    f.write(private_key.save_pkcs1())

print("Keys generated")