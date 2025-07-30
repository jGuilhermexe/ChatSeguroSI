from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

# Gera parâmetros DH
parameters = dh.generate_parameters(generator=2, key_size=512)  # pode usar 1024 ou 2048 se quiser mais seguro

# Salva em arquivo PEM
with open("dh_params.pem", "wb") as f:
    f.write(parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    ))
