from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization


# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ GENERATE_DH_PARAMS.PY ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Esse arquivo foi responsável por gerar a dh_params.pem, que é crucial pra que o algoritmo Diffie-Hellman (DH)
# funcione com sucesso, como o DH necessita de dois números grandes que são usados pelos clientes para gerar as 
# suas chaves efêmeras, acaba que fica um peso um pouco maior, a dh_params.pem serve pra evitar uma carga a mais.


# Responsável por gerar os parâmetros Diffie Hellman
parameters = dh.generate_parameters(generator=2, key_size=512)

# Salva no arquivo PEM
with open("dh_params.pem", "wb") as f:
    f.write(parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    ))
