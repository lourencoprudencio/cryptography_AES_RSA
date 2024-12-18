**PT**

# Python Criptografia com AES e RSA

Este programa é uma aplicação gráfica em Python que demonstra a utilização de técnicas de criptografia com os algoritmos AES (Advanced Encryption Standard) e RSA (Rivest-Shamir-Adleman). A interface gráfica permite-nos cifrar e decifrar textos utilizando esses mesmos algoritmos e verificar os logs das operações realizadas.

---

## Funcionalidades

- **Criptografia AES (Simétrica):**
  - Permite cifrar e decifrar texto usando uma key de 256 bits.
  - Utiliza o modo de operação **CFB (Cipher Feedback)** para maior segurança.

- **Criptografia RSA (Assimétrica):**
  - Permite cifrar e decifrar texto utilizando um par de keys RSA (pública e privada).
  - Utiliza o esquema de padding **OAEP (Optimal Asymmetric Encryption Padding)** com SHA-256.

- **Logs das Operações dentro do programa:**
  - Todas as operações de criptografia e descriptografia são registradas num arquivo de logs `logs_operacoes.txt`.

---

## Pré-requisitos

Certifica-te de ter o Python 3.8 ou superior instalado, juntamente com as seguintes bibliotecas:
- **tkinter** (Interface gráfica padrão do Python)
- **cryptography** (Para operações criptográficas)

Para instalar a biblioteca `cryptography`, usa o comando no terminal:
```bash
pip install cryptography
```

---

## Estrutura do Projeto

- **main.py**: Arquivo principal que tem toda a lógica do programa e a interface gráfica.
- **logs_operacoes.txt**: Arquivo criado automaticamente para armazenar os registros das operações.

---

## Descrição Técnica das Bibliotecas e Funções

### Bibliotecas

1. **tkinter**(https://docs.python.org/3/library/tkinter.html):
   - É a biblioteca padrão do Python para criação de interfaces gráficas.
   - Permite construir janelas, botões, caixas de texto, etiquetas, entre outros componentes interativos.
   - Facilita a criação de aplicações desktop intuitivas e com boa experiência para o user.

2. **cryptography**(https://cryptography.io/en/latest/):
   - É uma biblioteca robusta e moderna para implementação de criptografia segura no Python.
   - Oferece suporte para algoritmos de criptografia simétrica (AES) e assimétrica (RSA).
   - Possui funções para hashing, gestão de keys e modos de operação como CFB e OAEP.
   - Altamente utilizada nas aplicações que exigem segurança de dados, como sistemas bancários, transmissão de dados e proteção de informações sensíveis.

3. **datetime**(https://docs.python.org/3/library/datetime.html):
   - Fornece classes para manipulação de datas e horários.
   - Usada neste programa para registrar o timestamp das operações realizadas nos logs.
   - É essencial para acompanhar quando cada operação de criptografia/descriptografia foi executada.

4. **os**(https://docs.python.org/3/library/os.html):
   - Oferece funções para interação com o sistema operacional.
   - Usada para criar, gerir e aceder o destino do arquivo de logs.
   - Facilita a manipulação de ficheiros e diretórios de forma portátil entre diferentes sistemas operativos.

---

### Conceitos Criptográficos Utilizados

#### **CFB (Cipher Feedback):**
- É um modo de operação para algoritmos de criptografia de bloco, como AES.
- Transforma o cifrador do bloco num cifrador de fluxo, permitindo processar dados de qualquer tamanho.
- Funciona cifrando o vetor de inicialização (IV) com a key e combinando o resultado com o texto plano apartir de uma operação XOR.
- Cada bloco cifrado é usado como entrada para cifrar o próximo bloco.
- Benefícios:
  - Não requer preenchimento (padding) para dados de tamanho arbitrário.
  - Adequado para transmissões de dados em tempo real.

#### **OAEP (Optimal Asymmetric Encryption Padding):**
- É um esquema de preenchimento (padding) usado com RSA para garantir maior segurança contra ataques criptográficos.
- Utiliza uma combinação de funções hash (neste caso, SHA-256) e geradores de "máscaras" para aleatorizar os dados antes de serem cifrados.
- Benefícios:
  - Proteção contra ataques baseados em texto plano ou estruturas previsíveis.
  - Garante que mensagens semelhantes cifradas criem textos cifrados completamente diferentes.



---

### Funções do Programa

1. **Cifrar AES:**
   - Usa uma key simétrica (`key_aes`) e um vetor de inicialização (`iv`) criados automaticamente.
   - Texto é cifrado usando o algoritmo AES no modo CFB.

   ```python
   def cifrar_aes(texto):
       cipher = Cipher(algorithms.AES(key_aes), modes.CFB(iv), backend=default_backend())
       encryptor = cipher.encryptor()
       return (encryptor.update(texto.encode("utf-8")) + encryptor.finalize()).hex()
   ```

2. **Decifrar AES:**
   - Reverte o processo de cifrar usando a mesma key e vetor de inicialização.
   - Necessário passar o texto cifrado em formato hexadecimal.

   ```python
   def decifrar_aes(texto_cifrado):
       cipher = Cipher(algorithms.AES(key_aes), modes.CFB(iv), backend=default_backend())
       decryptor = cipher.decryptor()
       return (decryptor.update(bytes.fromhex(texto_cifrado)) + decryptor.finalize()).decode("utf-8")
   ```

3. **Cifrar RSA:**
   - Usa a key pública para cifrar texto.
   - O esquema de padding OAEP garante segurança adicional.

   ```python
   def cifrar_rsa(texto):
       return key_publica.encrypt(
           texto.encode("utf-8"),
           padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
       ).hex()
   ```

4. **Decifrar RSA:**
   - Usa a key privada para decifrar o texto cifrado.
   - Somente quem tem a key privada pode realizar essa operação.

   ```python
   def decifrar_rsa(texto_cifrado):
       return key_privada.decrypt(
           bytes.fromhex(texto_cifrado),
           padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
       ).decode("utf-8")
   ```

5. **Registar Logs:**
   - Registra a operação realizada e o resultado num ficheiro de texto. `logs_operacoes.txt` que pode ser acedido ao clicar no **Ver Logs**

   ```python
   def registar_log(operacao, resultado):
       with open(log_file, "a", encoding="utf-8") as f:
           f.write(f"[{hora}] Operação: {operacao}\nResultado: {resultado}\n\n")
   ```

---

## O que é RSA e AES?

- **AES (Advanced Encryption Standard):**
  - Algoritmo de criptografia simétrica, ou seja, usa a mesma key para cifrar e decifrar.
  - Muito rápido e adequado para grandes volumes de dados.
  - Utilizado em várias aplicações modernas como Wi-Fi, bancos de dados e transmissões seguras.

- **RSA (Rivest-Shamir-Adleman):**
  - Algoritmo de criptografia assimétrica que usa um par de keys: pública e privada.
  - A key pública cifra os dados, e apenas a key privada correspondente pode decifrá-los.
  - Muito seguro, mas mais lento que AES, ideal para pequenos volumes de dados ou para compartilhar chaves secretas.
  - Frequentemente usado em combinação com AES: RSA para troca de chaves seguras e AES para criptografia de dados.

## Padding

- **Padding :**
- É uma técnica usada para ajustar o tamanho dos dados antes de realizar a criptografia.
- Necessária em algoritmos de bloco como RSA, onde o tamanho da mensagem deve coincidir com o tamanho do bloco.
- O padding garante que mensagens menores sejam preenchidas com dados extras seguros, mantendo a integridade e a segurança da mensagem.
- Exemplo: OAEP é um dos esquemas de padding mais utilizados para RSA.

## SHA-256
- **[SHA-256]:**
- Parte da família de funções de hash criptográficas SHA-2.
- Produz um resumo (digest) fixo de 256 bits para qualquer tamanho de entrada.
- Usada para verificação de integridade, assinaturas digitais e criação de "máscaras" em esquemas como o OAEP.
- Benefícios:
  - Extremamente segura contra colisões (onde dois inputs diferentes criam o mesmo hash).
  - Amplamente utilizada nas aplicações como certificados digitais, blockchains e autenticação.

---

## Como Usar

1. Executa o programa:
   ```bash
   python main.py
   ```

2. Escreve o texto na área de entrada.

3. Escolhe uma das opções:
   - **Cifrar AES / Decifrar AES**
   - **Cifrar RSA / Decifrar RSA**

4. Vê o resultado na área de saída.

5. Para rever as operações realizadas, clica no botão **Ver Logs**.

---

## Outros

- **Lourenço Prudêncio**
- GitHub: [lourencoprudencio](https://github.com/lourencoprudencio)
- Repositório do projeto: (https://github.com/lourencoprudencio/cryptography_AES_RSA)

------------------------------------------------------------------------------------------------------------------------------------------
**EN**

# Python Cryptography with AES and RSA

This program is a graphical Python application demonstrating the use of encryption techniques with the AES (Advanced Encryption Standard) and RSA (Rivest-Shamir-Adleman) algorithms. The graphical interface allows users to encrypt and decrypt text using these algorithms and review logs of the performed operations.

---

## Features

- **AES Encryption (Symmetric):**
  - Allows encrypting and decrypting text using a 256-bit key.
  - Uses the **CFB (Cipher Feedback)** operation mode for enhanced security.

- **RSA Encryption (Asymmetric):**
  - Allows encrypting and decrypting text using an RSA key pair (public and private keys).
  - Utilizes the **OAEP (Optimal Asymmetric Encryption Padding)** scheme with SHA-256.

- **Operation Logs within the Program:**
  - All encryption and decryption operations are recorded in a `logs_operacoes.txt` file.

---

## Prerequisites

Ensure you have Python 3.8 or later installed, along with the following libraries:
- **[tkinter](https://docs.python.org/3/library/tkinter.html)** (Standard graphical interface library in Python)
- **[cryptography](https://cryptography.io/en/latest/)** (For cryptographic operations)

To install the `cryptography` library, run the following command in the terminal:
```bash
pip install cryptography
```

---

## Project Structure

- **main.py**: The main file containing the program's logic and graphical interface.
- **logs_operacoes.txt**: Automatically generated file to store operation logs.

---

## Technical Description of Libraries and Functions

## Libraries

1. **[tkinter](https://docs.python.org/3/library/tkinter.html):**
   - The standard Python library for creating graphical interfaces.
   - Enables building windows, buttons, text boxes, labels, and other interactive components.
   - Facilitates the creation of intuitive desktop applications with good user experience.

2. **[cryptography](https://cryptography.io/en/latest/):**
   - A robust and modern library for implementing secure cryptography in Python.
   - Supports symmetric (AES) and asymmetric (RSA) encryption algorithms.
   - Includes functions for hashing, key management, and operation modes like CFB and OAEP.
   - Widely used in applications requiring data security, such as banking systems, data transmission, and sensitive information protection.

3. **[datetime](https://docs.python.org/3/library/datetime.html):**
   - Provides classes for manipulating dates and times.
   - Used in this program to record the timestamp of operations in the logs.
   - Essential for tracking when each encryption/decryption operation was performed.

4. **[os](https://docs.python.org/3/library/os.html):**
   - Offers functions for interacting with the operating system.
   - Used to create, manage, and access the path for the log file.
   - Facilitates portable file and directory manipulation across different operating systems.

---

## Cryptographic Concepts Used

## **CFB (Cipher Feedback):**
- A mode of operation for block encryption algorithms like AES.
- Converts a block cipher into a stream cipher, enabling processing of data of any size.
- Operates by encrypting the initialization vector (IV) with the key and combining the result with plaintext using an XOR operation.
- Each encrypted block is used as input to encrypt the next block.
- Benefits:
  - Does not require padding for arbitrarily sized data.
  - Suitable for real-time data transmissions.

## **OAEP (Optimal Asymmetric Encryption Padding):**
- A padding scheme used with RSA to provide enhanced security against cryptographic attacks.
- Combines hash functions (e.g., SHA-256) and mask generators to randomize data before encryption.
- Benefits:
  - Protects against attacks based on predictable plaintext structures.
  - Ensures that similar plaintexts produce entirely different ciphertexts.

## **Padding:**
- A technique used to adjust data size before performing encryption.
- Necessary for block algorithms like RSA, where the message size must match the block size.
- Padding ensures smaller messages are securely filled with extra data while maintaining message integrity and security.
- Example: OAEP is one of the most widely used padding schemes for RSA.

## **[SHA-256]:**
- Part of the SHA-2 family of cryptographic hash functions.
- Produces a fixed 256-bit digest for any input size.
- Used for integrity verification, digital signatures, and generating masks in schemes like OAEP.
- Benefits:
  - Extremely secure against collisions (where two different inputs generate the same hash).
  - Widely used in applications like digital certificates, blockchains, and authentication.

---

## Program Functions

1. **Encrypt AES:**
   - Uses a symmetric key (`key_aes`) and an initialization vector (`iv`) generated automatically.
   - Text is encrypted using the AES algorithm in CFB mode.

   ```python
   def cifrar_aes(texto):
       cipher = Cipher(algorithms.AES(key_aes), modes.CFB(iv), backend=default_backend())
       encryptor = cipher.encryptor()
       return (encryptor.update(texto.encode("utf-8")) + encryptor.finalize()).hex()
   ```

2. **Decrypt AES:**
   - Reverses the encryption process using the same key and initialization vector.
   - Requires the encrypted text in hexadecimal format.

   ```python
   def decifrar_aes(texto_cifrado):
       cipher = Cipher(algorithms.AES(key_aes), modes.CFB(iv), backend=default_backend())
       decryptor = cipher.decryptor()
       return (decryptor.update(bytes.fromhex(texto_cifrado)) + decryptor.finalize()).decode("utf-8")
   ```

3. **Encrypt RSA:**
   - Uses the public key to encrypt text.
   - The OAEP padding scheme ensures additional security.

   ```python
   def cifrar_rsa(texto):
       return key_publica.encrypt(
           texto.encode("utf-8"),
           padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
       ).hex()
   ```

4. **Decrypt RSA:**
   - Uses the private key to decrypt encrypted text.
   - Only the corresponding private key can perform this operation.

   ```python
   def decifrar_rsa(texto_cifrado):
       return key_privada.decrypt(
           bytes.fromhex(texto_cifrado),
           padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
       ).decode("utf-8")
   ```

5. **Log Operations:**
   - Records the performed operation and its result in a text file `logs_operacoes.txt`, which can be accessed by clicking **View Logs**.

   ```python
   def registar_log(operacao, resultado):
       with open(log_file, "a", encoding="utf-8") as f:
           f.write(f"[{hora}] Operation: {operacao}\nResult: {resultado}\n\n")
   ```

---

## What is RSA and AES?

- **AES (Advanced Encryption Standard):**
  - A symmetric encryption algorithm, meaning it uses the same key for encryption and decryption.
  - Very fast and suitable for large volumes of data.
  - Used in various modern applications like Wi-Fi, databases, and secure transmissions.

- **RSA (Rivest-Shamir-Adleman)**:
  - An asymmetric encryption algorithm that uses a key pair: public and private keys.
  - The public key encrypts the data, and only the corresponding private key can decrypt it.
  - Very secure but slower than AES, ideal for small volumes of data or sharing secret keys.
  - Often used in combination with AES: RSA for secure key exchange and AES for data encryption.

---

## How to Use

1. Run the program:
   ```bash
   python main.py
   ```

2. Enter text in the input area.

3. Choose one of the options:
   - **Encrypt AES / Decrypt AES**
   - **Encrypt RSA / Decrypt RSA**

4. View the result in the output area.

5. To review the performed operations, click the **View Logs** button.

---

## Others

- **Lourenço Prudêncio**
- GitHub: [lourencoprudencio](https://github.com/lourencoprudencio)
- Project Repository: (https://github.com/lourencoprudencio/cryptography_AES_RSA)
