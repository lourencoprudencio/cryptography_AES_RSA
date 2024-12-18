## Lourenço Prudêncio
## GitHub: [lourencoprudencio](https://github.com/lourencoprudencio)
## Repositório do projeto: (https://github.com/lourencoprudencio/cryptography_AES_RSA)

# Importação de bibliotecas necessárias
from tkinter import Tk, Label, Text, END, messagebox, Toplevel, Scrollbar  # Elementos básicos para a interface gráfica
from tkinter import ttk, Frame  # Componentes adicionais da interface gráfica
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # Funções para criptografia AES
from cryptography.hazmat.primitives.asymmetric import rsa, padding  # Funções para criptografia RSA
from cryptography.hazmat.primitives import hashes  # Hashing (SHA-256)
from cryptography.hazmat.backends import default_backend  # Backend para operações criptográficas
from datetime import datetime  # Manipulação de datas e horas
import os  # Interação com o sistema operativo, como gerir ficheiros e caminhos

# Variáveis e configuração inicial
log_file = os.path.join(os.getcwd(), "logs_operacoes.txt")  # Caminho absoluto para o ficheiro de logs
key_aes = os.urandom(32)  # Criação de uma Key AES de 256 bits
iv = os.urandom(16)  # Criação de um vetor de inicialização (IV) de 16 bytes
key_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)  # Criação da Key privada RSA
key_publica = key_privada.public_key()  # Derivação da Key pública a partir da Key privada

# Funções de registo e manipulação de logs
def registar_log(operacao, resultado):
    """
    Regista a operação e o resultado no ficheiro de logs.
    """
    try:
        with open(log_file, "a", encoding="utf-8") as f:  # Abre o ficheiro de logs em modo de adição
            hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Obtém a data e hora atuais
            f.write(f"[{hora}] Operação: {operacao}\nResultado: {resultado}\n\n")  # Escreve a operação e o resultado
    except Exception as e:
        messagebox.showerror("Erro de Logs", f"Erro ao gravar no ficheiro de logs: {e}")  # Mostra uma mensagem de erro

def limpar_logs():
    """
    Limpa o conteúdo do ficheiro de logs.
    """
    try:
        with open(log_file, "w", encoding="utf-8") as f:  # Abre o ficheiro de logs no modo de escrita
            f.write("")  # Apaga o conteúdo do ficheiro
        messagebox.showinfo("Logs limpas", "O ficheiro de logs foi limpo com sucesso.")  # Mostra mensagem de sucesso
    except Exception as e:
        messagebox.showerror("Erro ao limpar logs", f"Erro: {e}")  # Mostra uma mensagem de erro em caso de falha

# Funções de criptografia AES
def cifrar_aes(texto):
    """
    Cifra texto usando AES (modo CFB).
    """
    try:
        cipher = Cipher(algorithms.AES(key_aes), modes.CFB(iv), backend=default_backend())  # Configura o AES
        encryptor = cipher.encryptor()  # Inicializa o cifrador
        resultado = (encryptor.update(texto.encode("utf-8")) + encryptor.finalize()).hex()  # Cifra o texto e converte para hex
        registar_log("Cifrar AES", resultado)  # Regista a operação nos logs
        return resultado  # Retorna o texto cifrado
    except Exception as e:
        return f"Erro: {e}"  # Retorna uma mensagem de erro em caso de falha

def decifrar_aes(texto_cifrado):
    """
    Decifra texto cifrado usando AES (modo CFB).
    """
    try:
        cipher = Cipher(algorithms.AES(key_aes), modes.CFB(iv), backend=default_backend())  # Configura o AES
        decryptor = cipher.decryptor()  # Inicializa o decifrador
        resultado = (decryptor.update(bytes.fromhex(texto_cifrado)) + decryptor.finalize()).decode("utf-8")  # Decifra e converte para texto
        registar_log("Decifrar AES", resultado)  # Regista a operação nos logs
        return resultado  # Retorna o texto decifrado
    except Exception as e:
        return f"Erro: {e}"  # Retorna uma mensagem de erro em caso de falha

# Funções de criptografia RSA
def cifrar_rsa(texto):
    """
    Cifra texto usando RSA com padding OAEP.
    """
    try:
        resultado = key_publica.encrypt(
            texto.encode("utf-8"),  # Converte o texto para bytes
            padding.OAEP(  # Configura o padding OAEP
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Máscara de Criação usando SHA-256
                algorithm=hashes.SHA256(),  # Algoritmo principal de hash (SHA-256)
                label=None  # Sem label adicional
            )
        ).hex()  # Converte o resultado cifrado para hexadecimal
        registar_log("Cifrar RSA", resultado)  # Regista a operação nos logs
        return resultado  # Retorna o texto cifrado
    except Exception as e:
        return f"Erro: {e}"  # Retorna uma mensagem de erro em caso de falha

def decifrar_rsa(texto_cifrado):
    """
    Decifra texto cifrado usando RSA com padding OAEP.
    """
    try:
        resultado = key_privada.decrypt(
            bytes.fromhex(texto_cifrado),  # Converte o texto cifrado hexadecimal para bytes
            padding.OAEP(  # Configura o padding OAEP
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Máscara de Criação usando SHA-256
                algorithm=hashes.SHA256(),  # Algoritmo principal de hash (SHA-256)
                label=None  # Sem label adicional
            )
        ).decode("utf-8")  # Converte o texto decifrado para string
        registar_log("Decifrar RSA", resultado)  # Regista a operação nos logs
        return resultado  # Retorna o texto decifrado
    except Exception as e:
        return f"Erro: {e}"  # Retorna uma mensagem de erro em caso de falha

# Funções para a interface gráfica
def abrir_logs():
    """
    Abre os logs numa nova janela.
    """
    janela_logs = Toplevel()  # Cria uma nova janela
    janela_logs.title("Logs do Programa")  # Define o título da janela
    janela_logs.geometry("600x400")  # Define as dimensões da janela

    texto_logs = Text(janela_logs)  # Área de texto para mostrar os logs
    texto_logs.pack(expand=True, fill="both")  # Preenche a janela com a área de texto

    try:
        with open(log_file, "r", encoding="utf-8") as f:  # Abre o ficheiro de logs
            texto_logs.insert("1.0", f.read())  # Insere o conteúdo do ficheiro na área de texto
    except FileNotFoundError:
        texto_logs.insert("1.0", "Sem logs disponíveis.")  # Mostra mensagem caso o ficheiro não exista
    except Exception as e:
        texto_logs.insert("1.0", f"Erro ao abrir logs: {e}")  # Mostra mensagem de erro em caso de falha

def interface_grafica():
    """
    Configura e inicia a interface gráfica do programa.
    """
    def sair():
        janela.quit()  # Fecha o programa

    def inserir_saida(funcao):
        """
        Obtém o texto da entrada, processa-o com a função selecionada e apresenta o resultado.
        """
        texto = entrada_texto.get("1.0", END).strip()  # Lê o texto da área de entrada
        if texto:
            resultado = funcao(texto)  # Processa o texto com a função fornecida
            saida_texto.delete("1.0", END)  # Limpa a área de saída
            saida_texto.insert(END, resultado)  # Insere o resultado na área de saída
        else:
            messagebox.showwarning("Informação", "Introduza um texto válido!")  # Mostra aviso se o texto estiver vazio

    # Configuração da janela principal
    janela = Tk()
    janela.title("Python Criptografia")  # Define o título da janela principal
    janela.geometry("800x700")  # Define o tamanho da janela

    # Entrada de texto
    Label(janela, text="Informação de Entrada:", font=("Arial", 12)).pack(pady=5)  # Etiqueta para entrada
    entrada_texto = Text(janela, height=5, width=90, font=("Arial", 10))  # Caixa de entrada
    entrada_texto.pack(pady=5)

    # Botões AES
    Label(janela, text="Funções AES", font=("Arial", 12, "bold")).pack(pady=5)  # Etiqueta para funções AES
    frame_aes = Frame(janela)  # Agrupa os botões AES
    frame_aes.pack()
    ttk.Button(frame_aes, text="Cifrar AES", command=lambda: inserir_saida(cifrar_aes)).grid(row=0, column=0, padx=10)
    ttk.Button(frame_aes, text="Decifrar AES", command=lambda: inserir_saida(decifrar_aes)).grid(row=0, column=1, padx=10)

    # Botões RSA
    Label(janela, text="Funções RSA", font=("Arial", 12, "bold")).pack(pady=5)  # Etiqueta para funções RSA
    frame_rsa = Frame(janela)  # Agrupa os botões RSA
    frame_rsa.pack()
    ttk.Button(frame_rsa, text="Cifrar RSA", command=lambda: inserir_saida(cifrar_rsa)).grid(row=0, column=0, padx=10)
    ttk.Button(frame_rsa, text="Decifrar RSA", command=lambda: inserir_saida(decifrar_rsa)).grid(row=0, column=1, padx=10)

    # Botões de logs
    ttk.Button(janela, text="Ver Logs", command=abrir_logs).pack(pady=5)  # Botão para ver logs
    ttk.Button(janela, text="Limpar Logs", command=limpar_logs).pack(pady=5)  # Botão para limpar logs

    # Saída de texto
    Label(janela, text="Informação de Saída:", font=("Arial", 12)).pack(pady=5)  # Etiqueta para saída
    saida_texto = Text(janela, height=5, width=90, font=("Arial", 10))  # Caixa de saída
    saida_texto.pack(pady=5)

    # Botão para sair
    ttk.Button(janela, text="Sair", command=sair).pack(pady=10)  # Botão para sair do programa

    janela.mainloop()  # Inicia o loop da interface gráfica

# Execução do programa
if __name__ == "__main__":
    interface_grafica()  # Inicia a interface gráfica