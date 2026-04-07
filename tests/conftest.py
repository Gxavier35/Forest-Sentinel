import os
import sys

# Adiciona o diretório 'src' ao sys.path para que os testes encontrem os módulos
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
