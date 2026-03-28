import os
import sys
import time
from rdflib import Graph, Namespace, RDFS, RDF, URIRef, Literal

class SegDinAndroidOntology:
    def __init__(self, ontology_file):
        """
        Inicializa o sistema com a ontologia SegDinAndroid
        """
        self.graph = Graph()
        self.ontology_file = ontology_file
        self.ns = Namespace("http://www.SegDinAndroid.org/SegDinAndroid/")
        
        try:
            if os.path.exists(ontology_file):
                self.graph.parse(ontology_file, format="turtle")
            else:
                print(f"Erro: Arquivo não encontrado - {ontology_file}")
                sys.exit(1)
        except Exception as e:
            print(f"Erro ao carregar ontologia: {e}")
            sys.exit(1)
    
    def limpar_tela(self):
        """Limpa a tela do terminal"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def exibir_cabecalho(self):
        """Exibe o cabeçalho do programa"""
        print("╔" + "═" * 78 + "╗")
        print("║" + " " * 78 + "║")
        print("║" + " " * 15 + "SegDinAndroid Versão 1.0" + " " * 38 + "║")
        print("║" + " " * 8 + "Gerenciamento da Segurança Dinâmica no Smartphone Android" + " " * 9 + "║")
        print("║" + " " * 78 + "║")
        print("╚" + "═" * 78 + "╝")
        print()
    
    def exibir_menu(self):
        """Exibe o menu principal"""
        print("┌" + "─" * 78 + "┐")
        print("│" + " " * 25 + "MENU PRINCIPAL" + " " * 37 + "│")
        print("├" + "─" * 78 + "┤")
        print("│" + " " * 78 + "│")
        print("│  [1]  Conceitos relacionados à análise de segurança dinâmica      │")
        print("│       estruturados no contexto do smartphone Android.            │")
        print("│" + " " * 78 + "│")
        print("│  [2]  Tecnologias, modelos, técnicas ou ferramentas de segurança │")
        print("│       da informação mais comumente usadas no smartphone Android. │")
        print("│" + " " * 78 + "│")
        print("│  [3]  Tipos de malware mais comumente encontrados ao usar o      │")
        print("│       smartphone Android.                                        │")
        print("│" + " " * 78 + "│")
        print("│  [4]  Encerrar o programa.                                       │")
        print("│" + " " * 78 + "│")
        print("└" + "─" * 78 + "┘")
        print()
    
    def get_label(self, uri):
        """Obtém o label de um recurso"""
        for _, _, obj in self.graph.triples((uri, RDFS.label, None)):
            if isinstance(obj, Literal):
                return str(obj)
        return None
    
    def get_subclasses_of_kind(self):
        """Obtém todas as subclasses de Kind"""
        subclasses = []
        for s, p, o in self.graph.triples((None, RDFS.subClassOf, self.ns.Kind)):
            if isinstance(s, URIRef):
                label = self.get_label(s)
                if label:
                    subclasses.append(label)
        return sorted(subclasses)
    
    def get_instances_of_subkind(self):
        """Obtém todas as instâncias que são subclasses de SubKind"""
        instances = []
        for s, p, o in self.graph.triples((None, RDFS.subClassOf, self.ns.SubKind)):
            if isinstance(s, URIRef):
                label = self.get_label(s)
                if label:
                    instances.append(label)
        return sorted(instances)
    
    def get_malware_instances(self):
        """Obtém as instâncias que são subclasses de Malware"""
        malware_instances = []
        for s, p, o in self.graph.triples((None, RDFS.subClassOf, self.ns.Malware)):
            if isinstance(s, URIRef):
                label = self.get_label(s)
                if label:
                    malware_instances.append(label)
        return sorted(malware_instances)
    
    def exibir_resposta(self, titulo, conteudo):
        """Exibe a resposta formatada de forma elegante"""
        self.limpar_tela()
        self.exibir_cabecalho()
        
        print("┌" + "─" * 78 + "┐")
        print("│" + " " * 78 + "│")
        print("│" + " " * 20 + titulo + " " * (58 - len(titulo)) + "│")
        print("│" + " " * 78 + "│")
        print("├" + "─" * 78 + "┤")
        print("│" + " " * 78 + "│")
        
        # Quebra o conteúdo em linhas de até 76 caracteres
        linhas = []
        linha_atual = ""
        for palavra in conteudo.split():
            if len(linha_atual) + len(palavra) + 1 <= 76:
                if linha_atual:
                    linha_atual += " " + palavra
                else:
                    linha_atual = palavra
            else:
                linhas.append(linha_atual)
                linha_atual = palavra
        if linha_atual:
            linhas.append(linha_atual)
        
        for linha in linhas:
            print("│ " + linha.ljust(76) + " │")
        
        print("│" + " " * 78 + "│")
        print("└" + "─" * 78 + "┘")
        
        # Aguarda 3 segundos e volta ao menu
        time.sleep(3)
    
    def opcao_conceitos(self):
        """CQ1: Subclasses de Kind"""
        subclasses_kind = self.get_subclasses_of_kind()
        
        if subclasses_kind:
            lista_subclasses = ", ".join(subclasses_kind)
            resposta = f"Os conceitos relacionados à análise de segurança dinâmica são estruturados em {lista_subclasses}."
        else:
            resposta = "Nenhuma subclasse de Kind encontrada na ontologia."
        
        self.exibir_resposta("CQ1 - CONCEITOS ESTRUTURADOS", resposta)
    
    def opcao_tecnologias(self):
        """CQ2: Tecnologias e ferramentas"""
        tecnologias = self.get_instances_of_subkind()
        
        if tecnologias:
            resposta = f"As tecnologias, modelos, técnicas ou ferramentas de segurança mais comumente usadas no smartphone Android são {', '.join(tecnologias)}."
        else:
            resposta = "Nenhuma tecnologia encontrada na ontologia."
        
        self.exibir_resposta("CQ2 - TECNOLOGIAS E FERRAMENTAS", resposta)
    
    def opcao_malware(self):
        """CQ3: Tipos de malware"""
        malware = self.get_malware_instances()
        
        if malware:
            resposta = f"Os tipos de malware mais comumente encontrados ao utilizar o smartphone Android são {', '.join(malware)}."
        else:
            resposta = "Nenhuma instância de malware encontrada na ontologia."
        
        self.exibir_resposta("CQ3 - TIPOS DE MALWARE", resposta)
    
    def encerrar_programa(self):
        """Encerra o programa com animação"""
        self.limpar_tela()
        self.exibir_cabecalho()
        
        print("┌" + "─" * 78 + "┐")
        print("│" + " " * 78 + "│")
        print("│" + " " * 28 + "ENCERRANDO PROGRAMA" + " " * 34 + "│")
        print("│" + " " * 78 + "│")
        print("├" + "─" * 78 + "┤")
        print("│" + " " * 78 + "│")
        
        # Animação de carregamento
        for i in range(3):
            print("│" + " " * 30 + "●" + " " * (47 - i*2) + "│")
            time.sleep(0.3)
        
        print("│" + " " * 78 + "│")
        print("│" + " " * 25 + "Obrigado por utilizar o sistema!" + " " * 26 + "│")
        print("│" + " " * 78 + "│")
        print("└" + "─" * 78 + "┘")
        
        time.sleep(1.5)
        sys.exit(0)
    
    def run(self):
        """Executa o programa principal"""
        while True:
            self.limpar_tela()
            self.exibir_cabecalho()
            self.exibir_menu()
            
            try:
                opcao = input("  ┌─ Opção: ").strip()
                print("  └" + "─" * 70)
                
                if opcao == '1':
                    self.opcao_conceitos()
                elif opcao == '2':
                    self.opcao_tecnologias()
                elif opcao == '3':
                    self.opcao_malware()
                elif opcao == '4':
                    self.encerrar_programa()
                else:
                    self.limpar_tela()
                    self.exibir_cabecalho()
                    print("┌" + "─" * 78 + "┐")
                    print("│" + " " * 78 + "│")
                    print("│" + " " * 25 + "OPÇÃO INVÁLIDA!" + " " * 40 + "│")
                    print("│" + " " * 20 + "Digite 1, 2, 3 ou 4." + " " * 40 + "│")
                    print("│" + " " * 78 + "│")
                    print("└" + "─" * 78 + "┘")
                    time.sleep(2)
                    
            except KeyboardInterrupt:
                self.encerrar_programa()
            except Exception as e:
                print(f"\n  Erro: {e}")
                time.sleep(2)

# Execução do programa
if __name__ == "__main__":
    if len(sys.argv) > 1:
        ontology_file = sys.argv[1]
    else:
        ontology_file = r"D:\output_directory\SegDinAndroid\SegDinAndroid.ttl"
    
    if not os.path.exists(ontology_file):
        print(f"╔" + "═" * 78 + "╗")
        print(f"║" + " " * 78 + "║")
        print(f"║" + " " * 15 + "ERRO: Arquivo não encontrado!" + " " * 35 + "║")
        print(f"║" + " " * 10 + f"{ontology_file}" + " " * (78 - len(ontology_file) - 10) + "║")
        print(f"║" + " " * 78 + "║")
        print(f"╚" + "═" * 78 + "╝")
        sys.exit(1)
    
    programa = SegDinAndroidOntology(ontology_file)
    programa.run()