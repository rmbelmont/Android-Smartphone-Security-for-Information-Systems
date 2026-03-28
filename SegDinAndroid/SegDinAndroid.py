from rdflib import Graph, Namespace, Literal, URIRef
from rdflib.namespace import RDF, RDFS, OWL, XSD
import os
from datetime import datetime

class SecurityOntology:
    """
    Classe principal para criar e gerenciar a ontologia de segurança SegDinAndroid
    """
    
    def __init__(self, base_uri="http://www.example.org/SegDinAndroid/"):
        """
        Inicializa a ontologia com namespaces e estruturas básicas
        
        Args:
            base_uri: URI base para a ontologia SegDinAndroid
        """
        # Criar o grafo RDF
        self.graph = Graph()
        
        # Definir namespaces
        self.base_uri = base_uri
        self.ONT = Namespace(base_uri)
        self.SEGDIN = Namespace(base_uri)
        self.NEST = Namespace("http://SegDinAndroid.org/nest/")
        
        # Bind dos namespaces para melhor legibilidade
        self.graph.bind("segdin", self.SEGDIN)
        self.graph.bind("ont", self.ONT)
        self.graph.bind("nest", self.NEST)
        self.graph.bind("owl", OWL)
        self.graph.bind("rdfs", RDFS)
        
        # Dicionários para armazenar instâncias
        self.domain_instances = {}
        self.kind_instances = {}
        self.subkind_instances = {}
        self.subclass_instances = {}  # Novo dicionário para subclasses
        
        # Criar as classes e propriedades da ontologia
        self._create_classes()
        self._create_properties()
        self._create_subclasses()  # Novo método para criar subclasses
        
    def _create_classes(self):
        """Cria as classes da ontologia"""
        classes = [
            ("SecurityDomain", "Security Domain"),
            ("Kind", "Kind"),
            ("SubKind", "SubKind"),
            ("FunctionalComplex", "Functional Complex")
        ]
        
        for class_name, label in classes:
            class_uri = self.ONT[class_name]
            self.graph.add((class_uri, RDF.type, OWL.Class))
            self.graph.add((class_uri, RDFS.label, Literal(label)))
            self.graph.add((class_uri, RDFS.comment, Literal(f"Class representing {label} in SegDinAndroid ontology")))
    
    def _create_subclasses(self):
        """Cria as subclasses (SubKind) como subclasses de Kind"""
        
        # Definir os kinds principais
        kinds = {
            "Malware": "Malware security category",
            "Privacy and Compliance": "Privacy and compliance security category",
            "OS & Framework Security": "Operating system and framework security category"
        }
        
        # Criar os kinds como classes
        for kind_name, description in kinds.items():
            uri_name = kind_name.replace(" ", "").replace("&", "")
            kind_uri = self.ONT[uri_name]
            self.graph.add((kind_uri, RDF.type, OWL.Class))
            self.graph.add((kind_uri, RDFS.subClassOf, self.ONT.Kind))
            self.graph.add((kind_uri, RDFS.label, Literal(kind_name)))
            self.graph.add((kind_uri, RDFS.comment, Literal(description)))
            self.kind_instances[kind_name] = kind_uri
        
        # Definir todas as subclasses (SubKind) com seus respectivos kinds pais
        subclasses_data = {
            # OS & Framework Security subclasses
            "FridaDetection": {"parent": "OS & Framework Security", "description": "Frida detection techniques"},
            "Fuzzing": {"parent": "OS & Framework Security", "description": "Fuzzing security testing"},
            "KernelTesting": {"parent": "OS & Framework Security", "description": "Kernel security testing"},
            "NativeService": {"parent": "OS & Framework Security", "description": "Native service security"},
            "TEE": {"parent": "OS & Framework Security", "description": "Trusted Execution Environment"},
            
            # Privacy and Compliance subclasses
            "AnalyticsLibrary": {"parent": "Privacy and Compliance", "description": "Analytics library security"},
            "AppGenerator": {"parent": "Privacy and Compliance", "description": "Application generator security"},
            "Authentication": {"parent": "Privacy and Compliance", "description": "Authentication mechanisms"},
            "Compliance": {"parent": "Privacy and Compliance", "description": "Compliance checking"},
            "DynamicTaintAnalysis": {"parent": "Privacy and Compliance", "description": "Dynamic taint analysis"},
            "LeakingPII": {"parent": "Privacy and Compliance", "description": "PII leakage detection"},
            "MobileBrowser": {"parent": "Privacy and Compliance", "description": "Mobile browser security"},
            "Obfuscation": {"parent": "Privacy and Compliance", "description": "Code obfuscation techniques"},
            "Permission": {"parent": "Privacy and Compliance", "description": "Permission security"},
            "PortSecurity": {"parent": "Privacy and Compliance", "description": "Port security measures"},
            "SensitiveInput": {"parent": "Privacy and Compliance", "description": "Sensitive input protection"},
            "SoftwareComposition": {"parent": "Privacy and Compliance", "description": "Software composition analysis"},
            
            # Malware subclasses
            "AnomalyDetection": {"parent": "Malware", "description": "Anomaly detection for malware"},
            "DynamicCodeLoading": {"parent": "Malware", "description": "Dynamic code loading analysis"},
            "MachineEvolution": {"parent": "Malware", "description": "Machine evolution techniques"},
            "MachineLearning": {"parent": "Malware", "description": "Machine learning for malware"},
            "MemoryDetection": {"parent": "Malware", "description": "Memory-based detection"},
            "TraceDetection": {"parent": "Malware", "description": "Trace-based detection"},
            "Visualization": {"parent": "Malware", "description": "Security visualization"},
            "SSLTLS": {"parent": "Malware", "description": "SSL/TLS security"}
        }
        
        # Criar cada subclasse
        for subclass_name, data in subclasses_data.items():
            parent_name = data["parent"]
            description = data["description"]
            
            # Criar URI para a subclasse
            subclass_uri = self.ONT[subclass_name]
            
            # Adicionar como classe
            self.graph.add((subclass_uri, RDF.type, OWL.Class))
            
            # Adicionar como subclasse do Kind correspondente
            if parent_name in self.kind_instances:
                self.graph.add((subclass_uri, RDFS.subClassOf, self.kind_instances[parent_name]))
            
            # Também adicionar como subclasse de SubKind
            self.graph.add((subclass_uri, RDFS.subClassOf, self.ONT.SubKind))
            
            # Adicionar labels e comentários
            self.graph.add((subclass_uri, RDFS.label, Literal(subclass_name)))
            self.graph.add((subclass_uri, RDFS.comment, Literal(description)))
            
            # Armazenar nos dicionários
            self.subclass_instances[subclass_name] = subclass_uri
            
            # Também adicionar como instância de Security Domain (para compatibilidade)
            self.graph.add((subclass_uri, RDF.type, self.ONT.SecurityDomain))
            self.graph.add((subclass_uri, self.ONT.belongsToDomain, self.kind_instances[parent_name]))
    
    def _create_properties(self):
        """Cria as propriedades da ontologia SegDinAndroid"""
        properties = [
            ("hasKind", "has kind", self.ONT.SecurityDomain, self.ONT.Kind),
            ("hasSubKind", "has subkind", self.ONT.Kind, self.ONT.SubKind),
            ("belongsToDomain", "belongs to domain", self.ONT.Kind, self.ONT.SecurityDomain),
            ("belongsToKind", "belongs to kind", self.ONT.SubKind, self.ONT.Kind),
            ("hasFunctionalComplex", "has functional complex", self.ONT.SecurityDomain, self.ONT.FunctionalComplex),
            ("hasSubclass", "has subclass", self.ONT.Kind, OWL.Class)  # Nova propriedade
        ]
        
        for prop_name, label, domain, range_ in properties:
            prop_uri = self.ONT[prop_name]
            self.graph.add((prop_uri, RDF.type, OWL.ObjectProperty))
            self.graph.add((prop_uri, RDFS.label, Literal(label)))
            self.graph.add((prop_uri, RDFS.domain, domain))
            self.graph.add((prop_uri, RDFS.range, range_))
            self.graph.add((prop_uri, RDFS.comment, Literal(f"Property that {label}")))
    
    def create_security_domains(self):
        """Cria todas as instâncias de Security Domain"""
        
        # Domínios principais de Malware
        malware_domains = [
            "Malware", "AnomalyDetection", "DynamicCodeLoading",
            "MachineEvolution", "MachineLearning", "MemoryDetection",
            "TraceDetection", "Visualization"
        ]
        
        for domain in malware_domains:
            self._add_domain(domain)
        
        # OS & Framework Security
        self._add_domain("OS & Framework Security")
        
        # Sub-domínios de OS & Framework Security
        os_subdomains = [
            "FridaDetection", "Fuzzing", "KernelTesting",
            "NativeService", "TEE"
        ]
        
        for domain in os_subdomains:
            self._add_domain(domain)
        
        # Privacy and Compliance
        self._add_domain("Privacy and Compliance")
        
        # Sub-domínios de Privacy and Compliance
        privacy_subdomains = [
            "AnalyticsLibrary", "AppGenerator", "Authentication",
            "Compliance", "DynamicTaintAnalysis", "LeakingPII",
            "MobileBrowser", "Obfuscation", "Permission",
            "PortSecurity", "SensitiveInput", "SoftwareComposition"
        ]
        
        for domain in privacy_subdomains:
            self._add_domain(domain)
        
        # SSL/TLS
        self._add_domain("SSL/TLS")
        
    def _add_domain(self, domain_name):
        """Adiciona um domínio de segurança"""
        uri_name = domain_name.replace(" ", "").replace("&", "").replace("/", "")
        domain_uri = self.ONT[uri_name]
        self.graph.add((domain_uri, RDF.type, self.ONT.SecurityDomain))
        self.graph.add((domain_uri, RDFS.label, Literal(domain_name)))
        self.domain_instances[domain_name] = domain_uri
    
    def create_functional_complexes(self):
        """Cria os Functional Complexes"""
        complexes = [
            ("Malware", "MalwareAnalysisSystem", "Malware Analysis System", "System for analyzing and detecting malware"),
            ("Privacy and Compliance", "PrivacyProtectionFramework", "Privacy Protection Framework", "Framework for privacy compliance"),
            ("OS & Framework Security", "SystemSecurityFramework", "System Security Framework", "Security framework for OS and frameworks")
        ]
        
        for kind_name, uri_name, complex_name, description in complexes:
            if kind_name in self.kind_instances:
                complex_uri = self.ONT[uri_name]
                self.graph.add((complex_uri, RDF.type, self.ONT.FunctionalComplex))
                self.graph.add((complex_uri, RDFS.label, Literal(complex_name)))
                self.graph.add((complex_uri, RDFS.comment, Literal(description)))
                self.graph.add((self.kind_instances[kind_name], 
                              self.ONT.hasFunctionalComplex, complex_uri))
    
    def build_ontology(self):
        """Método principal para construir toda a ontologia SegDinAndroid"""
        print("Construindo ontologia SegDinAndroid...")
        print("-" * 50)
        
        print("1. Criando classes e subclasses...")
        # As classes e subclasses já foram criadas no __init__
        print(f"   ✓ {len(self.kind_instances)} kinds criados")
        print(f"   ✓ {len(self.subclass_instances)} subclasses criadas")
        
        print("2. Criando Security Domains...")
        self.create_security_domains()
        print(f"   ✓ {len(self.domain_instances)} domínios criados")
        
        print("3. Criando Functional Complexes...")
        self.create_functional_complexes()
        print("   ✓ Functional complexes criados")
        
        print("-" * 50)
        print("✓ Ontologia SegDinAndroid construída com sucesso!")
    
    def save_ontology(self, output_dir="output", formats=None):
        """Salva a ontologia SegDinAndroid em diferentes formatos"""
        if formats is None:
            formats = ['turtle', 'xml', 'json-ld']
        
        # Criar diretório se não existir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            print(f"\n✓ Diretório criado: {output_dir}")
        else:
            print(f"\n✓ Diretório já existe: {output_dir}")
        
        format_map = {
            'turtle': ('ttl', 'turtle'),
            'xml': ('rdf', 'xml'),
            'json-ld': ('jsonld', 'json-ld'),
            'n3': ('n3', 'n3')
        }
        
        saved_files = []
        
        for fmt in formats:
            if fmt in format_map:
                extension, rdflib_format = format_map[fmt]
                filename = f"SegDinAndroid.{extension}"
                filepath = os.path.join(output_dir, filename)
                
                try:
                    self.graph.serialize(destination=filepath, format=rdflib_format)
                    saved_files.append(filepath)
                    print(f"✓ Salvo: {filepath}")
                except Exception as e:
                    print(f"✗ Erro ao salvar {fmt}: {e}")
        
        # Salvar versão latest
        for fmt in formats:
            if fmt in format_map:
                extension, rdflib_format = format_map[fmt]
                latest_file = os.path.join(output_dir, f"SegDinAndroid_latest.{extension}")
                try:
                    self.graph.serialize(destination=latest_file, format=rdflib_format)
                    print(f"✓ Versão atualizada salva: {latest_file}")
                except Exception as e:
                    print(f"✗ Erro ao salvar versão latest: {e}")
        
        return saved_files
    
    def print_statistics(self):
        """Imprime estatísticas da ontologia SegDinAndroid"""
        print("\n" + "="*60)
        print("ESTATÍSTICAS DA ONTOLOGIA SegDinAndroid")
        print("="*60)
        print(f"Total de triplas: {len(self.graph)}")
        print(f"Kinds (classes principais): {len(self.kind_instances)}")
        print(f"SubKinds (subclasses): {len(self.subclass_instances)}")
        print(f"Security Domains (instâncias): {len(self.domain_instances)}")
        
        # Contar classes OWL
        classes = set()
        for s, p, o in self.graph.triples((None, RDF.type, OWL.Class)):
            classes.add(s)
        print(f"Total de classes OWL: {len(classes)}")
        
        # Contar propriedades
        properties = set()
        for s, p, o in self.graph.triples((None, RDF.type, OWL.ObjectProperty)):
            properties.add(s)
        print(f"Propriedades: {len(properties)}")
        
        print(f"\nNamespace principal: {self.base_uri}")
        print("Prefixos registrados:")
        for prefix, namespace in self.graph.namespaces():
            print(f"  {prefix}: {namespace}")
    
    def print_hierarchy(self):
        """Imprime a hierarquia completa da ontologia SegDinAndroid"""
        print("\n" + "="*60)
        print("HIERARQUIA DE CLASSES - SegDinAndroid")
        print("="*60)
        
        # Mostrar a hierarquia de classes
        for kind_name, kind_uri in self.kind_instances.items():
            print(f"\n📁 {kind_name}")
            print("   └── Subclasses:")
            
            # Encontrar todas as subclasses deste kind
            subclasses = []
            for subclass_name, subclass_uri in self.subclass_instances.items():
                # Verificar se é subclasse deste kind
                if (subclass_uri, RDFS.subClassOf, kind_uri) in self.graph:
                    subclasses.append(subclass_name)
            
            if subclasses:
                for subclass in sorted(subclasses):
                    print(f"        • {subclass}")
            else:
                print("        (nenhuma subclasse definida)")
            
            # Mostrar Functional Complex se houver
            for s, p, o in self.graph.triples((kind_uri, self.ONT.hasFunctionalComplex, None)):
                label = self.graph.value(o, RDFS.label)
                if label:
                    print(f"   └── Functional Complex: {label}")
        
        print("\n" + "="*60)

def main():
    """Função principal para executar a ontologia SegDinAndroid"""
    print("\n" + "="*60)
    print("SISTEMA DE ONTOLOGIA SegDinAndroid")
    print("="*60)
    
    # Criar a ontologia
    ontology = SecurityOntology("http://www.SegDinAndroid.org/SegDinAndroid/")
    
    # Construir a ontologia
    ontology.build_ontology()
    
    # Imprimir estatísticas
    ontology.print_statistics()
    
    # Imprimir hierarquia
    ontology.print_hierarchy()
    
    # Salvar a ontologia
    print("\n" + "="*60)
    print("SALVANDO ONTOLOGIA SegDinAndroid")
    print("="*60)
    
    output_directory = r"D:\output_directory\SegDinAndroid"
    
    print(f"\nTentando salvar em: {output_directory}")
    
    saved_files = ontology.save_ontology(output_dir=output_directory)
    
    print("\n" + "="*60)
    print("EXECUÇÃO CONCLUÍDA COM SUCESSO!")
    print("="*60)
    print(f"\nArquivos da ontologia SegDinAndroid salvos em: {output_directory}")
    for file in saved_files:
        print(f"  • {os.path.basename(file)}")
    
    return ontology

if __name__ == "__main__":
    # Executar a ontologia
    ontology = main()
    
    # Exibir exemplo da hierarquia de classes
    print("\n" + "="*60)
    print("EXEMPLO DA HIERARQUIA DE CLASSES")
    print("="*60)
    
    # Mostrar todas as relações de subclasse
    print("\nRelações de subclasse (rdfs:subClassOf):")
    for s, p, o in ontology.graph.triples((None, RDFS.subClassOf, None)):
        s_label = ontology.graph.value(s, RDFS.label)
        o_label = ontology.graph.value(o, RDFS.label)
        if s_label and o_label:
            print(f"  {s_label} → {o_label}")