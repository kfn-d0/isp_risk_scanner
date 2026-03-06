import os
import shutil
from pathlib import Path

def clean_project():
    print(" Iniciando a limpeza do projeto...\n")
    
    base_dir = Path(__file__).parent
    
    db_path = base_dir / "data" / "historico.db"
    if db_path.exists():
        try:
            db_path.unlink()
            print(f"  [OK] Banco de dados removido: {db_path.relative_to(base_dir)}")
        except Exception as e:
            print(f" [ERRO] Não foi possível remover o BD: {e}")
    else:
        print("  [INFO] Banco de dados (historico.db) não encontrado. Já estava limpo.")

    cache_count = 0
    for p in base_dir.rglob("__pycache__"):
        if p.is_dir():
            try:
                shutil.rmtree(p)
                print(f"️  [OK] Cache de compilação removido: {p.relative_to(base_dir)}")
                cache_count += 1
            except Exception as e:
                print(f"[ERRO] Falha ao remover cache {p.relative_to(base_dir)}: {e}")
    
    if cache_count == 0:
        print("  [INFO] Nenhuma pasta de cache (__pycache__) encontrada.")
        
    print("\n Limpeza concluída com sucesso! O ambiente está restaurado e pronto para a próxima demonstração.")

if __name__ == "__main__":
    clean_project()
