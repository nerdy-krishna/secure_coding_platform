# src/app/analysis/context_bundler.py

import logging
from pathlib import Path
from typing import Dict, List, Optional, Set

import networkx as nx
from pydantic import BaseModel, Field

from .repository_map import RepositoryMap

logger = logging.getLogger(__name__)


class ContextBundle(BaseModel):
    """
    A bundle containing a target file and the content of its direct dependencies.
    """
    target_file_path: str = Field(..., description="The main file to be analyzed.")
    context_files: Dict[str, str] = Field(
        ...,
        description="A map of file paths to their full content, including the target file and its dependencies."
    )


class _ImportResolver:
    """
    A helper class to resolve import statements to absolute file paths within the repo.
    """
    def __init__(self, all_file_paths: Set[str]):
        # A set of all file paths for quick lookups. E.g., {'src/app/main.py', ...}
        self.all_file_paths = all_file_paths
        # A map from dir paths to the files they contain. E.g., {'src/app/db': {'crud.py', 'models.py'}}
        self.dir_to_files = self._build_dir_map()

    def _build_dir_map(self) -> Dict[str, Set[str]]:
        dir_map: Dict[str, Set[str]] = {}
        for path_str in self.all_file_paths:
            path = Path(path_str)
            parent_dir = str(path.parent)
            if parent_dir not in dir_map:
                dir_map[parent_dir] = set()
            dir_map[parent_dir].add(path.name)
        return dir_map

    def resolve(self, importing_file_path: str, import_statement: str) -> Optional[str]:
        """
        Tries to resolve an import statement to a file path.
        Handles absolute and relative imports.
        """
        # Basic cleanup for import statements
        import_statement = import_statement.strip()
        if ' ' in import_statement:
            # Handle cases like "from x import y" -> "x"
            parts = import_statement.split(' ')
            if parts[0] == 'from':
                import_statement = parts[1]
            else:
                import_statement = parts[0]

        # Handle relative imports
        if import_statement.startswith('.'):
            return self._resolve_relative_import(importing_file_path, import_statement)
        else:
            return self._resolve_absolute_import(import_statement)

    def _resolve_absolute_import(self, import_path: str) -> Optional[str]:
        """Resolves an absolute import like 'app.db.crud'."""
        # Try to resolve module path to file path
        # 'app.db.crud' -> 'app/db/crud'
        potential_path_prefix = import_path.replace('.', '/')
        
        # Check for a direct file match: 'app/db/crud.py'
        file_path_guess = f"{potential_path_prefix}.py"
        if file_path_guess in self.all_file_paths:
            return file_path_guess
            
        # Check for a package match: 'app/db/crud/__init__.py'
        package_path_guess = f"{potential_path_prefix}/__init__.py"
        if package_path_guess in self.all_file_paths:
            return package_path_guess

        return None

    def _resolve_relative_import(self, base_file: str, import_path: str) -> Optional[str]:
        """Resolves a relative import like '.models' or '..utils'."""
        base_dir = Path(base_file).parent
        
        # Count leading dots to determine level
        level = 0
        for char in import_path:
            if char == '.':
                level += 1
            else:
                break
        
        # Go up the directory tree
        for _ in range(level - 1):
            base_dir = base_dir.parent
            
        # Get the rest of the import path
        rest_of_path = import_path[level:]
        
        # Join with the base directory
        final_path = base_dir / rest_of_path.replace('.', '/')
        
        # Check for a direct file match
        file_path_guess = f"{final_path}.py"
        if file_path_guess in self.all_file_paths:
            return file_path_guess
            
        # Check for a package match
        package_path_guess = f"{final_path}/__init__.py"
        if package_path_guess in self.all_file_paths:
            return package_path_guess
            
        return None


class ContextBundlingEngine:
    """
    Builds a dependency graph from a RepositoryMap and creates context-rich
    bundles for each file.
    """

    def __init__(self, repository_map: RepositoryMap, files: Dict[str, str]):
        self.repository_map = repository_map
        self.files = files
        self.resolver = _ImportResolver(set(files.keys()))
        self.graph = self._build_dependency_graph()

    def _build_dependency_graph(self) -> nx.DiGraph:
        """
        Builds a directed graph representing file dependencies.
        """
        graph = nx.DiGraph()
        all_file_paths = self.repository_map.files.keys()

        for file_path in all_file_paths:
            graph.add_node(file_path)

        for file_path, file_summary in self.repository_map.files.items():
            for imp in file_summary.imports:
                resolved_path = self.resolver.resolve(file_path, imp)
                if resolved_path and resolved_path in all_file_paths:
                    # Add an edge from the importing file to the imported file
                    graph.add_edge(file_path, resolved_path)
        
        return graph

    def create_bundles(self) -> List[ContextBundle]:
        """
        Creates a context bundle for each file in the repository map.
        """
        logger.info("Creating context bundles for all files in the repository map.")
        bundles: List[ContextBundle] = []

        for file_path in self.repository_map.files:
            context_files: Dict[str, str] = {}
            
            # Add the target file itself
            context_files[file_path] = self.files[file_path]
            
            # Find direct dependencies from the graph
            if file_path in self.graph:
                dependencies = self.graph.successors(file_path)
                for dep_path in dependencies:
                    if dep_path in self.files:
                        context_files[dep_path] = self.files[dep_path]
            
            bundles.append(
                ContextBundle(
                    target_file_path=file_path,
                    context_files=context_files
                )
            )
        
        logger.info(f"Successfully created {len(bundles)} context bundles.")
        return bundles