# src/app/analysis/repository_map.py

import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

from pydantic import BaseModel, Field
import tree_sitter # Added for version logging
import tree_sitter_languages # Added for version logging
from tree_sitter import Language, Node, Parser, Tree # Language is important
from tree_sitter_languages import get_language

# Custom exception for grammar loading issues
class GrammarLoadingError(Exception):
    pass

# --- Pydantic Models for Repository Structure ---

class Symbol(BaseModel):
    """Represents a defined symbol in a file, like a function or class."""
    name: str = Field(..., description="The name of the symbol.")
    type: str = Field(..., description="The type of the symbol (e.g., 'function', 'class').")
    line_number: int = Field(..., description="The line number where the symbol is defined.")

class FileSummary(BaseModel):
    """A summary of a single file's structure."""
    path: str = Field(..., description="The path to the file.")
    imports: List[str] = Field(default_factory=list, description="A list of imported modules.")
    symbols: List[Symbol] = Field(default_factory=list, description="A list of symbols defined in the file.")
    errors: List[str] = Field(default_factory=list, description="Any errors encountered during parsing.")

class RepositoryMap(BaseModel):
    """The complete map of the repository's structure."""
    files: Dict[str, FileSummary] = Field(default_factory=dict, description="A mapping from file paths to their summaries.")

# --- Language-Specific Queries for Tree-sitter ---

LANGUAGE_QUERIES = {
    "python": {
        "imports": """
            (import_statement name: (dotted_name) @import)
            (import_from_statement module_name: (dotted_name) @import)
        """,
        "symbols": """
            (function_definition name: (identifier) @name) @type
            (class_definition name: (identifier) @name) @type
        """,
    },
    "java": {
        "imports": "(import_declaration (scoped_identifier) @import)",
        "symbols": """
            (class_declaration name: (identifier) @name) @type
            (method_declaration name: (identifier) @name) @type
            (interface_declaration name: (identifier) @name) @type
        """,
    },
    "javascript": {
        "imports": """
            (import_statement source: (string) @import)
            (call_expression function: (identifier) @_func (#eq? @_func "require") arguments: (arguments (string) @import))
        """,
        "symbols": """
            (function_declaration name: (identifier) @name) @type
            (class_declaration name: (identifier) @name) @type
            (method_definition name: (property_identifier) @name) @type
            (variable_declarator name: (identifier) @name value: [(arrow_function) (function)]) @type
        """,
    },
    "typescript": {
        "imports": """
            (import_statement source: (string) @import)
        """,
        "symbols": """
            (function_declaration name: (identifier) @name) @type
            (class_declaration name: (type_identifier) @name) @type
            (method_definition name: (property_identifier) @name) @type
            (interface_declaration name: (type_identifier) @name) @type
        """,
    },
    "go": {
        "imports": "(import_spec (interpreted_string_literal) @import)",
        "symbols": """
            (function_declaration name: (identifier) @name) @type
            (method_declaration name: (field_identifier) @name) @type
            (type_spec (type_identifier) @name) @type
        """,
    },
    "c_sharp": {
        "imports": "(using_directive (name_equals) @import)",
        "symbols": """
            (class_declaration name: (identifier) @name) @type
            (method_declaration name: (identifier) @name) @type
            (interface_declaration name: (identifier) @name) @type
            (struct_declaration name: (identifier) @name) @type
        """,
    },
    "c_plus_plus": {
        "imports": "(preproc_include path: [ (string_literal) (system_lib_string) ] @import)",
        "symbols": """
            (function_definition declarator: (function_declarator declarator: (identifier) @name)) @type
            (class_specifier name: (type_identifier) @name) @type
            (struct_specifier name: (type_identifier) @name) @type
        """,
    },
    "php": {
        "imports": """
            (use_declaration) @import
            (require_expression) @import
            (include_expression) @import
        """,
        "symbols": """
            (function_definition name: (name) @name) @type
            (class_declaration name: (name) @name) @type
            (method_declaration name: (name) @name) @type
        """,
    },
    "ruby": {
        "imports": """
            (call method: (identifier) @_func (#eq? @_func "require") argument: (string) @import)
        """,
        "symbols": """
            (class name: (constant) @name) @type
            (module name: (constant) @name) @type
            (method name: (identifier) @name) @type
        """,
    },
    "rust": {
        "imports": "(use_declaration (use_wildcard) @import)",
        "symbols": """
            (function_item name: (identifier) @name) @type
            (struct_item name: (type_identifier) @name) @type
            (enum_item name: (type_identifier) @name) @type
            (impl_item) @type
        """,
    },
    "kotlin": {
        "imports": "(import_header (identifier) @import)",
        "symbols": """
            (class_declaration name: (simple_identifier) @name) @type
            (function_declaration name: (simple_identifier) @name) @type
        """,
    },
    "swift": {
        "imports": "(import_declaration import_path: (identifier) @import)",
        "symbols": """
            (class_declaration name: (identifier) @name) @type
            (struct_declaration name: (identifier) @name) @type
            (function_declaration name: (identifier) @name) @type
        """,
    },
    "sql": {
        "imports": "", # SQL does not have a standard import mechanism
        "symbols": """
            (create_function_statement) @type
            (create_procedure_statement) @type
            (create_table_statement) @type
            (create_view_statement) @type
        """,
    },
    "bash": {
        "imports": "(command name: (command_name (word) @_cmd) (#eq? @_cmd \"source\") argument: (word) @import)",
        "symbols": "(function_definition (word) @name) @type",
    },
    "html": {
        "imports": """
            (element (start_tag (tag_name) @_tag (#eq? @_tag "script")) (attribute (attribute_name) @_attr (#eq? @_attr "src") (quoted_attribute_value (attribute_value) @import)))
            (element (self_closing_tag (tag_name) @_tag (#eq? @_tag "link")) (attribute (attribute_name) @_attr (#eq? @_attr "href") (quoted_attribute_value (attribute_value) @import)))
        """,
        "symbols": "", # Not applicable in the same way
    },
    "css": {
        "imports": "(import_statement (string_value) @import)",
        "symbols": "(class_selector (class_name) @name) @type",
    },
    "r": {"imports": "", "symbols": ""},
    "matlab": {"imports": "", "symbols": ""},
}


class RepositoryMappingEngine:
    """
    Parses a collection of source code files using tree-sitter to create a
    structured map of the repository, identifying imports and key symbols.
    """
    def __init__(self):
        self.parser = Parser()
        self.supported_languages: Dict[str, Language] = {}
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)


    def _get_language_handler(self, file_path: str) -> Tuple[str, Language]:
        """
        Determines the tree-sitter language based on the file extension.
        Raises GrammarLoadingError if the language cannot be loaded.
        """
        lang_map = {
            ".py": "python", ".java": "java", ".js": "javascript", ".mjs": "javascript",
            ".cs": "c_sharp", ".sql": "sql", ".ts": "typescript", ".go": "go",
            ".cpp": "c_plus_plus", ".hpp": "c_plus_plus", ".h": "c_plus_plus", ".c": "c",
            ".php": "php", ".kt": "kotlin", ".kts": "kotlin", ".swift": "swift",
            ".rb": "ruby", ".r": "r", ".rs": "rust", ".m": "matlab", ".sh": "bash",
            ".html": "html", ".css": "css",
        }
        extension = Path(file_path).suffix
        lang_name = lang_map.get(extension)

        if not lang_name:
            raise GrammarLoadingError(f"No language configured for file extension '{extension}' (file: {file_path})")

        try:
            self.logger.info(
                f"Attempting to load grammar for '{lang_name}'. "
                f"tree-sitter-languages version: {tree_sitter_languages.__version__}"
            )
            language = get_language(lang_name) # This is where the original error occurs
            if language is None: # Defensive check, get_language usually raises on failure
                raise GrammarLoadingError(f"get_language('{lang_name}') returned None for {file_path}")
            return lang_name, language
        except Exception as e:
            # This catches the original "TypeError: __init__()..." and other loading issues
            self.logger.error(f"Failed to load grammar for language '{lang_name}' for {file_path}: {e}", exc_info=True)
            raise GrammarLoadingError(f"Could not load grammar for language '{lang_name}' (file: {file_path}): {e}") from e

    def _execute_query(self, tree: Tree, language: Language, lang_name: str, query_name: str) -> List[Tuple[Node, str]]:
        """Executes a named tree-sitter query and returns the captures."""
        if lang_name == "csharp": lang_name = "c_sharp"
        if lang_name == "cpp": lang_name = "c_plus_plus"

        query_string = LANGUAGE_QUERIES.get(lang_name, {}).get(query_name)
        if not query_string:
            return []
        
        try:
            query = language.query(query_string)
            captures = query.captures(tree.root_node)
            return captures # type: ignore
        except Exception as e:
            self.logger.error(f"Failed to execute query '{query_name}' for {lang_name}: {e}")
            return []

    def _parse_file(self, file_path: str, content: str) -> FileSummary:
        """Parses a single file and extracts its structure."""
        summary = FileSummary(path=file_path)
        
        # _get_language_handler now raises GrammarLoadingError if it fails.
        # The error will propagate up to create_map if not caught here.
        lang_name, language = self._get_language_handler(file_path)

        self.parser.set_language(language) # type: ignore
        
        try:
            tree = self.parser.parse(bytes(content, "utf8"))
        except Exception as e:
            summary.errors.append(f"Tree-sitter failed to parse file: {e}")
            return summary

        import_captures = self._execute_query(tree, language, lang_name, "imports")
        for node, _ in import_captures:
            # FIX: Check if node.text is not None before decoding
            if node.text:
                summary.imports.append(node.text.decode('utf8').strip('\'"<>'))
        
        symbol_captures = self._execute_query(tree, language, lang_name, "symbols")
        
        processed_symbols = {}
        for node, capture_name in symbol_captures:
            if capture_name == "type":
                symbol_type = node.type
                name_node = next((n for n, c in symbol_captures if c == 'name' and n.start_byte >= node.start_byte and n.end_byte <= node.end_byte), None)
                
                if name_node and name_node.text:
                    # FIX: Check if name_node.text is not None before decoding
                    symbol_name = name_node.text.decode('utf8')
                    line_number = node.start_point[0] + 1
                    
                    if (symbol_name, line_number) not in processed_symbols:
                        symbol = Symbol(name=symbol_name, type=symbol_type, line_number=line_number)
                        summary.symbols.append(symbol)
                        processed_symbols[(symbol_name, line_number)] = symbol
        return summary

    def create_map(self, files: Dict[str, str]) -> RepositoryMap:
        """
        Creates a complete repository map from a dictionary of file paths to content.
        If any file fails critical parsing due to grammar issues, this method
        will raise a GrammarLoadingError.
        """
        self.logger.info(f"Starting repository mapping for {len(files)} files.")
        repo_map = RepositoryMap()
        for file_path, content in files.items():
            if not content.strip():
                self.logger.info(f"Skipping empty file: {file_path}")
                repo_map.files[file_path] = FileSummary(path=file_path, errors=["Skipped empty file."])
                continue
            
            self.logger.info(f"Parsing file: {file_path}")
            try:
                file_summary = self._parse_file(file_path, content)
                repo_map.files[file_path] = file_summary
            except GrammarLoadingError as e:
                # Log as warning and skip the file, but continue with others.
                self.logger.warning(f"Skipping file due to GrammarLoadingError: {file_path}. Error: {e}")
                summary = FileSummary(path=file_path)
                summary.errors.append(f"Skipped due to missing language grammar: {str(e)}")
                repo_map.files[file_path] = summary
                # Continue with other files
            except Exception as e: # Catch other unexpected errors during _parse_file for this specific file
                self.logger.error(f"Unexpected error parsing file {file_path}, skipping this file: {e}", exc_info=True)
                summary = FileSummary(path=file_path)
                summary.errors.append(f"Unexpected error during parsing: {str(e)}")
                repo_map.files[file_path] = summary
                # Continue with other files for non-GrammarLoadingError issues
        
        self.logger.info("Repository mapping complete.")
        return repo_map
