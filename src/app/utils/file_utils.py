import os
from typing import Optional

LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".html": "html",
    ".css": "css",
    ".scss": "css",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".md": "markdown",
    ".sh": "shell",
    ".swift": "swift",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".rs": "rust",
    ".scala": "scala",
    ".pl": "perl",
    ".pm": "perl",
    ".r": "r",
    ".lua": "lua",
    ".sql": "sql",
    ".xml": "xml",
    ".dart": "dart",
    ".vue": "vue",
    ".svelte": "svelte",
}

def get_language_from_filename(filename: str) -> Optional[str]:
    """Infers language from file extension."""
    if not filename:
        return None
    ext = os.path.splitext(filename)[1].lower()
    return LANGUAGE_EXTENSIONS.get(ext)
