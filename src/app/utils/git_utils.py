import logging
import os
import shutil
import tempfile
from typing import List, Dict, Optional

from fastapi import HTTPException

# Import GitPython. If 'git' executable is not found, GitPython's import
# itself will raise an ImportError with a descriptive message.
import git

logger = logging.getLogger(__name__)

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
    ext = os.path.splitext(filename)[1].lower()
    return LANGUAGE_EXTENSIONS.get(ext)


def clone_repo_and_get_files(repo_url: str) -> List[Dict[str, str]]:
    """
    Clones a Git repository to a temporary directory, extracts relevant files,
    and returns them as a list of dictionaries.
    """
    files_data = []
    temp_dir = tempfile.mkdtemp()
    try:
        logger.info(f"Cloning repository {repo_url} to {temp_dir}")
        git.Repo.clone_from(repo_url, temp_dir, depth=1) # Shallow clone for speed

        for root, _, filenames in os.walk(temp_dir):
            if ".git" in root.split(os.sep):  # Skip .git directory
                continue
            for filename in filenames:
                file_path = os.path.join(root, filename)
                relative_path = os.path.relpath(file_path, temp_dir)
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    # Remove null bytes, as they are invalid in PostgreSQL UTF-8 strings
                    content = content.replace("\x00", "") 
                    language = get_language_from_filename(filename)
                    files_data.append(
                        {
                            "path": relative_path,
                            "content": content,
                            "language": language or "unknown", # Default to unknown if not recognized
                        }
                    )
                except Exception as e:
                    logger.warning(
                        f"Could not read or process file {file_path}: {e}"
                    )
        logger.info(f"Successfully extracted {len(files_data)} files from {repo_url}")
    except git.GitCommandError as e:
        logger.error(f"Failed to clone repository {repo_url}: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to clone repository: {e.stderr or e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred while processing repository {repo_url}: {e}")
        raise HTTPException(status_code=500, detail=f"Error processing repository: {str(e)}")
    finally:
        shutil.rmtree(temp_dir) # Clean up the temporary directory
    return files_data
