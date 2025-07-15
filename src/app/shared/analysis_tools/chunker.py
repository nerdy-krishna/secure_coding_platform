# src/app/shared/analysis_tools/chunker.py
import logging
from typing import List, Dict, Any
from app.shared.analysis_tools.repository_map import FileSummary
from app.core.schemas import CodeChunk

logger = logging.getLogger(__name__)

def semantic_chunker(file_content: str, file_summary: FileSummary) -> List[CodeChunk]:
    """
    Splits a file's content into semantic chunks based on function/class boundaries.

    Each chunk is a dictionary containing the symbol name, its code, and line numbers.

    A more advanced one would need to find the full block, which is complex.
    Let's assume tree-sitter gives us accurate start/end lines for the whole block.
    The current Symbol object only has `line_number`. This is a problem.
    The `Node` object from tree-sitter has `start_point` and `end_point`.

    """
    chunks = []
    lines = file_content.splitlines(keepends=True)
    
    # Sort symbols by their starting line number to process the file in order
    sorted_symbols = sorted(file_summary.symbols, key=lambda s: s.line_number)

    if not sorted_symbols:
        logger.warning(f"File {file_summary.path} has content but no parsable symbols. Treating as a single chunk.")
        return [{
            "symbol_name": file_summary.path,
            "code": file_content,
            "start_line": 1,
            "end_line": len(lines)
        }]

    for symbol in sorted_symbols:
        # line_number is 1-based, so we subtract 1 for 0-based list index
        start_index = symbol.line_number - 1
        end_index = symbol.end_line_number 

        chunk_content = "".join(lines[start_index:end_index])
        
        chunks.append({
            "symbol_name": symbol.name,
            "code": chunk_content,
            "start_line": symbol.line_number,
            "end_line": symbol.end_line_number,
        })
    
    logger.info(f"Successfully split {file_summary.path} into {len(chunks)} semantic chunks.")
    return chunks