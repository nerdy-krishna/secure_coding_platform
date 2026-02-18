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

    # --- Extract Preamble: all lines before the first symbol (Imports, constants, etc.) ---
    # We treat everything before the first symbol as "preamble" to be shared, 
    # BUT we also want the first chunk to explicitly *own* that region for scanning purposes 
    # if it's not covered by a specialized "preamble" chunk (which we don't have).
    # However, to avoid duplication in "fixes", we usually stick to the symbol.
    # But for "Scanning Comments", we need to see them.
    # Strategy: The Preamble is prepended as CONTEXT (commented out or marked) in Issue #4.
    # Now, for Issue #6, we want to include gaps *between* symbols.
    
    first_symbol_line = sorted_symbols[0].line_number  # 1-based
    
    # 1. Generate the shared preamble context (as implemented in Issue #4)
    preamble_context = ""
    if first_symbol_line > 1:
        preamble_lines = lines[:first_symbol_line - 1]
        preamble_text = "".join(preamble_lines).strip()
        if preamble_text:
            preamble_context = f"# --- [FILE PREAMBLE: imports & constants] ---\n{preamble_text}\n# --- [END FILE PREAMBLE] ---\n\n"

    last_end_line = 0 # 0-based index of the last processed line
    
    for i, symbol in enumerate(sorted_symbols):
        # symbol.line_number is 1-based.
        symbol_start_idx = symbol.line_number - 1
        symbol_end_idx = symbol.end_line_number 
        
        # Check for gap before this symbol (but after the previous symbol)
        # For the first symbol, the "gap" is the preamble. 
        # We might want to include the preamble in the FIRST chunk's *scan scope* 
        # so findings in imports/constants are reported.
        # Let's say we extend the start backwards to 'last_end_line'.
        
        # If it's the first symbol, 'last_end_line' is 0. 
        # So we capture 0 to symbol_start_idx.
        # If it's the second symbol, 'last_end_line' is prev_symbol_end.
        
        # However, we must be careful not to duplicate the Preamble Context as "Code to be fixed" 
        # and "Context".
        # If we include the preamble in the first chunk's "code", we don't need to prepend `preamble_context` 
        # because it's already there!
        
        # Decision: For the FIRST chunk, we include the top of file (lines 0 to symbol_start).
        # For subsequent chunks, we include the gap (prev_end to current_start).
        
        current_start_idx = symbol_start_idx
        
        # Extend backwards to cover the gap
        if current_start_idx > last_end_line:
            current_start_idx = last_end_line
        
        # Update the chunk's content to include the gap
        chunk_content = "".join(lines[current_start_idx:symbol_end_idx])
        
        # Calculate the effective start line (1-based)
        chunk_start_line = current_start_idx + 1
        
        # Prepend preamble context ONLY if we are NOT the first chunk (because the first chunk already contains it naturally)
        # Wait, if we extended the first chunk to 0, it CONTAINS the imports.
        # So we don't need `preamble_context` for the first chunk.
        # But subsequent chunks (which don't include lines 0-N) DO need the preamble context.
        
        final_code = chunk_content
        if i > 0 and preamble_context:
            final_code = f"{preamble_context}{chunk_content}"
            
        chunks.append({
            "symbol_name": symbol.name,
            "code": final_code,
            "start_line": chunk_start_line,
            "end_line": symbol.end_line_number,
        })
        
        last_end_line = symbol_end_idx
        
    # Check for trailing content after the last symbol
    if last_end_line < len(lines):
        # formatting cleanup or footer comments
        # We can append this to the LAST chunk, or create a new "Footer" chunk.
        # Appending to the last chunk is safest to ensure it gets scanned.
        if chunks:
            last_chunk = chunks[-1]
            trailing_content = "".join(lines[last_end_line:])
            if trailing_content.strip():
                 # Append to the code
                 last_chunk['code'] += trailing_content
                 last_chunk['end_line'] = len(lines)
                 logger.info(f"Appended trailing content to last chunk '{last_chunk['symbol_name']}'")
    
    logger.info(f"Successfully split {file_summary.path} into {len(chunks)} semantic chunks with gap coverage.")
    return chunks