# Fork follow-ups

- [ ] Move OCR-only dependencies (`pymupdf`, `google-cloud-vision`) behind an optional extra such as `workspace-mcp[ocr]`, with clear runtime errors when OCR tools are unavailable.
- [ ] Refactor PDF/OCR tools so `ocr_pdf_to_file` uses a shared internal OCR helper instead of calling the decorated MCP tool wrapper.
- [ ] Add focused tests for fork-only extras:
  - Excel and Word module import/registration.
  - Cloud Vision scope and permission mapping.
  - PyMuPDF extraction helper on a small fixture PDF.
  - `ENABLED_SERVICES=drive,excel,word` compatibility with upstream `WORKSPACE_MCP_TOOLS`.
- [ ] Re-evaluate whether Excel and Word should remain standalone services or move under Drive/Docs/Sheets tool subsets.
- [ ] Run a real OAuth smoke test with Flatbee credentials:
  - Drive `list_drive_items`.
  - Excel `list_excel_files`.
  - Word `list_word_files`.
  - OCR auth path for Cloud Vision scope.
