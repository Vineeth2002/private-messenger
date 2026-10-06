# 05 - AI and Language Privacy (future; not in V1)

Status: ARCHITECTURAL (frozen, future).

- Language Lens: one canonical, immutable underlying message; per-recipient presentation preference
  (Original/English/Hindi/Telugu/...). Translation/rewrite is a DERIVED artifact.
- Learning Mode: original, translation, word-level explanation, pronunciation, save phrase.
- Future AI is an extension of communication, not an ambient assistant: rewrite, shorten, translate,
  explain, summarize, semantic search, extract dates/tasks, voice transcription, document Q&A.
- Default model: message decrypted on the recipient device -> AI runs after decryption -> canonical
  message unchanged -> output stored as a derived artifact.
- No server-side ambient model inspects a user's plaintext chat history. Heavy inference may later
  use privacy-preserving India-hosted infrastructure; that design requires its own review.
