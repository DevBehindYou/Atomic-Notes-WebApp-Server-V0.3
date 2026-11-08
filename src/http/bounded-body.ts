/**
 * Reads at most [maxBytes] of [stream] as strict UTF-8. Returns undefined,
 * after cancelling the stream, when it is larger or is not valid UTF-8.
 * Nothing beyond the cap is read or held. Used for inbound request bodies and
 * outbound responses alike.
 */
export async function readBoundedStreamUtf8(
  stream: ReadableStream<Uint8Array> | null, maxBytes: number,
): Promise<string | undefined> {
  if (stream === null) return '';
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        return undefined;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  }
}
