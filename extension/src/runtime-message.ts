export async function sendRuntimeMessage<T>(message: unknown): Promise<T> {
  if (!chrome.runtime?.id) {
    throw new Error("扩展环境已更新或失效");
  }
  return await chrome.runtime.sendMessage(message) as T;
}
