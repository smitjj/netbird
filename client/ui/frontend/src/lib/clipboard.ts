import { Clipboard } from "@wailsio/runtime";

// copyText writes through the native pasteboard: on macOS, WKWebView rejects
// navigator.clipboard.writeText from the wails:// page with NotAllowedError.
export const copyText = (text: string): Promise<void> => Clipboard.SetText(text);
