import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type LockReason = "inactivity" | "manual" | "os_session_lock" | "os_suspend";

export interface LockedEventPayload {
  reason: LockReason;
}

export interface ClipboardArmedPayload {
  field: string;
  ttl_secs: number;
}

export async function subscribeVaultEvents(handlers: {
  onLocked: (payload: LockedEventPayload) => void;
  onClipboardArmed: (payload: ClipboardArmedPayload) => void;
  onClipboardCleared: () => void;
}): Promise<UnlistenFn> {
  const unlistenLocked = await listen<LockedEventPayload>("vault://locked", (ev) =>
    handlers.onLocked(ev.payload)
  );
  const unlistenArmed = await listen<ClipboardArmedPayload>(
    "vault://clipboard-armed",
    (ev) => handlers.onClipboardArmed(ev.payload)
  );
  const unlistenCleared = await listen("vault://clipboard-cleared", () =>
    handlers.onClipboardCleared()
  );

  return () => {
    unlistenLocked();
    unlistenArmed();
    unlistenCleared();
  };
}
