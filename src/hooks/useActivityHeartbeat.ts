// src/hooks/useActivityHeartbeat.ts
import { useEffect, useRef } from "react";
import { vaultCommands } from "../ipc/commands";

const THROTTLE_MS = 2000;

export function useActivityHeartbeat(enabled: boolean) {
  const lastSentRef = useRef<number>(0);

  useEffect(() => {
    if (!enabled) return;

    const notify = () => {
      const now = Date.now();
      if (now - lastSentRef.current >= THROTTLE_MS) {
        lastSentRef.current = now;
        void vaultCommands.recordUserActivity().catch(() => {});
      }
    };

    window.addEventListener("pointerdown", notify, { passive: true });
    window.addEventListener("keydown", notify, { passive: true });
    window.addEventListener("wheel", notify, { passive: true });

    return () => {
      window.removeEventListener("pointerdown", notify);
      window.removeEventListener("keydown", notify);
      window.removeEventListener("wheel", notify);
    };
  }, [enabled]);
}
