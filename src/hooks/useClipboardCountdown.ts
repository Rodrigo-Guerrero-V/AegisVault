// src/hooks/useClipboardCountdown.ts
import { useCallback, useEffect, useState } from "react";
import { vaultCommands } from "../ipc/commands";

export interface ClipboardBannerState {
  field: string;
  totalSecs: number;
  remainingSecs: number;
}

export function useClipboardCountdown() {
  const [banner, setBanner] = useState<ClipboardBannerState | null>(null);

  const armCountdown = useCallback((field: string, ttlSecs: number) => {
    setBanner({
      field,
      totalSecs: ttlSecs,
      remainingSecs: ttlSecs,
    });
  }, []);

  const clearBanner = useCallback(() => {
    setBanner(null);
  }, []);

  const purgeNow = useCallback(async () => {
    await vaultCommands.clearClipboardNow();
    setBanner(null);
  }, []);

  useEffect(() => {
    if (!banner) return;
    const timer = window.setInterval(() => {
      setBanner((prev) => {
        if (!prev) return null;
        if (prev.remainingSecs <= 1) return null;
        return { ...prev, remainingSecs: prev.remainingSecs - 1 };
      });
    }, 1000);
    return () => window.clearInterval(timer);
  }, [banner !== null]);

  return { banner, armCountdown, clearBanner, purgeNow };
}
