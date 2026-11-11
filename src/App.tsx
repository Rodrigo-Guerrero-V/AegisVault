// src/App.tsx
import { useEffect, useState } from "react";
import { ClipboardX } from "lucide-react";
import { useActivityHeartbeat } from "./hooks/useActivityHeartbeat";
import { useClipboardCountdown } from "./hooks/useClipboardCountdown";
import { vaultCommands } from "./ipc/commands";
import { subscribeVaultEvents, type LockReason } from "./ipc/events";
import type { VaultStatusDto } from "./ipc/types";
import { OnboardingView } from "./views/OnboardingView";
import { UnlockView } from "./views/UnlockView";
import { VaultView } from "./views/VaultView";

export function App() {
  const [status, setStatus] = useState<VaultStatusDto | null>(null);
  const [lastLockReason, setLastLockReason] = useState<LockReason | null>(null);
  const { banner, armCountdown, clearBanner, purgeNow } = useClipboardCountdown();

  const isUnlocked = Boolean(status && status.initialized && !status.locked);
  useActivityHeartbeat(isUnlocked);

  useEffect(() => {
    void vaultCommands.getVaultStatus().then(setStatus);

    let dispose: (() => void) | undefined;
    void subscribeVaultEvents({
      onLocked: ({ reason }) => {
        setLastLockReason(reason);
        clearBanner();
        setStatus((prev) => (prev ? { ...prev, locked: true } : prev));
      },
      onClipboardArmed: ({ field, ttl_secs }) => {
        armCountdown(field, ttl_secs);
      },
      onClipboardCleared: () => {
        clearBanner();
      },
    }).then((unlisten) => {
      dispose = unlisten;
    });

    return () => {
      dispose?.();
    };
  }, [armCountdown, clearBanner]);

  if (!status) {
    return <div className="auth-shell">Cargando estado criptográfico...</div>;
  }

  return (
    <>
      {!status.initialized ? (
        <OnboardingView
          onInitialized={(session) =>
            setStatus({
              initialized: true,
              locked: false,
              hello_enabled: session.hello_enabled,
              hello_available: status.hello_available,
            })
          }
        />
      ) : status.locked ? (
        <UnlockView
          helloEnabled={status.hello_enabled}
          lastLockReason={lastLockReason}
          onUnlocked={(session) => {
            setLastLockReason(null);
            setStatus((prev) =>
              prev
                ? { ...prev, locked: false, hello_enabled: session.hello_enabled }
                : prev
            );
          }}
          onHelloInvalidated={() =>
            setStatus((prev) => (prev ? { ...prev, hello_enabled: false } : prev))
          }
        />
      ) : (
        <VaultView />
      )}

      {banner && (
        <div className="clipboard-toast">
          <div style={{ fontSize: 13 }}>
            Secreto (<strong>{banner.field}</strong>) en portapapeles · autolimpieza en{" "}
            <strong className="mono">{banner.remainingSecs}s</strong>
          </div>
          <button className="btn btn-secondary" onClick={() => void purgeNow()}>
            <ClipboardX size={14} />
            Limpiar ahora
          </button>
        </div>
      )}
    </>
  );
}
