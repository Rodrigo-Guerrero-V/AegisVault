import { useState } from "react";
import { Fingerprint, Lock, Shield } from "lucide-react";
import { vaultCommands } from "../ipc/commands";
import { parseVaultError, type VaultSessionInfo } from "../ipc/types";
import type { LockReason } from "../ipc/events";

interface Props {
  helloEnabled: boolean;
  lastLockReason: LockReason | null;
  onUnlocked: (session: VaultSessionInfo) => void;
  onHelloInvalidated: () => void;
}

export function UnlockView({
  helloEnabled,
  lastLockReason,
  onUnlocked,
  onHelloInvalidated,
}: Props) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handlePasswordUnlock = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const session = await vaultCommands.unlockWithPassword(password);
      setPassword("");
      onUnlocked(session);
    } catch (err) {
      setError(parseVaultError(err).message);
    } finally {
      setBusy(false);
    }
  };

  const handleHelloUnlock = async () => {
    setBusy(true);
    setError(null);
    try {
      const session = await vaultCommands.unlockWithHello();
      onUnlocked(session);
    } catch (err) {
      const parsed = parseVaultError(err);
      if (parsed.code === "HELLO_INVALIDATED") {
        onHelloInvalidated();
      }
      if (parsed.code !== "HELLO_CANCELLED") {
        setError(parsed.message);
      }
    } finally {
      setBusy(false);
    }
  };

  const reasonText: Record<LockReason, string> = {
    inactivity: "Sesión bloqueada automáticamente por inactividad.",
    manual: "Bóveda bloqueada manualmente.",
    os_session_lock: "Bóveda bloqueada al bloquearse la sesión de Windows.",
    os_suspend: "Bóveda bloqueada por suspensión de energía del equipo.",
  };

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <div className="brand-header">
          <div className="brand-badge">
            <Shield size={22} />
          </div>
          <div>
            <h2 style={{ margin: 0, fontSize: 20 }}>Bóveda bloqueada</h2>
            <span style={{ fontSize: 12.5, color: "var(--text-secondary)" }}>
              AegisVault · Claves purgadas de memoria RAM
            </span>
          </div>
        </div>

        {lastLockReason && (
          <div className="alert-box alert-warn">{reasonText[lastLockReason]}</div>
        )}
        {error && <div className="alert-box alert-error">{error}</div>}

        {helloEnabled && (
          <button
            type="button"
            className="btn btn-secondary"
            style={{ width: "100%", marginBottom: 16, padding: "11px 14px" }}
            disabled={busy}
            onClick={handleHelloUnlock}
          >
            <Fingerprint size={18} color="var(--accent)" />
            Desbloquear con Windows Hello
          </button>
        )}

        <form onSubmit={handlePasswordUnlock}>
          <div className="field-group">
            <label className="field-label">Contraseña Maestra</label>
            <input
              className="text-input"
              type="password"
              autoFocus
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Ingresa tu Contraseña Maestra"
            />
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: "100%" }}
            disabled={busy || password.length === 0}
          >
            <Lock size={15} />
            {busy ? "Verificando AEAD..." : "Desbloquear bóveda"}
          </button>
        </form>
      </div>
    </div>
  );
}
