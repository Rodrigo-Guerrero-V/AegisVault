import { useState } from "react";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { FolderOpen, Shield, TriangleAlert } from "lucide-react";
import { vaultCommands } from "../ipc/commands";
import { parseVaultError, type VaultSessionInfo } from "../ipc/types";

interface Props {
  onInitialized: (session: VaultSessionInfo) => void;
}

export function OnboardingView({ onInitialized }: Props) {
  const [mode, setMode] = useState<"create" | "restore">("create");
  const [masterPassword, setMasterPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [backupPassword, setBackupPassword] = useState("");
  const [backupPath, setBackupPath] = useState("");
  const [ackNoRecovery, setAckNoRecovery] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const pickBackupFile = async () => {
    const selected = await openDialog({
      multiple: false,
      filters: [{ name: "Respaldo AegisVault", extensions: ["aegisvault"] }],
    });
    if (typeof selected === "string") {
      setBackupPath(selected);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (masterPassword.length < 12) {
      setError("La Contraseña Maestra debe tener al menos 12 caracteres.");
      return;
    }
    if (masterPassword !== confirmPassword) {
      setError("Las contraseñas maestras no coinciden.");
      return;
    }

    setBusy(true);
    try {
      if (mode === "create") {
        const session = await vaultCommands.createVault(masterPassword, ackNoRecovery);
        onInitialized(session);
      } else {
        if (!backupPath) {
          setError("Selecciona un archivo .aegisvault para restaurar.");
          setBusy(false);
          return;
        }
        const session = await vaultCommands.restoreEncryptedBackup(
          backupPath,
          backupPassword,
          masterPassword,
          ackNoRecovery
        );
        onInitialized(session);
      }
    } catch (err) {
      setError(parseVaultError(err).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="auth-shell">
      <div className="auth-card">
        <div className="brand-header">
          <div className="brand-badge">
            <Shield size={22} />
          </div>
          <div>
            <h2 style={{ margin: 0, fontSize: 20 }}>AegisVault</h2>
            <span style={{ fontSize: 12.5, color: "var(--text-secondary)" }}>
              Bóveda Local Zero-Knowledge · AES-256-GCM + Argon2id
            </span>
          </div>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 16 }}>
          <button
            type="button"
            className={`btn ${mode === "create" ? "btn-primary" : "btn-secondary"}`}
            onClick={() => setMode("create")}
          >
            Crear nueva bóveda
          </button>
          <button
            type="button"
            className={`btn ${mode === "restore" ? "btn-primary" : "btn-secondary"}`}
            onClick={() => setMode("restore")}
          >
            Restaurar .aegisvault
          </button>
        </div>

        <div className="alert-box alert-warn" style={{ display: "flex", gap: 10 }}>
          <TriangleAlert size={18} style={{ flexShrink: 0, marginTop: 2 }} />
          <div>
            <strong>Sin servidor ni recuperación de contraseña:</strong> Tu Contraseña Maestra
            jamás se almacena en este equipo ni se envía por red. Si la olvidas y no posees un
            respaldo cifrado <code>.aegisvault</code>, los datos serán irrecuperables.
          </div>
        </div>

        {error && <div className="alert-box alert-error">{error}</div>}

        <form onSubmit={handleSubmit}>
          {mode === "restore" && (
            <>
              <div className="field-group">
                <label className="field-label">Archivo de respaldo (.aegisvault)</label>
                <div style={{ display: "flex", gap: 8 }}>
                  <input
                    className="text-input"
                    readOnly
                    value={backupPath}
                    placeholder="Ningún archivo seleccionado"
                  />
                  <button type="button" className="btn btn-secondary" onClick={pickBackupFile}>
                    <FolderOpen size={15} />
                    Elegir
                  </button>
                </div>
              </div>

              <div className="field-group">
                <label className="field-label">Contraseña del archivo de respaldo</label>
                <input
                  className="text-input"
                  type="password"
                  required
                  value={backupPassword}
                  onChange={(e) => setBackupPassword(e.target.value)}
                />
              </div>
            </>
          )}

          <div className="field-group">
            <label className="field-label">
              {mode === "create" ? "Contraseña Maestra (mínimo 12 caracteres)" : "Nueva Contraseña Maestra local"}
            </label>
            <input
              className="text-input"
              type="password"
              required
              minLength={12}
              value={masterPassword}
              onChange={(e) => setMasterPassword(e.target.value)}
            />
          </div>

          <div className="field-group">
            <label className="field-label">Confirmar Contraseña Maestra</label>
            <input
              className="text-input"
              type="password"
              required
              minLength={12}
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
            />
          </div>

          <label
            style={{
              display: "flex",
              alignItems: "flex-start",
              gap: 9,
              fontSize: 12.5,
              color: "var(--text-secondary)",
              marginBottom: 18,
              cursor: "pointer",
            }}
          >
            <input
              type="checkbox"
              checked={ackNoRecovery}
              onChange={(e) => setAckNoRecovery(e.target.checked)}
              style={{ marginTop: 3 }}
            />
            <span>
              Entiendo que no existe recuperación de Contraseña Maestra y que debo exportar un
              respaldo cifrado desde Ajustes.
            </span>
          </label>

          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: "100%" }}
            disabled={busy || !ackNoRecovery}
          >
            {busy
              ? "Derivando clave con Argon2id (64 MiB)..."
              : mode === "create"
              ? "Inicializar bóveda cifrada"
              : "Restaurar y cifrar bóveda"}
          </button>
        </form>
      </div>
    </div>
  );
}
