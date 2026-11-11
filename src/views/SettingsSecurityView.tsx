import { useEffect, useState } from "react";
import {
  Download,
  EyeOff,
  Fingerprint,
  KeyRound,
  Moon,
  ShieldAlert,
  Sun,
  Upload,
} from "lucide-react";
import { useTheme } from "../hooks/useTheme";
import { vaultCommands } from "../ipc/commands";
import { parseVaultError, type SecurityPrefsDto } from "../ipc/types";

interface Props {
  onVaultMutated: () => void;
}

export function SettingsSecurityView({ onVaultMutated }: Props) {
  const { isDark, preference, setDarkMode, resetToSystem } = useTheme();
  const [prefs, setPrefs] = useState<SecurityPrefsDto | null>(null);
  const [lockSecs, setLockSecs] = useState(300);
  const [clipSecs, setClipSecs] = useState(25);
  const [captureProtected, setCaptureProtected] = useState(true);

  const [helloPassword, setHelloPassword] = useState("");

  const [currPass, setCurrPass] = useState("");
  const [newPass, setNewPass] = useState("");
  const [confirmNewPass, setConfirmNewPass] = useState("");

  const [exportMasterPass, setExportMasterPass] = useState("");
  const [exportBackupPass, setExportBackupPass] = useState("");
  const [corruptRecoveryMsg, setCorruptRecoveryMsg] = useState<string | null>(null);
  const [importBackupPass, setImportBackupPass] = useState("");

  const [feedback, setFeedback] = useState<{ type: "ok" | "err"; msg: string } | null>(null);
  const [busy, setBusy] = useState(false);

  const refreshPrefs = async () => {
    try {
      const p = await vaultCommands.getSecurityPrefs();
      setPrefs(p);
      setLockSecs(p.lock_timeout_secs);
      setClipSecs(p.clipboard_ttl_secs);
      setCaptureProtected(p.capture_protection_enabled);
    } catch (err) {
      notifyErr(err);
    }
  };

  useEffect(() => {
    void refreshPrefs();
  }, []);

  const notifyOk = (msg: string) => setFeedback({ type: "ok", msg });
  const notifyErr = (err: unknown) => {
    const parsed = parseVaultError(err);
    if (parsed.code !== "DIALOG_CANCELLED") {
      setFeedback({ type: "err", msg: parsed.message });
    }
  };

  const handleSaveTimers = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await vaultCommands.updateSecurityPrefs(lockSecs, clipSecs, captureProtected);
      notifyOk("Preferencias autenticadas de autoprotección actualizadas.");
    } catch (err) {
      notifyErr(err);
    } finally {
      setBusy(false);
    }
  };

  const handleToggleCaptureProtection = async (enabled: boolean) => {
    setCaptureProtected(enabled);
    setBusy(true);
    try {
      await vaultCommands.updateSecurityPrefs(lockSecs, clipSecs, enabled);
      notifyOk(
        enabled
          ? "Protección contra capturas de pantalla activada (WDA_EXCLUDEFROMCAPTURE)."
          : "Protección contra capturas desactivada temporalmente."
      );
    } catch (err) {
      setCaptureProtected(!enabled);
      notifyErr(err);
    } finally {
      setBusy(false);
    }
  };

  const handleRotatePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPass.length < 12) {
      setFeedback({
        type: "err",
        msg: "La nueva Contraseña Maestra requiere mínimo 12 caracteres.",
      });
      return;
    }
    if (newPass !== confirmNewPass) {
      setFeedback({
        type: "err",
        msg: "La confirmación de la nueva contraseña no coincide.",
      });
      return;
    }
    setBusy(true);
    try {
      const res = await vaultCommands.changeMasterPassword(currPass, newPass);
      setCurrPass("");
      setNewPass("");
      setConfirmNewPass("");
      await refreshPrefs();
      notifyOk(
        res.hello_was_reset
          ? "Contraseña Maestra rotada con nuevo salt. Windows Hello fue invalidado por seguridad."
          : "Contraseña Maestra rotada con éxito."
      );
    } catch (err) {
      notifyErr(err);
    } finally {
      setBusy(false);
    }
  };

  const runExport = async (skipCorrupted: boolean) => {
    setBusy(true);
    setCorruptRecoveryMsg(null);
    try {
      const res = await vaultCommands.exportEncryptedBackup(
        exportMasterPass,
        exportBackupPass,
        skipCorrupted
      );
      setExportMasterPass("");
      setExportBackupPass("");
      notifyOk(
        res.skipped_corrupted > 0
          ? `Respaldo exportado omitiendo ${res.skipped_corrupted} registro(s) dañados.`
          : "Respaldo cifrado .aegisvault exportado correctamente."
      );
    } catch (err) {
      const parsed = parseVaultError(err);
      if (parsed.code === "DIALOG_CANCELLED") {
        return;
      }
      if (parsed.code === "DATA_CORRUPTED") {
        setCorruptRecoveryMsg(parsed.message);
        return;
      }
      setFeedback({ type: "err", msg: parsed.message });
    } finally {
      setBusy(false);
    }
  };

  const handleExport = async (e: React.FormEvent) => {
    e.preventDefault();
    await runExport(false);
  };

  const handleImport = async () => {
    if (!importBackupPass) {
      setFeedback({
        type: "err",
        msg: "Ingresa primero la contraseña del archivo .aegisvault.",
      });
      return;
    }

    setBusy(true);
    try {
      const stats = await vaultCommands.importEncryptedBackup(importBackupPass);
      setImportBackupPass("");
      onVaultMutated();
      const skippedTotal = stats.folders_skipped + stats.items_skipped;
      const skipSuffix =
        skippedTotal > 0
          ? ` (${stats.folders_skipped} carpetas y ${stats.items_skipped} ítems idénticos omitidos sin duplicar).`
          : ".";
      notifyOk(
        `Importación completada: ${stats.folders_imported} carpetas y ${stats.items_imported} ítems fusionados${skipSuffix}`
      );
    } catch (err) {
      notifyErr(err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="settings-wrap">
      <h2 style={{ marginTop: 0 }}>Seguridad y Respaldos</h2>

      {feedback && (
        <div className={`alert-box ${feedback.type === "ok" ? "alert-ok" : "alert-error"}`}>
          {feedback.msg}
        </div>
      )}

      {/* Apariencia: Tema claro / oscuro */}
      <div className="secret-field-card" style={{ display: "block", marginBottom: 18 }}>
        <div className="set-row">
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
              {isDark ? (
                <Moon size={18} color="var(--accent)" />
              ) : (
                <Sun size={18} color="var(--accent)" />
              )}
              <h4 style={{ margin: 0 }}>Tema oscuro</h4>
            </div>
            <p style={{ fontSize: 13, color: "var(--text-secondary)", margin: 0 }}>
              Tema claro por defecto. Se activa automáticamente con{" "}
              <code>prefers-color-scheme: dark</code> o de forma manual desde este interruptor
              {preference === null ? " (siguiendo al sistema)." : " (selección manual activa)."}
            </p>
          </div>
          <label className="switch">
            <input
              type="checkbox"
              checked={isDark}
              onChange={(e) => setDarkMode(e.target.checked)}
              aria-label="Activar tema oscuro"
            />
            <span className="track" />
          </label>
        </div>
        {preference !== null && (
          <div style={{ marginTop: 10 }}>
            <button type="button" className="btn btn-secondary btn-small" onClick={resetToSystem}>
              Seguir preferencia del sistema
            </button>
          </div>
        )}
      </div>

      {/* Protección anticaptura Win32 WDA_EXCLUDEFROMCAPTURE */}
      <div className="secret-field-card" style={{ display: "block", marginBottom: 18 }}>
        <div className="set-row">
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
              <EyeOff size={18} color="var(--accent)" />
              <h4 style={{ margin: 0 }}>Bloquear capturas de pantalla</h4>
            </div>
            <p style={{ fontSize: 13, color: "var(--text-secondary)", margin: 0 }}>
              Oculta la ventana ante herramientas de captura, grabación de escritorio y Windows
              Recall mediante <code>WDA_EXCLUDEFROMCAPTURE</code>.
            </p>
          </div>
          <label className="switch">
            <input
              type="checkbox"
              checked={captureProtected}
              disabled={busy}
              onChange={(e) => void handleToggleCaptureProtection(e.target.checked)}
              aria-label="Bloquear capturas de pantalla"
            />
            <span className="track" />
          </label>
        </div>
      </div>

      {/* Tiempos de autoprotección */}
      <form onSubmit={handleSaveTimers} className="secret-field-card" style={{ display: "block" }}>
        <h4 style={{ marginTop: 0 }}>Autoprotección de sesión y portapapeles</h4>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
          <div className="field-group">
            <label className="field-label">Bloqueo por inactividad (segundos)</label>
            <input
              type="number"
              min={15}
              max={3600}
              className="text-input"
              value={lockSecs}
              onChange={(e) => setLockSecs(Number(e.target.value))}
            />
          </div>
          <div className="field-group">
            <label className="field-label">Autolimpieza de portapapeles (segundos)</label>
            <input
              type="number"
              min={5}
              max={300}
              className="text-input"
              value={clipSecs}
              onChange={(e) => setClipSecs(Number(e.target.value))}
            />
          </div>
        </div>
        <button type="submit" className="btn btn-primary" disabled={busy}>
          Guardar preferencias
        </button>
      </form>

      {/* Windows Hello opcional */}
      <div className="secret-field-card" style={{ display: "block", marginTop: 18 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
          <Fingerprint size={18} color="var(--accent)" />
          <h4 style={{ margin: 0 }}>Desbloqueo rápido con Windows Hello (TPM)</h4>
        </div>
        <p style={{ fontSize: 12.5, color: "var(--text-secondary)", marginTop: 0 }}>
          Envuelve una copia autenticada de <code>VaultKey</code> dentro de Microsoft Passport KSP
          sin reemplazar jamás tu Contraseña Maestra.
        </p>

        {prefs?.hello_enabled ? (
          <button
            type="button"
            className="btn btn-danger"
            disabled={busy}
            onClick={async () => {
              try {
                await vaultCommands.disableWindowsHello();
                await refreshPrefs();
                notifyOk("Atajo de Windows Hello desactivado y clave TPM eliminada.");
              } catch (err) {
                notifyErr(err);
              }
            }}
          >
            Desactivar Windows Hello
          </button>
        ) : (
          <div style={{ display: "flex", gap: 8 }}>
            <input
              type="password"
              className="text-input"
              placeholder="Confirma tu Contraseña Maestra"
              value={helloPassword}
              onChange={(e) => setHelloPassword(e.target.value)}
            />
            <button
              type="button"
              className="btn btn-secondary"
              disabled={busy || !prefs?.hello_available || !helloPassword}
              onClick={async () => {
                try {
                  await vaultCommands.enableWindowsHello(helloPassword);
                  setHelloPassword("");
                  await refreshPrefs();
                  notifyOk("Windows Hello habilitado correctamente.");
                } catch (err) {
                  notifyErr(err);
                }
              }}
            >
              {prefs?.hello_available ? "Habilitar Hello" : "No disponible en este equipo"}
            </button>
          </div>
        )}
      </div>

      {/* Rotación de Contraseña Maestra */}
      <form
        onSubmit={handleRotatePassword}
        className="secret-field-card"
        style={{ display: "block", marginTop: 18 }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
          <KeyRound size={18} color="var(--accent)" />
          <h4 style={{ margin: 0 }}>Cambiar Contraseña Maestra</h4>
        </div>
        <div className="field-group">
          <label className="field-label">Contraseña Maestra actual</label>
          <input
            type="password"
            className="text-input"
            required
            value={currPass}
            onChange={(e) => setCurrPass(e.target.value)}
          />
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <div className="field-group">
            <label className="field-label">Nueva Contraseña Maestra (mín. 12, alta entropía)</label>
            <input
              type="password"
              className="text-input"
              required
              minLength={12}
              value={newPass}
              onChange={(e) => setNewPass(e.target.value)}
            />
          </div>
          <div className="field-group">
            <label className="field-label">Confirmar nueva contraseña</label>
            <input
              type="password"
              className="text-input"
              required
              minLength={12}
              value={confirmNewPass}
              onChange={(e) => setConfirmNewPass(e.target.value)}
            />
          </div>
        </div>
        <button type="submit" className="btn btn-primary" disabled={busy}>
          Re-derivar clave y actualizar envoltura
        </button>
      </form>

      {/* Exportación e importación .aegisvault */}
      <form
        onSubmit={handleExport}
        className="secret-field-card"
        style={{ display: "block", marginTop: 18 }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
          <ShieldAlert size={18} color="var(--warning)" />
          <h4 style={{ margin: 0 }}>Respaldos Cifrados (.aegisvault)</h4>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
          <div className="field-group">
            <label className="field-label">Contraseña Maestra actual (verificación)</label>
            <input
              type="password"
              className="text-input"
              required
              value={exportMasterPass}
              onChange={(e) => setExportMasterPass(e.target.value)}
            />
          </div>
          <div className="field-group">
            <label className="field-label">Contraseña para cifrar el archivo (mín. 12)</label>
            <input
              type="password"
              className="text-input"
              required
              minLength={12}
              value={exportBackupPass}
              onChange={(e) => setExportBackupPass(e.target.value)}
            />
          </div>
        </div>

        {corruptRecoveryMsg && (
          <div className="alert-box alert-warn" style={{ marginBottom: 12 }}>
            <div style={{ marginBottom: 8 }}>{corruptRecoveryMsg}</div>
            <button
              type="button"
              className="btn btn-secondary btn-small"
              disabled={busy}
              onClick={() => void runExport(true)}
            >
              Exportar omitiendo registros dañados
            </button>
          </div>
        )}

        <button type="submit" className="btn btn-primary" disabled={busy}>
          <Download size={15} />
          Exportar respaldo .aegisvault
        </button>

        <hr style={{ borderColor: "var(--border-subtle)", margin: "18px 0" }} />

        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <input
            type="password"
            className="text-input"
            placeholder="Contraseña del respaldo .aegisvault a fusionar"
            value={importBackupPass}
            onChange={(e) => setImportBackupPass(e.target.value)}
          />
          <button type="button" className="btn btn-secondary" disabled={busy} onClick={handleImport}>
            <Upload size={15} />
            Importar respaldo
          </button>
        </div>
      </form>
    </div>
  );
}
